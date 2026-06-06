from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from appsec_harness.agents import CrawlerAgent, discovery_agent_definitions
from appsec_harness.config import AppConfig
from appsec_harness.memory import FileMemory
from appsec_harness.models import CrawledPage, CrawlResult


class FakeCrawlTool:
    class definition:
        name = "fake_crawl"

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(self, url: str, max_pages: int, max_depth: int) -> CrawlResult:
        self.calls.append({"url": url, "max_pages": max_pages, "max_depth": max_depth})
        return CrawlResult(start_url=url, pages=[], out_of_scope=["https://outside.test"], failed=[], robots=None)


class StaticCrawlTool:
    class definition:
        name = "static_crawl"

    def __init__(self, result: CrawlResult) -> None:
        self.result = result
        self.calls = 0

    def run(self, url: str, max_pages: int, max_depth: int) -> CrawlResult:
        self.calls += 1
        return self.result


class FakeKatanaTool(StaticCrawlTool):
    class definition:
        name = "katana_docker_crawler"


class FakeExtractifyTool:
    class definition:
        name = "extractify_js_endpoint_discovery"

    def __init__(self, result: CrawlResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def run(self, start_url: str, js_urls: list[str]) -> CrawlResult:
        self.calls.append({"start_url": start_url, "js_urls": js_urls})
        return self.result


class FakeJsStaticTool(FakeExtractifyTool):
    class definition:
        name = "js_static_endpoint_discovery"


class AgentToolBoundaryTests(unittest.TestCase):
    def test_crawler_agent_invokes_its_owned_tool_and_writes_memory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tool = FakeCrawlTool()
            memory = FileMemory(Path(directory))
            agent = CrawlerAgent(crawl_tool=tool)

            result = agent.discover("https://example.test", memory, max_pages=7, max_depth=3)

            self.assertEqual(result.out_of_scope, ["https://outside.test"])
            self.assertEqual(tool.calls, [{"url": "https://example.test", "max_pages": 7, "max_depth": 3}])

            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            memory_items = json.loads((Path(directory) / "memory.json").read_text(encoding="utf-8"))

            self.assertTrue(any(event["action"] == "tool_call" and event["agent"] == "crawler" for event in events))
            self.assertTrue(any(item["kind"] == "out_of_scope" and item["source"] == "crawler" for item in memory_items))

    def test_crawler_agent_selects_katana_for_javascript_heavy_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            primary = StaticCrawlTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[
                        CrawledPage(
                            url="https://example.test/",
                            status=200,
                            content_type="text/html",
                            title="SPA",
                            headers={},
                            links=[],
                            references=["https://example.test/static/js/main.chunk.js"],
                            forms=[],
                        )
                    ],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                )
            )
            katana = FakeKatanaTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[
                        CrawledPage(
                            url="https://api.example.test/v1/users",
                            status=200,
                            content_type="application/json",
                            title=None,
                            headers={},
                            links=[],
                            references=[],
                            forms=[],
                        )
                    ],
                    out_of_scope=["https://outside.test/api"],
                    failed=[],
                    robots=None,
                )
            )
            extractify = FakeExtractifyTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[
                        CrawledPage(
                            url="https://api.example.test/v1/users",
                            status=0,
                            content_type="",
                            title=None,
                            headers={},
                            links=[],
                            references=["https://example.test/static/js/main.chunk.js"],
                            forms=[],
                        )
                    ],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                )
            )
            memory = FileMemory(Path(directory))
            agent = CrawlerAgent(crawl_tool=primary, additional_tools=[katana, extractify])

            result = agent.discover("https://example.test", memory, max_pages=10, max_depth=2)

            self.assertEqual(primary.calls, 1)
            self.assertEqual(katana.calls, 1)
            self.assertEqual(extractify.calls[0]["js_urls"], ["https://example.test/static/js/main.chunk.js"])
            self.assertIn("https://api.example.test/v1/users", {page.url for page in result.pages})
            self.assertEqual(result.out_of_scope, ["https://outside.test/api"])

            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(
                any(
                    event["action"] == "tool_selection"
                    and "Selecting Katana" in event["message"]
                    and event["agent"] == "crawler"
                    for event in events
                )
            )

    def test_crawler_agent_skips_katana_without_javascript_heavy_signal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            primary = StaticCrawlTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[
                        CrawledPage(
                            url="https://example.test/",
                            status=200,
                            content_type="text/html",
                            title="Plain HTML",
                            headers={},
                            links=["https://example.test/about"],
                            references=[],
                            forms=[],
                        )
                    ],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                )
            )
            katana = FakeKatanaTool(CrawlResult("https://example.test/", [], [], [], None))
            memory = FileMemory(Path(directory))
            agent = CrawlerAgent(crawl_tool=primary, additional_tools=[katana])

            result = agent.discover("https://example.test", memory, max_pages=10, max_depth=2)

            self.assertEqual(primary.calls, 1)
            self.assertEqual(katana.calls, 0)
            self.assertEqual([page.url for page in result.pages], ["https://example.test/"])

    def test_crawler_agent_selects_extractify_for_javascript_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            primary = StaticCrawlTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[
                        CrawledPage(
                            url="https://example.test/",
                            status=200,
                            content_type="text/html",
                            title="App",
                            headers={},
                            links=[],
                            references=["https://example.test/app.js"],
                            forms=[],
                        )
                    ],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                )
            )
            extractify = FakeExtractifyTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[
                        CrawledPage(
                            url="https://example.test/api/login",
                            status=0,
                            content_type="",
                            title=None,
                            headers={},
                            links=[],
                            references=["https://example.test/app.js"],
                            forms=[],
                        )
                    ],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                )
            )
            memory = FileMemory(Path(directory))
            agent = CrawlerAgent(crawl_tool=primary, additional_tools=[extractify])

            result = agent.discover("https://example.test", memory, max_pages=10, max_depth=2)

            self.assertEqual(extractify.calls, [{"start_url": "https://example.test/", "js_urls": ["https://example.test/app.js"]}])
            self.assertIn("https://example.test/api/login", {page.url for page in result.pages})

            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(
                any(
                    event["action"] == "tool_call"
                    and event["data"].get("tool") == "extractify_js_endpoint_discovery"
                    for event in events
                )
            )

    def test_crawler_agent_selects_static_js_analysis_for_javascript_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            primary = StaticCrawlTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[
                        CrawledPage(
                            url="https://example.test/",
                            status=200,
                            content_type="text/html",
                            title="App",
                            headers={},
                            links=[],
                            references=["https://example.test/shell.js"],
                            forms=[],
                        )
                    ],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                )
            )
            js_static = FakeJsStaticTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[
                        CrawledPage(
                            url="https://api.example.test/api/private/auth/login",
                            status=0,
                            content_type="",
                            title=None,
                            headers={},
                            links=[],
                            references=["https://example.test/shell.js"],
                            forms=[],
                        )
                    ],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                )
            )
            memory = FileMemory(Path(directory))
            agent = CrawlerAgent(crawl_tool=primary, additional_tools=[js_static])

            result = agent.discover("https://example.test", memory, max_pages=10, max_depth=2)

            self.assertEqual(js_static.calls, [{"start_url": "https://example.test/", "js_urls": ["https://example.test/shell.js"]}])
            self.assertIn("https://api.example.test/api/private/auth/login", {page.url for page in result.pages})

            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(
                any(
                    event["action"] == "tool_call"
                    and event["data"].get("tool") == "js_static_endpoint_discovery"
                    for event in events
                )
            )

    def test_crawler_agent_tool_result_includes_failure_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            primary = StaticCrawlTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[],
                    out_of_scope=[],
                    failed=[{"url": "https://example.test/", "error": "tool failed"}],
                    robots=None,
                )
            )
            memory = FileMemory(Path(directory))
            agent = CrawlerAgent(crawl_tool=primary)

            agent.discover("https://example.test", memory, max_pages=10, max_depth=2)

            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            tool_result = next(event for event in events if event["action"] == "tool_result")

            self.assertEqual(tool_result["data"]["failed"], 1)
            self.assertEqual(tool_result["data"]["failures"][0]["error"], "tool failed")

    def test_discovery_agent_definitions_include_agent_owned_tools(self) -> None:
        definitions = {definition.name: definition for definition in discovery_agent_definitions(AppConfig())}

        self.assertEqual(
            [tool.name for tool in definitions["crawler"].tools],
            [
                "crawl_application",
                "katana_docker_crawler",
                "extractify_js_endpoint_discovery",
                "js_static_endpoint_discovery",
            ],
        )
        self.assertIsNone(definitions["sbom_compiler"].tools)
        self.assertIsNone(definitions["summarizer"].tools)


if __name__ == "__main__":
    unittest.main()
