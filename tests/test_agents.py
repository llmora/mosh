from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from open_security_harness.crews.discovery.agents import CrawlerAgent, discovery_agent_definitions
from open_security_harness.config import AppConfig
from open_security_harness.memory import FileMemory
from open_security_harness.models import CrawledPage, CrawlResult, DiscoveryCandidate


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


class SequenceCrawlTool:
    class definition:
        name = "crawl_application"

    def __init__(self, results: list[CrawlResult]) -> None:
        self.results = results
        self.calls: list[dict[str, object]] = []

    def run(self, url: str, max_pages: int, max_depth: int) -> CrawlResult:
        self.calls.append({"url": url, "max_pages": max_pages, "max_depth": max_depth})
        if len(self.calls) <= len(self.results):
            return self.results[len(self.calls) - 1]
        return self.results[-1]


class FakeKatanaTool(StaticCrawlTool):
    class definition:
        name = "katana_docker_crawler"


class FakeDirbTool(StaticCrawlTool):
    class definition:
        name = "dirb_docker_discovery"


class FakeExtractifyTool:
    class definition:
        name = "extractify_js_endpoint_discovery"

    def __init__(self, result: CrawlResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        start_url: str,
        js_urls: list[str],
        contexts: list[dict[str, object]] | None = None,
    ) -> CrawlResult:
        call: dict[str, object] = {"start_url": start_url, "js_urls": js_urls}
        if contexts is not None:
            call["contexts"] = contexts
        self.calls.append(call)
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

    def test_crawler_agent_runs_dirb_and_merges_discovered_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            primary = SequenceCrawlTool(
                [
                    CrawlResult(
                        start_url="https://example.test/",
                        pages=[
                            CrawledPage(
                                url="https://example.test/",
                                status=200,
                                content_type="text/html",
                                title="Home",
                                headers={},
                                links=[],
                                references=[],
                                forms=[],
                            )
                        ],
                        out_of_scope=[],
                        failed=[],
                        robots=None,
                    ),
                    CrawlResult(
                        start_url="https://example.test/admin",
                        pages=[
                            CrawledPage(
                                url="https://example.test/admin",
                                status=200,
                                content_type="text/html",
                                title="Admin",
                                headers={},
                                links=[],
                                references=[],
                                forms=[],
                            )
                        ],
                        out_of_scope=[],
                        failed=[],
                        robots=None,
                    ),
                ]
            )
            dirb = FakeDirbTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                    candidates=[
                        DiscoveryCandidate(
                            url="https://example.test/admin",
                            status=200,
                            source_tool="dirb_docker_discovery",
                            kind="path",
                            confidence="confirmed",
                            reason="Dirb found the path.",
                            evidence=["https://example.test/"],
                            should_crawl=True,
                        )
                    ],
                )
            )
            memory = FileMemory(Path(directory))
            agent = CrawlerAgent(crawl_tool=primary, additional_tools=[dirb])

            result = agent.discover("https://example.test", memory, max_pages=10, max_depth=2)

            self.assertEqual(primary.calls[1]["url"], "https://example.test/admin")
            self.assertEqual(dirb.calls, 1)
            self.assertIn("https://example.test/admin", {page.url for page in result.pages})
            self.assertIn("https://example.test/admin", {candidate.url for candidate in result.candidates})

            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(
                any(
                    event["action"] == "tool_call"
                    and event["data"].get("tool") == "dirb_docker_discovery"
                    for event in events
                )
            )
            self.assertTrue(any(event["action"] == "candidate_selected" for event in events))

            memory_items = json.loads((Path(directory) / "memory.json").read_text(encoding="utf-8"))
            self.assertTrue(any(item["kind"] == "discovery_candidate" for item in memory_items))

    def test_crawler_agent_respects_candidate_follow_up_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            primary = SequenceCrawlTool(
                [
                    CrawlResult("https://example.test/", [], [], [], None),
                    CrawlResult(
                        "https://example.test/one",
                        [
                            CrawledPage(
                                url="https://example.test/one",
                                status=200,
                                content_type="text/html",
                                title=None,
                                headers={},
                                links=[],
                                references=[],
                                forms=[],
                            )
                        ],
                        [],
                        [],
                        None,
                    ),
                ]
            )
            dirb = FakeDirbTool(
                CrawlResult(
                    start_url="https://example.test/",
                    pages=[],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                    candidates=[
                        DiscoveryCandidate(
                            url="https://example.test/one",
                            source_tool="dirb_docker_discovery",
                            status=200,
                            kind="path",
                            confidence="confirmed",
                            reason="Dirb found the path.",
                            evidence=[],
                            should_crawl=True,
                        ),
                        DiscoveryCandidate(
                            url="https://example.test/two",
                            source_tool="dirb_docker_discovery",
                            status=200,
                            kind="path",
                            confidence="confirmed",
                            reason="Dirb found the path.",
                            evidence=[],
                            should_crawl=True,
                        ),
                    ],
                )
            )
            memory = FileMemory(Path(directory))
            agent = CrawlerAgent(crawl_tool=primary, additional_tools=[dirb], candidate_follow_up_limit=1)

            result = agent.discover("https://example.test", memory, max_pages=10, max_depth=2)

            self.assertEqual([call["url"] for call in primary.calls], ["https://example.test", "https://example.test/one"])
            self.assertNotIn("https://example.test/two", {page.url for page in result.pages})
            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(
                any(
                    event["action"] == "candidate_skipped"
                    and event["data"]["url"] == "https://example.test/two"
                    and event["data"]["reason"] == "follow_up_limit_reached"
                    for event in events
                )
            )

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
                            inline_scripts=["window.BACKOFFICE_API_BASE = 'https://api.example.test/api/private';"],
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

            self.assertEqual(
                js_static.calls,
                [
                    {
                        "start_url": "https://example.test/",
                        "js_urls": ["https://example.test/shell.js"],
                        "contexts": [
                            {
                                "source": "https://example.test/shell.js",
                                "page_url": "https://example.test/",
                                "inline_scripts": [
                                    "window.BACKOFFICE_API_BASE = 'https://api.example.test/api/private';"
                                ],
                            }
                        ],
                    }
                ],
            )
            self.assertIn("https://api.example.test/api/private/auth/login", {page.url for page in result.pages})

            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(
                any(
                    event["action"] == "tool_call"
                    and event["data"].get("tool") == "js_static_endpoint_discovery"
                    for event in events
                )
            )
            self.assertTrue(
                any(
                    event["action"] == "tool_result"
                    and "https://api.example.test/api/private/auth/login" in event["data"].get("page_urls", [])
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
                "dirb_docker_discovery",
                "extractify_js_endpoint_discovery",
                "js_static_endpoint_discovery",
            ],
        )
        self.assertIsNone(definitions["technology_mapper"].tools)
        self.assertIsNone(definitions["reporter"].tools)


if __name__ == "__main__":
    unittest.main()
