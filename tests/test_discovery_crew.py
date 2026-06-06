from __future__ import annotations

import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from appsec_harness.config import AppConfig
from appsec_harness.discovery_crew import (
    CREW_CONFIG_PACKAGE,
    CrewAIDiscoveryCrewRunner,
    CrewAIUnavailable,
    DiscoveryCrewState,
    _build_crawler_tool,
    _build_task_with_output_event,
)
from appsec_harness.memory import FileMemory
from appsec_harness.models import CrawledPage, CrawlResult


class FakeCrewAI:
    BaseModel = object
    BaseTool = object

    @staticmethod
    def Field(default, description: str = ""):
        return default


class FakeCrawlerAgent:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def discover(self, url: str, memory: FileMemory, max_pages: int, max_depth: int) -> CrawlResult:
        self.calls.append(url)
        return CrawlResult(
            start_url=url,
            pages=[
                CrawledPage(
                    url=url,
                    status=200,
                    content_type="text/html",
                    title=None,
                    headers={},
                    links=[],
                    references=[],
                    forms=[],
                )
            ],
            out_of_scope=[],
            failed=[],
            robots=None,
        )


class FakeTaskCrewAI:
    class Task:
        def __init__(self, config, agent, callback=None) -> None:
            self.config = config
            self.agent = agent
            self.callback = callback


class FakeTaskOutput:
    raw = "raw task output"
    json_dict = {"result": "ok"}

    def __str__(self) -> str:
        return "task output text"


class CrewAIDiscoveryCrewRunnerTests(unittest.TestCase):
    def test_requires_openrouter_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            runner = CrewAIDiscoveryCrewRunner(AppConfig(openrouter_api_key=None))

            with self.assertRaisesRegex(CrewAIUnavailable, "OPENROUTER_API_KEY"):
                runner.run("https://example.test", Path(directory), memory, max_pages=5, max_depth=3)

    def test_builds_crawler_agent_with_configured_discovery_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            runner = CrewAIDiscoveryCrewRunner(AppConfig(openrouter_api_key="test-key"))

            with patch("appsec_harness.discovery_crew._load_crewai", side_effect=CrewAIUnavailable("stop")):
                with self.assertRaisesRegex(CrewAIUnavailable, "stop"):
                    runner.run("https://example.test", Path(directory), memory, max_pages=5, max_depth=3)

            # The real wiring path is covered by build_discovery_agents, which the CrewAI runner now uses.
            from appsec_harness.agents import build_discovery_agents

            agents = build_discovery_agents(AppConfig(openrouter_api_key="test-key"))
            tool_names = [tool.name for tool in agents.crawler.available_tool_definitions]
            self.assertIn("katana_docker_crawler", tool_names)
            self.assertIn("dirb_docker_discovery", tool_names)
            self.assertIn("extractify_js_endpoint_discovery", tool_names)
            self.assertIn("js_static_endpoint_discovery", tool_names)

    def test_crewai_yaml_config_files_are_packaged(self) -> None:
        agents_yaml = resources.files(CREW_CONFIG_PACKAGE).joinpath("agents.yaml")
        tasks_yaml = resources.files(CREW_CONFIG_PACKAGE).joinpath("tasks.yaml")

        self.assertTrue(agents_yaml.is_file())
        self.assertTrue(tasks_yaml.is_file())
        self.assertIn("crawler:", agents_yaml.read_text(encoding="utf-8"))
        self.assertIn("crawl_application_task:", tasks_yaml.read_text(encoding="utf-8"))

    def test_crawler_tool_skips_previously_crawled_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            state = DiscoveryCrewState(
                target_url="https://example.test/path",
                report_dir=Path(directory),
                memory=memory,
                max_pages=5,
                max_depth=3,
            )
            crawler_agent = FakeCrawlerAgent()
            tool = _build_crawler_tool(FakeCrewAI, state, crawler_agent)

            first_result = json.loads(tool._run("https://Example.test/path#ignored"))
            second_result = json.loads(tool._run("https://example.test/path"))

            self.assertFalse(first_result["skipped"])
            self.assertTrue(second_result["skipped"])
            self.assertEqual(crawler_agent.calls, ["https://Example.test/path#ignored"])

            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(any(event["action"] == "tool_skip" for event in events))

            memory_items = json.loads((Path(directory) / "memory.json").read_text(encoding="utf-8"))
            crawl_registry = [item for item in memory_items if item["kind"] == "crawl_registry"]
            self.assertEqual(crawl_registry[-1]["content"]["urls"], ["https://example.test/path"])

    def test_crawler_tool_merges_distinct_crawl_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            state = DiscoveryCrewState(
                target_url="https://example.test/one",
                report_dir=Path(directory),
                memory=memory,
                max_pages=5,
                max_depth=3,
            )
            crawler_agent = FakeCrawlerAgent()
            tool = _build_crawler_tool(FakeCrewAI, state, crawler_agent)

            tool._run("https://example.test/one")
            result = json.loads(tool._run("https://example.test/two"))

            self.assertEqual(crawler_agent.calls, ["https://example.test/one", "https://example.test/two"])
            self.assertEqual(
                [page["url"] for page in result["crawl"]["pages"]],
                ["https://example.test/one", "https://example.test/two"],
            )
            self.assertEqual(
                result["crawled_urls"],
                ["https://example.test/one", "https://example.test/two"],
            )

    def test_task_callback_records_agent_output_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            state = DiscoveryCrewState(
                target_url="https://example.test",
                report_dir=Path(directory),
                memory=memory,
                max_pages=5,
                max_depth=3,
            )

            task = _build_task_with_output_event(
                FakeTaskCrewAI,
                state,
                config={"description": "crawl"},
                agent=object(),
                agent_name="crawler",
                task_name="crawl_application_task",
            )
            task.callback(FakeTaskOutput())

            events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            agent_output = next(event for event in events if event["action"] == "agent_output")
            self.assertEqual(agent_output["agent"], "crawler")
            self.assertEqual(agent_output["data"]["task"], "crawl_application_task")
            self.assertEqual(agent_output["data"]["output"]["raw"], "raw task output")
            self.assertEqual(agent_output["data"]["output"]["json_dict"], {"result": "ok"})


if __name__ == "__main__":
    unittest.main()
