from __future__ import annotations

import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from mosh.crews.discovery_live.agents import DiscoveryLiveReporterAgent
from mosh.config import AppConfig
from mosh.crews.discovery_live.crew import (
    CREW_CONFIG_PACKAGE,
    CrewAIDiscoveryLiveCrewRunner,
    CrewAIUnavailable,
    DiscoveryLiveCrewState,
    _build_crawler_tool,
    _build_report_tool,
    _build_task_with_output_event,
    _llm,
)
from mosh.memory import FileMemory
from mosh.models import CrawledPage, CrawlResult


class FakeCrewAI:
    BaseModel = object
    BaseTool = object

    @staticmethod
    def Field(default=None, description: str = "", default_factory=None):
        if default_factory is not None:
            return default_factory()
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


class FakeLLMCrewAI:
    class LLM:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs


class FakeTaskOutput:
    raw = "raw task output"
    json_dict = {"result": "ok"}

    def __str__(self) -> str:
        return "task output text"


class CrewAIDiscoveryLiveCrewRunnerTests(unittest.TestCase):
    def test_requires_openrouter_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            runner = CrewAIDiscoveryLiveCrewRunner(AppConfig(openrouter_api_key=None))

            with self.assertRaisesRegex(CrewAIUnavailable, "OPENROUTER_API_KEY"):
                runner.run("https://example.test", Path(directory), memory, max_pages=5, max_depth=3)

    def test_discovery_can_use_direct_deepseek_without_openrouter_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            runner = CrewAIDiscoveryLiveCrewRunner(AppConfig(deepseek_api_key="deepseek-key"))

            with patch("mosh.crews.discovery_live.crew._load_crewai", side_effect=CrewAIUnavailable("stop")):
                with self.assertRaisesRegex(CrewAIUnavailable, "stop"):
                    runner.run("https://example.test", Path(directory), memory, max_pages=5, max_depth=3)

    def test_llm_uses_direct_deepseek_endpoint_for_deepseek_models_when_key_exists(self) -> None:
        llm = _llm(FakeLLMCrewAI, AppConfig(deepseek_api_key="deepseek-key"), "deepseek/deepseek-v4-flash")

        self.assertEqual(llm.kwargs["model"], "deepseek-v4-flash")
        self.assertEqual(llm.kwargs["provider"], "deepseek")
        self.assertNotIn("base_url", llm.kwargs)
        self.assertEqual(llm.kwargs["api_key"], "deepseek-key")

    def test_llm_uses_openrouter_for_non_deepseek_models(self) -> None:
        llm = _llm(
            FakeLLMCrewAI,
            AppConfig(openrouter_api_key="openrouter-key", deepseek_api_key="deepseek-key"),
            "openai/gpt-5.2",
        )

        self.assertEqual(llm.kwargs["model"], "openai/gpt-5.2")
        self.assertEqual(llm.kwargs["provider"], "openai")
        self.assertEqual(llm.kwargs["base_url"], "https://openrouter.ai/api/v1")
        self.assertEqual(llm.kwargs["api_key"], "openrouter-key")

    def test_llm_accepts_optional_max_tokens(self) -> None:
        llm = _llm(
            FakeLLMCrewAI,
            AppConfig(openrouter_api_key="openrouter-key"),
            "openai/gpt-5.2",
            max_tokens=2048,
        )

        self.assertEqual(llm.kwargs["max_tokens"], 2048)

    def test_llm_uses_custom_openai_compatible_endpoint_when_configured(self) -> None:
        llm = _llm(
            FakeLLMCrewAI,
            AppConfig(
                custom_llm_api_key="custom-key",
                custom_llm_base_url="http://localhost:11434/v1",
                deepseek_api_key="deepseek-key",
                openrouter_api_key="openrouter-key",
            ),
            "custom/llama3.1",
        )

        self.assertEqual(llm.kwargs["model"], "llama3.1")
        self.assertEqual(llm.kwargs["provider"], "openai")
        self.assertEqual(llm.kwargs["base_url"], "http://localhost:11434/v1")
        self.assertEqual(llm.kwargs["api_key"], "custom-key")

    def test_llm_requires_custom_base_url_for_custom_model_prefix(self) -> None:
        with self.assertRaisesRegex(CrewAIUnavailable, "MOSH_LLM_BASE_URL"):
            _llm(
                FakeLLMCrewAI,
                AppConfig(custom_llm_api_key="custom-key", openrouter_api_key="openrouter-key"),
                "custom/llama3.1",
            )

    def test_builds_crawler_agent_with_configured_discovery_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            runner = CrewAIDiscoveryLiveCrewRunner(AppConfig(openrouter_api_key="test-key"))

            with patch("mosh.crews.discovery_live.crew._load_crewai", side_effect=CrewAIUnavailable("stop")):
                with self.assertRaisesRegex(CrewAIUnavailable, "stop"):
                    runner.run("https://example.test", Path(directory), memory, max_pages=5, max_depth=3)

            # The real wiring path is covered by build_discovery_live_agents, which the CrewAI runner now uses.
            from mosh.crews.discovery_live.agents import build_discovery_live_agents

            agents = build_discovery_live_agents(AppConfig(openrouter_api_key="test-key"))
            tool_names = [tool.name for tool in agents.crawler.available_tool_definitions]
            self.assertIn("katana_docker_crawler", tool_names)
            self.assertIn("dirb_docker_discovery", tool_names)
            self.assertIn("extractify_js_endpoint_discovery", tool_names)
            self.assertIn("js_static_endpoint_discovery", tool_names)

    def test_crewai_yaml_config_files_are_packaged(self) -> None:
        agents_yaml = resources.files(CREW_CONFIG_PACKAGE).joinpath("discovery_live/agents.yaml")
        tasks_yaml = resources.files(CREW_CONFIG_PACKAGE).joinpath("discovery_live/tasks.yaml")
        planning_yaml = [
            resources.files(CREW_CONFIG_PACKAGE).joinpath(f"planning/{file}")
            for file in [
                "evidence_linker_agents.yaml",
                "evidence_linker_tasks.yaml",
                "planner_agents.yaml",
                "planner_tasks.yaml",
                "critic_agents.yaml",
                "critic_tasks.yaml",
                "reporter_agents.yaml",
                "reporter_tasks.yaml",
                "engagement_refiner_agents.yaml",
                "engagement_refiner_tasks.yaml",
            ]
        ]
        source_agents_yaml = resources.files(CREW_CONFIG_PACKAGE).joinpath("discovery_source/agents.yaml")
        source_tasks_yaml = resources.files(CREW_CONFIG_PACKAGE).joinpath("discovery_source/tasks.yaml")

        self.assertTrue(agents_yaml.is_file())
        self.assertTrue(tasks_yaml.is_file())
        for path in planning_yaml:
            self.assertTrue(path.is_file(), str(path))
        self.assertTrue(source_agents_yaml.is_file())
        self.assertTrue(source_tasks_yaml.is_file())
        self.assertIn("crawler:", agents_yaml.read_text(encoding="utf-8"))
        self.assertIn("crawl_application_task:", tasks_yaml.read_text(encoding="utf-8"))
        planning_text = "\n".join(path.read_text(encoding="utf-8") for path in planning_yaml)
        self.assertIn("evidence_linker:", planning_text)
        self.assertIn("suggest_evidence_link_candidates_task:", planning_text)
        self.assertIn("planner:", planning_text)
        self.assertIn("draft_security_test_plan_task:", planning_text)
        self.assertIn("reporter:", planning_text)
        self.assertIn("write_security_test_plan_task:", planning_text)
        self.assertIn("engagement_refiner:", planning_text)
        self.assertIn("refine_engagement_template_task:", planning_text)
        self.assertIn("source_intake:", source_agents_yaml.read_text(encoding="utf-8"))
        self.assertIn("source_route_resolver:", source_agents_yaml.read_text(encoding="utf-8"))
        self.assertIn("source_component_mapper:", source_agents_yaml.read_text(encoding="utf-8"))
        self.assertIn("source_gap_analyst:", source_agents_yaml.read_text(encoding="utf-8"))
        self.assertIn("validate_source_task:", source_tasks_yaml.read_text(encoding="utf-8"))
        self.assertIn("resolve_source_routes_task:", source_tasks_yaml.read_text(encoding="utf-8"))
        self.assertIn("map_source_components_task:", source_tasks_yaml.read_text(encoding="utf-8"))
        self.assertIn("analyze_discovery_source_gaps_task:", source_tasks_yaml.read_text(encoding="utf-8"))

    def test_crawler_tool_skips_previously_crawled_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            state = DiscoveryLiveCrewState(
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
            state = DiscoveryLiveCrewState(
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
            state = DiscoveryLiveCrewState(
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

    def test_report_tool_schema_and_runner_accept_json_string_report_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            state = DiscoveryLiveCrewState(
                target_url="https://example.test",
                report_dir=Path(directory),
                memory=memory,
                max_pages=5,
                max_depth=3,
                crawl=CrawlResult(
                    start_url="https://example.test",
                    pages=[],
                    out_of_scope=[],
                    failed=[],
                    robots=None,
                ),
            )
            tool = _build_report_tool(FakeCrewAI, state, DiscoveryLiveReporterAgent())
            report = {
                "title": "Application Discovery Results",
                "executive_summary": "Summary",
                "application_description": "Description",
            }

            report_annotation = tool.args_schema.__annotations__["report"]
            self.assertIn("str", str(report_annotation))
            result = json.loads(tool._run(json.dumps(report)))

            self.assertEqual(result["structured_keys"], sorted(report.keys()))
            memory_items = json.loads((Path(directory) / "memory.json").read_text(encoding="utf-8"))
            llm_report = next(item for item in memory_items if item["kind"] == "llm_report")
            self.assertEqual(llm_report["content"]["structured"], report)


if __name__ == "__main__":
    unittest.main()
