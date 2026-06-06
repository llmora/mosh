from __future__ import annotations

import tempfile
import unittest
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from appsec_harness.config import AppConfig
from appsec_harness.discovery_crew import CREW_CONFIG_PACKAGE, CrewAIDiscoveryCrewRunner, CrewAIUnavailable
from appsec_harness.memory import FileMemory


class CrewAIDiscoveryCrewRunnerTests(unittest.TestCase):
    def test_requires_openrouter_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            runner = CrewAIDiscoveryCrewRunner(AppConfig(openrouter_api_key=None))

            with self.assertRaisesRegex(CrewAIUnavailable, "OPENROUTER_API_KEY"):
                runner.run("https://example.test", Path(directory), memory, max_pages=5, max_depth=3)

    def test_builds_crawler_agent_with_configured_katana_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            runner = CrewAIDiscoveryCrewRunner(AppConfig(openrouter_api_key="test-key"))

            with patch("appsec_harness.discovery_crew._load_crewai", side_effect=CrewAIUnavailable("stop")):
                with self.assertRaisesRegex(CrewAIUnavailable, "stop"):
                    runner.run("https://example.test", Path(directory), memory, max_pages=5, max_depth=3)

            # The real wiring path is covered by build_discovery_agents, which the CrewAI runner now uses.
            from appsec_harness.agents import build_discovery_agents

            agents = build_discovery_agents(AppConfig(openrouter_api_key="test-key"))
            self.assertIn(
                "katana_docker_crawler",
                [tool.name for tool in agents.crawler.available_tool_definitions],
            )

    def test_crewai_yaml_config_files_are_packaged(self) -> None:
        agents_yaml = resources.files(CREW_CONFIG_PACKAGE).joinpath("agents.yaml")
        tasks_yaml = resources.files(CREW_CONFIG_PACKAGE).joinpath("tasks.yaml")

        self.assertTrue(agents_yaml.is_file())
        self.assertTrue(tasks_yaml.is_file())
        self.assertIn("crawler:", agents_yaml.read_text(encoding="utf-8"))
        self.assertIn("crawl_application_task:", tasks_yaml.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
