from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from open_security_harness.config import AppConfig
from open_security_harness.crews.discovery.crew import DiscoveryOrchestrator
from open_security_harness.scope import report_dir_name
from tests.fakes import FakeCrewRunner
from tests.fixtures import fixture_server


class DiscoveryOrchestratorTests(unittest.TestCase):
    def test_delegates_execution_to_crewai_crew_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            crew_runner = FakeCrewRunner()
            with fixture_server() as url:
                report_dir = DiscoveryOrchestrator(
                    AppConfig(),
                    output_root=Path(directory) / "report",
                    crew_runner=crew_runner,
                ).run(url, max_pages=5, max_depth=1)

            events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            memory = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))

            self.assertEqual(report_dir.name, "discovery")
            self.assertEqual(report_dir.parent.name, report_dir_name(url))
            self.assertTrue(any(event["action"] == "start" and event["agent"] == "orchestrator" for event in events))
            self.assertTrue(any(event["action"] == "agent_output" and event["agent"] == "sbom_compiler" for event in events))
            self.assertFalse(any(item["kind"] == "component_inventory" for item in memory))
            self.assertEqual(crew_runner.calls[0]["target_url"], url)

    def test_default_limits_are_200_pages_and_configured_depth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            crew_runner = FakeCrewRunner()
            with fixture_server() as url:
                DiscoveryOrchestrator(
                    AppConfig(max_depth=5),
                    output_root=Path(directory) / "report",
                    crew_runner=crew_runner,
                ).run(url)

            self.assertEqual(crew_runner.calls[0]["max_pages"], 200)
            self.assertEqual(crew_runner.calls[0]["max_depth"], 5)


if __name__ == "__main__":
    unittest.main()
