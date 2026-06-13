from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from open_security_harness.cli import main
from open_security_harness.engagement import write_engagement_template
from open_security_harness.scope import report_dir_name
from tests.fakes import FakeCrewRunner, FakeSecurityPlanningRunner, FakeSecurityTestingRunner
from tests.fixtures import fixture_server


class CliTests(unittest.TestCase):
    def test_cli_reports_invalid_osh_yaml_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "osh.yaml").write_text(
                "models:\n  discovery:\n    crawlerr: openai/gpt-5.2\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            original_cwd = Path.cwd()
            os.chdir(directory)
            try:
                with contextlib.redirect_stderr(stderr):
                    exit_code = main(["discover", "https://example.test"])
            finally:
                os.chdir(original_cwd)

        self.assertEqual(exit_code, 1)
        self.assertIn("osh failed: Unknown model key `models.discovery.crawlerr`", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_writes_markdown_report_and_runtime_json_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with fixture_server() as url:
                stdout = io.StringIO()
                with patch("open_security_harness.crews.discovery.crew.build_discovery_crew_runner", return_value=FakeCrewRunner()):
                    with contextlib.redirect_stdout(stdout):
                        exit_code = main([url, "--output-root", str(Path(directory) / "report"), "--max-pages", "5"])

                report_dir = Path(directory) / "report" / report_dir_name(url) / "discovery"
                self.assertEqual(exit_code, 0)
                self.assertIn("Report written to", stdout.getvalue())
                self.assertTrue((report_dir / "report.md").exists())
                self.assertFalse((report_dir / "report.json").exists())
                self.assertTrue((report_dir / "events.json").exists())
                self.assertTrue((report_dir / "memory.json").exists())

                import json
                memory = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))
                self.assertTrue(any(item["kind"] == "llm_report" for item in memory))

    def test_cli_discover_subcommand_writes_discovery_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with fixture_server() as url:
                stdout = io.StringIO()
                with patch("open_security_harness.crews.discovery.crew.build_discovery_crew_runner", return_value=FakeCrewRunner()):
                    with contextlib.redirect_stdout(stdout):
                        exit_code = main(["discover", url, "--output-root", str(Path(directory) / "report"), "--max-pages", "5"])

                report_dir = Path(directory) / "report" / report_dir_name(url) / "discovery"
                self.assertEqual(exit_code, 0)
                self.assertTrue((report_dir / "report.md").exists())

    def test_cli_plan_security_subcommand_writes_security_test_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            discovery_dir = output_root / report_dir_name(target_url) / "discovery"
            discovery_dir.mkdir(parents=True)
            (discovery_dir / "report.md").write_text("# Discovery\n", encoding="utf-8")
            (discovery_dir / "memory.json").write_text("[]", encoding="utf-8")
            (discovery_dir / "events.json").write_text("[]", encoding="utf-8")
            stdout = io.StringIO()

            with patch(
                "open_security_harness.crews.security_planning.crew.build_security_test_planning_crew_runner",
                return_value=FakeSecurityPlanningRunner(),
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["plan-security", target_url, "--output-root", str(output_root)])

            report_dir = output_root / report_dir_name(target_url) / "security-test-planning"
            self.assertEqual(exit_code, 0)
            self.assertIn("Security test plan written to", stdout.getvalue())
            self.assertTrue((report_dir / "security_test_plan.md").exists())

    def test_cli_test_security_subcommand_writes_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            planning_dir = output_root / report_dir_name(target_url) / "security-test-planning"
            planning_dir.mkdir(parents=True)
            plan = {
                "title": "Security Test Plan",
                "test_hypotheses": [
                    {
                        "id": "HDR-001",
                        "title": "Security headers are present",
                        "priority": "medium",
                        "surface": "headers",
                        "requirements": ["No credentials required."],
                        "tools_expected": ["HTTP client"],
                    }
                ],
            }
            (planning_dir / "memory.json").write_text(
                json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]),
                encoding="utf-8",
            )
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, plan)
            engagement_file.write_text(
                (Path(directory) / "engagement_template.yaml")
                .read_text(encoding="utf-8")
                .replace("authorization_confirmed: false", "authorization_confirmed: true"),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with patch(
                "open_security_harness.crews.security_testing.crew.build_security_testing_crew_runner",
                return_value=FakeSecurityTestingRunner(),
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(
                        [
                            "test-security",
                            target_url,
                            "--output-root",
                            str(output_root),
                            "--engagement-file",
                            str(engagement_file),
                        ]
                    )

            report_dir = output_root / report_dir_name(target_url) / "security-testing"
            self.assertEqual(exit_code, 0)
            self.assertIn("Security testing preflight written to", stdout.getvalue())
            self.assertTrue((report_dir / "preflight.md").exists())

    def test_cli_test_security_subcommand_uses_default_engagement_template(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            planning_dir = output_root / report_dir_name(target_url) / "security-test-planning"
            planning_dir.mkdir(parents=True)
            plan = {
                "title": "Security Test Plan",
                "test_hypotheses": [
                    {
                        "id": "HDR-001",
                        "title": "Security headers are present",
                        "priority": "medium",
                        "surface": "headers",
                        "requirements": ["No credentials required."],
                        "tools_expected": ["HTTP client"],
                    }
                ],
            }
            (planning_dir / "memory.json").write_text(
                json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]),
                encoding="utf-8",
            )
            write_engagement_template(planning_dir, target_url, plan)
            stdout = io.StringIO()

            with patch(
                "open_security_harness.crews.security_testing.crew.build_security_testing_crew_runner",
                return_value=FakeSecurityTestingRunner(),
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["test-security", target_url, "--output-root", str(output_root)])

            report_dir = output_root / report_dir_name(target_url) / "security-testing"
            self.assertEqual(exit_code, 0)
            self.assertIn("Security testing preflight written to", stdout.getvalue())
            self.assertTrue((report_dir / "preflight.md").exists())


if __name__ == "__main__":
    unittest.main()
