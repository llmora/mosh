from __future__ import annotations

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mosh.cli import main
from mosh.engagement import write_engagement_template, write_engagement_template_mapping
from mosh.engagements import attach_asset, asset_discovery_dir, create_engagement, load_engagement
from mosh.scope import report_dir_name, source_report_dir_name
from tests.fakes import (
    FakeCrewRunner,
    FakeFinalReportingRunner,
    FakeSecurityPlanningRunner,
    FakeSecurityTestingRunner,
    FakeSourceDiscoveryRunner,
    FakeSourceSecurityTestingRunner,
)
from tests.fixtures import fixture_server, fixture_source_tree


def _source_engagement_template(source: str) -> dict[str, object]:
    return {
        "engagement": {
            "authorization_confirmed": True,
            "active_testing_allowed": False,
            "state_changing_tests_allowed": False,
            "notes": "Source-only preflight.",
        },
        "targets": {
            "production": {"source": source},
            "alternative": {"source": None},
        },
        "contacts": {"escalation": {"name": None, "email": None, "phone": None}},
        "limits": {
            "max_requests_per_test": 0,
            "max_rate_per_second": 0,
            "stop_on_sensitive_data": True,
            "evidence_redaction": True,
        },
        "credentials": {"authenticated_user": {"username": None, "password": None, "token": None}},
        "safe_test_data": {
            "marker_prefix": "SECTEST-DO-NOT-PROCESS",
            "email": None,
            "phone": None,
            "company": None,
            "customer_ids": [],
            "enterprise_account_ids": [],
            "activation_codes": [],
            "callback_listener_url": None,
        },
    }


class CliTests(unittest.TestCase):
    def test_cli_reports_invalid_mosh_yaml_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "mosh.yaml").write_text(
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
        self.assertIn("mosh failed: Unknown model key `models.discovery.crawlerr`", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_writes_markdown_report_and_runtime_json_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with fixture_server() as url:
                stdout = io.StringIO()
                with patch("mosh.crews.discovery.crew.build_discovery_crew_runner", return_value=FakeCrewRunner()):
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
                with patch("mosh.crews.discovery.crew.build_discovery_crew_runner", return_value=FakeCrewRunner()):
                    with contextlib.redirect_stdout(stdout):
                        exit_code = main(["discover", url, "--output-root", str(Path(directory) / "report"), "--max-pages", "5"])

                report_dir = Path(directory) / "report" / report_dir_name(url) / "discovery"
                self.assertEqual(exit_code, 0)
                self.assertTrue((report_dir / "report.md").exists())

    def test_cli_discover_source_subcommand_writes_source_discovery_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with fixture_source_tree() as source:
                stdout = io.StringIO()
                with patch(
                    "mosh.crews.source_discovery.crew.build_source_discovery_crew_runner",
                    return_value=FakeSourceDiscoveryRunner(),
                ):
                    with contextlib.redirect_stdout(stdout):
                        exit_code = main(["discover-source", str(source), "--output-root", str(Path(directory) / "report")])

                report_dir = Path(directory) / "report" / source_report_dir_name(source) / "source-discovery"
                self.assertEqual(exit_code, 0)
                self.assertIn("Source discovery report written to", stdout.getvalue())
                self.assertTrue((report_dir / "report.md").exists())
                self.assertTrue((report_dir / "events.json").exists())
                self.assertTrue((report_dir / "memory.json").exists())
                memory = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))
                self.assertTrue(any(item["kind"] == "source_index" for item in memory))

    def test_cli_engagement_create_and_attach_commands_write_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["engagement", "create", "--title", "Example App", "--output-root", str(output_root)])

            self.assertEqual(exit_code, 0)
            match = re.search(r"Engagement created: (eng_[a-z0-9]{8})", stdout.getvalue())
            self.assertIsNotNone(match)
            engagement_id = match.group(1)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "engagement",
                        "attach",
                        engagement_id,
                        "https://app.example.test",
                        "--output-root",
                        str(output_root),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertIn("Attached: asset_live_1 (live_url)", stdout.getvalue())
            engagement = load_engagement(output_root, engagement_id)
            self.assertEqual(engagement.title, "Example App")
            self.assertEqual([(asset.id, asset.type) for asset in engagement.assets], [("asset_live_1", "live_url")])
            manifest = json.loads((output_root / engagement_id / "engagement.json").read_text(encoding="utf-8"))
            self.assertEqual(list(manifest["assets"][0]), ["created_at", "id"])

    def test_cli_discover_engagement_dispatches_missing_assets_and_skips_current_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            with fixture_server() as url:
                with fixture_source_tree() as source:
                    engagement = create_engagement(output_root)
                    live_asset = attach_asset(output_root, engagement.id, url).asset
                    source_asset = attach_asset(output_root, engagement.id, str(source)).asset
                    live_runner = FakeCrewRunner()
                    source_runner = FakeSourceDiscoveryRunner()
                    stdout = io.StringIO()

                    with patch("mosh.crews.discovery.crew.build_discovery_crew_runner", return_value=live_runner):
                        with patch(
                            "mosh.crews.source_discovery.crew.build_source_discovery_crew_runner",
                            return_value=source_runner,
                        ):
                            with contextlib.redirect_stdout(stdout):
                                exit_code = main(["discover", engagement.id, "--output-root", str(output_root)])
                            with contextlib.redirect_stdout(io.StringIO()) as second_stdout:
                                second_exit_code = main(["discover", engagement.id, "--output-root", str(output_root)])
                            with contextlib.redirect_stdout(io.StringIO()):
                                refresh_exit_code = main(
                                    [
                                        "discover",
                                        engagement.id,
                                        "--asset",
                                        live_asset.id,
                                        "--refresh",
                                        "--output-root",
                                        str(output_root),
                                    ]
                                )

                    self.assertEqual(exit_code, 0)
                    self.assertEqual(second_exit_code, 0)
                    self.assertEqual(refresh_exit_code, 0)
                    self.assertEqual(len(live_runner.calls), 2)
                    self.assertEqual(len(source_runner.calls), 1)
                    self.assertTrue((asset_discovery_dir(output_root, engagement.id, live_asset.id) / "report.md").exists())
                    self.assertTrue((asset_discovery_dir(output_root, engagement.id, source_asset.id) / "report.md").exists())
                    self.assertIn("Discovery report for asset_live_1 written to", stdout.getvalue())
                    self.assertIn("Discovery report for asset_source_1 written to", stdout.getvalue())
                    self.assertIn("No assets need discovery", second_stdout.getvalue())
                    reloaded = load_engagement(output_root, engagement.id)
                    discovered_assets = {asset.id: asset.metadata.get("discovery") for asset in reloaded.assets}
                    self.assertIn("last_discovered_at", discovered_assets[live_asset.id])
                    self.assertIn("last_discovered_at", discovered_assets[source_asset.id])

    def test_cli_discover_engagement_asset_flag_selects_one_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            with fixture_server() as url:
                with fixture_source_tree() as source:
                    engagement = create_engagement(output_root)
                    live_asset = attach_asset(output_root, engagement.id, url).asset
                    source_asset = attach_asset(output_root, engagement.id, str(source)).asset
                    live_runner = FakeCrewRunner()
                    source_runner = FakeSourceDiscoveryRunner()

                    with patch("mosh.crews.discovery.crew.build_discovery_crew_runner", return_value=live_runner):
                        with patch(
                            "mosh.crews.source_discovery.crew.build_source_discovery_crew_runner",
                            return_value=source_runner,
                        ):
                            exit_code = main(
                                [
                                    "discover",
                                    engagement.id,
                                    "--asset",
                                    source_asset.id,
                                    "--output-root",
                                    str(output_root),
                                ]
                            )

                    self.assertEqual(exit_code, 0)
                    self.assertEqual(live_runner.calls, [])
                    self.assertEqual(len(source_runner.calls), 1)
                    self.assertFalse((asset_discovery_dir(output_root, engagement.id, live_asset.id) / "report.md").exists())
                    self.assertTrue((asset_discovery_dir(output_root, engagement.id, source_asset.id) / "report.md").exists())

    def test_cli_discover_engagement_reports_unsupported_asset_type(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            asset = attach_asset(output_root, engagement.id, "https://github.com/example/app").asset
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                exit_code = main(["discover", engagement.id, "--asset", asset.id, "--output-root", str(output_root)])

            self.assertEqual(exit_code, 1)
            self.assertIn("Discovery is not implemented for source_repo assets yet.", stderr.getvalue())

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
                "mosh.crews.security_planning.crew.build_security_test_planning_crew_runner",
                return_value=FakeSecurityPlanningRunner(),
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["plan-security", target_url, "--output-root", str(output_root)])

            report_dir = output_root / report_dir_name(target_url) / "security-test-planning"
            self.assertEqual(exit_code, 0)
            self.assertIn("Security test plan written to", stdout.getvalue())
            self.assertTrue((report_dir / "security_test_plan.md").exists())

    def test_cli_plan_security_subcommand_accepts_source_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = "/tmp/example-source"
            output_root = Path(directory) / "report"
            source_dir = output_root / source_report_dir_name(source) / "source-discovery"
            source_dir.mkdir(parents=True)
            (source_dir / "report.md").write_text("# Source Discovery\n", encoding="utf-8")
            (source_dir / "memory.json").write_text("[]", encoding="utf-8")
            (source_dir / "events.json").write_text("[]", encoding="utf-8")
            stdout = io.StringIO()

            with patch(
                "mosh.crews.security_planning.crew.build_security_test_planning_crew_runner",
                return_value=FakeSecurityPlanningRunner(),
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["plan-security", "--source", source, "--output-root", str(output_root)])

            report_dir = output_root / source_report_dir_name(source) / "security-test-planning"
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
                "mosh.crews.security_testing.crew.build_security_testing_crew_runner",
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

    def test_cli_test_security_subcommand_prints_blocked_test_unblock_details(self) -> None:
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
                    },
                    {
                        "id": "AUTH-002",
                        "title": "Admin role cannot read another tenant",
                        "priority": "critical",
                        "surface": "api",
                        "requirements": ["Admin credentials", "Safe customer IDs"],
                        "tools_expected": ["HTTP client"],
                    },
                ],
            }
            (planning_dir / "memory.json").write_text(
                json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]),
                encoding="utf-8",
            )
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, plan)
            engagement_file.write_text(
                (Path(directory) / "engagement_template.yaml").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with patch(
                "mosh.crews.security_testing.crew.build_security_testing_crew_runner",
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

            output = stdout.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Security testing has blocked tests remaining.", output)
            self.assertIn("- AUTH-002: Admin role cannot read another tenant (critical)", output)
            self.assertIn(
                "Add `credentials.admin.token` or both `credentials.admin.username` and `credentials.admin.password`.",
                output,
            )
            self.assertIn("Add a non-empty `safe_test_data.customer_ids` value.", output)

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
                "mosh.crews.security_testing.crew.build_security_testing_crew_runner",
                return_value=FakeSecurityTestingRunner(),
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["test-security", target_url, "--output-root", str(output_root)])

            report_dir = output_root / report_dir_name(target_url) / "security-testing"
            self.assertEqual(exit_code, 0)
            self.assertIn("Security testing preflight written to", stdout.getvalue())
            self.assertTrue((report_dir / "preflight.md").exists())

    def test_cli_test_security_subcommand_accepts_source_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_dir = Path(directory) / "example-source"
            source_file = source_dir / "api" / "routes" / "auth.js"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("function guard() { return true; }\n", encoding="utf-8")
            source = str(source_dir)
            output_root = Path(directory) / "report"
            source_root = output_root / source_report_dir_name(source)
            planning_dir = source_root / "security-test-planning"
            planning_dir.mkdir(parents=True)
            plan = {
                "title": "Source Security Test Plan",
                "test_hypotheses": [
                    {
                        "id": "SRC-001",
                        "title": "Route guard is enforced in source",
                        "priority": "high",
                        "surface": "authentication",
                        "requirements": ["No credentials required."],
                        "execution_mode": "source",
                        "affected_source": [{"path": "api/routes/auth.js", "start_line": 1, "end_line": 20}],
                    }
                ],
            }
            (planning_dir / "memory.json").write_text(
                json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]),
                encoding="utf-8",
            )
            write_engagement_template_mapping(planning_dir, _source_engagement_template(source))
            stdout = io.StringIO()

            with patch(
                "mosh.crews.security_testing.crew.build_security_testing_crew_runner",
                return_value=FakeSecurityTestingRunner(),
            ):
                with patch(
                    "mosh.crews.source_security_testing.crew.build_source_security_testing_crew_runner",
                    return_value=FakeSourceSecurityTestingRunner(),
                ):
                    with contextlib.redirect_stdout(stdout):
                        exit_code = main(["test-security", "--source", source, "--output-root", str(output_root)])

            report_dir = source_root / "source-security-testing"
            self.assertEqual(exit_code, 0)
            self.assertIn("Security testing preflight written to", stdout.getvalue())
            self.assertTrue((report_dir / "preflight.md").exists())
            self.assertTrue((report_dir / "executed_tests" / "SRC-001.md").exists())

    def test_cli_report_subcommand_writes_final_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            runner = FakeFinalReportingRunner()
            stdout = io.StringIO()

            with patch(
                "mosh.crews.reporting.crew.build_final_reporting_crew_runner",
                return_value=runner,
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["report", target_url, "--output-root", str(output_root)])

            report_path = output_root / report_dir_name(target_url) / "final-report" / "report.md"
            self.assertEqual(exit_code, 0)
            self.assertIn("Final report written to", stdout.getvalue())
            self.assertTrue(report_path.exists())


if __name__ == "__main__":
    unittest.main()
