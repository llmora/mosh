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
from mosh.engagement import load_engagement_file, write_engagement_template
from mosh.engagements import attach_asset, asset_discovery_dir, create_engagement, load_engagement
from mosh.harness_improvements import record_harness_improvement
from tests.fakes import (
    FakeCrewRunner,
    FakeFinalReportingRunner,
    FakeSecurityPlanningRunner,
    FakeSecurityTestingRunner,
    FakeDiscoverySourceRunner,
)
from tests.fixtures import fixture_server, fixture_source_tree


def _plan(test_id: str = "HDR-001") -> dict[str, object]:
    return {
        "title": "Engagement Security Test Plan",
        "test_hypotheses": [
            {
                "id": test_id,
                "title": "Security headers are present",
                "priority": "medium",
                "surface": "headers",
                "requirements": ["No credentials required."],
                "tools_expected": ["HTTP client"],
                "execution_mode": "live",
            }
        ],
    }


def _write_plan_memory(planning_dir: Path, plan: dict[str, object]) -> None:
    planning_dir.mkdir(parents=True, exist_ok=True)
    (planning_dir / "memory.json").write_text(
        json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]),
        encoding="utf-8",
    )
    (planning_dir / "plan.md").write_text("# Security Test Plan\n", encoding="utf-8")
    (planning_dir / "events.json").write_text("[]", encoding="utf-8")


def _write_discovery_live(discovery_dir: Path) -> None:
    discovery_dir.mkdir(parents=True, exist_ok=True)
    (discovery_dir / "report.md").write_text("# Live Discovery\n", encoding="utf-8")
    (discovery_dir / "events.json").write_text("[]", encoding="utf-8")
    (discovery_dir / "memory.json").write_text(
        json.dumps(
            [
                {
                    "kind": "crawled_page",
                    "content": {
                        "url": "https://app.example.test/api/status",
                        "status": 200,
                        "links": [],
                        "references": [],
                        "forms": [],
                    },
                },
                {
                    "kind": "llm_report",
                    "content": {
                        "structured": {
                            "executive_summary": "Discovery found a live API.",
                            "application_description": "Example application.",
                        }
                    },
                },
            ]
        ),
        encoding="utf-8",
    )


def _write_discovery_source(discovery_dir: Path) -> None:
    discovery_dir.mkdir(parents=True, exist_ok=True)
    (discovery_dir / "report.md").write_text("# Source Discovery\n", encoding="utf-8")
    (discovery_dir / "events.json").write_text("[]", encoding="utf-8")
    (discovery_dir / "memory.json").write_text(
        json.dumps(
            [
                {
                    "kind": "source_index",
                    "content": {
                        "inventory": {
                            "routes": [
                                {
                                    "method": "GET",
                                    "full_route": "/api/status",
                                    "path": "api/status.py",
                                    "line": 1,
                                }
                            ]
                        }
                    },
                }
            ]
        ),
        encoding="utf-8",
    )


class CliTests(unittest.TestCase):
    def test_cli_reports_invalid_mosh_yaml_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "mosh.yaml").write_text(
                "models:\n  discovery_live:\n    crawlerr: openai/gpt-5.2\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            original_cwd = Path.cwd()
            os.chdir(directory)
            try:
                with contextlib.redirect_stderr(stderr):
                    exit_code = main(["discover", "eng_12345678"])
            finally:
                os.chdir(original_cwd)

        self.assertEqual(exit_code, 1)
        self.assertIn("mosh failed: Unknown model key `models.discovery_live.crawlerr`", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_shortcut_url_creates_engagement_attaches_asset_and_runs_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            with fixture_server() as url:
                live_runner = FakeCrewRunner()
                stdout = io.StringIO()

                with patch("mosh.crews.discovery_live.crew.build_discovery_live_crew_runner", return_value=live_runner):
                    with contextlib.redirect_stdout(stdout):
                        exit_code = main([url, "--output-root", str(output_root)])

            match = re.search(r"Engagement created: (eng_[a-z0-9]{8})", stdout.getvalue())
            self.assertIsNotNone(match)
            engagement_id = match.group(1)
            engagement = load_engagement(output_root, engagement_id)

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(live_runner.calls), 1)
            self.assertEqual(live_runner.calls[0]["target_url"], url.rstrip("/"))
            self.assertEqual([(asset.id, asset.type) for asset in engagement.assets], [("asset_live_1", "live_url")])
            self.assertTrue((asset_discovery_dir(output_root, engagement_id, "asset_live_1") / "report.md").exists())
            self.assertIn("Attached: asset_live_1 (live_url)", stdout.getvalue())
            self.assertIn(f"Next: run `mosh plan {engagement_id}`.", stdout.getvalue())

    def test_cli_shortcut_source_path_creates_engagement_attaches_asset_and_runs_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            with fixture_source_tree() as source:
                source_runner = FakeDiscoverySourceRunner()
                stdout = io.StringIO()

                with patch(
                    "mosh.crews.discovery_source.crew.build_discovery_source_crew_runner",
                    return_value=source_runner,
                ):
                    with contextlib.redirect_stdout(stdout):
                        exit_code = main([str(source), "--output-root", str(output_root)])

            match = re.search(r"Engagement created: (eng_[a-z0-9]{8})", stdout.getvalue())
            self.assertIsNotNone(match)
            engagement_id = match.group(1)
            engagement = load_engagement(output_root, engagement_id)

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(source_runner.calls), 1)
            self.assertEqual(Path(source_runner.calls[0]["source"]), source.resolve())
            self.assertEqual([(asset.id, asset.type) for asset in engagement.assets], [("asset_source_1", "source_tree")])
            self.assertTrue((asset_discovery_dir(output_root, engagement_id, "asset_source_1") / "report.md").exists())
            self.assertIn("Attached: asset_source_1 (source_tree)", stdout.getvalue())
            self.assertIn(f"Next: run `mosh plan {engagement_id}`.", stdout.getvalue())

    def test_cli_discover_still_requires_engagement_id(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = main(["discover", "https://example.test"])

        self.assertEqual(exit_code, 1)
        self.assertIn("engagement not found", stderr.getvalue())

    def test_cli_shortcut_rejects_invalid_locator_before_creating_engagement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                exit_code = main(["not-a-real-target", "--output-root", str(output_root)])

            self.assertEqual(exit_code, 1)
            self.assertIn("Cannot infer asset type", stderr.getvalue())
            self.assertFalse(any(output_root.glob("eng_*")) if output_root.exists() else False)

    def test_cli_shortcut_rejects_unsupported_discovery_asset_before_creating_engagement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                exit_code = main(["https://github.com/example/app", "--output-root", str(output_root)])

            self.assertEqual(exit_code, 1)
            self.assertIn("Shortcut discovery supports live_url and source_tree assets", stderr.getvalue())
            self.assertFalse(any(output_root.glob("eng_*")) if output_root.exists() else False)

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
            self.assertIn(f"Next: run `mosh discover {engagement_id}`.", stdout.getvalue())
            engagement = load_engagement(output_root, engagement_id)
            self.assertEqual(engagement.title, "Example App")
            self.assertEqual([(asset.id, asset.type) for asset in engagement.assets], [("asset_live_1", "live_url")])
            manifest = json.loads((output_root / engagement_id / "engagement.json").read_text(encoding="utf-8"))
            self.assertEqual(list(manifest["assets"][0]), ["created_at", "id"])

    def test_cli_chat_records_engagement_directive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            stdout = io.StringIO()

            with patch.dict(
                os.environ,
                {
                    "OPENROUTER_API_KEY": "",
                    "DEEPSEEK_API_KEY": "",
                    "MOSH_LLM_API_KEY": "",
                    "MOSH_LLM_BASE_URL": "",
                },
                clear=True,
            ), contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "chat",
                        engagement.id,
                        "The /admin-dev URL is out of scope.",
                        "--output-root",
                        str(output_root),
                    ]
                )

            directives = json.loads(
                (output_root / engagement.id / "conversation" / "directives.json").read_text(encoding="utf-8")
            )
            messages = (output_root / engagement.id / "conversation" / "messages.jsonl").read_text(encoding="utf-8")
            self.assertEqual(exit_code, 0)
            self.assertIn("Recorded engagement directive", stdout.getvalue())
            self.assertEqual(directives["directives"][0]["kind"], "scope_override")
            self.assertEqual(directives["directives"][0]["target"]["action"], "exclude")
            self.assertEqual(len([line for line in messages.splitlines() if line.strip()]), 2)

    def test_cli_engagement_steer_set_show_and_clear(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            steer_path = Path(directory) / "steer.md"
            steer_path.write_text(
                "Focus on tenant isolation.\nPrioritize authorization bypass.\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "engagement",
                        "steer",
                        "set",
                        engagement.id,
                        "--file",
                        str(steer_path),
                        "--output-root",
                        str(output_root),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertIn("Engagement steer written", stdout.getvalue())
            template_path = output_root / engagement.id / "engagement_template.yaml"
            template = load_engagement_file(template_path)
            self.assertEqual(
                template["llm"]["engagement_steer"],
                "Focus on tenant isolation.\nPrioritize authorization bypass.",
            )
            self.assertIn("engagement_steer: |-", template_path.read_text(encoding="utf-8"))

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "engagement",
                        "steer",
                        "show",
                        engagement.id,
                        "--output-root",
                        str(output_root),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue(), "Focus on tenant isolation.\nPrioritize authorization bypass.\n")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "engagement",
                        "steer",
                        "clear",
                        engagement.id,
                        "--output-root",
                        str(output_root),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertIn("Engagement steer cleared", stdout.getvalue())
            template = load_engagement_file(template_path)
            self.assertIsNone(template["llm"]["engagement_steer"])

    def test_cli_discover_engagement_dispatches_missing_assets_and_skips_current_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            with fixture_server() as url:
                with fixture_source_tree() as source:
                    engagement = create_engagement(output_root)
                    live_asset = attach_asset(output_root, engagement.id, url).asset
                    source_asset = attach_asset(output_root, engagement.id, str(source)).asset
                    with contextlib.redirect_stdout(io.StringIO()):
                        main(
                            [
                                "engagement",
                                "steer",
                                "set",
                                engagement.id,
                                "--text",
                                "Focus discovery on authorization surfaces.",
                                "--output-root",
                                str(output_root),
                            ]
                        )
                    live_runner = FakeCrewRunner()
                    source_runner = FakeDiscoverySourceRunner()
                    stdout = io.StringIO()

                    with patch("mosh.crews.discovery_live.crew.build_discovery_live_crew_runner", return_value=live_runner):
                        with patch(
                            "mosh.crews.discovery_source.crew.build_discovery_source_crew_runner",
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
                    self.assertEqual(
                        live_runner.calls[0]["engagement_steer"],
                        "Focus discovery on authorization surfaces.",
                    )
                    self.assertEqual(
                        source_runner.calls[0]["engagement_steer"],
                        "Focus discovery on authorization surfaces.",
                    )
                    self.assertTrue((asset_discovery_dir(output_root, engagement.id, live_asset.id) / "report.md").exists())
                    self.assertTrue((asset_discovery_dir(output_root, engagement.id, source_asset.id) / "report.md").exists())
                    self.assertIn("Discovery report for asset_live_1 written to", stdout.getvalue())
                    self.assertIn("Discovery report for asset_source_1 written to", stdout.getvalue())
                    self.assertIn(f"Next: run `mosh plan {engagement.id}` when discovery is complete.", stdout.getvalue())
                    self.assertIn("No assets need discovery", second_stdout.getvalue())
                    self.assertIn(f"Next: run `mosh plan {engagement.id}`.", second_stdout.getvalue())

    def test_cli_discover_engagement_asset_flag_selects_one_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            with fixture_server() as url:
                with fixture_source_tree() as source:
                    engagement = create_engagement(output_root)
                    live_asset = attach_asset(output_root, engagement.id, url).asset
                    source_asset = attach_asset(output_root, engagement.id, str(source)).asset
                    live_runner = FakeCrewRunner()
                    source_runner = FakeDiscoverySourceRunner()

                    with patch("mosh.crews.discovery_live.crew.build_discovery_live_crew_runner", return_value=live_runner):
                        with patch(
                            "mosh.crews.discovery_source.crew.build_discovery_source_crew_runner",
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

    def test_cli_plan_engagement_runs_linking_and_writes_engagement_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            source = Path(directory) / "source"
            source.mkdir()
            engagement = create_engagement(output_root)
            live_asset = attach_asset(output_root, engagement.id, "https://app.example.test").asset
            source_asset = attach_asset(output_root, engagement.id, str(source)).asset
            _write_discovery_live(asset_discovery_dir(output_root, engagement.id, live_asset.id))
            _write_discovery_source(asset_discovery_dir(output_root, engagement.id, source_asset.id))
            stdout = io.StringIO()
            second_stdout = io.StringIO()
            runner = FakeSecurityPlanningRunner()

            with patch(
                "mosh.crews.planning.crew.build_security_test_planning_crew_runner",
                return_value=runner,
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["plan", engagement.id, "--output-root", str(output_root)])
                first_plan_content = (output_root / engagement.id / "plan" / "plan.md").read_text(encoding="utf-8")
                first_links_content = (output_root / engagement.id / "plan" / "links.json").read_text(encoding="utf-8")
                with contextlib.redirect_stdout(second_stdout):
                    second_exit_code = main(["plan", engagement.id, "--output-root", str(output_root)])

            report_dir = output_root / engagement.id / "plan"
            self.assertEqual(exit_code, 0)
            self.assertEqual(second_exit_code, 0)
            self.assertEqual(len(runner.calls), 1)
            self.assertIn("Security test plan written to", stdout.getvalue())
            self.assertIn(f"then run `mosh test {engagement.id}`.", stdout.getvalue())
            self.assertIn("Security test plan is current", second_stdout.getvalue())
            self.assertIn(f"then run `mosh test {engagement.id}`.", second_stdout.getvalue())
            self.assertTrue((report_dir / "plan.md").exists())
            self.assertTrue((output_root / engagement.id / "engagement_template.yaml").exists())
            self.assertFalse((report_dir / "engagement_template.yaml").exists())
            self.assertEqual((report_dir / "plan.md").read_text(encoding="utf-8"), first_plan_content)
            self.assertEqual((report_dir / "links.json").read_text(encoding="utf-8"), first_links_content)

    def test_cli_test_security_engagement_uses_root_template_and_plan_dir(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://app.example.test"
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, target_url)
            planning_dir = output_root / engagement.id / "plan"
            plan = _plan()
            _write_plan_memory(planning_dir, plan)
            write_engagement_template(output_root / engagement.id, target_url, plan)
            runner = FakeSecurityTestingRunner()
            stdout = io.StringIO()

            with patch(
                "mosh.crews.testing.crew.build_testing_crew_runner",
                return_value=runner,
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["test", engagement.id, "--output-root", str(output_root)])

            report_dir = output_root / engagement.id / "security-testing"
            preflight = (report_dir / "preflight.md").read_text(encoding="utf-8")
            self.assertEqual(exit_code, 0)
            self.assertIn("Security testing preflight written to", stdout.getvalue())
            self.assertIn(f"Next: run `mosh report {engagement.id}`.", stdout.getvalue())
            self.assertEqual(runner.calls[0]["target_url"], target_url)
            self.assertTrue((report_dir / "executed_tests" / "HDR-001.md").exists())
            self.assertIn(f"Engagement file: `{output_root / engagement.id / 'engagement_template.yaml'}`", preflight)
            self.assertFalse((planning_dir / "engagement_template.yaml").exists())

    def test_cli_test_security_hypothesis_option_runs_only_selected_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://app.example.test"
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, target_url)
            planning_dir = output_root / engagement.id / "plan"
            plan = {
                "title": "Engagement Security Test Plan",
                "test_hypotheses": [
                    {
                        "id": "HDR-001",
                        "title": "Security headers are present",
                        "priority": "medium",
                        "surface": "headers",
                        "requirements": ["No credentials required."],
                        "execution_mode": "live",
                    },
                    {
                        "id": "AUTH-001",
                        "title": "Private API requires authentication",
                        "priority": "high",
                        "surface": "authentication",
                        "requirements": ["No credentials required."],
                        "execution_mode": "live",
                    },
                ],
            }
            _write_plan_memory(planning_dir, plan)
            write_engagement_template(output_root / engagement.id, target_url, plan)
            runner = FakeSecurityTestingRunner()

            with patch(
                "mosh.crews.testing.crew.build_testing_crew_runner",
                return_value=runner,
            ):
                exit_code = main(
                    [
                        "test",
                        engagement.id,
                        "--hypothesis",
                        "AUTH-001",
                        "--output-root",
                        str(output_root),
                    ]
                )

            report_dir = output_root / engagement.id / "security-testing"
            preflight = (report_dir / "preflight.md").read_text(encoding="utf-8")
            self.assertEqual(exit_code, 0)
            self.assertEqual(runner.calls[0]["executable_pending"], ["AUTH-001"])
            self.assertFalse((report_dir / "executed_tests" / "HDR-001.md").exists())
            self.assertTrue((report_dir / "executed_tests" / "AUTH-001.md").exists())
            self.assertIn("Selected hypotheses: `AUTH-001`", preflight)

    def test_cli_test_security_hypothesis_option_reports_unknown_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://app.example.test"
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, target_url)
            planning_dir = output_root / engagement.id / "plan"
            plan = _plan()
            _write_plan_memory(planning_dir, plan)
            write_engagement_template(output_root / engagement.id, target_url, plan)
            runner = FakeSecurityTestingRunner()
            stderr = io.StringIO()

            with patch(
                "mosh.crews.testing.crew.build_testing_crew_runner",
                return_value=runner,
            ):
                with contextlib.redirect_stderr(stderr):
                    exit_code = main(
                        [
                            "test",
                            engagement.id,
                            "--hypothesis",
                            "MISSING-001",
                            "--output-root",
                            str(output_root),
                        ]
                    )

            self.assertEqual(exit_code, 1)
            self.assertEqual(runner.calls, [])
            self.assertIn("Unknown hypothesis ID(s): MISSING-001", stderr.getvalue())
            self.assertIn("Available hypothesis IDs: HDR-001", stderr.getvalue())

    def test_cli_report_subcommand_writes_final_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://app.example.test"
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            live_asset = attach_asset(output_root, engagement.id, target_url).asset
            _write_discovery_live(asset_discovery_dir(output_root, engagement.id, live_asset.id))
            _write_plan_memory(output_root / engagement.id / "plan", _plan())
            testing_dir = output_root / engagement.id / "security-testing"
            testing_dir.mkdir(parents=True)
            (testing_dir / "memory.json").write_text("[]", encoding="utf-8")
            runner = FakeFinalReportingRunner()
            stdout = io.StringIO()

            with patch(
                "mosh.crews.reporting.crew.build_final_reporting_crew_runner",
                return_value=runner,
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["report", engagement.id, "--output-root", str(output_root)])

            report_path = output_root / engagement.id / "final-report" / "report.md"
            self.assertEqual(exit_code, 0)
            self.assertIn("Final report written to", stdout.getvalue())
            self.assertIn(f"Next: review `{report_path}` and run `mosh improvements list {engagement.id}`.", stdout.getvalue())
            self.assertTrue(report_path.exists())
            self.assertEqual(runner.calls[0]["target_url"], target_url)

    def test_cli_improvements_list_reports_single_and_all_engagements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            first = create_engagement(output_root)
            second = create_engagement(output_root)
            for engagement in [first, second]:
                record_harness_improvement(
                    output_root,
                    engagement.id,
                    stage="testing",
                    agent="executor",
                    category="tooling",
                    impact="high",
                    title="Add JWT claim diff tool",
                    problem="JWT claims had to be decoded and compared manually.",
                    suggestion="Add a bounded JWT decode and claim diff helper.",
                    source_ref="AUTH-001",
                )

            single_stdout = io.StringIO()
            with contextlib.redirect_stdout(single_stdout):
                single_exit = main(["improvements", "list", first.id, "--output-root", str(output_root)])

            all_stdout = io.StringIO()
            with contextlib.redirect_stdout(all_stdout):
                all_exit = main(["improvements", "list", "--output-root", str(output_root)])

            self.assertEqual(single_exit, 0)
            self.assertIn(f"Harness improvements for {first.id}: 1 suggestion", single_stdout.getvalue())
            self.assertIn(f"Engagements: {first.id}", single_stdout.getvalue())
            self.assertNotIn(second.id, single_stdout.getvalue())
            self.assertEqual(all_exit, 0)
            self.assertIn("Harness improvements across all engagements: 1 suggestion", all_stdout.getvalue())
            self.assertIn(f"Engagements: {', '.join(sorted([first.id, second.id]))}", all_stdout.getvalue())
            self.assertIn("Occurrences: 2", all_stdout.getvalue())

    def test_cli_improvements_list_empty_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["improvements", "list", "--output-root", str(output_root)])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue(), "No harness improvements recorded.\n")


if __name__ == "__main__":
    unittest.main()
