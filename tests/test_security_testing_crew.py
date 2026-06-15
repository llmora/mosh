from __future__ import annotations

import json
import inspect
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mosh.config import AppConfig
from mosh.crews.discovery.crew import _load_crewai
from mosh.docker_tools import DockerToolResult
from mosh.engagement import write_engagement_template, write_engagement_template_mapping
from mosh.memory import FileMemory
from mosh.scope import report_dir_name, source_report_dir_name
from mosh.crews.security_testing.crew import (
    SecurityTestExecutionState,
    SecurityTestingOrchestrator,
    collect_security_testing_discovery_updates,
    _execution_metadata,
    _fallback_executor_evidence,
    _build_executor_crew,
    _build_reporter_crew,
    _build_reviewer_crew,
    _kickoff_capturing_tool_state,
    _build_run_security_command_tool,
    _run_one_security_test,
    _with_execution_metadata_mapping,
    hypothesis_fingerprint,
    plan_revision_id,
    _redact_text,
    _status_label,
    load_security_test_plan,
    render_executed_test_report,
    run_security_testing_preflight,
)
from mosh.crews.source_security_testing.crew import (
    SourceSecurityTestExecutionState,
    _cleanup_source_processes,
    _build_read_source_slice_tool,
    _build_request_local_http_tool,
    _build_run_source_command_tool,
    _build_start_source_process_tool,
    _build_stop_source_process_tool,
    _build_source_executor_crew,
    _build_source_reporter_crew,
    _build_source_reviewer_crew,
    _build_source_search_tool,
    _build_submit_source_evidence_tool,
    _build_write_workspace_file_tool,
    _run_bounded_source_search,
)
from tests.fakes import FakeSecurityTestingRunner, FakeSourceSecurityTestingRunner


def _plan() -> dict[str, object]:
    return {
        "title": "Security Test Plan",
        "scope_summary": "Fixture plan.",
        "assumptions": [],
        "test_hypotheses": [
            {
                "id": "API-001",
                "title": "Unauthenticated private API access is rejected",
                "surface": "api",
                "priority": "critical",
                "requirements": ["No credentials required for unauthenticated check."],
                "tools_expected": ["HTTP client"],
                "test_steps": ["Request endpoint without Authorization header."],
                "stopping_conditions": ["Stop after status code is recorded."],
            },
            {
                "id": "API-002",
                "title": "Admin and sales roles cannot cross tenant boundaries",
                "surface": "api",
                "priority": "critical",
                "requirements": ["Admin credentials", "Sales credentials", "Safe customer IDs"],
                "tools_expected": ["HTTP client"],
                "test_steps": ["Use admin and sales tokens to request customer_ids."],
                "stopping_conditions": ["Stop if sensitive data is returned."],
            },
        ],
        "deferred_test_opportunities": [],
        "not_in_scope": [],
        "open_questions": [],
    }


def _engagement_template(target: str) -> dict[str, object]:
    return {
        "engagement": {
            "authorization_confirmed": True,
            "active_testing_allowed": True,
            "state_changing_tests_allowed": True,
            "notes": None,
        },
        "targets": {
            "production": {"api": target},
            "alternative": {"api": None},
        },
        "contacts": {"escalation": {"name": None, "email": None, "phone": None}},
        "limits": {
            "max_requests_per_test": 100,
            "max_rate_per_second": 5,
            "stop_on_sensitive_data": True,
            "evidence_redaction": True,
        },
        "credentials": {},
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


def _source_engagement_template(source: str) -> dict[str, object]:
    template = _engagement_template(source)
    template["engagement"] = {
        "authorization_confirmed": True,
        "active_testing_allowed": False,
        "state_changing_tests_allowed": False,
        "notes": "Source-only preflight.",
    }
    template["targets"] = {
        "production": {"source": source},
        "alternative": {"source": None},
    }
    return template


class SecurityTestingCrewTests(unittest.TestCase):
    def test_load_security_test_plan_uses_structured_final_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            planning_dir = Path(directory)
            (planning_dir / "memory.json").write_text(
                json.dumps(
                    [
                        {
                            "kind": "security_test_plan_final",
                            "content": {"structured": _plan()},
                        }
                    ]
                ),
                encoding="utf-8",
            )

            plan = load_security_test_plan(planning_dir)

            self.assertEqual(plan["test_hypotheses"][0]["id"], "API-001")

    def test_security_testing_preflight_routes_by_execution_mode(self) -> None:
        plan = {
            "title": "Mixed plan",
            "test_hypotheses": [
                {
                    "id": "LIVE-001",
                    "title": "Live header check",
                    "priority": "medium",
                    "surface": "headers",
                    "requirements": ["No credentials required."],
                    "execution_mode": "live",
                },
                {
                    "id": "SRC-001",
                    "title": "Source authorization guard check",
                    "priority": "high",
                    "surface": "authentication",
                    "requirements": ["No credentials required."],
                    "execution_mode": "source",
                    "affected_source": [{"path": "api/routes/auth.js", "start_line": 1, "end_line": 20}],
                },
                {
                    "id": "COMBO-001",
                    "title": "Source-guided live verification",
                    "priority": "high",
                    "surface": "api",
                    "requirements": ["No credentials required."],
                    "execution_mode": "combined",
                    "affected_source": [{"path": "api/routes/accounts.js", "start_line": 10, "end_line": 30}],
                    "affected_runtime": [{"method": "GET", "url": "/api/accounts"}],
                },
                {
                    "id": "DEF-001",
                    "title": "Needs deployed runtime",
                    "priority": "medium",
                    "surface": "api",
                    "execution_mode": "deferred",
                    "requirements_to_proceed": ["Provide a staging URL."],
                },
            ],
        }
        engagement = _engagement_template(target="https://example.test")

        result = run_security_testing_preflight(plan, engagement, live_target_available=True, source_available=True)

        self.assertEqual([item["id"] for item in result.ready], ["LIVE-001"])
        self.assertEqual([item["id"] for item in result.source_ready], ["SRC-001"])
        self.assertEqual([item["id"] for item in result.combined], ["COMBO-001"])
        self.assertEqual([item["id"] for item in result.deferred], ["DEF-001"])
        self.assertEqual(result.blocked, [])

    def test_source_only_security_testing_executes_source_ready_tests_not_live_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_dir = Path(directory) / "example-source"
            source_file = source_dir / "api" / "routes" / "auth.js"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("function guard(req, res, next) { return next(); }\n", encoding="utf-8")
            source = str(source_dir)
            output_root = Path(directory) / "report"
            source_root = output_root / source_report_dir_name(source)
            planning_dir = source_root / "security-test-planning"
            planning_dir.mkdir(parents=True)
            plan = {
                "title": "Source plan",
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
            live_runner = FakeSecurityTestingRunner()
            source_runner = FakeSourceSecurityTestingRunner()

            report_dir = SecurityTestingOrchestrator(
                AppConfig(),
                output_root=output_root,
                crew_runner=live_runner,
                source_crew_runner=source_runner,
            ).run(
                source=source,
            )

            self.assertEqual(report_dir, source_root / "source-security-testing")
            self.assertEqual(live_runner.calls, [])
            self.assertEqual(source_runner.calls[0]["source_ready_pending"], ["SRC-001"])
            preflight = (report_dir / "preflight.md").read_text(encoding="utf-8")
            self.assertIn("Source-routed tests: `1`", preflight)
            self.assertIn("No live tests are ready to execute.", preflight)
            self.assertIn("These tests are routed to source security testing", preflight)
            self.assertTrue((report_dir / "executed_tests" / "SRC-001.md").exists())
            memory = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))
            preflight_memory = next(item["content"] for item in memory if item["kind"] == "security_testing_preflight")
            self.assertEqual([item["id"] for item in preflight_memory["source_ready"]], ["SRC-001"])
            self.assertEqual(preflight_memory["ready_pending"], [])
            self.assertEqual(preflight_memory["source_ready_pending"], ["SRC-001"])

    def test_security_testing_preflight_uses_alternative_targets_and_blocks_missing_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            domain_dir = output_root / report_dir_name(target_url)
            planning_dir = domain_dir / "security-test-planning"
            planning_dir.mkdir(parents=True)
            (planning_dir / "memory.json").write_text(
                json.dumps(
                    [
                        {
                            "kind": "security_test_plan_final",
                            "content": {"structured": _plan()},
                        }
                    ]
                ),
                encoding="utf-8",
            )
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, _plan())
            template = (Path(directory) / "engagement_template.yaml").read_text(encoding="utf-8")
            template = template.replace("api: null", 'api: "https://staging-api.example.test/api/private"', 1)
            engagement_file.write_text(template, encoding="utf-8")

            runner = FakeSecurityTestingRunner()
            report_dir = SecurityTestingOrchestrator(AppConfig(), output_root=output_root, crew_runner=runner).run(
                target_url,
                engagement_file=engagement_file,
            )

            preflight = (report_dir / "preflight.md").read_text(encoding="utf-8")
            self.assertIn("https://staging-api.example.test/api/private", preflight)
            self.assertIn("**API-001**", preflight)
            self.assertIn("**API-002**", preflight)
            self.assertNotIn("authorization_confirmed is not true", preflight)
            self.assertIn("missing credential material for admin", preflight)
            self.assertIn("missing credential material for sales", preflight)
            self.assertEqual(runner.calls[0]["ready_pending"], ["API-001"])
            self.assertTrue((report_dir / "executed_tests" / "API-001.md").exists())
            self.assertFalse((report_dir / "executed_tests" / "API-002.md").exists())

    def test_security_testing_skips_matching_accepted_execution_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            domain_dir = output_root / report_dir_name(target_url)
            planning_dir = domain_dir / "security-test-planning"
            executed_dir = domain_dir / "security-testing" / "executed_tests"
            planning_dir.mkdir(parents=True)
            executed_dir.mkdir(parents=True)
            (planning_dir / "memory.json").write_text(
                json.dumps(
                    [
                        {
                            "kind": "security_test_plan_final",
                            "content": {"structured": _plan()},
                        }
                    ]
                ),
                encoding="utf-8",
            )
            current_hypothesis = _plan()["test_hypotheses"][0]
            report_path = executed_dir / "API-001.md"
            metadata = _execution_metadata(
                test_id="API-001",
                plan_revision_id=plan_revision_id(_plan()),
                hypothesis_fingerprint=hypothesis_fingerprint(current_hypothesis),
                evidence={"status": "no-finding"},
                review={"accepted": True},
                report_path=str(report_path),
            )
            report_path.write_text(_with_execution_metadata_mapping("# already executed\n", metadata), encoding="utf-8")
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, _plan())
            engagement_file.write_text((Path(directory) / "engagement_template.yaml").read_text(encoding="utf-8"), encoding="utf-8")
            runner = FakeSecurityTestingRunner()

            report_dir = SecurityTestingOrchestrator(AppConfig(), output_root=output_root, crew_runner=runner).run(
                target_url,
                engagement_file=engagement_file,
            )

            self.assertEqual(runner.calls, [])
            self.assertIn("# already executed", (report_dir / "executed_tests" / "API-001.md").read_text(encoding="utf-8"))

    def test_source_security_testing_skips_matching_accepted_execution_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_dir = Path(directory) / "example-source"
            source_file = source_dir / "api" / "routes" / "auth.js"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("function guard() { return true; }\n", encoding="utf-8")
            source = str(source_dir)
            output_root = Path(directory) / "report"
            source_root = output_root / source_report_dir_name(source)
            planning_dir = source_root / "security-test-planning"
            executed_dir = source_root / "source-security-testing" / "executed_tests"
            planning_dir.mkdir(parents=True)
            executed_dir.mkdir(parents=True)
            plan = {
                "title": "Source plan",
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
            current_hypothesis = plan["test_hypotheses"][0]
            report_path = executed_dir / "SRC-001.md"
            metadata = _execution_metadata(
                test_id="SRC-001",
                plan_revision_id=plan_revision_id(plan),
                hypothesis_fingerprint=hypothesis_fingerprint(current_hypothesis),
                evidence={"status": "no-finding"},
                review={"accepted": True},
                report_path=str(report_path),
            )
            metadata.update({"execution_mode": "source", "evidence_type": "source", "source": source})
            report_path.write_text(_with_execution_metadata_mapping("# source already executed\n", metadata), encoding="utf-8")
            write_engagement_template_mapping(planning_dir, _source_engagement_template(source))
            live_runner = FakeSecurityTestingRunner()
            source_runner = FakeSourceSecurityTestingRunner()

            report_dir = SecurityTestingOrchestrator(
                AppConfig(),
                output_root=output_root,
                crew_runner=live_runner,
                source_crew_runner=source_runner,
            ).run(source=source)

            self.assertEqual(live_runner.calls, [])
            self.assertEqual(source_runner.calls, [])
            preflight = (report_dir / "preflight.md").read_text(encoding="utf-8")
            self.assertIn("`current`: matching accepted execution already exists", preflight)
            self.assertIn("# source already executed", (report_dir / "executed_tests" / "SRC-001.md").read_text(encoding="utf-8"))

    def test_execution_metadata_preserves_canonical_status(self) -> None:
        metadata = _execution_metadata(
            test_id="API-002",
            plan_revision_id="plan",
            hypothesis_fingerprint="fingerprint",
            evidence={"status": "finding"},
            review={"accepted": True},
            report_path="report/API-002.md",
        )

        self.assertEqual(metadata["status"], "finding")

    def test_security_testing_reruns_changed_hypothesis_and_archives_previous_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            domain_dir = output_root / report_dir_name(target_url)
            planning_dir = domain_dir / "security-test-planning"
            executed_dir = domain_dir / "security-testing" / "executed_tests"
            planning_dir.mkdir(parents=True)
            executed_dir.mkdir(parents=True)
            plan = _plan()
            changed_hypothesis = dict(plan["test_hypotheses"][0])
            changed_hypothesis["test_steps"] = ["Request endpoint without Authorization header.", "Also verify WWW-Authenticate."]
            plan["test_hypotheses"][0] = changed_hypothesis
            (planning_dir / "memory.json").write_text(
                json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]),
                encoding="utf-8",
            )
            old_report_path = executed_dir / "API-001.md"
            old_metadata = _execution_metadata(
                test_id="API-001",
                plan_revision_id="old-plan",
                hypothesis_fingerprint="old-fingerprint",
                evidence={"status": "no-finding"},
                review={"accepted": True},
                report_path=str(old_report_path),
            )
            old_report_path.write_text(_with_execution_metadata_mapping("# old execution\n", old_metadata), encoding="utf-8")
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, plan)
            engagement_file.write_text((Path(directory) / "engagement_template.yaml").read_text(encoding="utf-8"), encoding="utf-8")
            runner = FakeSecurityTestingRunner()

            report_dir = SecurityTestingOrchestrator(AppConfig(), output_root=output_root, crew_runner=runner).run(
                target_url,
                engagement_file=engagement_file,
            )

            self.assertEqual(runner.calls[0]["ready_pending"], ["API-001"])
            history_files = list((report_dir / "executed_tests" / "history").glob("API-001__old-fingerpr*__v1.md"))
            self.assertEqual(len(history_files), 1)
            self.assertIn("# old execution", history_files[0].read_text(encoding="utf-8"))
            self.assertIn("Fake execution completed", (report_dir / "executed_tests" / "API-001.md").read_text(encoding="utf-8"))

    def test_security_testing_reruns_legacy_report_without_metadata_and_preserves_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            domain_dir = output_root / report_dir_name(target_url)
            planning_dir = domain_dir / "security-test-planning"
            executed_dir = domain_dir / "security-testing" / "executed_tests"
            planning_dir.mkdir(parents=True)
            executed_dir.mkdir(parents=True)
            (planning_dir / "memory.json").write_text(
                json.dumps([{"kind": "security_test_plan_final", "content": {"structured": _plan()}}]),
                encoding="utf-8",
            )
            (executed_dir / "API-001.md").write_text("# legacy execution\n", encoding="utf-8")
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, _plan())
            engagement_file.write_text((Path(directory) / "engagement_template.yaml").read_text(encoding="utf-8"), encoding="utf-8")
            runner = FakeSecurityTestingRunner()

            report_dir = SecurityTestingOrchestrator(AppConfig(), output_root=output_root, crew_runner=runner).run(
                target_url,
                engagement_file=engagement_file,
            )

            self.assertEqual(runner.calls[0]["ready_pending"], ["API-001"])
            history_files = list((report_dir / "executed_tests" / "history").glob("API-001__legacy__v1.md"))
            self.assertEqual(len(history_files), 1)
            self.assertIn("# legacy execution", history_files[0].read_text(encoding="utf-8"))

    def test_security_testing_feeds_new_discovery_updates_and_refreshes_planning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            domain_dir = output_root / report_dir_name(target_url)
            discovery_dir = domain_dir / "discovery"
            planning_dir = domain_dir / "security-test-planning"
            discovery_dir.mkdir(parents=True)
            planning_dir.mkdir(parents=True)
            (discovery_dir / "report.md").write_text("# Discovery\n\n## Existing\n\nOriginal.\n", encoding="utf-8")
            (discovery_dir / "memory.json").write_text(
                json.dumps(
                    [
                        {
                            "kind": "security_testing_discovery_feedback",
                            "content": {
                                "updates": [
                                    {
                                        "test_id": "OLD-001",
                                        "type": "endpoint",
                                        "detail": "https://api.example.test/api/private/old",
                                        "confidence": "confirmed",
                                        "evidence": ["prior run"],
                                    }
                                ]
                            },
                            "source": "security_testing_orchestrator",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (discovery_dir / "events.json").write_text("[]", encoding="utf-8")
            (planning_dir / "memory.json").write_text(
                json.dumps([{"kind": "security_test_plan_final", "content": {"structured": _plan()}}]),
                encoding="utf-8",
            )
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, _plan())
            engagement_file.write_text((Path(directory) / "engagement_template.yaml").read_text(encoding="utf-8"), encoding="utf-8")
            planning_runner = _CountingPlanningRunner()

            report_dir = SecurityTestingOrchestrator(
                AppConfig(openrouter_api_key="test-key"),
                output_root=output_root,
                crew_runner=_DiscoveryFeedbackSecurityTestingRunner(),
                planning_crew_runner=planning_runner,
            ).run(target_url, engagement_file=engagement_file)

            discovery_memory = json.loads((discovery_dir / "memory.json").read_text(encoding="utf-8"))
            feedback_items = [item for item in discovery_memory if item["kind"] == "security_testing_discovery_feedback"]
            self.assertEqual(len(feedback_items), 2)
            self.assertIn("Express 4.18.2", json.dumps(feedback_items))
            discovery_report = (discovery_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Security Testing Feedback", discovery_report)
            self.assertIn("Express 4.18.2", discovery_report)
            self.assertIn("https://api.example.test/api/private/old", discovery_report)
            self.assertEqual(len(planning_runner.calls), 1)
            testing_events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(any(event["action"] == "security_planning_refresh_complete" for event in testing_events))

    def test_duplicate_discovery_feedback_does_not_refresh_planning_again(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            domain_dir = output_root / report_dir_name(target_url)
            discovery_dir = domain_dir / "discovery"
            planning_dir = domain_dir / "security-test-planning"
            discovery_dir.mkdir(parents=True)
            planning_dir.mkdir(parents=True)
            (discovery_dir / "report.md").write_text("# Discovery\n", encoding="utf-8")
            (discovery_dir / "memory.json").write_text(
                json.dumps(
                    [
                        {
                            "kind": "security_testing_discovery_feedback",
                            "content": {
                                "updates": [
                                    {
                                        "test_id": "API-001",
                                        "type": "component",
                                        "detail": "Express 4.18.2 is exposed by the API service header.",
                                        "confidence": "confirmed",
                                        "evidence": ["X-Powered-By: Express 4.18.2"],
                                    }
                                ]
                            },
                            "source": "security_testing_orchestrator",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (discovery_dir / "events.json").write_text("[]", encoding="utf-8")
            (planning_dir / "memory.json").write_text(
                json.dumps([{"kind": "security_test_plan_final", "content": {"structured": _plan()}}]),
                encoding="utf-8",
            )
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, _plan())
            engagement_file.write_text((Path(directory) / "engagement_template.yaml").read_text(encoding="utf-8"), encoding="utf-8")
            planning_runner = _CountingPlanningRunner()

            report_dir = SecurityTestingOrchestrator(
                AppConfig(openrouter_api_key="test-key"),
                output_root=output_root,
                crew_runner=_DiscoveryFeedbackSecurityTestingRunner(),
                planning_crew_runner=planning_runner,
            ).run(target_url, engagement_file=engagement_file)

            self.assertEqual(planning_runner.calls, [])
            testing_events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(any(event["action"] == "discovery_feedback_duplicate_skipped" for event in testing_events))

    def test_source_security_testing_feeds_discovery_updates_and_refreshes_planning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_dir = Path(directory) / "example-source"
            source_dir.mkdir()
            source = str(source_dir)
            output_root = Path(directory) / "report"
            source_root = output_root / source_report_dir_name(source)
            source_discovery_dir = source_root / "source-discovery"
            planning_dir = source_root / "security-test-planning"
            source_discovery_dir.mkdir(parents=True)
            planning_dir.mkdir(parents=True)
            (source_discovery_dir / "report.md").write_text("# Source Discovery\n", encoding="utf-8")
            (source_discovery_dir / "memory.json").write_text("[]", encoding="utf-8")
            (source_discovery_dir / "events.json").write_text("[]", encoding="utf-8")
            plan = {
                "title": "Source plan",
                "test_hypotheses": [
                    {
                        "id": "SRC-API-001",
                        "title": "Frontend API inventory",
                        "priority": "medium",
                        "surface": "spa",
                        "execution_mode": "source",
                        "affected_source": [{"path": "website/app.js", "start_line": 1, "end_line": 20}],
                    }
                ],
            }
            (planning_dir / "memory.json").write_text(
                json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]),
                encoding="utf-8",
            )
            write_engagement_template_mapping(planning_dir, _source_engagement_template(source))
            planning_runner = _CountingPlanningRunner()

            report_dir = SecurityTestingOrchestrator(
                AppConfig(openrouter_api_key="test-key"),
                output_root=output_root,
                crew_runner=FakeSecurityTestingRunner(),
                source_crew_runner=_DiscoveryFeedbackSourceSecurityTestingRunner(),
                planning_crew_runner=planning_runner,
            ).run(source=source)

            discovery_memory = json.loads((source_discovery_dir / "memory.json").read_text(encoding="utf-8"))
            feedback_items = [item for item in discovery_memory if item["kind"] == "security_testing_discovery_feedback"]
            self.assertEqual(len(feedback_items), 1)
            self.assertIn("GET ${API_BASE}/team", json.dumps(feedback_items))
            discovery_report = (source_discovery_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Security Testing Feedback", discovery_report)
            self.assertIn("GET ${API_BASE}/team", discovery_report)
            self.assertIn("Cloudflare Pages", discovery_report)
            self.assertEqual(len(planning_runner.calls), 1)
            self.assertEqual(planning_runner.calls[0]["source"], source)
            testing_events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(any(event["action"] == "security_planning_refresh_complete" for event in testing_events))

    def test_collect_security_testing_discovery_updates_deduplicates_explicit_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            memory = FileMemory(report_dir)
            memory.add_item(
                "security_test_execution_bundle",
                {
                    "test_id": "API-001",
                    "final_evidence": {
                        "discovery_updates": [
                            {
                                "type": "endpoint",
                                "detail": "https://api.example.test/api/private/status",
                                "confidence": "confirmed",
                                "evidence": ["curl returned 401"],
                            },
                            {
                                "type": "endpoint",
                                "detail": "https://api.example.test/api/private/status",
                                "confidence": "confirmed",
                                "evidence": ["curl returned 401"],
                            },
                        ]
                    },
                },
                "security_test_coordinator",
            )

            updates = collect_security_testing_discovery_updates(report_dir)

            self.assertEqual(len(updates), 1)
            self.assertEqual(updates[0]["test_id"], "API-001")
            self.assertEqual(updates[0]["type"], "endpoint")

    def test_collect_security_testing_discovery_updates_accepts_grouped_dict_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            memory = FileMemory(report_dir)
            memory.add_item(
                "security_test_execution_bundle",
                {
                    "test_id": "SPA-001",
                    "final_evidence": {
                        "discovery_updates": {
                            "frontend_api_endpoints_inventoried": [
                                "GET ${API_BASE}/team",
                                "POST ${API_BASE}/team/invite",
                            ],
                            "deployment_config": {
                                "platform": "Cloudflare Pages",
                                "production_api_base": "https://api.example.test/api/v1/enterprise/portal",
                            },
                        }
                    },
                },
                "source_security_test_coordinator",
            )

            updates = collect_security_testing_discovery_updates(report_dir)

            self.assertEqual(
                {(update["type"], update["detail"]) for update in updates},
                {
                    ("endpoint", "GET ${API_BASE}/team"),
                    ("endpoint", "POST ${API_BASE}/team/invite"),
                    ("configuration", "Cloudflare Pages"),
                    ("endpoint", "https://api.example.test/api/v1/enterprise/portal"),
                },
            )
            self.assertTrue(all(update["test_id"] == "SPA-001" for update in updates))

    def test_security_command_tool_blocks_out_of_scope_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            state = SecurityTestExecutionState(
                target_url="https://example.test",
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "API-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "API-001"},
                engagement={"credentials": {}},
                targets={"api": "https://api.example.test/api/private"},
                executed_report_path=report_dir / "executed_tests" / "API-001.md",
            )
            tool = _build_run_security_command_tool(_FakeCrewAI, AppConfig(), state)

            result = json.loads(tool._run("curl https://evil.example/path", "scope test"))

            self.assertTrue(result["blocked"])
            self.assertEqual(result["blocked_hosts"], ["evil.example"])
            self.assertEqual(state.commands, [])

    def test_security_command_tool_runs_in_workspace_and_redacts_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            state = SecurityTestExecutionState(
                target_url="https://example.test",
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "API-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "API-001"},
                engagement={"credentials": {"admin": {"username": "admin@example.test", "password": "secret", "token": "tok123"}}},
                targets={"api": "https://api.example.test/api/private"},
                executed_report_path=report_dir / "executed_tests" / "API-001.md",
            )
            fake_runner = _FakeDockerRunner(DockerToolResult(exit_code=0, stdout="token tok123\n", stderr=""))

            with patch("mosh.crews.security_testing.crew.DockerToolRunner", return_value=fake_runner):
                tool = _build_run_security_command_tool(_FakeCrewAI, AppConfig(), state)
                result = json.loads(tool._run("curl https://api.example.test/api/private/auth/me", "auth check"))

            self.assertEqual(fake_runner.calls[0]["volumes"], [(str(state.workspace_dir.resolve()), "/work")])
            self.assertEqual(fake_runner.calls[0]["workdir"], "/work")
            self.assertIn("[REDACTED]", result["stdout"])
            self.assertNotIn("tok123", json.dumps(result))

    def test_source_read_slice_tool_is_bounded_to_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_file = source_root / "api" / "routes" / "auth.js"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("function guard() {\n  return true;\n}\n", encoding="utf-8")
            outside_file = Path(directory) / "outside.js"
            outside_file.write_text("secret\n", encoding="utf-8")
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001"},
                engagement={"credentials": {}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
            )
            tool = _build_read_source_slice_tool(_FakeCrewAI, state)

            result = json.loads(tool._run("api/routes/auth.js", 1, 2, "guard check"))

            self.assertEqual(result["path"], "api/routes/auth.js")
            self.assertEqual(result["start_line"], 1)
            self.assertIn("function guard", result["content"])
            with self.assertRaises(ValueError):
                tool._run("../outside.js", 1, 1, "escape check")

    def test_source_search_tool_searches_nonignored_text_and_generated_dirs_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            (source_root / "build").mkdir(parents=True)
            (source_root / "src").mkdir(parents=True)
            (source_root / "src" / "app.js").write_text("const csrf = true;\n", encoding="utf-8")
            (source_root / ".env.example").write_text("CSRF_SECRET=example\n", encoding="utf-8")
            (source_root / "build" / "generated.js").write_text("const csrf = false;\n", encoding="utf-8")
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001"},
                engagement={"credentials": {}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
            )
            tool = _build_source_search_tool(_FakeCrewAI, state)

            result = json.loads(tool._run("csrf", "csrf search", regex=False, limit=10, path_glob=None))
            env_result = _run_bounded_source_search(source_root, "CSRF_SECRET", limit=10)

            paths = {match["path"] for match in result["matches"]}
            self.assertIn("src/app.js", paths)
            self.assertNotIn("build/generated.js", paths)
            self.assertEqual(env_result["matches"][0]["path"], ".env.example")

    def test_source_command_tool_mounts_source_read_only_and_blocks_external_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001"},
                engagement={"credentials": {"admin": {"token": "tok123"}}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
            )
            fake_runner = _FakeDockerRunner(DockerToolResult(exit_code=0, stdout="token tok123\n", stderr=""))

            with patch("mosh.crews.source_security_testing.crew.DockerToolRunner", return_value=fake_runner):
                tool = _build_run_source_command_tool(_FakeCrewAI, AppConfig(), state)
                blocked = json.loads(tool._run("curl https://example.test/private", "external check"))
                result = json.loads(tool._run("curl http://127.0.0.1:8000/health", "local runtime check"))

            self.assertTrue(blocked["blocked"])
            self.assertEqual(blocked["blocked_hosts"], ["example.test"])
            self.assertEqual(fake_runner.calls[0]["volumes"][0], (str(source_root.resolve()), "/source", "ro"))
            self.assertEqual(fake_runner.calls[0]["volumes"][1], (str(state.workspace_dir.resolve()), "/work"))
            self.assertEqual(fake_runner.calls[0]["workdir"], "/work")
            self.assertIn("[REDACTED]", result["stdout"])
            self.assertNotIn("tok123", json.dumps(result))

    def test_source_command_tool_accepts_explicit_env_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001"},
                engagement={"credentials": {"admin": {"token": "secret-env-value"}}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
            )
            fake_runner = _FakeDockerRunner(DockerToolResult(exit_code=0, stdout="mode enabled\n", stderr=""))

            with patch("mosh.crews.source_security_testing.crew.DockerToolRunner", return_value=fake_runner):
                tool = _build_run_source_command_tool(_FakeCrewAI, AppConfig(), state)
                result = json.loads(
                    tool._run(
                        "python3 /work/harness.py",
                        "env experiment",
                        env={"FEATURE_FLAG": "enabled", "TOKEN": "secret-env-value"},
                        timeout=10,
                    )
                )

            self.assertEqual(fake_runner.calls[0]["env"], {"FEATURE_FLAG": "enabled", "TOKEN": "secret-env-value"})
            self.assertEqual(result["env"]["FEATURE_FLAG"], "enabled")
            self.assertEqual(result["env"]["TOKEN"], "[REDACTED]")
            self.assertNotIn("secret-env-value", json.dumps(result))

    def test_write_workspace_file_tool_is_bounded_to_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001"},
                engagement={"credentials": {}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
            )
            tool = _build_write_workspace_file_tool(_FakeCrewAI, state)

            result = json.loads(tool._run("harnesses/routes.py", "print('routes')\n", "route introspection", executable=True))

            self.assertEqual(result["path"], "harnesses/routes.py")
            self.assertTrue((state.workspace_dir / "harnesses" / "routes.py").exists())
            self.assertTrue(result["executable"])
            with self.assertRaises(ValueError):
                tool._run("../escape.py", "print('no')\n", "escape attempt")

    def test_source_evidence_submission_normalizes_false_positive_finding_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "AUTH-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "AUTH-001"},
                engagement={"credentials": {}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "AUTH-001.md",
            )
            tool = _build_submit_source_evidence_tool(_FakeCrewAI, state)

            tool._run(
                {
                    "status": "finding",
                    "summary": "Model mismatch: customer auth is not JWT-based as hypothesized.",
                    "result": "No authentication bypasses found. No remediation required.",
                    "finding": None,
                }
            )

            self.assertEqual(state.evidence["status"], "no-finding")
            memory = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))
            structured = next(item["content"]["structured"] for item in memory if item["kind"] == "source_security_test_execution_evidence")
            self.assertEqual(structured["status"], "no-finding")

    def test_source_evidence_submission_normalizes_disproved_hypothesis_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "AUTH-002",
                memory=FileMemory(report_dir),
                hypothesis={"id": "AUTH-002"},
                engagement={"credentials": {}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "AUTH-002.md",
            )
            tool = _build_submit_source_evidence_tool(_FakeCrewAI, state)

            tool._run(
                {
                    "status": "finding",
                    "hypothesis_validated": False,
                    "summary": "Authentication is applied to all developer routes, contrary to the hypothesis.",
                    "result": "The original no-auth hypothesis is disproved. Residual hardening gaps remain.",
                    "original_hypothesis_result": "All routes are behind router-level auth middleware.",
                    "residual_findings": [
                        {"title": "Developer role is coarse", "severity": "medium", "evidence": ["api/private/developer.js:595"]}
                    ],
                    "finding": None,
                }
            )

            self.assertEqual(state.evidence["status"], "no-finding")
            memory = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))
            structured = next(item["content"]["structured"] for item in memory if item["kind"] == "source_security_test_execution_evidence")
            self.assertEqual(structured["status"], "no-finding")

    def test_start_source_process_tool_runs_detached_read_only_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001"},
                engagement={"credentials": {"admin": {"token": "tok123"}}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
            )
            docker_calls: list[list[str]] = []

            def fake_docker(command, timeout):
                docker_calls.append(command)
                return DockerToolResult(exit_code=0, stdout="container-123\n", stderr="")

            with patch("mosh.crews.source_security_testing.crew._run_docker_cli", side_effect=fake_docker):
                tool = _build_start_source_process_tool(_FakeCrewAI, AppConfig(security_tool_image="image:test"), state)
                result = json.loads(
                    tool._run(
                        "python3 -m http.server 8000",
                        "stand up fixture API",
                        container_port=8000,
                        host_port=18000,
                        env={"TOKEN": "tok123"},
                    )
                )

            self.assertEqual(result["container_id"], "container-123")
            self.assertEqual(result["local_url"], "http://host.docker.internal:18000")
            self.assertIn(f"{source_root.resolve()}:/source:ro", docker_calls[0])
            self.assertIn(f"{state.workspace_dir.resolve()}:/work", docker_calls[0])
            self.assertIn("TOKEN=tok123", docker_calls[0])
            self.assertEqual(result["env"]["TOKEN"], "[REDACTED]")

    def test_request_local_http_tool_blocks_external_hosts_and_records_local_requests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001"},
                engagement={"credentials": {"admin": {"token": "tok123"}}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
            )
            fake_runner = _FakeDockerRunner(DockerToolResult(exit_code=0, stdout="HTTP/1.1 200 OK\n\nok tok123", stderr=""))

            with patch("mosh.crews.source_security_testing.crew.DockerToolRunner", return_value=fake_runner):
                tool = _build_request_local_http_tool(_FakeCrewAI, AppConfig(), state)
                blocked = json.loads(tool._run("https://example.test/api", "external request"))
                result = json.loads(
                    tool._run(
                        "http://host.docker.internal:18000/api/routes",
                        "local route request",
                        headers={"Authorization": "Bearer tok123"},
                    )
                )

            self.assertTrue(blocked["blocked"])
            self.assertEqual(blocked["blocked_hosts"], ["example.test"])
            self.assertIn("host.docker.internal", fake_runner.calls[0]["args"][-1])
            self.assertEqual(result["headers"]["Authorization"], "Bearer [REDACTED]")
            self.assertIn("[REDACTED]", result["stdout"])

    def test_stop_source_process_tool_only_stops_known_containers_and_captures_logs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001"},
                engagement={"credentials": {"admin": {"token": "tok123"}}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
                local_processes=[{"container_id": "container-123", "status": "started"}],
            )
            docker_calls: list[list[str]] = []

            def fake_docker(command, timeout):
                docker_calls.append(command)
                if command[1] == "logs":
                    return DockerToolResult(exit_code=0, stdout="booted tok123\n", stderr="")
                return DockerToolResult(exit_code=0, stdout="container-123\n", stderr="")

            with patch("mosh.crews.source_security_testing.crew._run_docker_cli", side_effect=fake_docker):
                tool = _build_stop_source_process_tool(_FakeCrewAI, state)
                blocked = json.loads(tool._run("other-container", "scope guard"))
                result = json.loads(tool._run("container-123", "cleanup"))

            self.assertTrue(blocked["blocked"])
            self.assertEqual(docker_calls[0][:3], ["docker", "logs", "--tail"])
            self.assertEqual(docker_calls[1][:3], ["docker", "rm", "-f"])
            self.assertEqual(result["status"], "stopped")
            self.assertIn("[REDACTED]", result["logs_stdout"])

    def test_dynamic_source_fixture_can_use_harness_env_process_and_local_http(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            (source_root / "app.py").write_text(
                "import os\n\n"
                "def routes():\n"
                "    prefix = os.environ.get('API_PREFIX', '/api')\n"
                "    return [prefix + '/health']\n",
                encoding="utf-8",
            )
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-DYN",
                memory=FileMemory(report_dir),
                hypothesis={
                    "id": "SRC-DYN",
                    "title": "Runtime route table honors API_PREFIX",
                    "execution_mode": "source",
                    "source_assessment_type": "local-runtime-service",
                },
                engagement={"credentials": {"admin": {"token": "tok123"}}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-DYN.md",
            )
            fake_runner = _FakeDockerRunner(DockerToolResult(exit_code=0, stdout="HTTP/1.1 200 OK\n\n/api/health tok123", stderr=""))
            docker_calls: list[list[str]] = []

            def fake_docker(command, timeout):
                docker_calls.append(command)
                if command[1] == "logs":
                    return DockerToolResult(exit_code=0, stdout="started tok123\n", stderr="")
                if command[1] == "rm":
                    return DockerToolResult(exit_code=0, stdout="container-123\n", stderr="")
                return DockerToolResult(exit_code=0, stdout="container-123\n", stderr="")

            with (
                patch("mosh.crews.source_security_testing.crew.DockerToolRunner", return_value=fake_runner),
                patch("mosh.crews.source_security_testing.crew._run_docker_cli", side_effect=fake_docker),
            ):
                write_tool = _build_write_workspace_file_tool(_FakeCrewAI, state)
                command_tool = _build_run_source_command_tool(_FakeCrewAI, AppConfig(), state)
                start_tool = _build_start_source_process_tool(_FakeCrewAI, AppConfig(security_tool_image="image:test"), state)
                request_tool = _build_request_local_http_tool(_FakeCrewAI, AppConfig(), state)
                stop_tool = _build_stop_source_process_tool(_FakeCrewAI, state)

                harness = json.loads(
                    write_tool._run(
                        "harnesses/inspect_routes.py",
                        "import os, sys\nsys.path.insert(0, '/source')\nimport app\nprint(app.routes())\n",
                        "Inspect route table under controlled env",
                    )
                )
                command = json.loads(
                    command_tool._run(
                        "python3 /work/harnesses/inspect_routes.py",
                        "Run route harness with API_PREFIX override",
                        env={"API_PREFIX": "/api", "TOKEN": "tok123"},
                    )
                )
                process = json.loads(
                    start_tool._run(
                        "python3 -m http.server 8000",
                        "Expose local fixture service",
                        container_port=8000,
                        host_port=18000,
                        env={"TOKEN": "tok123"},
                    )
                )
                request = json.loads(
                    request_tool._run(
                        "http://host.docker.internal:18000/routes",
                        "Request local route table",
                        headers={"Authorization": "Bearer tok123"},
                    )
                )
                stopped = json.loads(stop_tool._run("container-123", "Stop local fixture service"))

            self.assertEqual(harness["path"], "harnesses/inspect_routes.py")
            self.assertEqual(command["env"]["API_PREFIX"], "/api")
            self.assertEqual(command["env"]["TOKEN"], "[REDACTED]")
            self.assertEqual(process["container_id"], "container-123")
            self.assertEqual(request["headers"]["Authorization"], "Bearer [REDACTED]")
            self.assertEqual(stopped["status"], "stopped")
            self.assertEqual(len(state.workspace_files), 1)
            self.assertEqual(len(state.commands), 1)
            self.assertEqual(len(state.local_requests), 1)
            self.assertEqual(len([item for item in state.local_processes if item["status"] == "started"]), 1)
            self.assertIn(f"{source_root.resolve()}:/source:ro", docker_calls[0])
            self.assertNotIn("tok123", json.dumps([command, request, stopped]))

    def test_source_process_cleanup_stops_unstopped_processes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            report_dir = Path(directory) / "report"
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001"},
                engagement={"credentials": {"admin": {"token": "tok123"}}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
                local_processes=[
                    {"container_id": "container-123", "status": "started"},
                    {"container_id": "container-456", "status": "started"},
                    {"container_id": "container-456", "status": "stopped"},
                ],
            )
            docker_calls: list[list[str]] = []

            def fake_docker(command, timeout):
                docker_calls.append(command)
                if command[1] == "logs":
                    return DockerToolResult(exit_code=0, stdout="booted tok123\n", stderr="")
                return DockerToolResult(exit_code=0, stdout="container-123\n", stderr="")

            with patch("mosh.crews.source_security_testing.crew._run_docker_cli", side_effect=fake_docker):
                _cleanup_source_processes(state)

            self.assertEqual(len(docker_calls), 2)
            self.assertEqual(docker_calls[0][:3], ["docker", "logs", "--tail"])
            self.assertEqual(docker_calls[1][:3], ["docker", "rm", "-f"])
            cleanup = state.local_processes[-1]
            self.assertTrue(cleanup["automatic_cleanup"])
            self.assertEqual(cleanup["container_id"], "container-123")
            self.assertEqual(cleanup["status"], "stopped")
            self.assertIn("[REDACTED]", cleanup["logs_stdout"])

    def test_executed_source_report_has_dynamic_evidence_sections(self) -> None:
        markdown = render_executed_test_report(
            target_url="source:/tmp/example",
            hypothesis={"id": "SRC-DYN", "title": "Runtime route table", "surface": "api", "priority": "high"},
            targets={},
            evidence={"status": "no-finding", "summary": "Local runtime behaved as expected.", "observations": []},
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
            execution_bundle={
                "workspace_files": [{"path": "harnesses/routes.py", "purpose": "Inspect routes", "bytes": 42}],
                "local_processes": [
                    {
                        "status": "started",
                        "local_url": "http://host.docker.internal:18000",
                        "purpose": "Local fixture service",
                    }
                ],
                "local_requests": [
                    {
                        "method": "GET",
                        "url": "http://host.docker.internal:18000/routes",
                        "exit_code": 0,
                        "purpose": "Inspect route table",
                    }
                ],
            },
            report_content=None,
        )

        self.assertIn("## Dynamic Source Evidence", markdown)
        self.assertIn("### Generated Workspace Files", markdown)
        self.assertIn("`harnesses/routes.py`", markdown)
        self.assertIn("### Local Processes", markdown)
        self.assertIn("http://host.docker.internal:18000", markdown)
        self.assertIn("### Local HTTP Requests", markdown)
        self.assertIn("`GET` `http://host.docker.internal:18000/routes`", markdown)

    def test_security_command_tool_redacts_jwts_not_listed_in_engagement(self) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InNhbGVzIn0."
            "lBZ4s7STySFXbK2H7E6PUiQ9eKPYDzix0N9fLq3aD8M"
        )

        self.assertNotIn(jwt, _redact_text(f'TOKEN="{jwt}"', {"credentials": {}}))
        self.assertEqual(
            _redact_text(f"Authorization: Bearer {jwt}", {"credentials": {}}),
            "Authorization: Bearer [REDACTED]",
        )

    def test_security_testing_sub_crews_use_packaged_yaml_without_report_config_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            state = SecurityTestExecutionState(
                target_url="https://example.test",
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "API-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "API-001", "title": "Auth", "surface": "api", "priority": "high"},
                engagement={"credentials": {}},
                targets={"api": "https://api.example.test/api/private"},
                executed_report_path=report_dir / "executed_tests" / "API-001.md",
            )
            config = AppConfig(openrouter_api_key="test-key")

            for builder in (_build_executor_crew, _build_reviewer_crew, _build_reporter_crew):
                crew = builder(_FakeRuntimeCrewAI, config, state).crew()
                self.assertEqual(len(crew.agents), 1)
                self.assertEqual(len(crew.tasks), 1)

            self.assertFalse((report_dir / ".crew_config").exists())

    def test_source_security_testing_sub_crews_use_packaged_yaml_without_report_config_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "report"
            source_root = Path(directory) / "source"
            source_root.mkdir()
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001", "title": "Auth", "surface": "api", "priority": "high"},
                engagement={"credentials": {}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
            )
            config = AppConfig(openrouter_api_key="test-key")

            for builder in (_build_source_executor_crew, _build_source_reviewer_crew, _build_source_reporter_crew):
                crew = builder(_FakeRuntimeCrewAI, config, state).crew()
                self.assertEqual(len(crew.agents), 1)
                self.assertEqual(len(crew.tasks), 1)

            self.assertFalse((report_dir / ".crew_config").exists())

    def test_security_testing_subcrews_use_packaged_subset_yaml_with_real_crewai(self) -> None:
        crewai = _load_crewai()
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            state = SecurityTestExecutionState(
                target_url="https://example.test",
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "API-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "API-001", "title": "Auth", "surface": "api", "priority": "high"},
                engagement={"credentials": {}},
                targets={"api": "https://api.example.test/api/private"},
                executed_report_path=report_dir / "executed_tests" / "API-001.md",
            )
            config = AppConfig(openrouter_api_key="test-key")

            crews = [
                _build_executor_crew(crewai, config, state),
                _build_reviewer_crew(crewai, config, state),
                _build_reporter_crew(crewai, config, state),
            ]

            self.assertEqual(len(crews), 3)
            self.assertFalse((report_dir / ".crew_config").exists())

    def test_source_security_testing_subcrews_use_packaged_subset_yaml_with_real_crewai(self) -> None:
        crewai = _load_crewai()
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "report"
            source_root = Path(directory) / "source"
            source_root.mkdir()
            state = SourceSecurityTestExecutionState(
                source=str(source_root),
                source_root=source_root,
                source_context={},
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "SRC-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "SRC-001", "title": "Auth", "surface": "api", "priority": "high"},
                engagement={"credentials": {}},
                targets={},
                executed_report_path=report_dir / "executed_tests" / "SRC-001.md",
            )
            config = AppConfig(openrouter_api_key="test-key")

            crews = [
                _build_source_executor_crew(crewai, config, state),
                _build_source_reviewer_crew(crewai, config, state),
                _build_source_reporter_crew(crewai, config, state),
            ]

            self.assertEqual(len(crews), 3)
            self.assertFalse((report_dir / ".crew_config").exists())

    def test_kickoff_ignores_post_tool_failure_when_evidence_was_captured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            state = SecurityTestExecutionState(
                target_url="https://example.test",
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "API-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "API-001"},
                engagement={"credentials": {}},
                targets={"api": "https://api.example.test/api/private"},
                executed_report_path=report_dir / "executed_tests" / "API-001.md",
                evidence={"status": "no-finding", "summary": "Captured before CrewAI failed."},
            )

            _kickoff_capturing_tool_state(
                _FailingCrew("Input should be a valid string"),
                state,
                agent_name="executor",
                task_name="execute_security_test_task",
                captured=lambda: state.evidence is not None,
                inputs={"target_url": "https://example.test"},
            )

            events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            self.assertEqual(events[-1]["action"], "crew_post_tool_failure_ignored")
            self.assertIn("Input should be a valid string", events[-1]["data"]["error"])

    def test_kickoff_ignores_post_tool_failure_when_commands_were_captured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            state = SecurityTestExecutionState(
                target_url="https://example.test",
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "API-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "API-001"},
                engagement={"credentials": {}},
                targets={"api": "https://api.example.test/api/private"},
                executed_report_path=report_dir / "executed_tests" / "API-001.md",
                commands=[{"command": "curl https://api.example.test/api/private", "exit_code": 0}],
            )

            _kickoff_capturing_tool_state(
                _FailingCrew("Input should be a valid string"),
                state,
                agent_name="executor",
                task_name="execute_security_test_task",
                captured=lambda: state.evidence is not None or bool(state.commands),
                inputs={"target_url": "https://example.test"},
            )
            fallback = _fallback_executor_evidence(state)

            self.assertEqual(fallback["status"], "inconclusive")
            self.assertEqual(fallback["commands"], state.commands)

    def test_kickoff_raises_post_tool_failure_without_captured_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            state = SecurityTestExecutionState(
                target_url="https://example.test",
                report_dir=report_dir,
                workspace_dir=report_dir / "workspaces" / "API-001",
                memory=FileMemory(report_dir),
                hypothesis={"id": "API-001"},
                engagement={"credentials": {}},
                targets={"api": "https://api.example.test/api/private"},
                executed_report_path=report_dir / "executed_tests" / "API-001.md",
            )

            with self.assertRaises(RuntimeError):
                _kickoff_capturing_tool_state(
                    _FailingCrew("executor failed before submitting evidence"),
                    state,
                    agent_name="executor",
                    task_name="execute_security_test_task",
                    captured=lambda: state.evidence is not None,
                    inputs={"target_url": "https://example.test"},
                )

    def test_security_testing_tasks_treat_effective_targets_as_canonical(self) -> None:
        task_yaml = (
            Path("src/mosh/crews/security_testing/tasks.yaml")
            .read_text(encoding="utf-8")
            .lower()
        )
        compact_task_yaml = " ".join(task_yaml.split())

        self.assertIn("effective target mappings as canonical", task_yaml)
        self.assertIn("rewrite discovered paths", task_yaml)
        self.assertIn("attempt production urls", task_yaml)
        self.assertEqual(task_yaml.count("effective target mappings json:"), 3)
        self.assertIn("canonical for review", task_yaml)
        self.assertIn("do not request a re-run", task_yaml)
        self.assertIn("write the report against the effective target mappings", task_yaml)
        self.assertIn("discovery evidence urls from execution targets", task_yaml)
        self.assertIn("accepted_artifacts", task_yaml)
        self.assertIn("execution bundle json", task_yaml)
        self.assertIn("useful_artifacts", task_yaml)
        self.assertIn("resolution:", task_yaml)
        self.assertIn("developer/app-owner guidance", task_yaml)
        self.assertIn("hypothesis_validated", task_yaml)
        self.assertIn("original_hypothesis_result", task_yaml)
        self.assertIn("residual_findings", task_yaml)
        self.assertIn("planning priority is not finding severity", compact_task_yaml)
        self.assertIn("do not reuse the planned priority as finding severity", compact_task_yaml)
        self.assertEqual(
            inspect.getsource(_run_one_security_test).count('"targets": json.dumps(targets, sort_keys=True)'),
            3,
        )
        self.assertIn('"execution_bundle": json.dumps(execution_bundle, sort_keys=True)', inspect.getsource(_run_one_security_test))

    def test_source_security_testing_tasks_separate_original_hypothesis_from_residual_findings(self) -> None:
        task_yaml = "\n".join(
            [
                Path("src/mosh/crews/source_security_testing/executor_tasks.yaml").read_text(encoding="utf-8"),
                Path("src/mosh/crews/source_security_testing/reviewer_tasks.yaml").read_text(encoding="utf-8"),
                Path("src/mosh/crews/source_security_testing/reporter_tasks.yaml").read_text(encoding="utf-8"),
            ]
        ).lower()
        compact_task_yaml = " ".join(task_yaml.split())

        self.assertIn("hypothesis_validated", task_yaml)
        self.assertIn("original_hypothesis_result", task_yaml)
        self.assertIn("residual_findings", task_yaml)
        self.assertIn("planning priority is not finding severity", compact_task_yaml)
        self.assertIn("do not reuse the planned priority as finding severity", compact_task_yaml)
        self.assertIn("do not render it as finding confirmed", compact_task_yaml)

    def test_executed_test_report_includes_effective_targets(self) -> None:
        markdown = render_executed_test_report(
            target_url="https://example.test",
            hypothesis={"id": "API-001", "title": "API auth", "surface": "api", "priority": "high"},
            targets={"api": "https://preprod-api.example.test/api/private"},
            evidence={"status": "no-finding", "summary": "Checked mapped target.", "result": "No issue."},
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
        )

        self.assertIn("- Effective targets:", markdown)
        self.assertIn("api: `https://preprod-api.example.test/api/private`", markdown)

    def test_executed_test_report_renders_human_readable_status(self) -> None:
        markdown = render_executed_test_report(
            target_url="https://example.test",
            hypothesis={"id": "API-002", "title": "Bundle access", "surface": "api", "priority": "high"},
            evidence={"status": "finding", "summary": "Admin can download bundle.", "result": "Finding."},
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
        )

        self.assertIn("## Status\n\nFinding Confirmed\n", markdown)
        self.assertNotIn("## Status\n\nfinding\n", markdown)

    def test_executed_test_report_downgrades_contradictory_finding_status(self) -> None:
        evidence = {
            "status": "finding",
            "summary": "Customer auth is session-token based, not JWT as hypothesized.",
            "result": "No authentication bypasses found via source inspection. No remediation required.",
            "finding": None,
        }

        markdown = render_executed_test_report(
            target_url="source:/tmp/example",
            hypothesis={"id": "AUTH-001", "title": "JWT middleware bypass", "surface": "authentication", "priority": "critical"},
            evidence=evidence,
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
            report_content={"status": "finding", "finding": None, "result": evidence["result"]},
        )
        metadata = _execution_metadata(
            test_id="AUTH-001",
            plan_revision_id="plan",
            hypothesis_fingerprint="fingerprint",
            evidence=evidence,
            review={"accepted": True},
            report_path="executed_tests/AUTH-001.md",
            report_content={"status": "finding", "finding": None, "result": evidence["result"]},
        )

        self.assertIn("## Status\n\nNo Finding\n", markdown)
        self.assertNotIn("## Status\n\nFinding Confirmed\n", markdown)
        self.assertEqual(metadata["status"], "no-finding")

    def test_executed_test_report_downgrades_disproved_hypothesis_with_residual_risks(self) -> None:
        evidence = {
            "status": "finding",
            "hypothesis_validated": False,
            "summary": "Router-level JWT authentication is applied to all developer routes, contrary to the hypothesis.",
            "result": (
                "The hypothesis claim is wrong: auth exists at the router level. "
                "Residual hardening gaps remain, including coarse role authorization and no route-specific rate limits."
            ),
            "original_hypothesis_result": "All inspected developer routes are behind router-level JWT middleware.",
            "residual_findings": [
                {
                    "title": "Developer routes use coarse role authorization",
                    "severity": "medium",
                    "evidence": ["api/private/developer.js:595"],
                }
            ],
            "finding": None,
        }

        markdown = render_executed_test_report(
            target_url="source:/tmp/example",
            hypothesis={
                "id": "AUTH-002",
                "title": "Private developer router has no authentication middleware",
                "surface": "authentication",
                "priority": "critical",
            },
            evidence=evidence,
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
            report_content={
                "status": "finding",
                "hypothesis_validated": False,
                "finding": None,
                "result": evidence["result"],
            },
        )
        metadata = _execution_metadata(
            test_id="AUTH-002",
            plan_revision_id="plan",
            hypothesis_fingerprint="fingerprint",
            evidence=evidence,
            review={"accepted": True},
            report_path="executed_tests/AUTH-002.md",
            report_content={
                "status": "finding",
                "hypothesis_validated": False,
                "finding": None,
                "result": evidence["result"],
            },
        )

        self.assertIn("## Status\n\nNo Finding\n", markdown)
        self.assertNotIn("## Status\n\nFinding Confirmed\n", markdown)
        self.assertEqual(metadata["status"], "no-finding")

    def test_structured_residual_finding_is_not_downgraded_by_disproved_original_hypothesis(self) -> None:
        markdown = render_executed_test_report(
            target_url="source:/tmp/example",
            hypothesis={
                "id": "AUTH-002",
                "title": "Private developer router has no authentication middleware",
                "surface": "authentication",
                "priority": "critical",
            },
            evidence={
                "status": "finding",
                "hypothesis_validated": False,
                "summary": "Authentication exists, contrary to the hypothesis, but a separate authorization issue was confirmed.",
                "result": "Developer routes use coarse role authorization for privileged actions.",
                "finding": {
                    "title": "Developer routes rely on coarse role authorization",
                    "severity": "medium",
                    "impact": "A developer-role token can reach unrelated privileged actions.",
                    "recommendation": "Add action-scoped authorization checks.",
                    "evidence": ["api/private/developer.js:595"],
                },
            },
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
        )

        self.assertIn("## Status\n\nFinding Confirmed\n", markdown)

    def test_status_labels_cover_security_testing_states(self) -> None:
        self.assertEqual(_status_label("needs-review"), "Needs Review")
        self.assertEqual(_status_label("needs-rerun"), "Needs Re-Run")
        self.assertEqual(_status_label("rerun-requested"), "Re-Run Requested")
        self.assertEqual(_status_label("partial-finding"), "Partial Finding")
        self.assertEqual(_status_label("not-applicable"), "Not Applicable")
        self.assertEqual(_status_label("error"), "Execution Error")
        self.assertEqual(_status_label("custom_status"), "Custom Status")

    def test_executed_test_report_renders_artifact_sibling_fields_even_with_observations(self) -> None:
        markdown = render_executed_test_report(
            target_url="https://example.test",
            hypothesis={"id": "HDR-001", "title": "CSP", "surface": "headers", "priority": "medium"},
            evidence={
                "status": "finding",
                "summary": "CSP is missing.",
                "observations": {"csp": "absent"},
                "result": "Missing CSP.",
                "recommended_csp_policy": "default-src 'self'; object-src 'none'; base-uri 'self';",
            },
            review={"accepted": True, "summary": "Accepted.", "accepted_artifacts": ["content_security_policy"]},
            commands=[],
        )

        self.assertIn("## Useful Artifacts", markdown)
        self.assertIn("### content_security_policy", markdown)
        self.assertIn("default-src 'self'; object-src 'none'; base-uri 'self';", markdown)

    def test_executed_test_report_renders_artifacts_from_prior_attempt_bundle(self) -> None:
        markdown = render_executed_test_report(
            target_url="https://example.test",
            hypothesis={"id": "HDR-001", "title": "CSP", "surface": "headers", "priority": "medium"},
            evidence={
                "status": "inconclusive",
                "summary": "Final attempt used fallback evidence.",
                "observations": [],
                "result": "No final conclusion.",
            },
            review={"accepted": False, "summary": "Needs re-run."},
            commands=[],
            execution_bundle={
                "artifacts": [
                    {
                        "type": "recommended_policy",
                        "name": "content_security_policy",
                        "value": "script-src 'self'; object-src 'none';",
                        "source_revision": 1,
                        "status": "draft",
                        "review_status": "preserved",
                    }
                ]
            },
        )

        self.assertIn("### content_security_policy", markdown)
        self.assertNotIn("Source revision:", markdown)
        self.assertNotIn("Review status:", markdown)
        self.assertIn("script-src 'self'; object-src 'none';", markdown)
        self.assertIn("## Resolution", markdown)
        self.assertIn("Use the preserved `content_security_policy` artifact", markdown)

    def test_executed_test_report_renders_concrete_artifacts_and_skips_descriptors(self) -> None:
        markdown = render_executed_test_report(
            target_url="https://example.test",
            hypothesis={"id": "CORS-001", "title": "CORS", "surface": "cors", "priority": "high"},
            evidence={
                "status": "finding",
                "summary": "Wildcard CORS.",
                "result": "Token theft amplification.",
                "artifacts": {
                    "cors_policy_summary": "ACAO is wildcard on authenticated API endpoints; ACAC is absent.",
                    "recommended_remediation": "Restrict ACAO to approved origins and add Vary: Origin.",
                },
            },
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
            report_content={
                "useful_artifacts": [
                    {
                        "name": "cors_policy_summary",
                        "type": "artifact",
                        "description": "CORS policy summary covering all findings.",
                        "source": "executor evidence artifacts",
                    },
                    {
                        "name": "commands",
                        "type": "artifact",
                        "description": "All curl commands used for testing.",
                        "source": "executor evidence artifacts",
                    },
                ]
            },
        )

        self.assertIn("### cors_policy_summary", markdown)
        self.assertIn("ACAO is wildcard on authenticated API endpoints", markdown)
        self.assertIn("### recommended_remediation", markdown)
        self.assertIn("Restrict ACAO to approved origins", markdown)
        self.assertNotIn("### commands", markdown)
        self.assertNotIn("Type: `artifact`", markdown)
        self.assertNotIn("Review status:", markdown)

    def test_executed_test_report_renders_explicit_resolution(self) -> None:
        markdown = render_executed_test_report(
            target_url="https://example.test",
            hypothesis={"id": "HDR-001", "title": "CSP", "surface": "headers", "priority": "medium"},
            evidence={"status": "finding", "summary": "CSP is missing.", "result": "Missing CSP."},
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
            report_content={
                "resolution": [
                    "Set Content-Security-Policy on all HTML responses.",
                    "Start with report-only mode, then enforce after validating reports.",
                ]
            },
        )

        self.assertIn("## Resolution", markdown)
        self.assertIn("Set Content-Security-Policy", markdown)
        self.assertIn("report-only mode", markdown)

    def test_executed_test_report_splits_inline_numbered_resolution(self) -> None:
        markdown = render_executed_test_report(
            target_url="https://example.test",
            hypothesis={"id": "CORS-001", "title": "CORS", "surface": "cors", "priority": "high"},
            evidence={"status": "finding", "summary": "Wildcard CORS.", "result": "Finding."},
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
            report_content={
                "resolution": (
                    "Remove Access-Control-Allow-Origin: * from authenticated API endpoints. "
                    "2. Add Vary: Origin to responses that include Access-Control-Allow-Origin. "
                    "3. Reduce JWT expiry to limit token theft impact."
                )
            },
        )

        self.assertIn("1. Remove Access-Control-Allow-Origin", markdown)
        self.assertIn("2. Add Vary: Origin", markdown)
        self.assertIn("3. Reduce JWT expiry", markdown)
        self.assertNotIn("endpoints. 2. Add", markdown)

    def test_executed_test_report_uses_finding_recommendation_as_resolution_fallback(self) -> None:
        markdown = render_executed_test_report(
            target_url="https://example.test",
            hypothesis={"id": "CORS-001", "title": "CORS", "surface": "headers", "priority": "high"},
            evidence={"status": "finding", "summary": "Wildcard CORS.", "result": "Finding."},
            review={"accepted": True, "summary": "Accepted."},
            commands=[],
            report_content={
                "finding": {
                    "severity": "high",
                    "title": "Wildcard CORS",
                    "recommendation": "Restrict Access-Control-Allow-Origin to approved application origins.",
                }
            },
        )

        self.assertIn("## Resolution", markdown)
        self.assertIn("Restrict Access-Control-Allow-Origin", markdown)


class _FakeCrewAI:
    BaseModel = object
    BaseTool = object

    @staticmethod
    def Field(default=None, description: str = ""):
        return default


class _FakeRuntimeCrewAI(_FakeCrewAI):
    class Process:
        sequential = "sequential"

    class LLM:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

    class Agent:
        def __init__(self, config, llm, tools, allow_delegation) -> None:
            self.config = config
            self.llm = llm
            self.tools = tools
            self.allow_delegation = allow_delegation

    class Task:
        def __init__(self, config, agent, callback=None) -> None:
            self.config = config
            self.agent = agent
            self.callback = callback

    class Crew:
        def __init__(self, agents, tasks, process, verbose) -> None:
            self.agents = agents
            self.tasks = tasks
            self.process = process
            self.verbose = verbose

    @staticmethod
    def CrewBase(cls):
        if isinstance(getattr(cls, "agents_config", None), str):
            cls.agents_config = _FakeRuntimeCrewAI._load_config_blocks(cls.agents_config)
        if isinstance(getattr(cls, "tasks_config", None), str):
            cls.tasks_config = _FakeRuntimeCrewAI._load_config_blocks(cls.tasks_config)
        return cls

    @staticmethod
    def _load_config_blocks(path: str) -> dict[str, str]:
        blocks: dict[str, list[str]] = {}
        current_key: str | None = None
        current_block: list[str] = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                if current_key is not None:
                    blocks[current_key] = current_block
                current_key = line.rstrip()[:-1]
                current_block = []
            elif current_key is not None:
                current_block.append(line)
        if current_key is not None:
            blocks[current_key] = current_block
        return {key: "\n".join(value) for key, value in blocks.items()}

    @staticmethod
    def agent(fn):
        return fn

    @staticmethod
    def task(fn):
        return fn

    @staticmethod
    def crew(fn):
        return fn


class _DiscoveryFeedbackSecurityTestingRunner:
    def run(self, target_url, report_dir, memory, plan, engagement, preflight, ready_pending) -> None:
        memory.add_item(
            "security_test_execution_bundle",
            {
                "test_id": "API-001",
                "final_evidence": {
                    "status": "no-finding",
                    "summary": "Execution discovered a backend version header.",
                    "discovery_updates": [
                        {
                            "type": "component",
                            "detail": "Express 4.18.2 is exposed by the API service header.",
                            "confidence": "confirmed",
                            "evidence": ["X-Powered-By: Express 4.18.2"],
                        }
                    ],
                },
                "final_review": {"accepted": True},
                "attempts": [],
                "artifacts": [],
                "commands": [],
            },
            "security_test_coordinator",
        )


class _DiscoveryFeedbackSourceSecurityTestingRunner:
    def run(self, source, source_discovery_dir, report_dir, memory, plan, engagement, preflight, source_ready_pending) -> None:
        memory.add_item(
            "security_test_execution_bundle",
            {
                "test_id": "SRC-API-001",
                "final_evidence": {
                    "status": "finding",
                    "summary": "Source execution discovered frontend API endpoints.",
                    "discovery_updates": {
                        "frontend_api_endpoints_inventoried": [
                            "GET ${API_BASE}/team",
                            "POST ${API_BASE}/team/invite",
                        ],
                        "deployment_config": {
                            "platform": "Cloudflare Pages",
                        },
                    },
                },
                "final_review": {"accepted": True},
                "attempts": [],
                "artifacts": [],
                "commands": [],
            },
            "source_security_test_coordinator",
        )


class _CountingPlanningRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(self, target_url, discovery_dir, report_dir, memory, source=None, source_discovery_dir=None):
        self.calls.append(
            {
                "target_url": target_url,
                "discovery_dir": str(discovery_dir),
                "report_dir": str(report_dir),
                "source": source,
                "source_discovery_dir": str(source_discovery_dir) if source_discovery_dir else None,
            }
        )
        memory.add_item(
            "security_test_plan_final",
            {
                "structured": _refreshed_plan(),
                "critic_review": {"accepted": True},
            },
            "reporter",
        )
        return _PlanningResult(_refreshed_plan(), {"accepted": True}, accepted=True, iterations=1)


def _refreshed_plan() -> dict[str, object]:
    return {
        "title": "Refreshed plan",
        "test_hypotheses": [
            {
                "id": "API-001",
                "title": "Refreshed test",
                "requirements": ["No credentials required."],
            }
        ],
    }


class _PlanningResult:
    def __init__(self, plan, critic_review, accepted: bool, iterations: int) -> None:
        self.plan = plan
        self.critic_review = critic_review
        self.accepted = accepted
        self.iterations = iterations


class _FakeDockerRunner:
    def __init__(self, result: DockerToolResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        args,
        input_text=None,
        timeout=60,
        tty=False,
        volumes=None,
        workdir=None,
        env=None,
    ):
        self.calls.append(
            {
                "args": args,
                "input_text": input_text,
                "timeout": timeout,
                "tty": tty,
                "volumes": volumes,
                "workdir": workdir,
                "env": env,
            }
        )
        return self.result


class _FailingCrew:
    def __init__(self, message: str) -> None:
        self.message = message

    def crew(self):
        return self

    def kickoff(self, inputs):
        raise RuntimeError(self.message)


if __name__ == "__main__":
    unittest.main()
