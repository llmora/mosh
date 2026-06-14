from __future__ import annotations

import json
import inspect
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mosh.config import AppConfig
from mosh.docker_tools import DockerToolResult
from mosh.engagement import write_engagement_template
from mosh.memory import FileMemory
from mosh.scope import report_dir_name
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
)
from tests.fakes import FakeSecurityTestingRunner


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

    def test_security_testing_skip_emits_event_and_stores_ids(self) -> None:
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
            report_path.write_text(
                _with_execution_metadata_mapping("# already executed\n", metadata),
                encoding="utf-8",
            )
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, _plan())
            engagement_file.write_text(
                (Path(directory) / "engagement_template.yaml").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            runner = FakeSecurityTestingRunner()

            orchestrator = SecurityTestingOrchestrator(
                AppConfig(),
                output_root=output_root,
                crew_runner=runner,
            )
            report_dir = orchestrator.run(target_url, engagement_file=engagement_file)

            self.assertEqual(
                getattr(orchestrator, "_skipped_test_ids", []),
                ["API-001"],
            )
            events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            skip_events = [
                e for e in events
                if e.get("action") == "tests_skipped" and e.get("agent") == "orchestrator"
            ]
            self.assertEqual(len(skip_events), 1)
            self.assertEqual(skip_events[0]["data"]["skipped_ids"], ["API-001"])

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
        self.assertEqual(
            inspect.getsource(_run_one_security_test).count('"targets": json.dumps(targets, sort_keys=True)'),
            3,
        )
        self.assertIn('"execution_bundle": json.dumps(execution_bundle, sort_keys=True)', inspect.getsource(_run_one_security_test))

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


class _CountingPlanningRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(self, target_url, discovery_dir, report_dir, memory):
        self.calls.append(
            {
                "target_url": target_url,
                "discovery_dir": str(discovery_dir),
                "report_dir": str(report_dir),
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
    ):
        self.calls.append(
            {
                "args": args,
                "input_text": input_text,
                "timeout": timeout,
                "tty": tty,
                "volumes": volumes,
                "workdir": workdir,
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
