from __future__ import annotations

import json
import inspect
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_harness.config import AppConfig
from appsec_harness.docker_tools import DockerToolResult
from appsec_harness.engagement import write_engagement_template
from appsec_harness.memory import FileMemory
from appsec_harness.scope import report_dir_name
from appsec_harness.crews.security_testing.crew import (
    SecurityTestExecutionState,
    SecurityTestingOrchestrator,
    collect_security_testing_discovery_updates,
    _fallback_executor_evidence,
    _kickoff_capturing_tool_state,
    _build_run_security_command_tool,
    _run_one_security_test,
    _redact_text,
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

    def test_security_testing_skips_already_executed_ready_tests(self) -> None:
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
            (executed_dir / "API-001.md").write_text("# already executed\n", encoding="utf-8")
            engagement_file = Path(directory) / "engagement.yaml"
            write_engagement_template(Path(directory), target_url, _plan())
            engagement_file.write_text((Path(directory) / "engagement_template.yaml").read_text(encoding="utf-8"), encoding="utf-8")
            runner = FakeSecurityTestingRunner()

            report_dir = SecurityTestingOrchestrator(AppConfig(), output_root=output_root, crew_runner=runner).run(
                target_url,
                engagement_file=engagement_file,
            )

            self.assertEqual(runner.calls, [])
            self.assertEqual((report_dir / "executed_tests" / "API-001.md").read_text(encoding="utf-8"), "# already executed\n")

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

            with patch("appsec_harness.crews.security_testing.crew.DockerToolRunner", return_value=fake_runner):
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
                agent_name="security_test_executor",
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
                agent_name="security_test_executor",
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
                    agent_name="security_test_executor",
                    task_name="execute_security_test_task",
                    captured=lambda: state.evidence is not None,
                    inputs={"target_url": "https://example.test"},
                )

    def test_security_testing_tasks_treat_effective_targets_as_canonical(self) -> None:
        task_yaml = (
            Path("src/appsec_harness/crews/security_testing/tasks.yaml")
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
        self.assertIn("Source revision: `1`", markdown)
        self.assertIn("script-src 'self'; object-src 'none';", markdown)
        self.assertIn("## Resolution", markdown)
        self.assertIn("Use the preserved `content_security_policy` artifact", markdown)

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
            "security_test_finalizer",
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
