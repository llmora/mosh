from __future__ import annotations

import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path

from appsec_harness.config import AppConfig
from appsec_harness.discovery_crew import CREW_CONFIG_PACKAGE
from appsec_harness.memory import FileMemory
from appsec_harness.scope import report_dir_name
from appsec_harness.security_planning_crew import (
    SecurityTestPlanningOrchestrator,
    SecurityTestPlanningState,
    _build_write_security_test_plan_tool,
    load_discovery_context,
)
from appsec_harness.security_test_planning_reporting import render_security_test_plan, write_security_test_plan
from tests.fakes import FakeSecurityPlanningRunner


class FakeCrewAI:
    BaseModel = object
    BaseTool = object

    @staticmethod
    def Field(default=None, description: str = ""):
        return default


def _plan() -> dict[str, object]:
    return {
        "title": "Security Test Plan",
        "scope_summary": "Plan based on discovery output.",
        "assumptions": ["Testing is authorised."],
        "test_hypotheses": [
            {
                "id": "API-001",
                "title": "Private API rejects unauthenticated access",
                "surface": "api",
                "priority": "high",
                "hypothesis": "Discovered private API endpoints should require authentication.",
                "organisational_risk": "Unauthenticated private API access could expose sensitive account data.",
                "business_value": "Validates a high-impact control before deeper API testing.",
                "evidence": ["https://api.example.test/api/private/auth/me"],
                "requirements": ["No credentials required for unauthenticated check.", "Valid credentials for authenticated baseline."],
                "tools_expected": ["HTTP client", "CORS/header inspection tool"],
                "preconditions": ["Discovery output identifies the API endpoint."],
                "test_steps": ["Request endpoint without Authorization header.", "Repeat with a valid token if credentials exist."],
                "expected_secure_behavior": "Unauthenticated requests return 401 or 403.",
                "interesting_failure_modes": ["200 OK without credentials."],
                "safety_notes": ["Do not brute force credentials."],
                "stopping_conditions": ["Stop after confirming auth enforcement or unexpected access."],
                "status": "planned",
            }
        ],
        "deferred_test_opportunities": [
            {
                "title": "Review linked customer portal",
                "surface": "linked application",
                "evidence": ["Discovery report referenced https://portal.example.test"],
                "organisational_risk": "The linked portal may share authentication or customer data flows.",
                "business_value": "Confirms whether a related customer-facing system should be included in later testing.",
                "defer_reason": "Needs explicit scope confirmation before testing.",
                "requirements_to_proceed": ["Written authorization for portal.example.test", "Portal test credentials if authentication is required."],
                "suggested_next_step": "Ask the owner whether portal.example.test is in scope for the next crew.",
            }
        ],
        "not_in_scope": ["Credential attacks."],
        "open_questions": ["Are test credentials available?"],
    }


class SecurityTestPlanningTests(unittest.TestCase):
    def test_render_security_test_plan_includes_requirements_and_tools(self) -> None:
        review = {"accepted": True, "summary": "Accepted.", "blocking_findings": [], "non_blocking_suggestions": []}

        markdown = render_security_test_plan(
            "https://example.test",
            _plan(),
            review,
            accepted=True,
            iterations=1,
        )

        self.assertIn("#### Requirements", markdown)
        self.assertIn("Valid credentials for authenticated baseline.", markdown)
        self.assertIn("#### Tools Expected", markdown)
        self.assertIn("HTTP client", markdown)
        self.assertIn("#### Organisational Risk", markdown)
        self.assertIn("could expose sensitive account data", markdown)
        self.assertIn("#### Business Value", markdown)
        self.assertIn("before deeper API testing", markdown)
        self.assertIn("## Deferred Test Opportunities", markdown)
        self.assertIn("### Review linked customer portal", markdown)
        self.assertIn("Needs explicit scope confirmation", markdown)
        self.assertIn("portal.example.test is in scope", markdown)

    def test_write_security_test_plan_removes_stale_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            (report_dir / "security_test_plan.json").write_text("stale\n", encoding="utf-8")

            write_security_test_plan(
                report_dir,
                "https://example.test",
                _plan(),
                {"accepted": True},
                accepted=True,
                iterations=1,
            )

            self.assertTrue((report_dir / "security_test_plan.md").exists())
            self.assertFalse((report_dir / "security_test_plan.json").exists())

    def test_render_security_test_plan_filters_placeholder_critic_items(self) -> None:
        review = {
            "accepted": False,
            "summary": "Needs revision.",
            "blocking_findings": [{"title": "Item"}, {"issue": "API auth baseline is missing."}],
            "non_blocking_suggestions": [{"item": "Item"}, {"suggestion": "Group tests by surface."}],
        }

        markdown = render_security_test_plan(
            "https://example.test",
            _plan(),
            review,
            accepted=False,
            iterations=1,
        )

        self.assertNotIn("- **Item**", markdown)
        self.assertIn("- **API auth baseline is missing.**", markdown)
        self.assertIn("- **Group tests by surface.**", markdown)

    def test_write_plan_tool_preserves_structured_plan_when_finalizer_sends_markdown_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            state = SecurityTestPlanningState(
                target_url="https://example.test",
                discovery_dir=report_dir / "discovery",
                report_dir=report_dir,
                memory=FileMemory(report_dir),
                discovery_context={},
                current_plan=_plan(),
                current_review={"accepted": True, "summary": "Accepted."},
                accepted=True,
                iterations=1,
            )
            tool = _build_write_security_test_plan_tool(FakeCrewAI, state)

            tool._run(
                {"content": "# Finalizer-authored Markdown should not replace structured plan"},
                {"content": "## Critic Review Markdown should not replace structured review"},
            )

            markdown = (report_dir / "security_test_plan.md").read_text(encoding="utf-8")
            self.assertIn("Private API rejects unauthenticated access", markdown)
            self.assertIn("Planner/critic accepted: `true`", markdown)
            self.assertIn("- Summary: Accepted.", markdown)

    def test_load_discovery_context_reads_discovery_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            discovery_dir = Path(directory)
            (discovery_dir / "report.md").write_text("# Discovery\n", encoding="utf-8")
            (discovery_dir / "memory.json").write_text('[{"kind":"summary"}]', encoding="utf-8")
            (discovery_dir / "events.json").write_text('[{"action":"complete"}]', encoding="utf-8")

            context = load_discovery_context(discovery_dir)

            self.assertEqual(context["report_markdown"], "# Discovery\n")
            self.assertEqual(context["memory"][0]["kind"], "summary")
            self.assertEqual(context["events"][0]["action"], "complete")

    def test_orchestrator_writes_under_security_test_planning_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            discovery_dir = output_root / report_dir_name(target_url) / "discovery"
            discovery_dir.mkdir(parents=True)
            (discovery_dir / "report.md").write_text("# Discovery\n", encoding="utf-8")
            (discovery_dir / "memory.json").write_text("[]", encoding="utf-8")
            (discovery_dir / "events.json").write_text("[]", encoding="utf-8")
            runner = FakeSecurityPlanningRunner()

            report_dir = SecurityTestPlanningOrchestrator(
                AppConfig(),
                output_root=output_root,
                crew_runner=runner,
            ).run(target_url)

            self.assertEqual(report_dir.name, "security-test-planning")
            self.assertTrue((report_dir / "security_test_plan.md").exists())
            self.assertEqual(runner.calls[0]["discovery_dir"], str(discovery_dir))
            events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(any(event["action"] == "start" for event in events))

    def test_missing_discovery_directory_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                load_discovery_context(Path(directory) / "missing")

    def test_security_planning_yaml_keeps_related_agents_and_tasks_together(self) -> None:
        agents = resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/agents.yaml").read_text(
            encoding="utf-8"
        )
        tasks = resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/tasks.yaml").read_text(
            encoding="utf-8"
        )

        self.assertIn("security_test_planner:", agents)
        self.assertIn("security_test_critic:", agents)
        self.assertIn("security_test_finalizer:", agents)
        self.assertIn("draft_security_test_plan_task:", tasks)
        self.assertIn("critique_security_test_plan_task:", tasks)
        self.assertIn("write_security_test_plan_task:", tasks)

    def test_security_planning_yaml_prioritizes_business_risk(self) -> None:
        agents = resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/agents.yaml").read_text(
            encoding="utf-8"
        )
        tasks = resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/tasks.yaml").read_text(
            encoding="utf-8"
        )

        self.assertIn("business risks", agents)
        self.assertIn("organisational_risk", tasks)
        self.assertIn("business_value", tasks)
        self.assertIn("deferred_test_opportunities", tasks)
        self.assertIn("requirements_to_proceed", tasks)
        self.assertIn("generic security checklist", tasks)


if __name__ == "__main__":
    unittest.main()
