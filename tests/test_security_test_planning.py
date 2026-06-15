from __future__ import annotations

import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from mosh.config import AppConfig
from mosh.crews.discovery.crew import CREW_CONFIG_PACKAGE
from mosh.engagement import (
    build_engagement_template,
    load_engagement_file,
    resolve_target_mapping,
    write_engagement_template_mapping,
)
from mosh.memory import FileMemory
from mosh.scope import report_dir_name
from mosh.crews.security_planning.crew import (
    CrewAISecurityTestPlanningCrewRunner,
    SecurityTestPlanningOrchestrator,
    SecurityTestPlanningState,
    _build_write_refined_engagement_template_tool,
    _build_write_security_test_plan_tool,
    _select_yaml_top_level_blocks,
    _write_security_planning_subset_configs,
    load_discovery_context,
)
from mosh.crews.security_planning.reporting import render_security_test_plan, write_security_test_plan
from tests.fakes import FakeSecurityPlanningRunner


class FakeCrewAI:
    BaseModel = object
    BaseTool = object

    @staticmethod
    def Field(default=None, description: str = ""):
        return default


class FakeRuntimeCrewAI(FakeCrewAI):
    critic_inputs: dict[str, object] | None = None

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
        def __init__(self, agents, tasks, process, verbose, event_listeners=None) -> None:
            self.agents = agents
            self.tasks = tasks
            self.process = process
            self.verbose = verbose
            self.event_listeners = event_listeners

        def kickoff(self, inputs):
            for task in self.tasks:
                for tool in task.agent.tools:
                    if tool.name == "submit_security_test_plan":
                        tool._run(_plan())
                    elif tool.name == "submit_security_test_plan_critique":
                        FakeRuntimeCrewAI.critic_inputs = inputs
                        submitted_plan = json.loads(inputs["security_test_plan"])
                        tool._run(
                            {
                                "accepted": bool(submitted_plan.get("test_hypotheses")),
                                "summary": "Reviewed structured security_test_plan JSON.",
                            }
                        )
                    elif tool.name == "write_security_test_plan":
                        tool._run(
                            json.loads(inputs["security_test_plan"]),
                            json.loads(inputs["critic_review"]),
                        )
                        raise RuntimeError("reporter post-processing failed")
            return None

    @staticmethod
    def CrewBase(cls):
        if isinstance(getattr(cls, "agents_config", None), str):
            cls.agents_config = FakeRuntimeCrewAI._load_config_blocks(cls.agents_config)
        if isinstance(getattr(cls, "tasks_config", None), str):
            cls.tasks_config = FakeRuntimeCrewAI._load_config_blocks(cls.tasks_config)
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
    def agent(func):
        return func

    @staticmethod
    def task(func):
        return func

    @staticmethod
    def crew(func):
        return func


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

    def test_write_plan_tool_preserves_structured_plan_when_reporter_sends_markdown_content(self) -> None:
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
                {"content": "# Reporter-authored Markdown should not replace structured plan"},
                {"content": "## Reviewer Decision Markdown should not replace structured review"},
            )

            markdown = (report_dir / "security_test_plan.md").read_text(encoding="utf-8")
            self.assertIn("Private API rejects unauthenticated access", markdown)
            self.assertIn("Planner/reviewer accepted: `true`", markdown)
            self.assertIn("- Summary: Accepted.", markdown)

    def test_refined_engagement_template_tool_rejects_invented_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            memory = FileMemory(report_dir)
            deterministic = build_engagement_template("https://example.test", _plan())
            state = SecurityTestPlanningState(
                target_url="https://example.test",
                discovery_dir=report_dir / "discovery",
                report_dir=report_dir,
                memory=memory,
                discovery_context={},
                current_plan=_plan(),
                current_review={"accepted": True, "summary": "Accepted."},
                accepted=True,
                iterations=1,
            )
            tool = _build_write_refined_engagement_template_tool(FakeCrewAI, state, deterministic)
            candidate = json.loads(json.dumps(deterministic))
            role = next(iter(candidate["credentials"]))
            candidate["credentials"][role]["username"] = "invented-user"

            result = json.loads(tool._run(candidate))

            self.assertTrue(result["fallback_used"])
            template = load_engagement_file(report_dir / "engagement_template.yaml")
            self.assertIsNone(template["credentials"][role]["username"])
            events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(any(event["action"] == "refinement_rejected" for event in events))

    def test_refined_engagement_template_tool_allows_existing_user_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            memory = FileMemory(report_dir)
            deterministic = build_engagement_template("https://example.test", _plan())
            role = next(iter(deterministic["credentials"]))
            existing = json.loads(json.dumps(deterministic))
            existing["credentials"][role]["username"] = "existing@example.test"
            existing["credentials"][role]["password"] = "existing-secret"
            write_engagement_template_mapping(report_dir, existing, preserve_existing=False, reject_candidate_credentials=False)
            state = SecurityTestPlanningState(
                target_url="https://example.test",
                discovery_dir=report_dir / "discovery",
                report_dir=report_dir,
                memory=memory,
                discovery_context={},
                current_plan=_plan(),
                current_review={"accepted": True, "summary": "Accepted."},
                accepted=True,
                iterations=1,
            )
            tool = _build_write_refined_engagement_template_tool(FakeCrewAI, state, deterministic)

            result = json.loads(tool._run(load_engagement_file(report_dir / "engagement_template.yaml")))

            self.assertFalse(result["fallback_used"])
            template = load_engagement_file(report_dir / "engagement_template.yaml")
            self.assertEqual(template["credentials"][role]["username"], "existing@example.test")
            self.assertEqual(template["credentials"][role]["password"], "existing-secret")

    def test_engagement_template_regeneration_preserves_user_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            existing = build_engagement_template("https://example.test", _plan())
            existing["targets"]["alternative"]["api"] = "https://staging-api.example.test/api/private"
            existing["credentials"]["admin"] = {
                "username": "admin@example.test",
                "password": "secret",
                "token": None,
                "status": "required",
                "needed_for": ["API-001"],
                "notes": "Generated explanation that should not remain in the simple template.",
            }
            existing["safe_test_data"]["customer_ids"] = {
                "values": ["cust_safe_1"],
                "status": "required",
                "needed_for": ["IDOR-001"],
            }
            existing["required_answers"] = [{"question": "Old verbose question", "needed_for": ["all"]}]
            write_engagement_template_mapping(report_dir, existing, preserve_existing=False, reject_candidate_credentials=False)
            original_text = (report_dir / "engagement_template.yaml").read_text(encoding="utf-8")

            write_engagement_template_mapping(report_dir, build_engagement_template("https://example.test", _plan()))

            template = load_engagement_file(report_dir / "engagement_template.yaml")
            backups = sorted((report_dir / "engagement_template.backups").glob("engagement_template-*.yaml"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(encoding="utf-8"), original_text)
            self.assertEqual(template["targets"]["alternative"]["api"], "https://staging-api.example.test/api/private")
            self.assertEqual(template["credentials"]["admin"]["username"], "admin@example.test")
            self.assertEqual(template["credentials"]["admin"]["password"], "secret")
            self.assertEqual(template["safe_test_data"]["customer_ids"], ["cust_safe_1"])
            self.assertNotIn("required_answers", template)
            self.assertNotIn("status", template["credentials"]["admin"])
            self.assertNotIn("needed_for", template["credentials"]["admin"])
            self.assertNotIn("notes", template["credentials"]["admin"])

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
            self.assertTrue((report_dir / "engagement_template.yaml").exists())
            self.assertEqual(runner.calls[0]["discovery_dir"], str(discovery_dir))
            events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(any(event["action"] == "start" for event in events))

    def test_engagement_template_contains_alternative_target_overrides_and_credential_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_url = "https://example.test"
            output_root = Path(directory) / "report"
            discovery_dir = output_root / report_dir_name(target_url) / "discovery"
            discovery_dir.mkdir(parents=True)
            (discovery_dir / "report.md").write_text("# Discovery\n", encoding="utf-8")
            (discovery_dir / "memory.json").write_text("[]", encoding="utf-8")
            (discovery_dir / "events.json").write_text("[]", encoding="utf-8")

            report_dir = SecurityTestPlanningOrchestrator(
                AppConfig(),
                output_root=output_root,
                crew_runner=FakeSecurityPlanningRunner(),
            ).run(target_url)

            template = load_engagement_file(report_dir / "engagement_template.yaml")
            self.assertIn("alternative", template["targets"])
            self.assertEqual(template["targets"]["production"]["api"], "https://api.example.test/api/private")
            self.assertIsNone(template["targets"]["alternative"]["website"])
            self.assertIn("authenticated_user", template["credentials"])
            self.assertNotIn("required_answers", template)
            for credential in template["credentials"].values():
                self.assertNotIn("status", credential)
                self.assertNotIn("needed_for", credential)
                self.assertNotIn("notes", credential)
            self.assertTrue(template["engagement"]["authorization_confirmed"])

            template["targets"]["alternative"]["api"] = "https://staging-api.example.test/api/private"
            resolved = resolve_target_mapping(template)
            self.assertEqual(resolved["api"], "https://staging-api.example.test/api/private")
            self.assertEqual(resolved["website"], "https://example.test")

    def test_engagement_template_ignores_regex_strings_that_look_like_urls(self) -> None:
        plan = json.loads(json.dumps(_plan()))
        plan["test_hypotheses"][0]["tools_expected"].append(
            r"Sentry DSN regex: https://[a-f0-9]{32}@[a-f0-9]{16}.ingest.sentry.io/[0-9]+"
        )

        template = build_engagement_template("https://example.test", plan)

        self.assertEqual(template["targets"]["production"]["api"], "https://api.example.test/api/private")

    def test_crewai_runner_writes_engagement_template_before_reporter_returns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            FakeRuntimeCrewAI.critic_inputs = None
            report_dir = Path(directory) / "security-test-planning"
            discovery_dir = Path(directory) / "discovery"
            discovery_dir.mkdir()
            (discovery_dir / "report.md").write_text("# Discovery\n", encoding="utf-8")
            (discovery_dir / "memory.json").write_text("[]", encoding="utf-8")
            (discovery_dir / "events.json").write_text("[]", encoding="utf-8")
            memory = FileMemory(report_dir)
            runner = CrewAISecurityTestPlanningCrewRunner(
                AppConfig(openrouter_api_key="test-key", refine_engagement_template_with_llm=False)
            )

            with patch("mosh.crews.security_planning.crew._load_crewai", return_value=FakeRuntimeCrewAI):
                with self.assertRaisesRegex(RuntimeError, "reporter post-processing failed"):
                    runner.run("https://example.test", discovery_dir, report_dir, memory)

            self.assertTrue((report_dir / "engagement_template.yaml").exists())
            self.assertIsNotNone(FakeRuntimeCrewAI.critic_inputs)
            critic_plan = json.loads(FakeRuntimeCrewAI.critic_inputs["security_test_plan"])
            self.assertEqual(critic_plan["test_hypotheses"][0]["id"], "API-001")
            events = json.loads((report_dir / "events.json").read_text(encoding="utf-8"))
            self.assertTrue(any(event["action"] == "engagement_template_written" for event in events))

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

        self.assertIn("planner:", agents)
        self.assertIn("reviewer:", agents)
        self.assertIn("reporter:", agents)
        self.assertIn("engagement_refiner:", agents)
        self.assertIn("draft_security_test_plan_task:", tasks)
        self.assertIn("critique_security_test_plan_task:", tasks)
        self.assertIn("write_security_test_plan_task:", tasks)
        self.assertIn("refine_engagement_template_task:", tasks)

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
        self.assertIn("{security_test_plan}", tasks)
        self.assertIn("Do not review the planner's prose summary", tasks)

    def test_security_planning_runtime_config_subsets_only_include_relevant_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            agents_path, tasks_path = _write_security_planning_subset_configs(
                Path(directory),
                "cycle",
                agent_keys=["planner", "reviewer"],
                task_keys=["draft_security_test_plan_task", "critique_security_test_plan_task"],
            )

            agents = Path(agents_path).read_text(encoding="utf-8")
            tasks = Path(tasks_path).read_text(encoding="utf-8")

        self.assertTrue(Path(agents_path).is_absolute())
        self.assertTrue(Path(tasks_path).is_absolute())
        self.assertIn("planner:", agents)
        self.assertIn("reviewer:", agents)
        self.assertNotIn("engagement_refiner:", agents)
        self.assertIn("draft_security_test_plan_task:", tasks)
        self.assertIn("critique_security_test_plan_task:", tasks)
        self.assertNotIn("refine_engagement_template_task:", tasks)

    def test_security_planning_yaml_subset_reports_missing_blocks(self) -> None:
        with self.assertRaisesRegex(KeyError, "missing_agent"):
            _select_yaml_top_level_blocks("planner:\n  role: Planner\n", ["missing_agent"])


if __name__ == "__main__":
    unittest.main()
