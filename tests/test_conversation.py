from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mosh.config import AppConfig
from mosh.conversation import (
    EngagementChatOrchestrator,
    LLMEngagementChatRunner,
    active_directives,
    active_directives_fingerprint,
    build_engagement_chat_context,
    directives_fingerprint,
    extract_directives,
    load_directives,
    load_messages,
)
from mosh.engagements import attach_asset, asset_discovery_dir, create_engagement


class ConversationTests(unittest.TestCase):
    def test_chat_persists_messages_and_scope_directive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")

            result = EngagementChatOrchestrator(output_root=output_root).ask(
                engagement.id,
                "The /admin-dev URL is out of scope.",
            )

            messages = load_messages(output_root, engagement.id)
            directives = load_directives(output_root, engagement.id)
            self.assertEqual([message["role"] for message in messages], ["user", "assistant"])
            self.assertEqual(len(directives), 1)
            self.assertEqual(directives[0]["kind"], "scope_override")
            self.assertEqual(directives[0]["target"]["path"], "/admin-dev")
            self.assertEqual(directives[0]["target"]["action"], "exclude")
            self.assertIn("Recorded engagement directive", result.response)
            self.assertEqual(result.directives[0]["id"], directives[0]["id"])

    def test_questions_do_not_create_actionable_directives(self) -> None:
        directives = extract_directives("Why was H-004 blocked?", "msg_test")
        self.assertEqual(directives, [])

    def test_chat_answers_from_existing_engagement_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            asset = attach_asset(output_root, engagement.id, "https://app.example.test").asset
            discovery_dir = asset_discovery_dir(output_root, engagement.id, asset.id)
            discovery_dir.mkdir(parents=True)
            (discovery_dir / "report.md").write_text(
                "# Discovery\n\nAuthentication observations mention login and password reset flows.\n",
                encoding="utf-8",
            )
            (discovery_dir / "memory.json").write_text("[]", encoding="utf-8")

            result = EngagementChatOrchestrator(output_root=output_root).ask(
                engagement.id,
                "What did discovery find about authentication?",
            )

            self.assertIn("Authentication observations", result.response)
            self.assertEqual(result.directives, [])

    def test_llm_chat_uses_json_response_and_persists_model_directive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            captured: dict[str, list[dict[str, str]]] = {}

            def completion(messages: list[dict[str, str]]) -> str:
                captured["messages"] = messages
                payload = json.loads(messages[1]["content"])
                self.assertEqual(payload["user_message"], "Focus testing on enterprise account workflows.")
                return json.dumps(
                    {
                        "answer": "I will prioritise enterprise account workflow coverage in planning.",
                        "artifact_refs": ["report/test-eng/plan/plan.md"],
                        "directives": [
                            {
                                "kind": "planning_focus",
                                "instruction": "Focus testing on enterprise account workflows.",
                                "stages": ["planning"],
                                "target": {"area": "enterprise_accounts"},
                            }
                        ],
                    }
                )

            runner = LLMEngagementChatRunner(AppConfig(openrouter_api_key="test-key"), completion=completion)

            result = EngagementChatOrchestrator(output_root=output_root, runner=runner).ask(
                engagement.id,
                "Focus testing on enterprise account workflows.",
            )

            self.assertEqual(result.response, "I will prioritise enterprise account workflow coverage in planning.")
            self.assertIn("Mosh engagement chat assistant", captured["messages"][0]["content"])
            directives = load_directives(output_root, engagement.id)
            self.assertEqual(len(directives), 1)
            self.assertEqual(directives[0]["kind"], "planning_focus")
            self.assertEqual(directives[0]["source_message_id"], result.user_message["id"])
            self.assertEqual(directives[0]["confidence"], "model")
            self.assertEqual(directives[0]["target"], {"area": "enterprise_accounts"})
            self.assertEqual(result.artifact_refs, ["report/test-eng/plan/plan.md"])

    def test_llm_chat_accepts_plain_text_model_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            runner = LLMEngagementChatRunner(
                AppConfig(openrouter_api_key="test-key"),
                completion=lambda _messages: "Use the clarification to re-run planning, then re-run affected tests.",
            )

            result = EngagementChatOrchestrator(output_root=output_root, runner=runner).ask(
                engagement.id,
                "What should I do next?",
            )

            self.assertEqual(result.response, "Use the clarification to re-run planning, then re-run affected tests.")
            self.assertNotIn("Relevant engagement context", result.response)
            self.assertNotIn("chat model response could not be used", result.response)

    def test_llm_chat_repairs_invalid_hypothesis_test_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")

            def completion(messages: list[dict[str, str]]) -> str:
                self.assertIn("Never suggest `mosh test <HYPOTHESIS_ID>`", messages[0]["content"])
                payload = json.loads(messages[1]["content"])
                self.assertIn(
                    f"uv run mosh test {engagement.id} --hypothesis <HYPOTHESIS_ID>",
                    payload["valid_cli_commands"],
                )
                return json.dumps(
                    {
                        "answer": "Run `mosh test SPA-001` to execute that hypothesis.",
                        "artifact_refs": [],
                        "directives": [],
                    }
                )

            runner = LLMEngagementChatRunner(AppConfig(openrouter_api_key="test-key"), completion=completion)

            result = EngagementChatOrchestrator(output_root=output_root, runner=runner).ask(
                engagement.id,
                "Which command should I run for SPA-001?",
            )

            self.assertIn(f"`mosh test {engagement.id} --hypothesis SPA-001`", result.response)
            self.assertNotIn("`mosh test SPA-001`", result.response)

    def test_llm_chat_retries_incomplete_json_answer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            calls: list[list[dict[str, str]]] = []

            def completion(messages: list[dict[str, str]]) -> str:
                calls.append(messages)
                if len(calls) == 1:
                    return json.dumps(
                        {
                            "answer": "Now that you have clarified this aspect, the next steps are:",
                            "artifact_refs": [],
                            "directives": [],
                        }
                    )
                self.assertIn("previous response could not be used", messages[-1]["content"])
                return json.dumps(
                    {
                        "answer": (
                            "Now that you have clarified this aspect, the next steps are:\n\n"
                            "1. Record the intended anonymous-user behavior.\n"
                            "2. Re-run planning so affected hypotheses are updated.\n"
                            "3. Re-run only the affected tests and regenerate the report."
                        ),
                        "artifact_refs": ["report/test-eng/plan/plan.md"],
                        "directives": [],
                    }
                )

            runner = LLMEngagementChatRunner(AppConfig(openrouter_api_key="test-key"), completion=completion)

            result = EngagementChatOrchestrator(output_root=output_root, runner=runner).ask(
                engagement.id,
                "Waht are the steps I need to take now that I have clarified this aspect?",
            )

            self.assertEqual(len(calls), 2)
            self.assertIn("1. Record the intended anonymous-user behavior.", result.response)
            self.assertEqual(result.artifact_refs, ["report/test-eng/plan/plan.md"])

    def test_llm_chat_payload_includes_structured_question_facts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            executed_dir = output_root / engagement.id / "security-testing" / "executed_tests"
            executed_dir.mkdir(parents=True)
            high_path = executed_dir / "HIGH-001.md"
            high_path.write_text(
                _executed_report(
                    "HIGH-001",
                    "Unauthenticated admin access",
                    status="finding",
                    priority="high",
                    summary="Admin data is reachable without authentication.",
                ),
                encoding="utf-8",
            )

            def completion(messages: list[dict[str, str]]) -> str:
                payload = json.loads(messages[1]["content"])
                facts = payload["question_facts"]
                self.assertIn("Highest confirmed finding: `HIGH-001`", facts["deterministic_answer"])
                self.assertEqual(facts["artifact_refs"], [str(high_path)])
                self.assertEqual(payload["testing"]["executed_tests"][0]["id"], "HIGH-001")
                return json.dumps(
                    {
                        "answer": "The highest confirmed finding is HIGH-001.",
                        "artifact_refs": [],
                        "directives": [],
                    }
                )

            runner = LLMEngagementChatRunner(AppConfig(openrouter_api_key="test-key"), completion=completion)

            result = EngagementChatOrchestrator(output_root=output_root, runner=runner).ask(
                engagement.id,
                "What is the highest finding?",
            )

            self.assertEqual(result.response, "The highest confirmed finding is HIGH-001.")
            self.assertEqual(result.artifact_refs, [str(high_path)])

    def test_llm_chat_payload_includes_report_excerpts_for_general_questions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            asset = attach_asset(output_root, engagement.id, "https://app.example.test").asset
            discovery_dir = asset_discovery_dir(output_root, engagement.id, asset.id)
            discovery_dir.mkdir(parents=True)
            report_path = discovery_dir / "report.md"
            report_path.write_text(
                "# Discovery\n\nAuthentication observations mention login and password reset flows.\n",
                encoding="utf-8",
            )
            (discovery_dir / "memory.json").write_text("[]", encoding="utf-8")

            def completion(messages: list[dict[str, str]]) -> str:
                payload = json.loads(messages[1]["content"])
                self.assertIn("Authentication observations", payload["discovery"][0]["report_excerpt"])
                self.assertEqual(payload["retrieved_artifact_excerpts"][0]["path"], str(report_path))
                self.assertIn("Authentication observations", payload["retrieved_artifact_excerpts"][0]["excerpt"])
                return json.dumps(
                    {
                        "answer": "Discovery identified login and password reset authentication flows.",
                        "artifact_refs": [str(report_path)],
                        "directives": [],
                    }
                )

            runner = LLMEngagementChatRunner(AppConfig(openrouter_api_key="test-key"), completion=completion)

            result = EngagementChatOrchestrator(output_root=output_root, runner=runner).ask(
                engagement.id,
                "What did discovery find about authentication?",
            )

            self.assertEqual(result.response, "Discovery identified login and password reset authentication flows.")
            self.assertEqual(result.artifact_refs, [str(report_path)])

    def test_llm_chat_payload_stays_compact_for_large_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            planning_dir = output_root / engagement.id / "plan"
            planning_dir.mkdir(parents=True)
            long_text = "x" * 2_000
            hypotheses = [
                {
                    "id": f"AUTH-{index:03d}",
                    "title": f"Authentication hypothesis {index} {long_text}",
                    "priority": "high",
                    "surface": "api",
                    "requirements": [long_text for _ in range(8)],
                }
                for index in range(80)
            ]
            (planning_dir / "memory.json").write_text(
                json.dumps(
                    [
                        {
                            "kind": "security_test_plan_final",
                            "content": {"structured": {"test_hypotheses": hypotheses}},
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (planning_dir / "plan.md").write_text(long_text * 5, encoding="utf-8")
            executed_dir = output_root / engagement.id / "security-testing" / "executed_tests"
            executed_dir.mkdir(parents=True)
            for index in range(40):
                (executed_dir / f"AUTH-{index:03d}.md").write_text(
                    _executed_report(
                        f"AUTH-{index:03d}",
                        f"Authentication test {index}",
                        status="finding",
                        priority="high",
                        summary=long_text,
                    ),
                    encoding="utf-8",
                )

            def completion(messages: list[dict[str, str]]) -> str:
                self.assertLess(len(messages[1]["content"]), 45_000)
                payload = json.loads(messages[1]["content"])
                self.assertEqual(len(payload["planning"]["hypotheses"]), 20)
                self.assertEqual(len(payload["testing"]["executed_tests"]), 12)
                return json.dumps({"answer": "The context is compact.", "artifact_refs": [], "directives": []})

            runner = LLMEngagementChatRunner(AppConfig(openrouter_api_key="test-key"), completion=completion)

            result = EngagementChatOrchestrator(output_root=output_root, runner=runner).ask(
                engagement.id,
                "What is the current engagement status?",
            )

            self.assertEqual(result.response, "The context is compact.")

    def test_llm_chat_falls_back_when_model_response_is_unusable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            executed_dir = output_root / engagement.id / "security-testing" / "executed_tests"
            executed_dir.mkdir(parents=True)
            (executed_dir / "HIGH-001.md").write_text(
                _executed_report(
                    "HIGH-001",
                    "Unauthenticated admin access",
                    status="finding",
                    priority="high",
                    summary="Admin data is reachable without authentication.",
                ),
                encoding="utf-8",
            )
            runner = LLMEngagementChatRunner(
                AppConfig(openrouter_api_key="test-key"),
                completion=lambda _messages: "{not json",
            )

            result = EngagementChatOrchestrator(output_root=output_root, runner=runner).ask(
                engagement.id,
                "What is the highest finding?",
            )

            self.assertIn("The chat model response could not be used", result.response)
            self.assertIn("Highest confirmed finding: `HIGH-001` (high).", result.response)
            self.assertNotIn("Relevant engagement context", result.response)

    def test_design_clarification_records_testing_context_directive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")

            EngagementChatOrchestrator(output_root=output_root).ask(
                engagement.id,
                "That's fine - production users are anonymous until they link an email, not test accounts.",
            )

            directives = load_directives(output_root, engagement.id)
            self.assertEqual(len(directives), 1)
            self.assertEqual(directives[0]["kind"], "engagement_context")
            self.assertEqual(directives[0]["target"], {"clarification": True})
            self.assertEqual(active_directives(output_root, engagement.id, stage="testing")[0]["id"], directives[0]["id"])

    def test_chat_answers_highest_finding_from_executed_test_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            executed_dir = output_root / engagement.id / "security-testing" / "executed_tests"
            executed_dir.mkdir(parents=True)
            (executed_dir / "LOW-001.md").write_text(
                _executed_report(
                    "LOW-001",
                    "Verbose server headers",
                    status="finding",
                    priority="low",
                    summary="Server headers disclose implementation details.",
                ),
                encoding="utf-8",
            )
            (executed_dir / "HIGH-001.md").write_text(
                _executed_report(
                    "HIGH-001",
                    "Unauthenticated admin access",
                    status="finding",
                    priority="high",
                    summary="Admin data is reachable without authentication.",
                ),
                encoding="utf-8",
            )

            result = EngagementChatOrchestrator(output_root=output_root).ask(
                engagement.id,
                "What is the highest finding?",
            )

            self.assertIn("Highest confirmed finding: `HIGH-001` (high).", result.response)
            self.assertIn("Admin data is reachable", result.response)
            self.assertIn("Source:", result.response)
            self.assertNotIn("Relevant engagement context", result.response)

    def test_chat_answers_currently_blocked_tests_from_preflight_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            testing_dir = output_root / engagement.id / "security-testing"
            testing_dir.mkdir(parents=True)
            (testing_dir / "preflight.md").write_text("# Security Testing Preflight\n", encoding="utf-8")
            (testing_dir / "memory.json").write_text(
                json.dumps(
                    [
                        {
                            "kind": "testing_preflight",
                            "content": {
                                "ready": [],
                                "blocked": [
                                    {
                                        "id": "AUTH-004",
                                        "title": "Enterprise account boundary check",
                                        "priority": "high",
                                        "blockers": ["missing credential material for enterprise"],
                                    }
                                ],
                                "deferred": [],
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )

            result = EngagementChatOrchestrator(output_root=output_root).ask(
                engagement.id,
                "What test is currently blocked?",
            )

            self.assertIn("Currently blocked: `1` test(s).", result.response)
            self.assertIn("`AUTH-004`: Enterprise account boundary check", result.response)
            self.assertIn("credentials.enterprise.token", result.response)
            self.assertNotIn("Relevant engagement context", result.response)

    def test_chat_answers_why_specific_test_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            testing_dir = output_root / engagement.id / "security-testing"
            testing_dir.mkdir(parents=True)
            (testing_dir / "preflight.md").write_text("# Security Testing Preflight\n", encoding="utf-8")
            (testing_dir / "memory.json").write_text(
                json.dumps(
                    [
                        {
                            "kind": "testing_preflight",
                            "content": {
                                "ready": [],
                                "blocked": [
                                    {
                                        "id": "AUTH-004",
                                        "title": "Enterprise account boundary check",
                                        "priority": "high",
                                        "blockers": ["missing safe_test_data.enterprise_account_ids"],
                                    }
                                ],
                                "deferred": [],
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )

            result = EngagementChatOrchestrator(output_root=output_root).ask(
                engagement.id,
                "Why is AUTH-004 blocked?",
            )

            self.assertIn("`AUTH-004` is currently blocked", result.response)
            self.assertIn("safe_test_data.enterprise_account_ids", result.response)
            self.assertNotIn("Relevant engagement context", result.response)

    def test_stage_directive_fingerprints_use_relevant_active_directives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            attach_asset(output_root, engagement.id, "https://app.example.test")
            empty_fingerprint = active_directives_fingerprint(output_root, engagement.id, stage="planning")

            EngagementChatOrchestrator(output_root=output_root).ask(
                engagement.id,
                "Focus testing on billing approval flows.",
            )

            planning = active_directives(output_root, engagement.id, stage="planning")
            testing = active_directives(output_root, engagement.id, stage="testing")
            self.assertEqual(len(planning), 1)
            self.assertEqual(testing, [])
            self.assertNotEqual(active_directives_fingerprint(output_root, engagement.id, stage="planning"), empty_fingerprint)
            self.assertEqual(active_directives_fingerprint(output_root, engagement.id, stage="testing"), directives_fingerprint([]))

    def test_context_includes_active_directives_without_duplicating_asset_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            asset = attach_asset(output_root, engagement.id, "https://app.example.test").asset
            EngagementChatOrchestrator(output_root=output_root).ask(
                engagement.id,
                "Discovery missed the /graphql endpoint.",
            )

            context = build_engagement_chat_context(output_root, engagement.id)

            self.assertEqual(context["engagement"]["assets"][0]["id"], asset.id)
            self.assertEqual(context["engagement"]["assets"][0]["locator"], "https://app.example.test")
            self.assertEqual(context["conversation"]["active_directives"][0]["kind"], "additional_discovery_fact")
            self.assertIn("/graphql", json.dumps(context["conversation"]["active_directives"]))


def _executed_report(test_id: str, title: str, *, status: str, priority: str, summary: str) -> str:
    return (
        "<!-- mosh-execution\n"
        + json.dumps(
            {
                "schema": "mosh.security-test-execution.v1",
                "test_id": test_id,
                "status": status,
                "review_accepted": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n-->\n\n"
        + f"# {test_id}: {title}\n\n"
        + "## Status\n\n"
        + ("Finding Confirmed" if status == "finding" else status)
        + "\n\n"
        + "## Scope\n\n"
        + f"- Priority: `{priority}`\n"
        + "- Surface: `api`\n\n"
        + "## Summary\n\n"
        + summary
        + "\n"
    )


if __name__ == "__main__":
    unittest.main()
