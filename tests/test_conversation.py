from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mosh.conversation import (
    EngagementChatOrchestrator,
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


if __name__ == "__main__":
    unittest.main()
