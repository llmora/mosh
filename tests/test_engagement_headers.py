from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mosh.engagement import (
    build_minimal_engagement_template,
    asset_request_headers,
    engagement_context_text,
    load_engagement_file,
    validate_engagement_template,
    write_engagement_template_mapping,
)
from mosh.conversation import build_engagement_chat_context
from mosh.engagements import create_engagement


class EngagementHeaderTests(unittest.TestCase):
    def test_request_headers_round_trip_and_survive_regeneration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            template = build_minimal_engagement_template()
            template["asset_request_headers"] = {
                "asset_live_1": {"X-Gateway-Id": "client-id", "X-Gateway-Secret": "client-secret"}
            }
            write_engagement_template_mapping(report_dir, template, preserve_existing=False, reject_candidate_credentials=False)
            self.assertEqual(
                asset_request_headers(load_engagement_file(report_dir / "engagement_template.yaml"), "asset_live_1"),
                {"X-Gateway-Id": "client-id", "X-Gateway-Secret": "client-secret"},
            )
            self.assertEqual(asset_request_headers(template, "asset_live_2"), {})
            write_engagement_template_mapping(report_dir, build_minimal_engagement_template())
            self.assertEqual(load_engagement_file(report_dir / "engagement_template.yaml")["asset_request_headers"], template["asset_request_headers"])

    def test_validates_header_names_and_single_line_values(self) -> None:
        template = build_minimal_engagement_template()
        template["asset_request_headers"] = {"asset_live_1": {"Bad Name": "id"}}
        with self.assertRaisesRegex(ValueError, "valid request header name"):
            validate_engagement_template(template)
        template["asset_request_headers"]["asset_live_1"] = {"X-Gateway": "secret\r\nInjected: yes"}
        with self.assertRaisesRegex(ValueError, "single-line"):
            validate_engagement_template(template)

    def test_generated_template_cannot_invent_request_headers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            template = build_minimal_engagement_template()
            write_engagement_template_mapping(report_dir, template)
            template["asset_request_headers"] = {
                "asset_live_1": {"X-Gateway": "secret"}
            }
            with self.assertRaisesRegex(ValueError, "must not change asset request headers"):
                write_engagement_template_mapping(report_dir, template)

    def test_request_headers_are_excluded_from_chat_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root, "Protected site")
            template = build_minimal_engagement_template()
            template["asset_request_headers"] = {
                "asset_live_1": {"X-Gateway-Id": "fixture-id", "X-Gateway-Secret": "fixture-secret"}
            }
            report_dir = output_root / engagement.id
            write_engagement_template_mapping(report_dir, template, preserve_existing=False, reject_candidate_credentials=False)
            self.assertNotIn("fixture-secret", engagement_context_text(report_dir / "engagement_template.yaml"))
            context = build_engagement_chat_context(output_root, engagement.id)
            self.assertNotIn("fixture-secret", str(context))


if __name__ == "__main__":
    unittest.main()
