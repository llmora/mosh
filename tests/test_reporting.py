from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from appsec_harness.models import CrawledPage, CrawlResult
from appsec_harness.crews.discovery.reporting import update_report_with_security_testing_feedback, write_reports


class ReportingTests(unittest.TestCase):
    def test_report_markdown_is_rendered_from_structured_agent_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            crawl = CrawlResult(
                start_url="https://example.test",
                pages=[
                    CrawledPage(
                        url="https://example.test",
                        status=200,
                        content_type="text/html",
                        title="Example",
                        headers={},
                        links=[],
                        references=[],
                        forms=[],
                    )
                ],
                out_of_scope=[],
                failed=[],
                robots=None,
            )
            report_content = {
                "title": "Agent Report",
                "executive_summary": "The summarizer wrote this.",
                "application_description": "A small example application.",
                "confirmed_findings": [
                    {
                        "title": "Example finding",
                        "detail": "The example page was discovered.",
                        "confidence": "confirmed",
                        "evidence": ["https://example.test"],
                    }
                ],
                "recommended_next_steps": [
                    {
                        "priority": "medium",
                        "action": "Review the discovered page",
                        "rationale": "It is part of the visible application surface.",
                    }
                ],
            }
            (Path(directory) / "report.json").write_text("stale\n", encoding="utf-8")

            markdown = write_reports(
                Path(directory),
                "https://example.test",
                crawl,
                components=[],
                summary={"pages_crawled": 1},
                report_content=report_content,
            )

            self.assertEqual((Path(directory) / "report.md").read_text(encoding="utf-8"), markdown)
            self.assertFalse((Path(directory) / "report.json").exists())
            self.assertIn("# Agent Report", markdown)
            self.assertIn("## Executive Summary", markdown)
            self.assertIn("## Application Description", markdown)
            self.assertIn("## Summary Statistics", markdown)
            self.assertIn("| Pages Crawled | 1 |", markdown)
            self.assertIn("## Confirmed Findings", markdown)
            self.assertIn("Example finding", markdown)

    def test_security_testing_feedback_section_is_replaced_in_discovery_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            (report_dir / "report.md").write_text(
                "# Discovery\n\n## Security Testing Feedback\n\nOld feedback.\n\n## Appendix\n\nExisting appendix.\n",
                encoding="utf-8",
            )

            markdown = update_report_with_security_testing_feedback(
                report_dir,
                [
                    {
                        "type": "component",
                        "detail": "Express 4.18.2 is exposed by the API service header.",
                        "confidence": "confirmed",
                        "test_id": "API-001",
                        "evidence": ["X-Powered-By: Express 4.18.2"],
                    }
                ],
            )

            self.assertNotIn("Old feedback", markdown)
            self.assertIn("Express 4.18.2", markdown)
            self.assertIn("## Appendix", markdown)


if __name__ == "__main__":
    unittest.main()
