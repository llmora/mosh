from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from appsec_harness.models import CrawledPage, CrawlResult
from appsec_harness.reporting import write_reports


class ReportingTests(unittest.TestCase):
    def test_report_markdown_is_authored_by_summarizer_agent(self) -> None:
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
            markdown_report = "# Agent Report\n\nThe summarizer wrote this.\n"
            agent_report = {"executive_summary": "The summarizer wrote this."}

            write_reports(
                Path(directory),
                "https://example.test",
                crawl,
                components=[],
                summary={"pages_crawled": 1},
                markdown_report=markdown_report,
                agent_report=agent_report,
            )

            self.assertEqual((Path(directory) / "report.md").read_text(encoding="utf-8"), markdown_report)

            report = json.loads((Path(directory) / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["report_markdown"], markdown_report)
            self.assertEqual(report["agent_report"], agent_report)
            self.assertEqual(report["summary"]["pages_crawled"], 1)


if __name__ == "__main__":
    unittest.main()
