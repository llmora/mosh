from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mosh.memory import FileMemory
from mosh.models import CrawledPage, CrawlResult
from mosh.crews.discovery_live.reporting import (
    apply_javascript_discovery_report_facts,
    build_javascript_discovery_summary,
    update_report_with_testing_feedback,
    write_reports,
)


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
                "executive_summary": "The reporter wrote this.",
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

    def test_javascript_discovery_facts_replace_contradicted_limitations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            memory.record_event(
                "crawler",
                "tool_call",
                "Invoking katana_docker_crawler",
                {"tool": "katana_docker_crawler"},
            )
            memory.record_event(
                "crawler",
                "tool_result",
                "katana_docker_crawler completed",
                {"failed": 0, "pages": 3},
            )
            memory.record_event(
                "crawler",
                "tool_call",
                "Invoking js_static_endpoint_discovery",
                {"tool": "js_static_endpoint_discovery", "javascript_urls": 1},
            )
            memory.record_event(
                "crawler",
                "tool_result",
                "js_static_endpoint_discovery completed",
                {"failed": 0, "pages": 2},
            )
            memory.record_event(
                "crawler",
                "tool_result",
                "source_map_discovery completed",
                {"checked": True, "javascript_assets": 1, "source_maps_found": 0, "failed": 0},
            )
            memory.add_item(
                "source_map_discovery",
                {
                    "checked": True,
                    "javascript_assets": 1,
                    "source_maps_found": 0,
                    "sources_with_content": 0,
                    "assets": [],
                    "failed": [],
                },
                "crawler",
            )
            summary = build_javascript_discovery_summary(memory)
            report_content = {
                "limitations": [
                    {
                        "title": "JavaScript Not Executed",
                        "detail": "The crawler did not execute JavaScript.",
                    },
                    {
                        "title": "JS Bundle Not Deeply Parsed",
                        "detail": "Routes inferred from string references only.",
                    },
                ]
            }

            normalized = apply_javascript_discovery_report_facts(report_content, summary)

            rendered_titles = [item["title"] for item in normalized["limitations"]]
            self.assertNotIn("JavaScript Not Executed", rendered_titles)
            self.assertNotIn("JS Bundle Not Deeply Parsed", rendered_titles)
            self.assertIn("Source Maps Not Available", rendered_titles)
            self.assertIn("source-level reconstruction", normalized["limitations"][0]["detail"])

    def test_javascript_discovery_summary_aggregates_source_maps_by_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            memory.record_event(
                "crawler",
                "tool_call",
                "Invoking js_static_endpoint_discovery",
                {"tool": "js_static_endpoint_discovery", "javascript_urls": 2},
            )
            memory.record_event(
                "crawler",
                "tool_result",
                "js_static_endpoint_discovery completed",
                {"failed": 0, "pages": 2},
            )
            memory.add_item(
                "source_map_discovery",
                {
                    "checked": True,
                    "javascript_assets": 2,
                    "source_maps_found": 1,
                    "sources_with_content": 3,
                    "start_url": "https://example.test/",
                    "assets": [
                        {
                            "source": "https://example.test/static/js/app.js",
                            "checked": 1,
                            "source_maps_found": 1,
                            "source_maps": [
                                {
                                    "url": "https://example.test/static/js/app.js.map",
                                    "source_root": "",
                                    "sources_count": 3,
                                    "sources_with_content": 3,
                                }
                            ],
                        }
                    ],
                    "failed": [],
                },
                "crawler",
            )
            memory.add_item(
                "source_map_discovery",
                {
                    "checked": True,
                    "javascript_assets": 1,
                    "source_maps_found": 0,
                    "sources_with_content": 0,
                    "start_url": "https://example.test/login",
                    "assets": [
                        {
                            "source": "https://example.test/static/js/app.js",
                            "checked": 1,
                            "source_maps_found": 0,
                            "source_maps": [],
                        }
                    ],
                    "failed": [],
                },
                "crawler",
            )

            summary = build_javascript_discovery_summary(memory)
            normalized = apply_javascript_discovery_report_facts(
                {
                    "limitations": [
                        {
                            "title": "No Source Maps Available",
                            "detail": "JavaScript bundles are minified without accompanying source map files.",
                        }
                    ]
                },
                summary,
            )

            self.assertEqual(summary["source_maps"]["source_maps_found"], 1)
            self.assertEqual(summary["source_maps"]["sources_with_content"], 3)
            self.assertEqual(len(summary["source_maps"]["assets"]), 1)
            self.assertEqual(normalized["limitations"], [])

    def test_javascript_discovery_preserves_source_map_limitation_when_maps_not_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))
            memory.record_event(
                "crawler",
                "tool_call",
                "Invoking js_static_endpoint_discovery",
                {"tool": "js_static_endpoint_discovery", "javascript_urls": 1},
            )
            memory.record_event(
                "crawler",
                "tool_result",
                "js_static_endpoint_discovery completed",
                {"failed": 0, "pages": 2},
            )
            summary = build_javascript_discovery_summary(memory)

            normalized = apply_javascript_discovery_report_facts(
                {
                    "limitations": [
                        {
                            "title": "JS Bundle Not Deeply Parsed",
                            "detail": "Routes inferred from string references only.",
                        },
                        {
                            "title": "Source Maps Not Checked",
                            "detail": "Source maps were not checked for discovered JavaScript bundles.",
                        },
                    ]
                },
                summary,
            )

            rendered_titles = [item["title"] for item in normalized["limitations"]]
            self.assertNotIn("JS Bundle Not Deeply Parsed", rendered_titles)
            self.assertIn("Source Maps Not Checked", rendered_titles)

    def test_routes_section_backfills_crawl_routes_missing_from_agent_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            crawl = CrawlResult(
                start_url="https://example.test",
                pages=[
                    CrawledPage(
                        url="https://example.test/login",
                        status=200,
                        content_type="text/html",
                        title="Login",
                        headers={},
                        links=[],
                        references=[],
                        forms=[],
                    ),
                    CrawledPage(
                        url="https://example.test/register",
                        status=0,
                        content_type="",
                        title=None,
                        headers={},
                        links=[],
                        references=["https://example.test/static/js/app.js"],
                        forms=[],
                    ),
                    CrawledPage(
                        url="https://example.test/static/js/app.js",
                        status=200,
                        content_type="application/javascript",
                        title=None,
                        headers={},
                        links=[],
                        references=[],
                        forms=[],
                    ),
                    CrawledPage(
                        url="https://example.test/js/%7B%7Bimage%7D%7D",
                        status=0,
                        content_type="",
                        title=None,
                        headers={},
                        links=[],
                        references=[],
                        forms=[],
                    ),
                ],
                out_of_scope=[],
                failed=[],
                robots=None,
            )

            markdown = write_reports(
                Path(directory),
                "https://example.test",
                crawl,
                components=[],
                summary={"pages_crawled": 4},
                report_content={
                    "title": "Agent Report",
                    "discovered_routes": [
                        {
                            "url": "https://example.test/login",
                            "status": 200,
                            "content_type": "text/html",
                            "notes": "Login route.",
                        }
                    ],
                },
            )

            routes_section = markdown.split("## API Endpoints", maxsplit=1)[0]
            route_lines = routes_section.splitlines()
            self.assertIn("https://example.test/login", routes_section)
            self.assertIn("https://example.test/register", routes_section)
            self.assertFalse(any(line.startswith("| https://example.test/static/js/app.js |") for line in route_lines))
            self.assertFalse(any(line.startswith("| https://example.test/js/%7B%7Bimage%7D%7D |") for line in route_lines))

    def test_testing_feedback_section_is_replaced_in_discovery_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            (report_dir / "report.md").write_text(
                "# Discovery\n\n## Security Testing Feedback\n\nOld feedback.\n\n## Appendix\n\nExisting appendix.\n",
                encoding="utf-8",
            )

            markdown = update_report_with_testing_feedback(
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
