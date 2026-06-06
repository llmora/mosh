from __future__ import annotations

from pathlib import Path

from appsec_harness.memory import FileMemory
from appsec_harness.models import CrawlResult
from appsec_harness.reporting import write_reports


class FakeCrewRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        target_url: str,
        report_dir: Path,
        memory: FileMemory,
        max_pages: int,
        max_depth: int,
    ):
        self.calls.append(
            {
                "target_url": target_url,
                "report_dir": str(report_dir),
                "max_pages": max_pages,
                "max_depth": max_depth,
            }
        )
        from appsec_harness.crawler import Crawler
        from appsec_harness.components import compile_component_inventory

        crawl = Crawler(timeout=3).crawl(target_url, max_pages=max_pages, max_depth=max_depth)
        memory.record_event("crawler", "task_received", "Crawl the target and discover app surface")
        memory.add_item("robots", crawl.robots or {"found": False}, "crawler")
        for page in crawl.pages:
            memory.add_item("crawled_page", page.to_dict(), "crawler")
        components = compile_component_inventory(crawl)
        memory.add_item("component_inventory", {"components": components}, "sbom_compiler")
        summary = {
            "pages_crawled": len(crawl.pages),
            "in_scope_references": sum(len(page.links) + len(page.references) + len(page.forms) for page in crawl.pages),
            "out_of_scope_references": len(crawl.out_of_scope),
            "components_identified": len(components),
            "failed_requests": len(crawl.failed),
        }
        memory.add_item("summary", summary, "summarizer")
        markdown_report = (
            f"# Application Discovery Report\n\n"
            f"Target: {crawl.start_url}\n\n"
            f"Pages crawled: {summary['pages_crawled']}\n"
        )
        memory.add_item("llm_report", {"markdown": markdown_report, "structured": {}}, "summarizer")
        write_reports(report_dir, crawl.start_url, crawl, components, summary, markdown_report)
        return FakeCrewResult(crawl, components, summary)


class FakeCrewResult:
    def __init__(self, crawl: CrawlResult, components: list[dict[str, str]], summary: dict[str, int]) -> None:
        self.crawl = crawl
        self.components = components
        self.summary = summary
