from __future__ import annotations

from pathlib import Path

from appsec_harness.memory import FileMemory
from appsec_harness.models import CrawlResult
from appsec_harness.crews.discovery.reporting import write_reports
from appsec_harness.crews.security_testing.crew import render_executed_test_report
from appsec_harness.crews.security_planning.reporting import write_security_test_plan


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
        from appsec_harness.crews.discovery.crawler import Crawler

        crawl = Crawler(timeout=3).crawl(target_url, max_pages=max_pages, max_depth=max_depth)
        memory.record_event("crawler", "task_received", "Crawl the target and discover app surface")
        memory.add_item("robots", crawl.robots or {"found": False}, "crawler")
        for page in crawl.pages:
            memory.add_item("crawled_page", page.to_dict(), "crawler")
        components: list[dict[str, str]] = []
        memory.record_event(
            "sbom_compiler",
            "agent_output",
            "sbom_compiler completed compile_components_task",
            {
                "task": "compile_components_task",
                "output": {
                    "text": "SBOM analysis is produced by the SBOM agent without a deterministic component tool.",
                },
            },
        )
        summary = {
            "pages_crawled": len(crawl.pages),
            "in_scope_references": sum(len(page.links) + len(page.references) + len(page.forms) for page in crawl.pages),
            "out_of_scope_references": len(crawl.out_of_scope),
            "components_identified": len(components),
            "failed_requests": len(crawl.failed),
        }
        memory.add_item("summary", summary, "summarizer")
        report_content = {
            "title": "Application Discovery Report",
            "executive_summary": f"Discovery completed for {crawl.start_url}.",
            "application_description": "Fixture application used by the test harness.",
            "target_scope": [
                {
                    "title": "Target",
                    "detail": crawl.start_url,
                    "confidence": "confirmed",
                    "evidence": [crawl.start_url],
                }
            ],
            "confirmed_findings": [
                {
                    "title": "Pages crawled",
                    "detail": str(summary["pages_crawled"]),
                    "confidence": "confirmed",
                    "evidence": [page.url for page in crawl.pages],
                }
            ],
        }
        memory.add_item("llm_report", {"structured": report_content}, "summarizer")
        write_reports(report_dir, crawl.start_url, crawl, components, summary, report_content)
        return FakeCrewResult(crawl, components, summary)


class FakeCrewResult:
    def __init__(self, crawl: CrawlResult, components: list[dict[str, str]], summary: dict[str, int]) -> None:
        self.crawl = crawl
        self.components = components
        self.summary = summary


class FakeSecurityPlanningRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(self, target_url: str, discovery_dir: Path, report_dir: Path, memory: FileMemory):
        self.calls.append(
            {
                "target_url": target_url,
                "discovery_dir": str(discovery_dir),
                "report_dir": str(report_dir),
            }
        )
        plan = {
            "title": "Security Test Plan",
            "scope_summary": "Plan derived from fixture discovery output.",
            "assumptions": ["Testing is authorised."],
            "test_hypotheses": [
                {
                    "id": "AUTH-001",
                    "title": "Private API requires authentication",
                    "surface": "authentication",
                    "priority": "high",
                    "hypothesis": "Private API endpoints should reject unauthenticated requests.",
                    "evidence": ["Fixture discovery report"],
                    "requirements": ["No credentials required for the unauthenticated variant."],
                    "tools_expected": ["HTTP client"],
                    "preconditions": ["Discovery report exists."],
                    "test_steps": ["Request the private API without a token."],
                    "expected_secure_behavior": "The API returns 401 or 403.",
                    "interesting_failure_modes": ["200 OK without credentials."],
                    "safety_notes": ["Do not brute force credentials."],
                    "stopping_conditions": ["Stop after observing authentication enforcement."],
                    "status": "planned",
                }
            ],
            "not_in_scope": [],
            "open_questions": [],
        }
        review = {"accepted": True, "summary": "Accepted.", "blocking_findings": [], "non_blocking_suggestions": []}
        memory.add_item("security_test_plan_final", {"structured": plan, "critic_review": review}, "security_test_finalizer")
        write_security_test_plan(report_dir, target_url, plan, review, accepted=True, iterations=1)
        return FakeSecurityPlanningResult(plan, review, accepted=True, iterations=1)


class FakeSecurityPlanningResult:
    def __init__(self, plan: dict[str, object], review: dict[str, object], accepted: bool, iterations: int) -> None:
        self.plan = plan
        self.critic_review = review
        self.accepted = accepted
        self.iterations = iterations


class FakeSecurityTestingRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(self, target_url, report_dir, memory, plan, engagement, preflight, ready_pending) -> None:
        self.calls.append(
            {
                "target_url": target_url,
                "report_dir": str(report_dir),
                "ready_pending": [item.get("id") for item in ready_pending],
            }
        )
        executed_dir = report_dir / "executed_tests"
        executed_dir.mkdir(parents=True, exist_ok=True)
        for hypothesis in ready_pending:
            test_id = str(hypothesis.get("id") or "unknown")
            markdown = render_executed_test_report(
                target_url=target_url,
                hypothesis=hypothesis,
                evidence={
                    "status": "no-finding",
                    "summary": "Fake execution completed.",
                    "result": "No finding in fake runner.",
                },
                review={"accepted": True, "summary": "Accepted."},
                commands=[],
            )
            (executed_dir / f"{test_id}.md").write_text(markdown, encoding="utf-8")
            memory.add_item(
                "executed_security_test_report",
                {"test_id": test_id, "path": str(executed_dir / f"{test_id}.md")},
                "security_test_reporter",
            )
