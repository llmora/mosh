from __future__ import annotations

from pathlib import Path

from mosh.memory import FileMemory
from mosh.models import CrawlResult
from mosh.crews.discovery_live.reporting import write_reports
from mosh.crews.discovery_source.agents import (
    DependencyConfigAgent,
    DiscoverySourceReporterAgent,
    SourceIntakeAgent,
    SourceMapperAgent,
)
from mosh.crews.discovery_source.reporting import write_discovery_source_report
from mosh.crews.testing.crew import (
    _archive_latest_report,
    _execution_metadata,
    _with_execution_metadata_mapping,
    hypothesis_fingerprint,
    plan_revision_id,
    render_executed_test_report,
)
from mosh.crews.planning.reporting import write_security_test_plan


class FakeRuntimeCrewAI:
    BaseModel = object
    BaseTool = object

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

    @staticmethod
    def Field(default=None, description: str = ""):
        return default

    @staticmethod
    def CrewBase(cls):
        if isinstance(getattr(cls, "agents_config", None), str):
            cls.agents_config = FakeRuntimeCrewAI._load_config_blocks(cls.agents_config)
        if isinstance(getattr(cls, "tasks_config", None), str):
            cls.tasks_config = FakeRuntimeCrewAI._load_config_blocks(cls.tasks_config)
        return cls

    @staticmethod
    def agent(fn):
        return fn

    @staticmethod
    def task(fn):
        return fn

    @staticmethod
    def crew(fn):
        return fn

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
        engagement_steer: str = "",
    ):
        self.calls.append(
            {
                "target_url": target_url,
                "report_dir": str(report_dir),
                "max_pages": max_pages,
                "max_depth": max_depth,
                "engagement_steer": engagement_steer,
            }
        )
        from mosh.crews.discovery_live.crawler import Crawler

        crawl = Crawler(timeout=3).crawl(target_url, max_pages=max_pages, max_depth=max_depth)
        memory.record_event("crawler", "task_received", "Crawl the target and discover app surface")
        memory.add_item("robots", crawl.robots or {"found": False}, "crawler")
        for page in crawl.pages:
            memory.add_item("crawled_page", page.to_dict(), "crawler")
        components: list[dict[str, str]] = []
        memory.record_event(
            "technology_mapper",
            "agent_output",
            "technology_mapper completed compile_components_task",
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
        memory.add_item("summary", summary, "reporter")
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
        memory.add_item("llm_report", {"structured": report_content}, "reporter")
        write_reports(report_dir, crawl.start_url, crawl, components, summary, report_content)
        return FakeCrewResult(crawl, components, summary)


class FakeCrewResult:
    def __init__(self, crawl: CrawlResult, components: list[dict[str, str]], summary: dict[str, int]) -> None:
        self.crawl = crawl
        self.components = components
        self.summary = summary


class FakeDiscoverySourceRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        source: str,
        report_dir: Path,
        memory: FileMemory,
        engagement_steer: str = "",
    ):
        self.calls.append(
            {
                "source": source,
                "report_dir": str(report_dir),
                "engagement_steer": engagement_steer,
            }
        )
        intake = SourceIntakeAgent()
        mapper = SourceMapperAgent()
        dependency_config = DependencyConfigAgent()
        reporter = DiscoverySourceReporterAgent()
        source_info = intake.validate(source, memory)
        inventory = mapper.inventory(str(source_info["path"]), memory)
        routes = mapper.routes(str(source_info["path"]), memory)
        resolved_route_records = []
        for route in routes.get("routes", []):
            if isinstance(route, dict) and route.get("full_route") == "/api/v1/users":
                resolved_route_records.append(
                    {
                        **route,
                        "route_resolution_source": "model-assisted",
                        "route_resolution_confidence": "high",
                        "route_resolution_reason": "Fixture confirms mounted Express router path.",
                    }
                )
            else:
                resolved_route_records.append(route)
        routes = {**routes, "routes": resolved_route_records}
        route_resolution = {
            "schema": "mosh.source-route-resolution.v1",
            "resolved_routes": [
                {
                    "full_route": "/api/v1/users",
                    "confidence": "high",
                    "reason": "Fixture confirms mounted Express router path.",
                    "evidence": ["apps/api/src/server.ts"],
                }
            ],
            "applied_count": 1,
        }
        dependencies = dependency_config.dependencies(str(source_info["path"]), memory)
        configuration = dependency_config.configuration(str(source_info["path"]), memory)
        component_map = {
            "schema": "mosh.source-component-map.v1",
            "application_purpose": "Fixture application used by the source discovery test harness.",
            "business_domain": "test fixture",
            "key_components": [
                {
                    "title": "HTTP API",
                    "detail": "Express and Flask route candidates were identified.",
                    "evidence": ["app.py", "apps/api/src/server.ts"],
                }
            ],
            "sensitive_data": [
                {
                    "title": "User records",
                    "detail": "User API route candidates are present.",
                    "evidence": ["/api/v1/users"],
                }
            ],
            "trust_boundaries": [
                {
                    "title": "Client to API",
                    "detail": "HTTP route candidates cross the external request boundary.",
                    "evidence": ["/api/v1/users"],
                }
            ],
        }
        gap_analysis = {
            "schema": "mosh.source-gap-analysis.v1",
            "gaps": [
                {
                    "title": "Source-only discovery needs live correlation",
                    "detail": "Route candidates should be correlated with deployed paths when a live URL is available.",
                    "evidence": ["/api/v1/users"],
                }
            ],
            "limitations": ["Fixture gap analysis is deterministic for tests."],
            "recommended_follow_up": ["Use source discovery output during security planning."],
        }
        memory.add_item("source_route_resolution", route_resolution, "source_route_resolver")
        memory.add_item("source_routes_resolved", routes, "source_route_resolver")
        memory.add_item("source_component_map", component_map, "source_component_mapper")
        memory.add_item("source_gap_analysis", gap_analysis, "source_gap_analyst")
        summary = reporter.summarize(source_info, inventory, routes, dependencies, configuration, memory)
        source_index = reporter.build_source_index(
            source_info,
            inventory,
            routes,
            dependencies,
            configuration,
            memory,
            route_resolution=route_resolution,
            component_map=component_map,
            gap_analysis=gap_analysis,
        )
        memory.add_item(
            "llm_report",
            {
                "structured": {
                    "title": "Source Discovery Report",
                    "executive_summary": "Fake source discovery completed.",
                }
            },
            "reporter",
        )
        write_discovery_source_report(
            report_dir,
            source_index,
            {"title": "Source Discovery Report", "executive_summary": "Fake source discovery completed."},
        )
        return FakeDiscoverySourceResult(source_index, summary)


class FakeDiscoverySourceResult:
    def __init__(self, source_index: dict[str, object], summary: dict[str, object]) -> None:
        self.source_index = source_index
        self.summary = summary


class FakeSecurityPlanningRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run_engagement(
        self,
        output_root: Path,
        engagement_id: str,
        report_dir: Path,
        memory: FileMemory,
    ):
        from mosh.evidence_links import build_evidence_links, load_evidence_links_if_current

        self.calls.append(
            {
                "output_root": str(output_root),
                "report_dir": str(report_dir),
                "engagement_id": engagement_id,
            }
        )
        links = load_evidence_links_if_current(output_root, engagement_id) or build_evidence_links(output_root, engagement_id)
        memory.add_item(
            "evidence_links",
            {
                "path": str(links.links_path),
                "links": len(links.payload.get("links") or []),
            },
            "evidence_linker",
        )
        plan = {
            "title": "Security Test Plan",
            "scope_summary": "Plan derived from engagement discovery output.",
            "assumptions": ["Testing is authorised."],
            "test_hypotheses": [
                {
                    "id": "COMBINED-001",
                    "title": "Source route maps to deployed endpoint",
                    "surface": "api",
                    "priority": "high",
                    "hypothesis": "Linked source and live evidence should guide combined verification.",
                    "evidence": ["Engagement evidence links"],
                    "requirements": ["No credentials required for baseline."],
                    "tools_expected": ["HTTP client", "source inspection"],
                    "preconditions": ["Discovery has run for attached assets."],
                    "test_steps": ["Inspect linked source route.", "Verify the corresponding live endpoint safely."],
                    "expected_secure_behavior": "The endpoint enforces expected controls.",
                    "interesting_failure_modes": ["Live behavior diverges from source assumptions."],
                    "safety_notes": ["Stay within attached asset scope."],
                    "stopping_conditions": ["Stop after bounded verification."],
                    "execution_mode": "combined",
                    "evidence_sources": ["live", "source"],
                    "affected_runtime": [{"method": "GET", "url": "https://app.example.test/api/status"}],
                    "affected_source": [{"path": "api/status.py", "start_line": 1, "end_line": 1}],
                    "verification_strategy": "source-guided-live-verification",
                    "status": "planned",
                }
            ],
            "deferred_test_opportunities": [],
            "not_in_scope": [],
            "open_questions": [],
        }
        review = {"accepted": True, "summary": "Accepted.", "blocking_findings": [], "non_blocking_suggestions": []}
        memory.add_item("security_test_plan_final", {"structured": plan, "critic_review": review}, "reporter")
        write_security_test_plan(report_dir, engagement_id, plan, review, accepted=True, iterations=1)
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

    def run(
        self,
        target_url,
        source,
        discovery_source_dir,
        evidence_links,
        report_dir,
        memory,
        plan,
        engagement,
        preflight,
        executable_pending,
    ) -> None:
        self.calls.append(
            {
                "target_url": target_url,
                "source": source,
                "discovery_source_dir": str(discovery_source_dir) if discovery_source_dir else None,
                "evidence_links": bool(evidence_links),
                "report_dir": str(report_dir),
                "ready_pending": [item.get("id") for item in executable_pending],
                "executable_pending": [item.get("id") for item in executable_pending],
            }
        )
        executed_dir = report_dir / "executed_tests"
        executed_dir.mkdir(parents=True, exist_ok=True)
        for hypothesis in executable_pending:
            test_id = str(hypothesis.get("id") or "unknown")
            archived = _archive_latest_report(report_dir, test_id, memory=memory)
            evidence_type = (
                "combined"
                if hypothesis.get("affected_source") and hypothesis.get("affected_runtime")
                else "source"
                if hypothesis.get("affected_source")
                else "live"
            )
            markdown = render_executed_test_report(
                target_url=target_url,
                hypothesis=hypothesis,
                evidence={
                    "status": "no-finding",
                    "summary": "Fake execution completed.",
                    "source_evidence": [{"path": "api/routes/auth.js", "start_line": 1, "end_line": 20}]
                    if evidence_type in {"source", "combined"}
                    else [],
                    "result": "No finding in fake runner.",
                },
                review={"accepted": True, "summary": "Accepted."},
                commands=[],
                targets=preflight.targets,
            )
            report_path = executed_dir / f"{test_id}.md"
            metadata = _execution_metadata(
                test_id=test_id,
                plan_revision_id=plan_revision_id(plan),
                hypothesis_fingerprint=hypothesis_fingerprint(hypothesis),
                evidence={
                    "status": "no-finding",
                    "summary": "Fake execution completed.",
                    "result": "No finding in fake runner.",
                },
                review={"accepted": True, "summary": "Accepted."},
                report_path=str(report_path),
                archived_previous_reports=archived,
            )
            metadata.update({"execution_mode": hypothesis.get("execution_mode"), "evidence_type": evidence_type, "source": source})
            report_path.write_text(_with_execution_metadata_mapping(markdown, metadata), encoding="utf-8")
            memory.add_item(
                "executed_security_test_report",
                {"test_id": test_id, "path": str(report_path), "evidence_type": evidence_type},
                "reporter",
            )


class FakeFinalReportingRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        target_url: str,
        report_dir: Path,
        memory: FileMemory,
        bundle: dict[str, object],
        engagement_steer: str = "",
    ) -> Path:
        self.calls.append(
            {
                "target_url": target_url,
                "report_dir": str(report_dir),
                "executed_tests": len(bundle.get("executed_tests", [])),
                "engagement_steer": engagement_steer,
            }
        )
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.md"
        report_path.write_text(
            "\n".join(
                [
                    f"# Security Testing Report: {target_url}",
                    "",
                    "## Summary of Findings",
                    "",
                    "Fake final report.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        memory.add_item("final_report", {"path": str(report_path)}, "writer")
        memory.add_item("final_report_review", {"accepted": True}, "reviewer")
        return report_path
