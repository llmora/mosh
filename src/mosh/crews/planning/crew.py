from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Callable, Protocol

from mosh.config import AppConfig
from mosh.crews.definitions import AgentDefinition
from mosh.crews.discovery_live.crew import (
    CREW_CONFIG_PACKAGE,
    CrewAIUnavailable,
    _build_task_with_output_event,
    _llm,
    _load_crewai,
)
from mosh.crews.events import MoshCrewAIEventListener
from mosh.engagement import build_engagement_template, load_engagement_file, write_engagement_template_mapping
from mosh.engagements import (
    Engagement,
    EngagementAsset,
    asset_discovery_dir,
    engagement_dir,
    engagement_plan_dir,
    load_engagement,
)
from mosh.evidence_links import EvidenceLinkResult, build_evidence_links, load_evidence_links_if_current
from mosh.memory import FileMemory
from mosh.models import Event, utc_now
from mosh.crews.planning.evidence_linker import build_model_assisted_linker
from mosh.crews.planning.reporting import write_security_test_plan


@dataclass
class SecurityTestPlanningState:
    target_url: str
    discovery_dir: Path
    report_dir: Path
    memory: FileMemory
    discovery_context: dict[str, Any]
    source: str | None = None
    discovery_source_dir: Path | None = None
    engagement_template_dir: Path | None = None
    current_plan: dict[str, Any] | None = None
    current_review: dict[str, Any] | None = None
    accepted: bool = False
    iterations: int = 0


@dataclass(frozen=True)
class SecurityTestPlanningResult:
    plan: dict[str, Any]
    critic_review: dict[str, Any] | None
    accepted: bool
    iterations: int


DISCOVERY_REPORT_MAX_CHARS = 60_000
COMPACT_TEXT_MAX_CHARS = 4_000
COMPACT_LIST_MAX_ITEMS = 100
COMPACT_MAPPING_MAX_ITEMS = 200
COMPACT_VALUE_MAX_DEPTH = 8
LIVE_CONTEXT_MAX_PAGES = 200
LIVE_CONTEXT_MAX_LINKS_PER_PAGE = 20
LIVE_CONTEXT_MAX_REFERENCES_PER_PAGE = 30
LIVE_CONTEXT_MAX_FORMS_PER_PAGE = 20
LIVE_CONTEXT_MAX_CANDIDATES = 200
LIVE_CONTEXT_MAX_OUT_OF_SCOPE = 100
LIVE_CONTEXT_MAX_FAILED_REQUESTS = 50
SOURCE_CONTEXT_MAX_APPS = 50
SOURCE_CONTEXT_MAX_ENTRYPOINTS = 100
SOURCE_CONTEXT_MAX_ROUTES = 200
SOURCE_CONTEXT_MAX_SECURITY_ITEMS = 100
SOURCE_CONTEXT_MAX_DEPENDENCIES = 200
SOURCE_CONTEXT_MAX_CONFIG = 150
SOURCE_CONTEXT_MAX_EVIDENCE_REFS = 200


class SecurityTestPlanningCrewRunner(Protocol):
    def run_engagement(
        self,
        output_root: Path,
        engagement_id: str,
        report_dir: Path,
        memory: FileMemory,
    ) -> SecurityTestPlanningResult:
        pass


def security_test_planning_agent_definitions(config: AppConfig) -> list[AgentDefinition]:
    return [
        AgentDefinition(
            name="orchestrator",
            role="Security test planning coordinator",
            goal="Coordinate security test planning work and persist planner/reviewer/reporter outputs.",
            model=config.models.planning.reporter,
        ),
        AgentDefinition(
            name="evidence_linker",
            role="Source and live evidence link candidate analyst",
            goal="Link source and live discovery evidence before planning hypotheses.",
            model=config.models.planning.evidence_linker,
        ),
        AgentDefinition(
            name="planner",
            role="Security test hypothesis planner",
            goal="Turn discovery findings into detailed, evidence-backed security test hypotheses.",
            model=config.models.planning.planner,
        ),
        AgentDefinition(
            name="reviewer",
            role="Security test plan reviewer",
            goal="Review test hypotheses for clarity, evidence, scope, safety, and missing requirements.",
            model=config.models.planning.reviewer,
        ),
        AgentDefinition(
            name="reporter",
            role="Security test plan reporter",
            goal="Persist the agreed planning output as a stable Markdown security test plan.",
            model=config.models.planning.reporter,
        ),
        AgentDefinition(
            name="engagement_refiner",
            role="Engagement template refiner",
            goal="Refine the generated engagement template for security test execution.",
            model=config.models.planning.engagement_refiner,
        ),
    ]


class CrewAISecurityTestPlanningCrewRunner:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def run_engagement(
        self,
        output_root: Path,
        engagement_id: str,
        report_dir: Path,
        memory: FileMemory,
    ) -> SecurityTestPlanningResult:
        missing_keys = self.config.missing_llm_api_keys_for_models(
            [
                self.config.models.planning.planner,
                self.config.models.planning.reviewer,
                self.config.models.planning.reporter,
                self.config.models.planning.engagement_refiner,
            ]
        )
        if missing_keys:
            raise CrewAIUnavailable(f"Missing LLM API key(s): {', '.join(missing_keys)}.")

        engagement = load_engagement(output_root, engagement_id)
        target_url, source = _engagement_primary_targets(engagement)
        discovery_source_dir = _first_asset_discovery_dir(output_root, engagement, "source_tree")
        memory.record_event(
            "orchestrator",
            "crew_start",
            "Starting CrewAI security test planning crew",
            {
                "target": engagement.id,
                "engagement": engagement.id,
                "target_url": target_url,
                "source": source,
                "discovery_dir": str(engagement_dir(output_root, engagement.id)),
                "discovery_source_dir": str(discovery_source_dir) if discovery_source_dir else None,
            },
        )
        evidence_links = run_planning_evidence_linking(self.config, output_root, engagement.id, memory=memory)
        discovery_context = load_engagement_assessment_evidence_bundle(
            output_root,
            engagement.id,
            evidence_links=evidence_links.payload,
        )
        crewai = _load_crewai()
        state = SecurityTestPlanningState(
            target_url=target_url,
            discovery_dir=engagement_dir(output_root, engagement.id),
            report_dir=report_dir,
            memory=memory,
            discovery_context=discovery_context,
            source=source,
            discovery_source_dir=discovery_source_dir,
            engagement_template_dir=engagement_dir(output_root, engagement.id),
        )

        return self._run_with_state(crewai, state)

    def _run_with_state(self, crewai: Any, state: SecurityTestPlanningState) -> SecurityTestPlanningResult:
        target_url = state.target_url
        source = state.source
        report_dir = state.report_dir
        memory = state.memory
        discovery_context = state.discovery_context
        max_attempts = self.config.planning_max_revisions + 1
        previous_plan: dict[str, Any] | None = None
        previous_review: dict[str, Any] | None = None
        for iteration in range(1, max_attempts + 1):
            state.current_plan = None
            state.current_review = None
            state.iterations = iteration
            planner_crew = _build_planning_planner_crew(crewai, self.config, state)
            planner_crew.crew().kickoff(
                inputs={
                    "target_url": target_url,
                    "iteration": iteration,
                    "max_attempts": max_attempts,
                    "discovery_context": json.dumps(discovery_context, sort_keys=True),
                    "previous_plan": json.dumps(previous_plan or {}, sort_keys=True),
                    "previous_critique": json.dumps(previous_review or {}, sort_keys=True),
                }
            )
            if state.current_plan is None:
                raise RuntimeError("Security test planner did not submit a plan.")

            critic_crew = _build_planning_critic_crew(crewai, self.config, state)
            critic_crew.crew().kickoff(
                inputs={
                    "target_url": target_url,
                    "iteration": iteration,
                    "max_attempts": max_attempts,
                    "security_test_plan": json.dumps(state.current_plan, sort_keys=True),
                    "planning_context": json.dumps(_planning_review_context(discovery_context), sort_keys=True),
                }
            )
            if state.current_review is None:
                raise RuntimeError("Security test critic did not submit a review.")
            previous_plan = state.current_plan
            previous_review = state.current_review
            state.accepted = bool(state.current_review.get("accepted"))
            if state.accepted:
                break

        if state.current_plan is None:
            raise RuntimeError("Security test planner did not produce a plan.")

        engagement_template_dir = _engagement_template_dir(state)
        deterministic_engagement_template = _build_planning_engagement_template(target_url, source, state.current_plan)
        engagement_template = write_engagement_template_mapping(engagement_template_dir, deterministic_engagement_template)
        current_engagement_template = load_engagement_file(engagement_template_dir / "engagement_template.yaml")
        memory.record_event(
            "orchestrator",
            "engagement_template_written",
            "Wrote deterministic engagement template before finalization",
            {"path": str(engagement_template_dir / "engagement_template.yaml"), "bytes": len(engagement_template.encode("utf-8"))},
        )

        reporter_crew = _build_planning_reporter_crew(crewai, self.config, state)
        reporter_crew.crew().kickoff(
            inputs={
                "target_url": target_url,
                "accepted": state.accepted,
                "iterations": state.iterations,
                "security_test_plan": json.dumps(state.current_plan, sort_keys=True),
                "critic_review": json.dumps(state.current_review or {}, sort_keys=True),
            }
        )

        if self.config.refine_engagement_template_with_llm:
            try:
                refinement_crew = _build_engagement_template_refinement_crew(
                    crewai,
                    self.config,
                    state,
                    deterministic_engagement_template,
                )
                refinement_crew.crew().kickoff(
                    inputs={
                        "target_url": target_url,
                        "security_test_plan": json.dumps(state.current_plan, sort_keys=True),
                        "engagement_template": json.dumps(current_engagement_template, sort_keys=True),
                    }
                )
                if not (engagement_template_dir / "engagement_template.yaml").exists():
                    engagement_template = write_engagement_template_mapping(engagement_template_dir, deterministic_engagement_template)
                    memory.record_event(
                        "engagement_refiner",
                        "refinement_missing",
                        "Engagement template refiner did not write a template; wrote deterministic fallback",
                        {"path": str(engagement_template_dir / "engagement_template.yaml"), "bytes": len(engagement_template.encode("utf-8"))},
                    )
            except Exception as exc:
                engagement_template = write_engagement_template_mapping(engagement_template_dir, deterministic_engagement_template)
                memory.record_event(
                    "engagement_refiner",
                    "refinement_failed",
                    "Engagement template refinement failed; wrote deterministic fallback",
                    {
                        "error": str(exc),
                        "path": str(engagement_template_dir / "engagement_template.yaml"),
                        "bytes": len(engagement_template.encode("utf-8")),
                    },
                )
        else:
            memory.record_event(
                "orchestrator",
                "engagement_template_refinement_skipped",
                "Skipped LLM engagement template refinement",
                {"reason": "disabled"},
            )

        memory.record_event(
            "orchestrator",
            "crew_complete",
            "CrewAI security test planning crew completed",
            {"target": target_url, "accepted": state.accepted, "iterations": state.iterations},
        )
        return SecurityTestPlanningResult(
            plan=state.current_plan,
            critic_review=state.current_review,
            accepted=state.accepted,
            iterations=state.iterations,
        )


def build_security_test_planning_crew_runner(config: AppConfig) -> SecurityTestPlanningCrewRunner:
    return CrewAISecurityTestPlanningCrewRunner(config)


class SecurityTestPlanningOrchestrator:
    def __init__(
        self,
        config: AppConfig,
        output_root: Path = Path("report"),
        event_sink: Callable[[Event], None] | None = None,
        crew_runner: SecurityTestPlanningCrewRunner | None = None,
    ) -> None:
        self.config = config
        self.output_root = output_root
        self.event_sink = event_sink
        self.crew_runner = crew_runner or build_security_test_planning_crew_runner(config)
        self.last_run_skipped = False

    def run(self, engagement_id: str) -> Path:
        self.last_run_skipped = False
        return self._run_engagement(engagement_id)

    def _run_engagement(self, engagement_id: str) -> Path:
        engagement = load_engagement(self.output_root, engagement_id)
        report_dir = engagement_plan_dir(self.output_root, engagement.id)
        engagement_root = engagement_dir(self.output_root, engagement.id)
        self.last_run_skipped = False
        if _engagement_plan_is_current(self.output_root, engagement, report_dir):
            self.last_run_skipped = True
            return report_dir
        memory = FileMemory(report_dir, event_sink=self.event_sink)
        agent_definitions = security_test_planning_agent_definitions(self.config)
        latest_discovered_at = _latest_engagement_discovery_timestamp(self.output_root, engagement)
        memory.record_event(
            "orchestrator",
            "start",
            "Starting security test planning crew",
            {
                "target": engagement.id,
                "engagement": engagement.id,
                "latest_discovered_at": latest_discovered_at,
                "agents": [agent.to_dict() for agent in agent_definitions],
            },
        )
        result = self.crew_runner.run_engagement(self.output_root, engagement.id, report_dir, memory)
        engagement_path = engagement_root / "engagement_template.yaml"
        if not engagement_path.exists():
            target_url, source = _engagement_primary_targets(engagement)
            engagement_template = write_engagement_template_mapping(
                engagement_root,
                _build_planning_engagement_template(target_url, source, result.plan),
            )
            memory.record_event(
                "orchestrator",
                "engagement_template_written",
                "Wrote deterministic engagement template",
                {"bytes": len(engagement_template.encode("utf-8"))},
            )
        memory.add_item(
            "engagement_template",
            {
                "path": str(engagement_path),
                "bytes": engagement_path.stat().st_size,
            },
            "orchestrator",
        )
        memory.add_item(
            "plan_run",
            {
                "latest_discovered_at": latest_discovered_at,
                "planned_at": utc_now(),
                "plan_path": str(report_dir / "plan.md"),
                "links_path": str(report_dir / "links.json"),
            },
            "orchestrator",
        )
        memory.record_event(
            "orchestrator",
            "complete",
            "Security test planning crew completed",
            {"report_dir": str(report_dir), "engagement": engagement.id},
        )
        return report_dir


def load_discovery_context(discovery_dir: Path) -> dict[str, Any]:
    if not discovery_dir.exists():
        raise FileNotFoundError(f"Discovery output not found: {discovery_dir}")
    memory = _read_json(discovery_dir / "memory.json", [])
    return {
        "schema": "mosh.live-discovery-planning-context.v1",
        "report_markdown": _truncate_text(_read_text(discovery_dir / "report.md"), DISCOVERY_REPORT_MAX_CHARS),
        "summary": _compact_value(_latest_memory_item(memory, "summary")),
        "structured_report": _latest_structured_report(memory),
        "robots": _compact_value(_latest_memory_item(memory, "robots")),
        "crawled_pages": _compact_crawled_pages(memory),
        "discovery_candidates": _compact_discovery_candidates(memory),
        "out_of_scope": _compact_memory_urls(memory, "out_of_scope", "urls", LIVE_CONTEXT_MAX_OUT_OF_SCOPE),
        "failed_requests": _compact_memory_urls(memory, "failed_requests", "requests", LIVE_CONTEXT_MAX_FAILED_REQUESTS),
        "context_limits": {
            "events_omitted": True,
            "raw_memory_omitted": True,
            "inline_scripts_omitted": True,
            "max_report_chars": DISCOVERY_REPORT_MAX_CHARS,
            "max_pages": LIVE_CONTEXT_MAX_PAGES,
            "max_links_per_page": LIVE_CONTEXT_MAX_LINKS_PER_PAGE,
            "max_references_per_page": LIVE_CONTEXT_MAX_REFERENCES_PER_PAGE,
            "max_forms_per_page": LIVE_CONTEXT_MAX_FORMS_PER_PAGE,
            "max_candidates": LIVE_CONTEXT_MAX_CANDIDATES,
            "max_nested_text_chars": COMPACT_TEXT_MAX_CHARS,
            "max_nested_list_items": COMPACT_LIST_MAX_ITEMS,
        },
    }


def load_discovery_source_context(discovery_source_dir: Path) -> dict[str, Any]:
    if not discovery_source_dir.exists():
        raise FileNotFoundError(f"Source discovery output not found: {discovery_source_dir}")
    memory = _read_json(discovery_source_dir / "memory.json", [])
    source_index = _latest_memory_item(memory, "source_index")
    source_index_mapping = source_index if isinstance(source_index, dict) else {}
    return {
        "schema": "mosh.discovery-source-planning-context.v1",
        "report_markdown": _truncate_text(_read_text(discovery_source_dir / "report.md"), DISCOVERY_REPORT_MAX_CHARS),
        "source_index": _compact_source_index(source_index_mapping),
        "component_map": _compact_value(_latest_memory_item(memory, "source_component_map")),
        "gap_analysis": _compact_value(_latest_memory_item(memory, "source_gap_analysis")),
        "route_resolution": _compact_value(
            _latest_memory_item(memory, "source_route_resolution") or source_index_mapping.get("route_resolution", {})
        ),
        "structured_report": _latest_structured_report(memory),
        "context_limits": {
            "events_omitted": True,
            "raw_memory_omitted": True,
            "source_files_omitted": True,
            "max_report_chars": DISCOVERY_REPORT_MAX_CHARS,
            "max_routes": SOURCE_CONTEXT_MAX_ROUTES,
            "max_dependencies": SOURCE_CONTEXT_MAX_DEPENDENCIES,
            "max_configuration": SOURCE_CONTEXT_MAX_CONFIG,
            "max_evidence_refs": SOURCE_CONTEXT_MAX_EVIDENCE_REFS,
            "max_nested_text_chars": COMPACT_TEXT_MAX_CHARS,
            "max_nested_list_items": COMPACT_LIST_MAX_ITEMS,
        },
    }


def load_engagement_assessment_evidence_bundle(
    output_root: Path,
    engagement_id: str,
    *,
    evidence_links: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = load_engagement(output_root, engagement_id)
    live_discoveries: list[dict[str, Any]] = []
    source_discoveries: list[dict[str, Any]] = []
    skipped_assets: list[dict[str, str]] = []
    for asset in engagement.assets:
        discovery_dir = asset_discovery_dir(output_root, engagement.id, asset.id)
        if asset.type == "live_url":
            if discovery_dir.exists():
                live_discoveries.append(
                    {
                        "asset_id": asset.id,
                        "discovery": load_discovery_context(discovery_dir),
                    }
                )
            else:
                skipped_assets.append({"id": asset.id, "type": asset.type, "reason": "missing discovery output"})
        elif asset.type == "source_tree":
            if discovery_dir.exists():
                source_discoveries.append(
                    {
                        "asset_id": asset.id,
                        "discovery": load_discovery_source_context(discovery_dir),
                    }
                )
            else:
                skipped_assets.append({"id": asset.id, "type": asset.type, "reason": "missing discovery output"})
        else:
            skipped_assets.append({"id": asset.id, "type": asset.type, "reason": "unsupported for planning"})
    if not live_discoveries and not source_discoveries:
        raise FileNotFoundError(f"No discovery output found for engagement: {engagement.id}")
    bundle = {
        "schema": "mosh.assessment-evidence-bundle.v1",
        "engagement": {
            "id": engagement.id,
            "title": engagement.title,
            "asset_refs": [{"id": asset.id, "type": asset.type} for asset in engagement.assets],
        },
        "discovery_live": _primary_asset_discovery_marker(live_discoveries),
        "discovery_source": _primary_asset_discovery_marker(source_discoveries),
        "asset_evidence": {
            "live": live_discoveries,
            "source": source_discoveries,
            "skipped": skipped_assets,
        },
        "correlation": {"evidence_links": evidence_links or {}},
        "prior_testing_feedback": {},
        "prior_source_testing_feedback": {},
    }
    bundle["execution_capabilities"] = _planning_execution_capabilities(
        has_live=bool(live_discoveries),
        has_source=bool(source_discoveries),
    )
    return bundle


def _planning_execution_capabilities(*, has_live: bool, has_source: bool) -> dict[str, Any]:
    return {
        "source": {
            "available": has_source,
            "tools": [
                "read_source_slice",
                "source_search",
                "write_workspace_file",
                "run_source_command",
                "start_source_process",
                "request_local_http",
                "stop_source_process",
            ]
            if has_source
            else [],
            "can_execute_when_available": [
                "bounded source file reads and cross-file searches",
                "manual route, middleware, configuration, prompt, and authorization-flow inspection",
                "small generated harnesses, framework-introspection scripts, and dependency checks in /work",
                "local source-derived services and localhost-only HTTP checks when build/run instructions are available",
            ]
            if has_source
            else [],
        },
        "live": {
            "available": has_live,
            "can_execute_when_available": [
                "safe scoped HTTP checks against already discovered or explicitly mapped targets",
                "source-guided live verification when credentials, authorization, and safe test data are satisfied",
            ]
            if has_live
            else [],
        },
        "planning_rules": [
            "Do not defer work solely because source inspection, source search, manual grep, route extraction, or prompt extraction is needed when source is available.",
            "Discovery extractor limitations are not execution blockers if bounded source-testing tools can resolve the gap.",
            "Prefer active hypotheses for in-scope tests when the attached assets and targets make the work specific and bounded, even if credentials or safe test data will be checked later by execution preflight.",
            "Represent normal execution readiness as requirements, preconditions, safety notes, and depends_on entries; defer only the portion that cannot yet be made specific, safe, or authorised enough to plan.",
            "Plan the source-executable portion as an active source hypothesis; keep only the genuinely absent asset, unsupported capability, out-of-scope, mobile-binary, or external-service portion deferred.",
        ],
    }


def _planning_review_context(assessment_context: dict[str, Any]) -> dict[str, Any]:
    context: dict[str, Any] = {
        "schema": "mosh.security-planning-review-context.v1",
        "source_available": _assessment_has_source(assessment_context),
        "live_available": _assessment_has_live(assessment_context),
        "execution_capabilities": assessment_context.get("execution_capabilities", {}),
    }
    engagement = assessment_context.get("engagement")
    if isinstance(engagement, dict):
        context["engagement"] = {
            "id": engagement.get("id"),
            "asset_refs": engagement.get("asset_refs"),
        }
    return context


def _latest_structured_report(memory: Any) -> dict[str, Any]:
    report = _latest_memory_item(memory, "llm_report")
    if isinstance(report, dict) and isinstance(report.get("structured"), dict):
        return _compact_mapping(report["structured"])
    return {}


def _compact_crawled_pages(memory: Any) -> list[dict[str, Any]]:
    pages = [
        item.get("content")
        for item in _list(memory)
        if isinstance(item, dict) and item.get("kind") == "crawled_page" and isinstance(item.get("content"), dict)
    ]
    compact_pages = []
    for page in pages[:LIVE_CONTEXT_MAX_PAGES]:
        compact_pages.append(
            {
                "url": _compact_value(page.get("url")),
                "status": page.get("status"),
                "content_type": _compact_value(page.get("content_type")),
                "title": _compact_value(page.get("title")),
                "headers": _security_relevant_headers(page.get("headers")),
                "links": _limit_items(page.get("links"), LIVE_CONTEXT_MAX_LINKS_PER_PAGE),
                "references": _limit_items(page.get("references"), LIVE_CONTEXT_MAX_REFERENCES_PER_PAGE),
                "forms": _limit_items(page.get("forms"), LIVE_CONTEXT_MAX_FORMS_PER_PAGE),
            }
        )
    return compact_pages


def _compact_discovery_candidates(memory: Any) -> list[dict[str, Any]]:
    candidates = [
        item.get("content")
        for item in _list(memory)
        if isinstance(item, dict)
        and item.get("kind") == "discovery_candidate"
        and isinstance(item.get("content"), dict)
    ]
    compact_candidates = []
    for candidate in candidates[:LIVE_CONTEXT_MAX_CANDIDATES]:
        compact_candidates.append(
            {
                "url": _compact_value(candidate.get("url")),
                "source_tool": _compact_value(candidate.get("source_tool")),
                "status": candidate.get("status"),
                "kind": _compact_value(candidate.get("kind")),
                "confidence": candidate.get("confidence"),
                "reason": _compact_value(candidate.get("reason")),
                "evidence": _limit_items(candidate.get("evidence"), 10),
                "should_crawl": candidate.get("should_crawl"),
            }
        )
    return compact_candidates


def _compact_memory_urls(memory: Any, kind: str, key: str, limit: int) -> list[Any]:
    content = _latest_memory_item(memory, kind)
    if not isinstance(content, dict):
        return []
    return _limit_items(content.get(key), limit)


def _security_relevant_headers(headers: Any) -> dict[str, Any]:
    if not isinstance(headers, dict):
        return {}
    relevant = {}
    names = {
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "set-cookie",
        "server",
        "x-powered-by",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "www-authenticate",
        "location",
    }
    for key, value in headers.items():
        if str(key).lower() in names:
            relevant[str(key)] = _compact_value(value)
    return relevant


def _compact_source_index(source_index: Any) -> dict[str, Any]:
    if not isinstance(source_index, dict):
        return {}
    inventory = source_index.get("inventory") if isinstance(source_index.get("inventory"), dict) else {}
    compact = {
        "schema": source_index.get("schema"),
        "source": source_index.get("source"),
        "summary": source_index.get("summary"),
        "inventory": {
            "apps": _limit_items(inventory.get("apps"), SOURCE_CONTEXT_MAX_APPS),
            "languages": inventory.get("languages"),
            "frameworks": _limit_items(inventory.get("frameworks"), SOURCE_CONTEXT_MAX_SECURITY_ITEMS),
            "entrypoints": _limit_items(inventory.get("entrypoints"), SOURCE_CONTEXT_MAX_ENTRYPOINTS),
            "routes": _limit_items(inventory.get("routes"), SOURCE_CONTEXT_MAX_ROUTES),
            "apis": _limit_items(inventory.get("apis"), SOURCE_CONTEXT_MAX_ROUTES),
            "auth": _limit_items(inventory.get("auth"), SOURCE_CONTEXT_MAX_SECURITY_ITEMS),
            "sessions": _limit_items(inventory.get("sessions"), SOURCE_CONTEXT_MAX_SECURITY_ITEMS),
            "data_stores": _limit_items(inventory.get("data_stores"), SOURCE_CONTEXT_MAX_SECURITY_ITEMS),
            "dependencies": _limit_items(inventory.get("dependencies"), SOURCE_CONTEXT_MAX_DEPENDENCIES),
            "configuration": _limit_items(inventory.get("configuration"), SOURCE_CONTEXT_MAX_CONFIG),
            "environment_variables": _limit_items(inventory.get("environment_variables"), SOURCE_CONTEXT_MAX_CONFIG),
            "compose_topology": _limit_items(inventory.get("compose_topology"), SOURCE_CONTEXT_MAX_SECURITY_ITEMS),
        },
        "evidence_refs": _limit_items(source_index.get("evidence_refs"), SOURCE_CONTEXT_MAX_EVIDENCE_REFS),
        "route_resolution": source_index.get("route_resolution"),
        "component_map": source_index.get("component_map"),
        "gap_analysis": source_index.get("gap_analysis"),
        "context_limits": {
            "files_omitted": True,
            "max_apps": SOURCE_CONTEXT_MAX_APPS,
            "max_entrypoints": SOURCE_CONTEXT_MAX_ENTRYPOINTS,
            "max_routes": SOURCE_CONTEXT_MAX_ROUTES,
            "max_dependencies": SOURCE_CONTEXT_MAX_DEPENDENCIES,
            "max_configuration": SOURCE_CONTEXT_MAX_CONFIG,
            "max_evidence_refs": SOURCE_CONTEXT_MAX_EVIDENCE_REFS,
        },
    }
    return _compact_mapping(compact)


def _primary_asset_discovery_marker(discoveries: list[dict[str, Any]]) -> dict[str, Any]:
    if not discoveries:
        return {}
    primary = discoveries[0]
    discovery = primary.get("discovery") if isinstance(primary.get("discovery"), dict) else {}
    marker: dict[str, Any] = {
        "available": True,
        "primary_asset_id": primary.get("asset_id"),
        "details": "See asset_evidence for compact per-asset discovery details.",
    }
    if isinstance(discovery.get("summary"), dict):
        marker["summary"] = discovery["summary"]
    source_index = discovery.get("source_index") if isinstance(discovery.get("source_index"), dict) else {}
    if isinstance(source_index.get("summary"), dict):
        marker["source_summary"] = source_index["summary"]
    return marker


def _truncate_text(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[:max_chars].rstrip() + f"\n\n[mosh: truncated to {max_chars} characters for planning context]\n"


def _limit_items(value: Any, limit: int) -> list[Any]:
    return [_compact_value(item) for item in _list(value)[: max(limit, 0)]]


def _compact_mapping(value: dict[str, Any], *, depth: int = 0) -> dict[str, Any]:
    if depth >= COMPACT_VALUE_MAX_DEPTH:
        return {"_omitted": "nested value exceeded planning context depth limit"}
    compact: dict[str, Any] = {}
    for index, (key, item) in enumerate(value.items()):
        if index >= COMPACT_MAPPING_MAX_ITEMS:
            compact["_omitted_keys"] = len(value) - COMPACT_MAPPING_MAX_ITEMS
            break
        if item not in (None, [], {}):
            compact[str(key)] = _compact_value(item, depth=depth + 1)
    return compact


def _compact_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= COMPACT_VALUE_MAX_DEPTH:
        return "[mosh: omitted nested value beyond planning context depth limit]"
    if isinstance(value, dict):
        return _compact_mapping(value, depth=depth + 1)
    if isinstance(value, list):
        compact = [_compact_value(item, depth=depth + 1) for item in value[:COMPACT_LIST_MAX_ITEMS]]
        if len(value) > COMPACT_LIST_MAX_ITEMS:
            compact.append({"_omitted_items": len(value) - COMPACT_LIST_MAX_ITEMS})
        return compact
    if isinstance(value, str):
        return _truncate_text(value, COMPACT_TEXT_MAX_CHARS)
    return value


def run_planning_evidence_linking(
    config: AppConfig,
    output_root: Path,
    engagement_id: str,
    *,
    memory: FileMemory | None = None,
) -> EvidenceLinkResult:
    current = load_evidence_links_if_current(output_root, engagement_id)
    if current is not None:
        if memory is not None:
            memory.add_item(
                "evidence_links",
                {
                    "path": str(current.links_path),
                    "links": len(current.payload.get("links") or []),
                    "pairs": len(current.payload.get("pairs") or []),
                    "reused": True,
                },
                "evidence_linker",
            )
            memory.record_event(
                "evidence_linker",
                "skipped_current",
                "Evidence links are current; reusing existing links.json",
                {
                    "path": str(current.links_path),
                    "links": len(current.payload.get("links") or []),
                },
            )
        return current
    if memory is not None:
        memory.record_event(
            "evidence_linker",
            "start",
            "Starting evidence linking as the first planning stage",
            {"engagement": engagement_id},
        )
    result = build_evidence_links(
        output_root,
        engagement_id,
        model_assisted_linker=build_model_assisted_linker(config, memory=memory),
    )
    if memory is not None:
        memory.add_item(
            "evidence_links",
            {
                "path": str(result.links_path),
                "links": len(result.payload.get("links") or []),
                "pairs": len(result.payload.get("pairs") or []),
            },
            "evidence_linker",
        )
        memory.record_event(
            "evidence_linker",
            "complete",
            "Evidence linking completed",
            {
                "path": str(result.links_path),
                "links": len(result.payload.get("links") or []),
            },
        )
    return result


def _latest_memory_item(memory: Any, kind: str) -> Any:
    if not isinstance(memory, list):
        return {}
    for item in reversed(memory):
        if isinstance(item, dict) and item.get("kind") == kind:
            return item.get("content") if isinstance(item.get("content"), dict) else item.get("content")
    return {}


def _engagement_plan_is_current(output_root: Path, engagement: Engagement, report_dir: Path) -> bool:
    latest_discovered_at = _latest_engagement_discovery_timestamp(output_root, engagement)
    if not latest_discovered_at:
        return False
    if (
        not (report_dir / "plan.md").exists()
        or not (report_dir / "links.json").exists()
        or not (engagement_dir(output_root, engagement.id) / "engagement_template.yaml").exists()
    ):
        return False
    if load_evidence_links_if_current(output_root, engagement.id) is None:
        return False
    latest_discovered = _parse_timestamp(latest_discovered_at)
    previous_discovered = _parse_timestamp(_latest_plan_discovery_timestamp(report_dir))
    if latest_discovered is None or previous_discovered is None:
        return False
    return previous_discovered >= latest_discovered


def _engagement_template_dir(state: SecurityTestPlanningState) -> Path:
    return state.engagement_template_dir or state.report_dir


def _latest_plan_discovery_timestamp(report_dir: Path) -> str | None:
    memory = _read_json(report_dir / "memory.json", [])
    if not isinstance(memory, list):
        return None
    for item in reversed(memory):
        if not isinstance(item, dict) or item.get("kind") != "plan_run":
            continue
        content = item.get("content")
        if isinstance(content, dict) and isinstance(content.get("latest_discovered_at"), str):
            return content["latest_discovered_at"]
    return None


def _latest_engagement_discovery_timestamp(output_root: Path, engagement: Engagement) -> str | None:
    timestamps: list[datetime] = []
    for asset in engagement.assets:
        discovery = asset.metadata.get("discovery") if isinstance(asset.metadata, dict) else None
        discovered_at = discovery.get("last_discovered_at") if isinstance(discovery, dict) else None
        parsed = _parse_timestamp(discovered_at) if isinstance(discovered_at, str) else None
        if parsed is not None:
            timestamps.append(parsed)
            continue
        artifact_timestamp = _latest_discovery_artifact_timestamp(output_root, engagement.id, asset.id)
        if artifact_timestamp is not None:
            timestamps.append(artifact_timestamp)
    if not timestamps:
        return None
    return max(timestamps).isoformat()


def _latest_discovery_artifact_timestamp(output_root: Path, engagement_id: str, asset_id: str) -> datetime | None:
    discovery_dir = asset_discovery_dir(output_root, engagement_id, asset_id)
    candidates = [discovery_dir / "report.md", discovery_dir / "memory.json", discovery_dir / "events.json"]
    mtimes = [path.stat().st_mtime for path in candidates if path.exists()]
    if not mtimes:
        return None
    return datetime.fromtimestamp(max(mtimes), timezone.utc)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _engagement_primary_targets(engagement: Engagement) -> tuple[str, str | None]:
    live = next((asset.locator for asset in engagement.assets if asset.type == "live_url"), "")
    source = next((asset.locator for asset in engagement.assets if asset.type == "source_tree"), None)
    if live:
        return live, source
    if source:
        return f"source:{source}", source
    return engagement.id, None


def _first_asset_discovery_dir(output_root: Path, engagement: Engagement, asset_type: str) -> Path | None:
    asset: EngagementAsset | None = next((item for item in engagement.assets if item.type == asset_type), None)
    if asset is None:
        return None
    return asset_discovery_dir(output_root, engagement.id, asset.id)


def _build_planning_engagement_template(target_url: str, source: str | None, plan: dict[str, Any]) -> dict[str, Any]:
    if target_url and not target_url.startswith("source:"):
        return build_engagement_template(target_url, plan)
    source_target = source or target_url.removeprefix("source:") or "source"
    return {
        "engagement": {
            "authorization_confirmed": True,
            "active_testing_allowed": False,
            "state_changing_tests_allowed": False,
            "notes": "Source-only planning template. Live execution targets are not configured.",
        },
        "targets": {
            "production": {"source": source_target},
            "alternative": {"source": None},
        },
        "contacts": {"escalation": {"name": None, "email": None, "phone": None}},
        "limits": {
            "max_requests_per_test": 0,
            "max_rate_per_second": 0,
            "stop_on_sensitive_data": True,
            "evidence_redaction": True,
        },
        "credentials": {"authenticated_user": {"username": None, "password": None, "token": None}},
        "safe_test_data": {
            "marker_prefix": "SECTEST-DO-NOT-PROCESS",
            "email": None,
            "phone": None,
            "company": None,
            "customer_ids": [],
            "enterprise_account_ids": [],
            "activation_codes": [],
            "callback_listener_url": None,
        },
    }


def _build_planning_planner_crew(crewai: Any, config: AppConfig, state: SecurityTestPlanningState):
    plan_tool = _build_submit_plan_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/planner_agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/planner_tasks.yaml"))

    @crewai.CrewBase
    class SecurityTestPlanningPlannerCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def planner(self):
            return crewai.Agent(
                config=self.agents_config["planner"],
                llm=_llm(crewai, config, config.models.planning.planner),
                tools=[plan_tool],
                allow_delegation=False,
            )

        @crewai.task
        def draft_security_test_plan_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["draft_security_test_plan_task"],
                agent=self.planner(),
                agent_name="planner",
                task_name="draft_security_test_plan_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.planner()],
                tasks=[self.draft_security_test_plan_task()],
                process=crewai.Process.sequential,
                verbose=True,
                event_listeners=[MoshCrewAIEventListener(state.memory)],
            )

    return SecurityTestPlanningPlannerCrew()


def _build_planning_critic_crew(crewai: Any, config: AppConfig, state: SecurityTestPlanningState):
    critique_tool = _build_submit_critique_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/critic_agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/critic_tasks.yaml"))

    @crewai.CrewBase
    class SecurityTestPlanningCriticCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def reviewer(self):
            return crewai.Agent(
                config=self.agents_config["reviewer"],
                llm=_llm(crewai, config, config.models.planning.reviewer),
                tools=[critique_tool],
                allow_delegation=False,
            )

        @crewai.task
        def critique_security_test_plan_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["critique_security_test_plan_task"],
                agent=self.reviewer(),
                agent_name="reviewer",
                task_name="critique_security_test_plan_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.reviewer()],
                tasks=[self.critique_security_test_plan_task()],
                process=crewai.Process.sequential,
                verbose=True,
                event_listeners=[MoshCrewAIEventListener(state.memory)],
            )

    return SecurityTestPlanningCriticCrew()


def _build_planning_reporter_crew(crewai: Any, config: AppConfig, state: SecurityTestPlanningState):
    write_tool = _build_write_security_test_plan_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/reporter_agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/reporter_tasks.yaml"))

    @crewai.CrewBase
    class SecurityTestPlanningReporterCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def reporter(self):
            return crewai.Agent(
                config=self.agents_config["reporter"],
                llm=_llm(crewai, config, config.models.planning.reporter),
                tools=[write_tool],
                allow_delegation=False,
            )

        @crewai.task
        def write_security_test_plan_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["write_security_test_plan_task"],
                agent=self.reporter(),
                agent_name="reporter",
                task_name="write_security_test_plan_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.reporter()],
                tasks=[self.write_security_test_plan_task()],
                process=crewai.Process.sequential,
                verbose=True,
                event_listeners=[MoshCrewAIEventListener(state.memory)],
            )

    return SecurityTestPlanningReporterCrew()


def _build_engagement_template_refinement_crew(
    crewai: Any,
    config: AppConfig,
    state: SecurityTestPlanningState,
    deterministic_template: dict[str, Any],
):
    write_tool = _build_write_refined_engagement_template_tool(crewai, state, deterministic_template)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/engagement_refiner_agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/engagement_refiner_tasks.yaml"))

    @crewai.CrewBase
    class EngagementTemplateRefinementCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def engagement_refiner(self):
            return crewai.Agent(
                config=self.agents_config["engagement_refiner"],
                llm=_llm(crewai, config, config.models.planning.engagement_refiner),
                tools=[write_tool],
                allow_delegation=False,
            )

        @crewai.task
        def refine_engagement_template_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["refine_engagement_template_task"],
                agent=self.engagement_refiner(),
                agent_name="engagement_refiner",
                task_name="refine_engagement_template_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.engagement_refiner()],
                tasks=[self.refine_engagement_template_task()],
                process=crewai.Process.sequential,
                verbose=True,
                event_listeners=[MoshCrewAIEventListener(state.memory)],
            )

    return EngagementTemplateRefinementCrew()


def _build_submit_plan_tool(crewai: Any, state: SecurityTestPlanningState):
    class SubmitPlanInput(crewai.BaseModel):
        plan: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured security test plan. Prefer a JSON object; a JSON string is accepted.",
        )

    class SubmitSecurityTestPlanTool(crewai.BaseTool):
        name: str = "submit_security_test_plan"
        description: str = "Submit the planner's structured security test hypotheses for critic review."
        args_schema: type[crewai.BaseModel] = SubmitPlanInput

        def _run(self, plan: Any) -> str:
            plan_content = _normalize_security_test_plan(_coerce_mapping(plan), state.discovery_context)
            state.current_plan = plan_content
            state.memory.add_item(
                "security_test_plan_draft",
                {"iteration": state.iterations, "structured": plan_content},
                "planner",
            )
            state.memory.record_event(
                "planner",
                "plan_submitted",
                "Security test planner submitted draft plan",
                {
                    "iteration": state.iterations,
                    "hypotheses": len(_list(plan_content.get("test_hypotheses"))),
                    "keys": sorted(plan_content.keys()),
                },
            )
            return json.dumps(
                {
                    "accepted": True,
                    "iteration": state.iterations,
                    "hypotheses": len(_list(plan_content.get("test_hypotheses"))),
                },
                sort_keys=True,
            )

    return SubmitSecurityTestPlanTool()


def _build_submit_critique_tool(crewai: Any, state: SecurityTestPlanningState):
    class SubmitCritiqueInput(crewai.BaseModel):
        review: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured critic review with accepted, summary, blocking_findings, and suggestions.",
        )

    class SubmitSecurityTestPlanCritiqueTool(crewai.BaseTool):
        name: str = "submit_security_test_plan_critique"
        description: str = "Submit the critic's structured review of the current security test plan."
        args_schema: type[crewai.BaseModel] = SubmitCritiqueInput

        def _run(self, review: Any) -> str:
            review_content = _coerce_mapping(review)
            review_content.setdefault("accepted", False)
            review_content = _apply_deterministic_review_guards(
                review_content,
                state.current_plan or {},
                state.discovery_context,
            )
            state.current_review = review_content
            state.memory.add_item(
                "security_test_plan_critique",
                {"iteration": state.iterations, "structured": review_content},
                "reviewer",
            )
            state.memory.record_event(
                "reviewer",
                "critique_submitted",
                "Security test critic submitted plan review",
                {
                    "iteration": state.iterations,
                    "accepted": bool(review_content.get("accepted")),
                    "blocking_findings": len(_list(review_content.get("blocking_findings"))),
                },
            )
            return json.dumps(
                {
                    "accepted": bool(review_content.get("accepted")),
                    "iteration": state.iterations,
                    "blocking_findings": len(_list(review_content.get("blocking_findings"))),
                },
                sort_keys=True,
            )

    return SubmitSecurityTestPlanCritiqueTool()


def _apply_deterministic_review_guards(
    review: dict[str, Any],
    plan: dict[str, Any],
    assessment_context: dict[str, Any],
) -> dict[str, Any]:
    guard_findings = _source_actionable_deferred_findings(plan, assessment_context)
    if not guard_findings:
        return review

    guarded = dict(review)
    blocking_findings = [item for item in _list(guarded.get("blocking_findings")) if isinstance(item, dict)]
    existing_ids = {_text(item.get("id")) for item in blocking_findings}
    for finding in guard_findings:
        if _text(finding.get("id")) not in existing_ids:
            blocking_findings.append(finding)
    guarded["blocking_findings"] = blocking_findings
    guarded["accepted"] = False
    summary = _text(guarded.get("summary"))
    guard_summary = (
        "Deterministic planning guard found deferred work that is executable with the attached source "
        "and source-testing tools; the planner must move the source-executable portion into active hypotheses."
    )
    guarded["summary"] = f"{summary} {guard_summary}".strip() if summary else guard_summary
    return guarded


def _source_actionable_deferred_findings(
    plan: dict[str, Any],
    assessment_context: dict[str, Any],
) -> list[dict[str, Any]]:
    if not _assessment_has_source(assessment_context):
        return []
    findings: list[dict[str, Any]] = []
    for index, opportunity in enumerate(_list(plan.get("deferred_test_opportunities")), start=1):
        if not isinstance(opportunity, dict):
            continue
        if not _deferred_opportunity_is_source_actionable(opportunity):
            continue
        title = _text(opportunity.get("title")) or f"Deferred opportunity {index}"
        findings.append(
            {
                "id": f"SOURCE-DEFER-{index:03d}",
                "severity": "blocking",
                "issue": (
                    f"Deferred opportunity `{title}` appears executable with the attached source asset. "
                    "Its defer reason or suggested next step asks for bounded source inspection/search/manual "
                    "extraction, which the source testing crew can perform."
                ),
                "required_change": (
                    "Move the source-executable portion into test_hypotheses with execution_mode `source` "
                    "when the immediate work is source-only, or `combined` only when the same executable test "
                    "must use both live and source evidence. Use source_assessment_type such as "
                    "`static-source-inspection`, `generated-harness`, or `local-runtime-service`, populate "
                    "affected_source, and keep only genuinely absent asset, unsupported capability, "
                    "out-of-scope, mobile-binary, deployment, or external-service work in "
                    "deferred_test_opportunities."
                ),
            }
        )
    return findings


def _deferred_opportunity_is_source_actionable(opportunity: dict[str, Any]) -> bool:
    action_text = " ".join(
        _text(opportunity.get(key))
        for key in ("defer_reason", "requirements_to_proceed", "suggested_next_step")
    ).lower()
    if not action_text:
        return False
    if _has_hard_defer_blocker(action_text):
        return False
    source_actions = (
        "source inspection",
        "source-inspect",
        "source access",
        "source analysis",
        "manual extraction",
        "manually extract",
        "grep",
        "route decorator",
        "read source",
        "inspect ",
        "review ",
        "extract ",
    )
    has_source_action = any(marker in action_text for marker in source_actions)
    has_source_file = any(suffix in action_text for suffix in (".js", ".ts", ".py", ".kt", ".swift", ".java", ".go", ".rb", ".php"))
    return has_source_action and has_source_file


def _has_hard_defer_blocker(text: str) -> bool:
    hard_blockers = (
        "apk",
        "ipa",
        "app store",
        "google play",
        "decompil",
        "emulator",
        "simulator",
        "physical device",
        "jailbroken",
        "jailbreak",
        "mobile app security testing",
        "production data",
        "external account",
        "apple developer account",
        "google play console",
        "app store connect",
        "missing live url",
        "missing source",
        "not attached",
    )
    return any(blocker in text for blocker in hard_blockers)


def _build_write_security_test_plan_tool(crewai: Any, state: SecurityTestPlanningState):
    class WritePlanInput(crewai.BaseModel):
        plan: dict[str, Any] | str = crewai.Field(..., description="Final structured security test plan.")
        critic_review: dict[str, Any] | str | None = crewai.Field(default=None, description="Final critic review.")

    class WriteSecurityTestPlanTool(crewai.BaseTool):
        name: str = "write_security_test_plan"
        description: str = "Persist the final security test plan as stable Markdown."
        args_schema: type[crewai.BaseModel] = WritePlanInput

        def _run(self, plan: Any, critic_review: Any = None) -> str:
            plan_content = _normalize_security_test_plan(
                _prefer_structured_mapping(_coerce_mapping(plan), state.current_plan),
                state.discovery_context,
            )
            review_content = (
                _prefer_structured_mapping(_coerce_mapping(critic_review), state.current_review)
                if critic_review is not None
                else state.current_review
            )
            state.current_plan = plan_content
            state.current_review = review_content
            markdown = write_security_test_plan(
                state.report_dir,
                state.target_url,
                plan_content,
                review_content,
                accepted=state.accepted,
                iterations=state.iterations,
            )
            state.memory.add_item(
                "security_test_plan_final",
                {
                    "accepted": state.accepted,
                    "iterations": state.iterations,
                    "structured": plan_content,
                    "critic_review": review_content,
                },
                "reporter",
            )
            state.memory.record_event(
                "reporter",
                "plan_written",
                "Security test reporter wrote Markdown plan",
                {
                    "report_dir": str(state.report_dir),
                    "accepted": state.accepted,
                    "iterations": state.iterations,
                    "markdown_bytes": len(markdown.encode("utf-8")),
                },
            )
            return json.dumps(
                {
                    "report_dir": str(state.report_dir),
                    "accepted": state.accepted,
                    "iterations": state.iterations,
                    "markdown_bytes": len(markdown.encode("utf-8")),
                },
                sort_keys=True,
            )

    return WriteSecurityTestPlanTool()


def _build_write_refined_engagement_template_tool(
    crewai: Any,
    state: SecurityTestPlanningState,
    deterministic_template: dict[str, Any],
):
    class WriteEngagementTemplateInput(crewai.BaseModel):
        template: dict[str, Any] | str = crewai.Field(
            ...,
            description="Refined engagement template. Prefer a JSON object; a JSON string is accepted.",
        )

    class WriteRefinedEngagementTemplateTool(crewai.BaseTool):
        name: str = "write_refined_engagement_template"
        description: str = "Persist a validated engagement_template.yaml for security test execution."
        args_schema: type[crewai.BaseModel] = WriteEngagementTemplateInput

        def _run(self, template: Any) -> str:
            candidate = _coerce_mapping(template)
            template_dir = _engagement_template_dir(state)
            fallback_used = False
            try:
                engagement_template = write_engagement_template_mapping(template_dir, candidate)
            except ValueError as exc:
                fallback_used = True
                engagement_template = write_engagement_template_mapping(template_dir, deterministic_template)
                state.memory.record_event(
                    "engagement_refiner",
                    "refinement_rejected",
                    "Refined engagement template was invalid; wrote deterministic fallback",
                    {"error": str(exc), "path": str(template_dir / "engagement_template.yaml")},
                )
            state.memory.add_item(
                "engagement_template_refinement",
                {
                    "path": str(template_dir / "engagement_template.yaml"),
                    "bytes": len(engagement_template.encode("utf-8")),
                    "fallback_used": fallback_used,
                },
                "engagement_refiner",
            )
            state.memory.record_event(
                "engagement_refiner",
                "engagement_template_written",
                "Engagement template refiner wrote engagement_template.yaml",
                {
                    "path": str(template_dir / "engagement_template.yaml"),
                    "bytes": len(engagement_template.encode("utf-8")),
                    "fallback_used": fallback_used,
                },
            )
            return json.dumps(
                {
                    "path": str(template_dir / "engagement_template.yaml"),
                    "bytes": len(engagement_template.encode("utf-8")),
                    "fallback_used": fallback_used,
                },
                sort_keys=True,
            )

    return WriteRefinedEngagementTemplateTool()


def _read_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _coerce_mapping(value: Any | None) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        return dumped if isinstance(dumped, dict) else {"content": dumped}
    if hasattr(value, "dict"):
        dumped = value.dict()
        return dumped if isinstance(dumped, dict) else {"content": dumped}
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"content": value}
        return parsed if isinstance(parsed, dict) else {"content": parsed}
    return {"content": value}


def _prefer_structured_mapping(candidate: dict[str, Any], fallback: dict[str, Any] | None) -> dict[str, Any]:
    if candidate and not _is_content_only_mapping(candidate):
        return candidate
    return fallback or candidate or {}


def _normalize_security_test_plan(plan: dict[str, Any], assessment_context: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(plan)
    default_mode = _default_execution_mode(assessment_context)
    source_only = _is_source_only_assessment(assessment_context)
    hypotheses = []
    for item in _list(normalized.get("test_hypotheses")):
        if not isinstance(item, dict):
            continue
        hypothesis = dict(item)
        requested_mode = _normalized_execution_mode(hypothesis.get("execution_mode"), default_mode)
        mode_was_downgraded = False
        if source_only and requested_mode in {"live", "combined"}:
            requested_mode = "deferred"
            mode_was_downgraded = True
            _append_unique_list_item(
                hypothesis,
                "requirements_to_proceed",
                "Provide a live URL, local runtime target, emulator, simulator, or container target for runtime verification.",
            )
        hypothesis["execution_mode"] = requested_mode
        if source_only:
            hypothesis["evidence_sources"] = _default_evidence_sources(assessment_context)
        else:
            hypothesis.setdefault("evidence_sources", _default_evidence_sources(assessment_context))
        hypothesis.setdefault("affected_runtime", [])
        hypothesis.setdefault("affected_source", _default_affected_source(hypothesis, assessment_context))
        if mode_was_downgraded:
            hypothesis["verification_strategy"] = _default_verification_strategy(hypothesis["execution_mode"])
        else:
            hypothesis.setdefault("verification_strategy", _default_verification_strategy(hypothesis["execution_mode"]))
        hypothesis["source_assessment_type"] = _normalized_source_assessment_type(
            hypothesis.get("source_assessment_type"),
            _default_source_assessment_type(hypothesis),
        )
        hypothesis["depends_on"] = _string_list(hypothesis.get("depends_on"))
        hypothesis["readiness_blockers"] = _normalized_readiness_blockers(hypothesis)
        hypothesis["execution_readiness"] = _normalized_execution_readiness(hypothesis)
        hypotheses.append(hypothesis)
    normalized["test_hypotheses"] = hypotheses
    normalized.setdefault("deferred_test_opportunities", [])
    return normalized


def _default_execution_mode(assessment_context: dict[str, Any]) -> str:
    has_live = _assessment_has_live(assessment_context)
    has_source = _assessment_has_source(assessment_context)
    if has_live and has_source:
        return "combined"
    if has_source:
        return "source"
    return "live"


def _is_source_only_assessment(assessment_context: dict[str, Any]) -> bool:
    return _assessment_has_source(assessment_context) and not _assessment_has_live(assessment_context)


def _assessment_has_source(assessment_context: dict[str, Any]) -> bool:
    source = assessment_context.get("discovery_source")
    if isinstance(source, dict) and source:
        return bool(source.get("available", True))
    asset_evidence = assessment_context.get("asset_evidence") if isinstance(assessment_context.get("asset_evidence"), dict) else {}
    source_assets = asset_evidence.get("source") if isinstance(asset_evidence.get("source"), list) else []
    return any(isinstance(item, dict) and item.get("discovery") for item in source_assets)


def _assessment_has_live(assessment_context: dict[str, Any]) -> bool:
    live = assessment_context.get("discovery_live")
    if isinstance(live, dict) and live:
        return bool(live.get("available", True))
    asset_evidence = assessment_context.get("asset_evidence") if isinstance(assessment_context.get("asset_evidence"), dict) else {}
    live_assets = asset_evidence.get("live") if isinstance(asset_evidence.get("live"), list) else []
    return any(isinstance(item, dict) and item.get("discovery") for item in live_assets)


def _normalized_execution_mode(value: Any, default: str) -> str:
    mode = _text(value).lower()
    return mode if mode in {"live", "source", "combined", "deferred"} else default


def _append_unique_list_item(target: dict[str, Any], key: str, value: str) -> None:
    items = _string_list(target.get(key))
    if value not in items:
        items.append(value)
    target[key] = items


def _default_evidence_sources(assessment_context: dict[str, Any]) -> list[str]:
    sources = []
    if _assessment_has_live(assessment_context):
        sources.append("live")
    if _assessment_has_source(assessment_context):
        sources.append("source")
    return sources or ["live"]


def _default_affected_source(hypothesis: dict[str, Any], assessment_context: dict[str, Any]) -> list[dict[str, Any]]:
    if hypothesis.get("execution_mode") == "live":
        return []
    source = assessment_context.get("discovery_source") if isinstance(assessment_context.get("discovery_source"), dict) else {}
    source_index = source.get("source_index") if isinstance(source.get("source_index"), dict) else {}
    if not source_index:
        asset_evidence = assessment_context.get("asset_evidence") if isinstance(assessment_context.get("asset_evidence"), dict) else {}
        source_assets = asset_evidence.get("source") if isinstance(asset_evidence.get("source"), list) else []
        for asset in source_assets:
            if not isinstance(asset, dict):
                continue
            discovery = asset.get("discovery") if isinstance(asset.get("discovery"), dict) else {}
            source_index = discovery.get("source_index") if isinstance(discovery.get("source_index"), dict) else {}
            if source_index:
                break
    evidence_refs = source_index.get("evidence_refs") if isinstance(source_index.get("evidence_refs"), list) else []
    return [item for item in evidence_refs[:5] if isinstance(item, dict)]


def _default_verification_strategy(execution_mode: str) -> str:
    if execution_mode == "source":
        return "source-inspection"
    if execution_mode == "combined":
        return "source-guided-live-verification"
    if execution_mode == "deferred":
        return "blocked-pending-inputs"
    return "live-verification"


def _normalized_source_assessment_type(value: Any, default: str) -> str:
    assessment_type = _text(value).lower()
    valid = {
        "static-source-inspection",
        "generated-harness",
        "local-runtime-service",
        "dependency-tool-scan",
        "deferred-live-verification",
        "live-verification",
        "source-guided-live-verification",
    }
    return assessment_type if assessment_type in valid else default


def _normalized_execution_readiness(hypothesis: dict[str, Any]) -> str:
    mode = _text(hypothesis.get("execution_mode")).lower()
    if mode == "deferred":
        return "deferred"
    readiness = _text(hypothesis.get("execution_readiness")).lower().replace("-", "_")
    valid = {"ready", "preflight_blocked", "depends_on", "deferred"}
    if readiness in valid:
        return readiness
    if _string_list(hypothesis.get("depends_on")):
        return "depends_on"
    if _normalized_readiness_blockers(hypothesis):
        return "preflight_blocked"
    return "ready"


def _normalized_readiness_blockers(hypothesis: dict[str, Any]) -> list[str]:
    explicit = _string_list(hypothesis.get("readiness_blockers"))
    if explicit:
        return explicit
    blockers: list[str] = []
    readiness_items = [
        item.lower()
        for key in ("requirements", "preconditions", "safety_notes")
        for item in _string_list(hypothesis.get(key))
    ]
    if _has_readiness_marker(readiness_items, ("credential", "test account", "jwt", "token")):
        blockers.append("Credential or test account material must be provided before execution.")
    if _has_readiness_marker(readiness_items, ("authorization", "authorisation", "permission", "approval")):
        blockers.append("Explicit authorization or permission must be confirmed before execution.")
    if _has_readiness_marker(readiness_items, ("safe test data", "synthetic", "test customer", "customer id", "activation code")):
        blockers.append("Safe test data must be provided before execution.")
    if _has_readiness_marker(readiness_items, ("budget", "billing", "cost ceiling", "cost limit")):
        blockers.append("Budget or cost limits must be agreed before execution.")
    return blockers


def _has_readiness_marker(items: list[str], markers: tuple[str, ...]) -> bool:
    negative_markers = (
        "no credentials required",
        "no credential required",
        "no test account required",
        "does not require authentication",
        "no authorization required",
        "no authorisation required",
        "no safe test data required",
        "no budget required",
    )
    for item in items:
        if any(marker in item for marker in negative_markers):
            continue
        if any(marker in item for marker in markers):
            return True
    return False


def _default_source_assessment_type(hypothesis: dict[str, Any]) -> str:
    mode = _text(hypothesis.get("execution_mode")).lower()
    if mode == "live":
        return "live-verification"
    if mode == "combined":
        return "source-guided-live-verification"
    if mode == "deferred":
        return "deferred-live-verification"

    combined_text = " ".join(
        _text(value).lower()
        for value in (
            hypothesis.get("verification_strategy"),
            hypothesis.get("hypothesis"),
            hypothesis.get("tools_expected"),
            hypothesis.get("test_steps"),
            hypothesis.get("preconditions"),
            hypothesis.get("requirements"),
        )
    )
    if any(token in combined_text for token in ("local runtime", "localhost", "start", "service", "http request", "route table")):
        return "local-runtime-service"
    if any(token in combined_text for token in ("harness", "fuzz", "function", "env override", "environment override", "script")):
        return "generated-harness"
    if any(token in combined_text for token in ("semgrep", "bandit", "pip-audit", "dependency", "lockfile", "scanner", "static tool")):
        return "dependency-tool-scan"
    return "static-source-inspection"


def _is_content_only_mapping(value: dict[str, Any]) -> bool:
    return set(value.keys()) == {"content"}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_list(value: Any) -> list[str]:
    return [text for text in (_text(item) for item in _list(value)) if text]


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""
