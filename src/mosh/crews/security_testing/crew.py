from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlparse

from mosh.config import AppConfig
from mosh.crews.discovery.reporting import update_report_with_security_testing_feedback
from mosh.crews.discovery.crew import (
    CREW_CONFIG_PACKAGE,
    CrewAIUnavailable,
    _build_task_with_output_event,
    _llm,
    _load_crewai,
)
from mosh.docker_tools import DockerToolResult, DockerToolRunner
from mosh.engagement import load_engagement_file, resolve_target_mapping
from mosh.memory import FileMemory
from mosh.models import Event, MemoryItem, utc_now
from mosh.scope import report_dir_name, source_report_dir_name


EXECUTION_METADATA_START = "<!-- mosh-execution"
EXECUTION_METADATA_END = "-->"


@dataclass(frozen=True)
class SecurityTestPreflightResult:
    ready: list[dict[str, Any]]
    blocked: list[dict[str, Any]]
    targets: dict[str, str]
    source_ready: list[dict[str, Any]] = field(default_factory=list)
    combined: list[dict[str, Any]] = field(default_factory=list)
    deferred: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SecurityTestExecutionState:
    target_url: str
    report_dir: Path
    workspace_dir: Path
    memory: FileMemory
    hypothesis: dict[str, Any]
    engagement: dict[str, Any]
    targets: dict[str, str]
    executed_report_path: Path
    plan_revision_id: str = ""
    hypothesis_fingerprint: str = ""
    revision: int = 1
    evidence: dict[str, Any] | None = None
    review: dict[str, Any] | None = None
    report_written: bool = False
    commands: list[dict[str, Any]] = field(default_factory=list)
    attempts: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    archived_report_paths: list[str] = field(default_factory=list)


class SecurityTestingCrewRunner(Protocol):
    def run(
        self,
        target_url: str,
        report_dir: Path,
        memory: FileMemory,
        plan: dict[str, Any],
        engagement: dict[str, Any],
        preflight: SecurityTestPreflightResult,
        ready_pending: list[dict[str, Any]],
    ) -> None:
        pass


class SecurityTestingOrchestrator:
    def __init__(
        self,
        config: AppConfig,
        output_root: Path = Path("report"),
        event_sink: Callable[[Event], None] | None = None,
        crew_runner: SecurityTestingCrewRunner | None = None,
        source_crew_runner: Any | None = None,
        planning_crew_runner: Any | None = None,
    ) -> None:
        self.config = config
        self.output_root = output_root
        self.event_sink = event_sink
        self.crew_runner = crew_runner or build_security_testing_crew_runner(config)
        self.source_crew_runner = source_crew_runner
        self.planning_crew_runner = planning_crew_runner

    def run(self, url: str | None = None, engagement_file: Path | None = None, *, source: str | None = None) -> Path:
        if not url and not source:
            raise ValueError("Security testing requires a target URL, a source path, or both.")
        domain_dir = self.output_root / (report_dir_name(url) if url else source_report_dir_name(source or "source"))
        discovery_dir = domain_dir / ("discovery" if url else "source-discovery")
        source_discovery_dir = self.output_root / source_report_dir_name(source) / "source-discovery" if source else None
        planning_dir = domain_dir / "security-test-planning"
        report_dir = domain_dir / ("security-testing" if url else "source-security-testing")
        engagement_path = engagement_file or planning_dir / "engagement_template.yaml"
        target = url or f"source:{source}"
        memory = FileMemory(report_dir, event_sink=self.event_sink)
        memory.record_event(
            "orchestrator",
            "start",
            "Starting security testing preflight",
            {"target": target, "source": source, "engagement_file": str(engagement_path)},
        )
        plan = load_security_test_plan(planning_dir)
        engagement = load_engagement_file(engagement_path)
        result = run_security_testing_preflight(
            plan,
            engagement,
            live_target_available=bool(url),
            source_available=bool(source),
        )
        ready_pending = _ready_pending_hypotheses(plan, result, report_dir)
        source_ready_pending = _source_ready_pending_hypotheses(plan, result, report_dir)
        markdown = render_preflight_report(target, engagement_path, result)
        (report_dir / "preflight.md").write_text(markdown, encoding="utf-8")
        memory.add_item(
            "security_testing_preflight",
            {
                "ready": result.ready,
                "blocked": result.blocked,
                "source_ready": result.source_ready,
                "combined": result.combined,
                "deferred": result.deferred,
                "targets": result.targets,
                "ready_pending": [_hypothesis_id(item) for item in ready_pending],
                "source_ready_pending": [_hypothesis_id(item) for item in source_ready_pending],
                "plan_revision_id": plan_revision_id(plan),
            },
            "security_test_coordinator",
        )
        executed_count = 0
        if ready_pending and url:
            memory.record_event(
                "orchestrator",
                "execution_start",
                "Starting security test execution",
                {"tests": [_hypothesis_id(item) for item in ready_pending]},
            )
            self.crew_runner.run(url, report_dir, memory, plan, engagement, result, ready_pending)
            executed_count += len(ready_pending)
            feedback_updates = collect_security_testing_discovery_updates(report_dir)
            new_feedback_updates = _new_discovery_feedback_updates(discovery_dir, feedback_updates)
            if new_feedback_updates:
                _feed_security_testing_updates_to_discovery(
                    discovery_dir=discovery_dir,
                    testing_memory=memory,
                    updates=new_feedback_updates,
                    source_report_dir=report_dir,
                )
                memory.record_event(
                    "orchestrator",
                    "security_planning_refresh_start",
                    "Starting security test planning refresh from security-testing discovery feedback",
                    {"updates": len(new_feedback_updates), "discovery_dir": str(discovery_dir)},
                )
                from mosh.crews.security_planning.crew import SecurityTestPlanningOrchestrator

                SecurityTestPlanningOrchestrator(
                    self.config,
                    output_root=self.output_root,
                    event_sink=self.event_sink,
                    crew_runner=self.planning_crew_runner,
                ).run(url, source=source)
                memory.record_event(
                    "orchestrator",
                    "security_planning_refresh_complete",
                    "Security test planning refresh completed from security-testing discovery feedback",
                    {"updates": len(new_feedback_updates)},
                )
            elif feedback_updates:
                memory.record_event(
                    "orchestrator",
                    "discovery_feedback_duplicate_skipped",
                    "Security-testing discovery feedback was already present; skipped planning refresh",
                    {"updates": len(feedback_updates)},
                )
            else:
                memory.record_event(
                    "orchestrator",
                    "discovery_feedback_skipped",
                    "No new security-testing discovery feedback was submitted",
                    {},
                )
        if source_ready_pending and source:
            memory.record_event(
                "orchestrator",
                "source_execution_start",
                "Starting source security test execution",
                {"tests": [_hypothesis_id(item) for item in source_ready_pending]},
            )
            self._source_runner().run(
                source,
                source_discovery_dir,
                report_dir,
                memory,
                plan,
                engagement,
                result,
                source_ready_pending,
            )
            executed_count += len(source_ready_pending)
        if not ready_pending and not source_ready_pending:
            memory.record_event(
                "orchestrator",
                "execution_skipped",
                "No ready pending security tests to execute",
                {
                    "ready": len(result.ready),
                    "source_ready": len(result.source_ready),
                    "combined": len(result.combined),
                    "deferred": len(result.deferred),
                    "already_executed": sorted(_current_executed_test_ids(report_dir)),
                },
            )
        memory.record_event(
            "orchestrator",
            "complete",
            "Security testing completed",
            {
                "ready": len(result.ready),
                "blocked": len(result.blocked),
                "source_ready": len(result.source_ready),
                "combined": len(result.combined),
                "deferred": len(result.deferred),
                "executed": executed_count,
                "report_dir": str(report_dir),
            },
        )
        return report_dir

    def _source_runner(self) -> Any:
        if self.source_crew_runner is None:
            from mosh.crews.source_security_testing.crew import build_source_security_testing_crew_runner

            self.source_crew_runner = build_source_security_testing_crew_runner(self.config)
        return self.source_crew_runner


def build_security_testing_crew_runner(config: AppConfig) -> SecurityTestingCrewRunner:
    return CrewAISecurityTestingCrewRunner(config)


class CrewAISecurityTestingCrewRunner:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def run(
        self,
        target_url: str,
        report_dir: Path,
        memory: FileMemory,
        plan: dict[str, Any],
        engagement: dict[str, Any],
        preflight: SecurityTestPreflightResult,
        ready_pending: list[dict[str, Any]],
    ) -> None:
        missing_keys = self.config.missing_llm_api_keys_for_models(
            [
                self.config.models.security_testing.executor,
                self.config.models.security_testing.reviewer,
                self.config.models.security_testing.reporter,
            ]
        )
        if missing_keys:
            raise CrewAIUnavailable(f"Missing LLM API key(s): {', '.join(missing_keys)}.")
        crewai = _load_crewai()
        current_plan_revision_id = plan_revision_id(plan)
        for hypothesis in ready_pending:
            _run_one_security_test(
                crewai=crewai,
                config=self.config,
                target_url=target_url,
                report_dir=report_dir,
                memory=memory,
                hypothesis=hypothesis,
                engagement=engagement,
                targets=preflight.targets,
                plan_revision_id=current_plan_revision_id,
            )


def _run_one_security_test(
    crewai: Any,
    config: AppConfig,
    target_url: str,
    report_dir: Path,
    memory: FileMemory,
    hypothesis: dict[str, Any],
    engagement: dict[str, Any],
    targets: dict[str, str],
    plan_revision_id: str,
) -> None:
    test_id = _hypothesis_id(hypothesis)
    current_hypothesis_fingerprint = hypothesis_fingerprint(hypothesis)
    workspace_dir = report_dir / "workspaces" / _safe_test_id(test_id)
    executed_report_path = report_dir / "executed_tests" / f"{_safe_test_id(test_id)}.md"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    executed_report_path.parent.mkdir(parents=True, exist_ok=True)
    state = SecurityTestExecutionState(
        target_url=target_url,
        report_dir=report_dir,
        workspace_dir=workspace_dir,
        memory=memory,
        hypothesis=hypothesis,
        engagement=engagement,
        targets=targets,
        executed_report_path=executed_report_path,
        plan_revision_id=plan_revision_id,
        hypothesis_fingerprint=current_hypothesis_fingerprint,
    )
    _archive_existing_latest_report(state)
    previous_review: dict[str, Any] | None = None
    max_attempts = config.security_execution_max_revisions + 1
    for revision in range(1, max_attempts + 1):
        state.revision = revision
        state.evidence = None
        state.review = None
        command_start = len(state.commands)
        executor_crew = _build_executor_crew(crewai, config, state)
        _kickoff_capturing_tool_state(
            executor_crew,
            state,
            agent_name="executor",
            task_name="execute_security_test_task",
            captured=lambda: state.evidence is not None or bool(state.commands),
            inputs={
                "target_url": target_url,
                "test_id": test_id,
                "revision": revision,
                "max_attempts": max_attempts,
                "hypothesis": json.dumps(hypothesis, sort_keys=True),
                "engagement": json.dumps(engagement, sort_keys=True),
                "targets": json.dumps(targets, sort_keys=True),
                "previous_review": json.dumps(previous_review or {}, sort_keys=True),
            },
        )
        if state.evidence is None:
            state.evidence = _fallback_executor_evidence(state)
            memory.add_item(
                "security_test_execution_evidence",
                {
                    "test_id": test_id,
                    "revision": revision,
                    "structured": state.evidence,
                    "fallback": True,
                },
                "executor",
            )
        reviewer_crew = _build_reviewer_crew(crewai, config, state)
        _kickoff_capturing_tool_state(
            reviewer_crew,
            state,
            agent_name="reviewer",
            task_name="review_security_test_evidence_task",
            captured=lambda: state.review is not None,
            inputs={
                "target_url": target_url,
                "test_id": test_id,
                "revision": revision,
                "max_attempts": max_attempts,
                "hypothesis": json.dumps(hypothesis, sort_keys=True),
                "targets": json.dumps(targets, sort_keys=True),
                "evidence": json.dumps(state.evidence or {}, sort_keys=True),
            },
        )
        if state.review is None:
            state.review = {
                "accepted": False,
                "summary": "Reviewer did not submit a review.",
                "requested_changes": ["Submit a structured review."],
            }
        _apply_review_artifact_decisions(state.artifacts, state.review)
        _record_execution_attempt(state, command_start)
        previous_review = state.review
        if state.review.get("accepted"):
            break

    execution_bundle = _execution_bundle(state)
    memory.add_item(
        "security_test_execution_bundle",
        execution_bundle,
        "security_test_coordinator",
    )
    reporter_crew = _build_reporter_crew(crewai, config, state)
    _kickoff_capturing_tool_state(
        reporter_crew,
        state,
        agent_name="reporter",
        task_name="write_executed_security_test_report_task",
        captured=lambda: state.report_written,
        inputs={
            "target_url": target_url,
            "test_id": test_id,
            "hypothesis": json.dumps(hypothesis, sort_keys=True),
            "targets": json.dumps(targets, sort_keys=True),
            "evidence": json.dumps(state.evidence or {}, sort_keys=True),
            "review": json.dumps(state.review or {}, sort_keys=True),
            "commands": json.dumps(state.commands, sort_keys=True),
            "execution_bundle": json.dumps(execution_bundle, sort_keys=True),
        },
    )
    if not state.report_written:
        markdown = render_executed_test_report(
            target_url=target_url,
            hypothesis=hypothesis,
            targets=targets,
            evidence=state.evidence or {},
            review=state.review or {},
            commands=state.commands,
            execution_bundle=execution_bundle,
        )
        markdown = _with_execution_metadata(markdown, state)
        state.executed_report_path.write_text(markdown, encoding="utf-8")
        state.report_written = True
        memory.record_event(
            "reporter",
            "report_fallback_written",
            "Wrote fallback executed test report",
            {"test_id": test_id, "path": str(state.executed_report_path)},
        )


def _kickoff_capturing_tool_state(
    crew_instance: Any,
    state: SecurityTestExecutionState,
    *,
    agent_name: str,
    task_name: str,
    captured: Callable[[], bool],
    inputs: dict[str, Any],
) -> None:
    try:
        crew_instance.crew().kickoff(inputs=inputs)
    except Exception as exc:
        if not captured():
            raise
        state.memory.record_event(
            agent_name,
            "crew_post_tool_failure_ignored",
            f"{task_name} failed after structured tool output was captured",
            {
                "task": task_name,
                "error": str(exc),
                "error_type": type(exc).__name__,
            },
        )


def _fallback_executor_evidence(state: SecurityTestExecutionState) -> dict[str, Any]:
    if state.commands:
        return {
            "status": "inconclusive",
            "summary": "Executor ran commands but did not submit structured evidence.",
            "observations": state.commands,
            "result": "Review the recorded command outputs; the executor did not provide a final supported conclusion.",
            "safety_notes": "Commands were captured by the security command tool and redacted before persistence.",
            "follow_up": "Reviewer should request a focused re-run if the command outputs are insufficient.",
            "commands": state.commands,
        }
    return {
        "status": "failed",
        "summary": "Executor did not submit structured evidence.",
        "observations": [],
        "result": "No executable evidence was captured for this hypothesis.",
        "safety_notes": "No command evidence was recorded.",
        "follow_up": "Re-run the test or simplify the hypothesis execution steps.",
        "commands": [],
    }


def _record_execution_attempt(state: SecurityTestExecutionState, command_start: int) -> None:
    attempt = {
        "revision": state.revision,
        "evidence": state.evidence or {},
        "review": state.review or {},
        "commands": state.commands[command_start:],
        "artifacts": [
            artifact
            for artifact in state.artifacts
            if artifact.get("source_revision") == state.revision
        ],
    }
    state.attempts.append(attempt)
    state.memory.add_item(
        "security_test_execution_attempt",
        {
            "test_id": _hypothesis_id(state.hypothesis),
            **attempt,
        },
        "security_test_coordinator",
    )


def _execution_bundle(state: SecurityTestExecutionState) -> dict[str, Any]:
    return {
        "test_id": _hypothesis_id(state.hypothesis),
        "plan_revision_id": state.plan_revision_id,
        "hypothesis_fingerprint": state.hypothesis_fingerprint,
        "final_evidence": state.evidence or {},
        "final_review": state.review or {},
        "attempts": state.attempts,
        "artifacts": state.artifacts,
        "commands": state.commands,
        "report_path": str(state.executed_report_path),
        "archived_previous_reports": state.archived_report_paths,
    }


def plan_revision_id(plan: dict[str, Any]) -> str:
    return _stable_fingerprint(plan)


def hypothesis_fingerprint(hypothesis: dict[str, Any]) -> str:
    return _stable_fingerprint(hypothesis)


def _stable_fingerprint(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _archive_existing_latest_report(state: SecurityTestExecutionState) -> None:
    state.archived_report_paths.extend(
        _archive_latest_report(
            report_dir=state.report_dir,
            test_id=_hypothesis_id(state.hypothesis),
            memory=state.memory,
        )
    )


def _archive_latest_report(report_dir: Path, test_id: str, memory: FileMemory | None = None) -> list[str]:
    report_path = report_dir / "executed_tests" / f"{_safe_test_id(test_id)}.md"
    if not report_path.exists():
        return []
    previous_metadata = _latest_execution_metadata(report_dir, test_id) or {}
    previous_fingerprint = _text(previous_metadata.get("hypothesis_fingerprint"))[:12] or "legacy"
    history_dir = report_path.parent / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    history_path = _next_history_report_path(history_dir, _safe_test_id(test_id), previous_fingerprint)
    report_path.replace(history_path)
    if memory:
        memory.record_event(
            "security_test_coordinator",
            "previous_report_archived",
            "Archived previous executed security test report before rerun",
            {
                "test_id": test_id,
                "archived_path": str(history_path),
                "previous_hypothesis_fingerprint": previous_metadata.get("hypothesis_fingerprint"),
            },
        )
    return [str(history_path)]


def _next_history_report_path(history_dir: Path, safe_test_id: str, fingerprint_prefix: str) -> Path:
    index = 1
    while True:
        candidate = history_dir / f"{safe_test_id}__{fingerprint_prefix}__v{index}.md"
        if not candidate.exists():
            return candidate
        index += 1


def _with_execution_metadata(markdown: str, state: SecurityTestExecutionState, report_content: dict[str, Any] | None = None) -> str:
    metadata = _execution_metadata(
        test_id=_hypothesis_id(state.hypothesis),
        plan_revision_id=state.plan_revision_id,
        hypothesis_fingerprint=state.hypothesis_fingerprint,
        evidence=state.evidence or {},
        review=state.review or {},
        report_path=str(state.executed_report_path),
        archived_previous_reports=state.archived_report_paths,
        report_content=report_content,
    )
    return _with_execution_metadata_mapping(markdown, metadata)


def _with_execution_metadata_mapping(markdown: str, metadata: dict[str, Any]) -> str:
    body = _strip_execution_metadata(markdown).lstrip()
    return (
        f"{EXECUTION_METADATA_START}\n"
        f"{json.dumps(metadata, indent=2, sort_keys=True)}\n"
        f"{EXECUTION_METADATA_END}\n\n"
        f"{body}"
    )


def _execution_metadata(
    *,
    test_id: str,
    plan_revision_id: str,
    hypothesis_fingerprint: str,
    evidence: dict[str, Any],
    review: dict[str, Any],
    report_path: str,
    archived_previous_reports: list[str] | None = None,
    report_content: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": "mosh.security-test-execution.v1",
        "test_id": test_id,
        "plan_revision_id": plan_revision_id,
        "hypothesis_fingerprint": hypothesis_fingerprint,
        "status": _text((report_content or {}).get("status")) or _text(evidence.get("status")) or "inconclusive",
        "review_accepted": bool(review.get("accepted")),
        "report_path": report_path,
        "archived_previous_reports": archived_previous_reports or [],
        "executed_at": utc_now(),
    }


def _latest_execution_metadata(report_dir: Path, test_id: str) -> dict[str, Any] | None:
    report_path = report_dir / "executed_tests" / f"{_safe_test_id(test_id)}.md"
    if not report_path.exists():
        return None
    return _extract_execution_metadata(report_path.read_text(encoding="utf-8"))


def _extract_execution_metadata(markdown: str) -> dict[str, Any] | None:
    if not markdown.startswith(EXECUTION_METADATA_START):
        return None
    end = markdown.find(EXECUTION_METADATA_END)
    if end < 0:
        return None
    payload = markdown[len(EXECUTION_METADATA_START) : end].strip()
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _strip_execution_metadata(markdown: str) -> str:
    if not markdown.startswith(EXECUTION_METADATA_START):
        return markdown
    end = markdown.find(EXECUTION_METADATA_END)
    if end < 0:
        return markdown
    return markdown[end + len(EXECUTION_METADATA_END) :]


def collect_security_testing_discovery_updates(report_dir: Path) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _read_json_list(report_dir / "memory.json"):
        if item.get("kind") != "security_test_execution_bundle":
            continue
        content = item.get("content") if isinstance(item.get("content"), dict) else {}
        for update in _updates_from_execution_bundle(content):
            fingerprint = _discovery_update_fingerprint(update)
            if fingerprint not in seen:
                seen.add(fingerprint)
                updates.append(update)
    return updates


def _updates_from_execution_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    test_id = _text(bundle.get("test_id")) or "unknown"
    candidates: list[Any] = []
    final_evidence = bundle.get("final_evidence") if isinstance(bundle.get("final_evidence"), dict) else {}
    candidates.extend(_explicit_discovery_updates(final_evidence))
    for attempt in _list(bundle.get("attempts")):
        if isinstance(attempt, dict) and isinstance(attempt.get("evidence"), dict):
            candidates.extend(_explicit_discovery_updates(attempt["evidence"]))

    updates: list[dict[str, Any]] = []
    for candidate in candidates:
        update = _normalize_discovery_update(candidate, test_id)
        if update:
            updates.append(update)
    return updates


def _explicit_discovery_updates(evidence: dict[str, Any]) -> list[Any]:
    updates: list[Any] = []
    for key in (
        "discovery_updates",
        "new_discovery",
        "new_discovery_facts",
        "discovery_feedback",
        "new_entry_points",
        "new_components",
    ):
        updates.extend(_list(evidence.get(key)))
    return updates


def _normalize_discovery_update(value: Any, test_id: str) -> dict[str, Any] | None:
    if isinstance(value, dict):
        detail = _text(value.get("detail") or value.get("summary") or value.get("value") or value.get("url") or value.get("endpoint"))
        if not detail:
            return None
        evidence = _string_list(value.get("evidence") or value.get("source_evidence") or value.get("references"))
        return {
            "test_id": _text(value.get("test_id")) or test_id,
            "type": _text(value.get("type") or value.get("kind") or value.get("category")) or "security-testing-fact",
            "detail": detail,
            "confidence": _text(value.get("confidence")) or "observed",
            "evidence": evidence,
            "source": "security-testing",
        }
    detail = _text(value)
    if not detail:
        return None
    return {
        "test_id": test_id,
        "type": "security-testing-fact",
        "detail": detail,
        "confidence": "observed",
        "evidence": [],
        "source": "security-testing",
    }


def _discovery_update_fingerprint(update: dict[str, Any]) -> str:
    return json.dumps(
        {
            "test_id": update.get("test_id"),
            "type": update.get("type"),
            "detail": update.get("detail"),
            "evidence": update.get("evidence"),
        },
        sort_keys=True,
    )


def _feed_security_testing_updates_to_discovery(
    *,
    discovery_dir: Path,
    testing_memory: FileMemory,
    updates: list[dict[str, Any]],
    source_report_dir: Path,
) -> None:
    discovery_dir.mkdir(parents=True, exist_ok=True)
    content = {
        "updates": updates,
        "source_report_dir": str(source_report_dir),
    }
    _append_existing_memory_item(
        discovery_dir,
        MemoryItem(
            kind="security_testing_discovery_feedback",
            content=content,
            source="security_testing_orchestrator",
        ),
    )
    report_updates = _all_discovery_feedback_updates(discovery_dir)
    update_report_with_security_testing_feedback(discovery_dir, report_updates)
    _append_existing_event(
        discovery_dir,
        Event(
            agent="security_testing_orchestrator",
            action="memory_write",
            message="Added security-testing discovery feedback to shared discovery memory",
            data={"kind": "security_testing_discovery_feedback", "content": content},
        ),
    )
    _append_existing_event(
        discovery_dir,
        Event(
            agent="security_testing_orchestrator",
            action="report_updated",
            message="Updated discovery report with security-testing feedback",
            data={"updates": len(report_updates), "new_updates": len(updates), "report": str(discovery_dir / "report.md")},
        ),
    )
    testing_memory.add_item(
        "security_testing_discovery_feedback",
        {
            "updates": updates,
            "discovery_dir": str(discovery_dir),
            "discovery_report": str(discovery_dir / "report.md"),
        },
        "security_testing_orchestrator",
    )


def _all_discovery_feedback_updates(discovery_dir: Path) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _read_json_list(discovery_dir / "memory.json"):
        if item.get("kind") != "security_testing_discovery_feedback":
            continue
        content = item.get("content") if isinstance(item.get("content"), dict) else {}
        for update in _list(content.get("updates")):
            if not isinstance(update, dict):
                continue
            fingerprint = _discovery_update_fingerprint(update)
            if fingerprint not in seen:
                seen.add(fingerprint)
                updates.append(update)
    return updates


def _new_discovery_feedback_updates(discovery_dir: Path, updates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    existing = {_discovery_update_fingerprint(update) for update in _all_discovery_feedback_updates(discovery_dir)}
    fresh: list[dict[str, Any]] = []
    seen = set(existing)
    for update in updates:
        fingerprint = _discovery_update_fingerprint(update)
        if fingerprint not in seen:
            seen.add(fingerprint)
            fresh.append(update)
    return fresh


def _append_existing_memory_item(report_dir: Path, item: MemoryItem) -> None:
    path = report_dir / "memory.json"
    items = _read_json_list(path)
    items.append(item.to_dict())
    _write_json(path, items)


def _append_existing_event(report_dir: Path, event: Event) -> None:
    path = report_dir / "events.json"
    events = _read_json_list(path)
    events.append(event.to_dict())
    _write_json(path, events)


def _read_json_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list")
    return data


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _preserve_evidence_artifacts(state: SecurityTestExecutionState, evidence: dict[str, Any]) -> None:
    for artifact in _extract_artifacts(evidence, state.revision):
        if _artifact_fingerprint(artifact) not in {_artifact_fingerprint(existing) for existing in state.artifacts}:
            state.artifacts.append(artifact)
            state.memory.add_item(
                "security_test_artifact",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "artifact": artifact,
                },
                "executor",
            )


def _extract_artifacts(evidence: dict[str, Any], revision: int) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    explicit_artifacts = evidence.get("artifacts")
    if isinstance(explicit_artifacts, list):
        for index, artifact in enumerate(explicit_artifacts, start=1):
            normalized = _normalize_artifact(artifact, revision, default_name=f"artifact_{index}")
            if normalized:
                artifacts.append(normalized)

    artifact_keys = {
        "recommended_csp_policy": ("recommended_policy", "content_security_policy"),
        "recommended_policy": ("recommended_policy", "recommended_policy"),
        "proof_of_concept": ("proof_of_concept", "proof_of_concept"),
        "poc": ("proof_of_concept", "proof_of_concept"),
        "generated_script": ("generated_script", "generated_script"),
        "endpoint_inventory": ("endpoint_inventory", "endpoint_inventory"),
        "auth_matrix": ("auth_matrix", "auth_matrix"),
    }
    for key, (artifact_type, name) in artifact_keys.items():
        if key in evidence and evidence.get(key) not in (None, "", [], {}):
            artifacts.append(
                {
                    "type": artifact_type,
                    "name": name,
                    "value": evidence[key],
                    "source_revision": revision,
                    "status": "draft",
                    "review_status": "preserved",
                }
            )
    return artifacts


def _normalize_artifact(value: Any, revision: int, default_name: str) -> dict[str, Any] | None:
    if isinstance(value, dict):
        artifact_value = value.get("value", value.get("content", value.get("body")))
        if artifact_value in (None, "", [], {}):
            artifact_value = {key: item for key, item in value.items() if key not in {"type", "name", "status", "review_status"}}
        if artifact_value in (None, "", [], {}):
            return None
        if _is_descriptor_only_artifact_value(artifact_value):
            return None
        return {
            "type": _text(value.get("type")) or "artifact",
            "name": _text(value.get("name")) or default_name,
            "value": artifact_value,
            "source_revision": int(value.get("source_revision") or revision),
            "status": _text(value.get("status")) or "draft",
            "review_status": _text(value.get("review_status")) or "preserved",
        }
    if value in (None, "", [], {}):
        return None
    if _is_descriptor_only_artifact_value(value):
        return None
    return {
        "type": "artifact",
        "name": default_name,
        "value": value,
        "source_revision": revision,
        "status": "draft",
        "review_status": "preserved",
    }


def _is_descriptor_only_artifact_value(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    keys = set(value)
    return bool(keys) and keys <= {"description", "source", "notes"}


def _artifact_fingerprint(artifact: dict[str, Any]) -> str:
    return json.dumps(
        {
            "type": artifact.get("type"),
            "name": artifact.get("name"),
            "value": artifact.get("value"),
        },
        sort_keys=True,
        default=str,
    )


def _apply_review_artifact_decisions(artifacts: list[dict[str, Any]], review: dict[str, Any]) -> None:
    accepted = _artifact_decision_names(review.get("accepted_artifacts"))
    rejected = _artifact_decision_names(review.get("rejected_artifacts"))
    for decision in _list(review.get("artifact_decisions")):
        if isinstance(decision, dict):
            name = _text(decision.get("name") or decision.get("artifact") or decision.get("id"))
            status = _text(decision.get("status") or decision.get("decision")).lower()
            if name and status in {"accepted", "valid", "include"}:
                accepted.add(name)
            elif name and status in {"rejected", "invalid", "exclude"}:
                rejected.add(name)
    for artifact in artifacts:
        name = _text(artifact.get("name"))
        if name in accepted:
            artifact["review_status"] = "accepted"
        elif name in rejected:
            artifact["review_status"] = "rejected"


def _artifact_decision_names(value: Any) -> set[str]:
    names: set[str] = set()
    for item in _list(value):
        if isinstance(item, dict):
            name = _text(item.get("name") or item.get("artifact") or item.get("id"))
        else:
            name = _text(item)
        if name:
            names.add(name)
    return names


def _build_executor_crew(crewai: Any, config: AppConfig, state: SecurityTestExecutionState):
    command_tool = _build_run_security_command_tool(crewai, config, state)
    evidence_tool = _build_submit_execution_evidence_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_testing/executor_agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_testing/executor_tasks.yaml"))

    @crewai.CrewBase
    class SecurityTestExecutorCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def executor(self):
            return crewai.Agent(
                config=self.agents_config["executor"],
                llm=_llm(crewai, config, config.models.security_testing.executor),
                tools=[command_tool, evidence_tool],
                allow_delegation=False,
            )

        @crewai.task
        def execute_security_test_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["execute_security_test_task"],
                agent=self.executor(),
                agent_name="executor",
                task_name="execute_security_test_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.executor()],
                tasks=[self.execute_security_test_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return SecurityTestExecutorCrew()


def _build_reviewer_crew(crewai: Any, config: AppConfig, state: SecurityTestExecutionState):
    review_tool = _build_submit_execution_review_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_testing/reviewer_agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_testing/reviewer_tasks.yaml"))

    @crewai.CrewBase
    class SecurityTestReviewerCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def reviewer(self):
            return crewai.Agent(
                config=self.agents_config["reviewer"],
                llm=_llm(crewai, config, config.models.security_testing.reviewer),
                tools=[review_tool],
                allow_delegation=False,
            )

        @crewai.task
        def review_security_test_evidence_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["review_security_test_evidence_task"],
                agent=self.reviewer(),
                agent_name="reviewer",
                task_name="review_security_test_evidence_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.reviewer()],
                tasks=[self.review_security_test_evidence_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return SecurityTestReviewerCrew()


def _build_reporter_crew(crewai: Any, config: AppConfig, state: SecurityTestExecutionState):
    report_tool = _build_write_executed_test_report_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_testing/reporter_agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_testing/reporter_tasks.yaml"))

    @crewai.CrewBase
    class SecurityTestReporterCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def reporter(self):
            return crewai.Agent(
                config=self.agents_config["reporter"],
                llm=_llm(crewai, config, config.models.security_testing.reporter),
                tools=[report_tool],
                allow_delegation=False,
            )

        @crewai.task
        def write_executed_security_test_report_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["write_executed_security_test_report_task"],
                agent=self.reporter(),
                agent_name="reporter",
                task_name="write_executed_security_test_report_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.reporter()],
                tasks=[self.write_executed_security_test_report_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return SecurityTestReporterCrew()


def _build_run_security_command_tool(crewai: Any, config: AppConfig, state: SecurityTestExecutionState):
    class SecurityCommandInput(crewai.BaseModel):
        command: str = crewai.Field(..., description="Shell command to run inside the security testing container.")
        purpose: str = crewai.Field(..., description="Why this command is needed for the current hypothesis.")

    class RunSecurityCommandTool(crewai.BaseTool):
        name: str = "run_security_command"
        description: str = "Run a shell command inside the disposable per-test Docker workspace."
        args_schema: type[crewai.BaseModel] = SecurityCommandInput

        def _run(self, command: str, purpose: str) -> str:
            blocked_hosts = _disallowed_hosts(command, state.targets)
            if blocked_hosts:
                state.memory.record_event(
                    "executor",
                    "tool_blocked",
                    "Blocked security command because it referenced out-of-scope hosts",
                    {
                        "test_id": _hypothesis_id(state.hypothesis),
                        "blocked_hosts": blocked_hosts,
                        "purpose": purpose,
                    },
                )
                return json.dumps(
                    {
                        "exit_code": 126,
                        "blocked": True,
                        "blocked_hosts": blocked_hosts,
                        "stdout": "",
                        "stderr": "Command references out-of-scope hosts.",
                    },
                    sort_keys=True,
                )

            runner = DockerToolRunner(config.security_tool_image)
            result = runner.run(
                ["bash", "-lc", command],
                timeout=config.security_command_timeout,
                volumes=[(str(state.workspace_dir.resolve()), "/work")],
                workdir="/work",
            )
            redacted = _redact_result(result, state.engagement)
            command_record = {
                "command": _redact_text(command, state.engagement),
                "purpose": purpose,
                "exit_code": redacted.exit_code,
                "stdout": _truncate(redacted.stdout),
                "stderr": _truncate(redacted.stderr),
            }
            state.commands.append(command_record)
            _append_command_log(state.workspace_dir, command_record)
            state.memory.record_event(
                "executor",
                "tool_result",
                "run_security_command completed",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "purpose": purpose,
                    "exit_code": redacted.exit_code,
                },
            )
            return json.dumps(command_record, sort_keys=True)

    return RunSecurityCommandTool()


def _build_submit_execution_evidence_tool(crewai: Any, state: SecurityTestExecutionState):
    class EvidenceInput(crewai.BaseModel):
        evidence: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured execution evidence, commands run, observations, status, and provisional result.",
        )

    class SubmitExecutionEvidenceTool(crewai.BaseTool):
        name: str = "submit_security_test_evidence"
        description: str = "Submit structured evidence from the security test execution."
        args_schema: type[crewai.BaseModel] = EvidenceInput

        def _run(self, evidence: Any) -> str:
            content = _coerce_mapping(evidence)
            content.setdefault("commands", state.commands)
            state.evidence = content
            _preserve_evidence_artifacts(state, content)
            state.memory.add_item(
                "security_test_execution_evidence",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "revision": state.revision,
                    "structured": content,
                },
                "executor",
            )
            state.memory.record_event(
                "executor",
                "evidence_submitted",
                "Security test executor submitted evidence",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "revision": state.revision,
                    "commands": len(state.commands),
                },
            )
            return json.dumps({"accepted": True, "commands": len(state.commands)}, sort_keys=True)

    return SubmitExecutionEvidenceTool()


def _build_submit_execution_review_tool(crewai: Any, state: SecurityTestExecutionState):
    class ReviewInput(crewai.BaseModel):
        review: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured review with accepted, summary, requested_changes, and safety concerns.",
        )

    class SubmitExecutionReviewTool(crewai.BaseTool):
        name: str = "submit_security_test_review"
        description: str = "Submit the reviewer decision for this security test evidence."
        args_schema: type[crewai.BaseModel] = ReviewInput

        def _run(self, review: Any) -> str:
            content = _coerce_mapping(review)
            content.setdefault("accepted", False)
            state.review = content
            state.memory.add_item(
                "security_test_execution_review",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "revision": state.revision,
                    "structured": content,
                },
                "reviewer",
            )
            state.memory.record_event(
                "reviewer",
                "review_submitted",
                "Security test reviewer submitted review",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "revision": state.revision,
                    "accepted": bool(content.get("accepted")),
                },
            )
            return json.dumps({"accepted": bool(content.get("accepted"))}, sort_keys=True)

    return SubmitExecutionReviewTool()


def _build_write_executed_test_report_tool(crewai: Any, state: SecurityTestExecutionState):
    class ReportInput(crewai.BaseModel):
        report: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured report content for executed_tests/{test_id}.md.",
        )

    class WriteExecutedTestReportTool(crewai.BaseTool):
        name: str = "write_executed_test_report"
        description: str = "Write the stable Markdown artifact for this executed security test."
        args_schema: type[crewai.BaseModel] = ReportInput

        def _run(self, report: Any) -> str:
            content = _coerce_mapping(report)
            markdown = render_executed_test_report(
                target_url=state.target_url,
                hypothesis=state.hypothesis,
                targets=state.targets,
                evidence=content.get("evidence") if isinstance(content.get("evidence"), dict) else state.evidence or content,
                review=content.get("review") if isinstance(content.get("review"), dict) else state.review or {},
                commands=state.commands,
                execution_bundle=_execution_bundle(state),
                report_content=content,
            )
            markdown = _with_execution_metadata(markdown, state, report_content=content)
            state.executed_report_path.write_text(markdown, encoding="utf-8")
            state.report_written = True
            state.memory.add_item(
                "executed_security_test_report",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "path": str(state.executed_report_path),
                    "bytes": len(markdown.encode("utf-8")),
                },
                "reporter",
            )
            state.memory.record_event(
                "reporter",
                "report_written",
                "Security test reporter wrote executed test report",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "path": str(state.executed_report_path),
                    "bytes": len(markdown.encode("utf-8")),
                },
            )
            return json.dumps({"path": str(state.executed_report_path), "bytes": len(markdown.encode("utf-8"))})

    return WriteExecutedTestReportTool()


def load_security_test_plan(planning_dir: Path) -> dict[str, Any]:
    memory_path = planning_dir / "memory.json"
    if not memory_path.exists():
        raise FileNotFoundError(f"Security planning memory not found: {memory_path}")
    items = json.loads(memory_path.read_text(encoding="utf-8"))
    if not isinstance(items, list):
        raise ValueError(f"{memory_path} must contain a JSON list")
    final_plans = [
        item.get("content", {}).get("structured")
        for item in items
        if item.get("kind") == "security_test_plan_final"
        and isinstance(item.get("content", {}).get("structured"), dict)
        and _has_hypotheses(item.get("content", {}).get("structured"))
    ]
    if final_plans:
        return final_plans[-1]
    draft_plans = [
        item.get("content", {}).get("structured")
        for item in items
        if item.get("kind") == "security_test_plan_draft"
        and isinstance(item.get("content", {}).get("structured"), dict)
        and _has_hypotheses(item.get("content", {}).get("structured"))
    ]
    if draft_plans:
        return draft_plans[-1]
    raise RuntimeError(f"No structured security test plan found in {memory_path}")


def run_security_testing_preflight(
    plan: dict[str, Any],
    engagement: dict[str, Any],
    *,
    live_target_available: bool = True,
    source_available: bool = False,
) -> SecurityTestPreflightResult:
    targets = resolve_target_mapping(engagement)
    ready: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    source_ready: list[dict[str, Any]] = []
    combined: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    for hypothesis in _hypotheses(plan):
        mode = _execution_mode(hypothesis)
        blockers: list[str] = []
        item = {
            "id": _text(hypothesis.get("id")) or "unknown",
            "title": _text(hypothesis.get("title")) or "Untitled test",
            "priority": _text(hypothesis.get("priority")) or "unknown",
            "surface": _text(hypothesis.get("surface")) or "unknown",
            "execution_mode": mode,
            "verification_strategy": _text(hypothesis.get("verification_strategy")) or _default_verification_strategy(mode),
            "evidence_sources": _string_list(hypothesis.get("evidence_sources")),
            "blockers": blockers,
        }
        if mode == "live":
            blockers.extend(_hypothesis_blockers(hypothesis, engagement, targets))
            if not live_target_available:
                blockers.append("live target URL is not available for this assessment")
            if blockers:
                blocked.append(item)
            else:
                ready.append(item)
        elif mode == "source":
            if not source_available:
                blockers.append("source code is not available for source execution")
            if not _list(hypothesis.get("affected_source")):
                blockers.append("affected_source is missing for source execution")
            if blockers:
                blocked.append(item)
            else:
                source_ready.append(item)
        elif mode == "combined":
            if live_target_available:
                blockers.extend(_hypothesis_blockers(hypothesis, engagement, targets))
            if not source_available:
                blockers.append("source code is not available for combined execution")
            if not live_target_available:
                blockers.append("live target URL is not available for combined execution")
            combined.append(item)
        elif mode == "deferred":
            blockers.extend(_deferred_reasons(hypothesis))
            deferred.append(item)
        else:
            blockers.append(f"unsupported execution_mode `{mode}`")
            blocked.append(item)
    return SecurityTestPreflightResult(
        ready=ready,
        blocked=blocked,
        targets=targets,
        source_ready=source_ready,
        combined=combined,
        deferred=deferred,
    )


def render_preflight_report(target_url: str, engagement_file: Path, result: SecurityTestPreflightResult) -> str:
    lines = [
        "# Security Testing Preflight",
        "",
        f"- Target URL: `{target_url}`",
        f"- Engagement file: `{engagement_file}`",
        f"- Ready tests: `{len(result.ready)}`",
        f"- Source-routed tests: `{len(result.source_ready)}`",
        f"- Combined tests: `{len(result.combined)}`",
        f"- Deferred tests: `{len(result.deferred)}`",
        f"- Blocked tests: `{len(result.blocked)}`",
        "",
        "## Effective Targets",
        "",
    ]
    if result.targets:
        for key, value in result.targets.items():
            lines.append(f"- {key}: `{value}`")
    else:
        lines.append("No targets resolved from the engagement file.")
    lines.extend(["", "## Ready Tests", ""])
    if result.ready:
        for item in result.ready:
            suffix = ""
            if item.get("execution_status"):
                suffix = f" - `{item['execution_status']}`: {item.get('execution_reason', '')}"
            lines.append(_preflight_item_line(item, suffix=suffix))
    else:
        lines.append("No live tests are ready to execute.")
    lines.extend(["", "## Source-Routed Tests", ""])
    if result.source_ready:
        for item in result.source_ready:
            suffix = ""
            if item.get("execution_status"):
                suffix = f" - `{item['execution_status']}`: {item.get('execution_reason', '')}"
            lines.append(_preflight_item_line(item, suffix=suffix))
        lines.append("")
        lines.append("These tests are routed to source security testing and are not sent to the live URL executor.")
    else:
        lines.append("No tests are routed to source security testing.")
    lines.extend(["", "## Combined Tests", ""])
    if result.combined:
        for item in result.combined:
            lines.append(_preflight_item_line(item))
            for blocker in item["blockers"]:
                lines.append(f"  - {blocker}")
        lines.append("")
        lines.append("Combined tests need coordinated source inspection and live verification before execution.")
    else:
        lines.append("No tests require combined source and live execution.")
    lines.extend(["", "## Deferred Tests", ""])
    if result.deferred:
        for item in result.deferred:
            lines.append(_preflight_item_line(item))
            for blocker in item["blockers"]:
                lines.append(f"  - {blocker}")
    else:
        lines.append("No tests are deferred.")
    lines.extend(["", "## Blocked Tests", ""])
    if result.blocked:
        for item in result.blocked:
            lines.append(_preflight_item_line(item))
            for blocker in item["blockers"]:
                lines.append(f"  - {blocker}")
    else:
        lines.append("No tests are blocked.")
    return "\n".join(lines).rstrip() + "\n"


def _execution_mode(hypothesis: dict[str, Any]) -> str:
    mode = _text(hypothesis.get("execution_mode")).lower()
    return mode or "live"


def _default_verification_strategy(execution_mode: str) -> str:
    if execution_mode == "source":
        return "source-inspection"
    if execution_mode == "combined":
        return "source-guided-live-verification"
    if execution_mode == "deferred":
        return "blocked-pending-inputs"
    return "live-verification"


def _deferred_reasons(hypothesis: dict[str, Any]) -> list[str]:
    reasons = _string_list(hypothesis.get("defer_reason"))
    reasons.extend(_string_list(hypothesis.get("requirements_to_proceed")))
    reasons.extend(_string_list(hypothesis.get("requirements")))
    return reasons or ["execution_mode is deferred"]


def _preflight_item_line(item: dict[str, Any], *, suffix: str = "") -> str:
    mode = _text(item.get("execution_mode")) or "live"
    strategy = _text(item.get("verification_strategy"))
    route = f"mode `{mode}`"
    if strategy:
        route = f"{route}, `{strategy}`"
    return f"- **{item['id']}**: {item['title']} ({item['priority']}; {route}){suffix}"


def render_blocked_tests_cli_summary(result: SecurityTestPreflightResult, engagement_file: Path) -> str:
    if not (result.blocked or result.combined or result.deferred):
        return ""
    lines: list[str] = [""]
    if result.blocked:
        lines.extend(
            [
                "Security testing has blocked tests remaining.",
                f"Update {engagement_file} and run security testing again:",
                "",
            ]
        )
        for item in result.blocked:
            lines.append(f"- {item['id']}: {item['title']} ({item['priority']})")
            blockers = item.get("blockers") if isinstance(item.get("blockers"), list) else []
            for blocker in blockers:
                lines.append(f"  - {_unblock_guidance(_text(blocker))}")
    if result.combined:
        if len(lines) > 1:
            lines.append("")
        lines.append("Combined tests need source and live coordination before execution:")
        for item in result.combined:
            lines.append(f"- {item['id']}: {item['title']} ({item['priority']})")
            blockers = item.get("blockers") if isinstance(item.get("blockers"), list) else []
            for blocker in blockers:
                lines.append(f"  - {_unblock_guidance(_text(blocker))}")
    if result.deferred:
        if len(lines) > 1:
            lines.append("")
        lines.append("Deferred tests were preserved for later scope or setup:")
        for item in result.deferred:
            lines.append(f"- {item['id']}: {item['title']} ({item['priority']})")
            blockers = item.get("blockers") if isinstance(item.get("blockers"), list) else []
            for blocker in blockers:
                lines.append(f"  - {_unblock_guidance(_text(blocker))}")
    return "\n".join(lines).rstrip()


def _unblock_guidance(blocker: str) -> str:
    guidance = {
        "authorization_confirmed is not true in the engagement file": (
            "Set `engagement.authorization_confirmed` to `true` after confirming authorization."
        ),
        "active_testing_allowed is not true in the engagement file": (
            "Set `engagement.active_testing_allowed` to `true` once active testing is approved."
        ),
        "state_changing_tests_allowed is not true for this state-changing test": (
            "Set `engagement.state_changing_tests_allowed` to `true` if state-changing tests are approved."
        ),
        "no effective target mappings were resolved": (
            "Add at least one non-empty URL under `targets.production` or `targets.alternative`."
        ),
    }
    if blocker in guidance:
        return guidance[blocker]
    if blocker.startswith("missing credential material for "):
        role = blocker.removeprefix("missing credential material for ").strip()
        return (
            f"Add `credentials.{role}.token` or both "
            f"`credentials.{role}.username` and `credentials.{role}.password`."
        )
    if blocker.startswith("missing safe_test_data."):
        key = blocker.removeprefix("missing safe_test_data.").strip()
        return f"Add a non-empty `safe_test_data.{key}` value."
    return blocker or "Review `preflight.md` for the missing engagement detail."


def render_executed_test_report(
    *,
    target_url: str,
    hypothesis: dict[str, Any],
    targets: dict[str, str] | None = None,
    evidence: dict[str, Any],
    review: dict[str, Any],
    commands: list[dict[str, Any]],
    execution_bundle: dict[str, Any] | None = None,
    report_content: dict[str, Any] | None = None,
) -> str:
    test_id = _hypothesis_id(hypothesis)
    status = _text((report_content or {}).get("status")) or _text(evidence.get("status")) or "inconclusive"
    title = _text(hypothesis.get("title")) or "Untitled test"
    summary = _text((report_content or {}).get("summary")) or _text(evidence.get("summary")) or "No summary provided."
    result = _text((report_content or {}).get("result")) or _text(evidence.get("result")) or "No result provided."
    finding = (report_content or {}).get("finding")
    artifacts = _report_artifacts(report_content, execution_bundle, evidence)
    resolution = _resolution_guidance(report_content, evidence, finding, artifacts)
    lines = [
        f"# {test_id}: {title}",
        "",
        "## Status",
        "",
        _status_label(status),
        "",
        "## Scope",
        "",
        f"- Target URL: `{target_url}`",
        f"- Surface: `{_text(hypothesis.get('surface')) or 'unknown'}`",
        f"- Priority: `{_text(hypothesis.get('priority')) or 'unknown'}`",
    ]
    if targets:
        lines.append("- Effective targets:")
        for key, value in targets.items():
            lines.append(f"  - {key}: `{value}`")
    lines.extend(
        [
            "",
            "## Summary",
            "",
            summary,
            "",
            "## Commands Run",
            "",
        ]
    )
    if commands:
        for index, command in enumerate(commands, start=1):
            lines.extend(
                [
                    f"### Command {index}",
                    "",
                    f"- Purpose: {command.get('purpose', '')}",
                    f"- Exit code: `{command.get('exit_code', '')}`",
                    "",
                    "```bash",
                    str(command.get("command", "")),
                    "```",
                ]
            )
            if command.get("stdout"):
                lines.extend(["", "Stdout:", "", "```text", str(command["stdout"]), "```"])
            if command.get("stderr"):
                lines.extend(["", "Stderr:", "", "```text", str(command["stderr"]), "```"])
            lines.append("")
    else:
        lines.extend(["No commands were recorded.", ""])
    _add_dynamic_source_sections(lines, execution_bundle)
    lines.extend(
        [
            "## Evidence",
            "",
            _markdown_value(evidence.get("observations") or evidence.get("evidence") or evidence),
            "",
            "## Result",
            "",
            result,
            "",
            "## Useful Artifacts",
            "",
        ]
    )
    if artifacts:
        for artifact in artifacts:
            lines.extend([f"### {_text(artifact.get('name')) or 'Artifact'}", "", _markdown_value(artifact.get("value")), ""])
    else:
        lines.extend(["None.", ""])
    lines.extend(
        [
            "## Finding",
            "",
        ]
    )
    if isinstance(finding, dict):
        for key in ("severity", "title", "impact", "recommendation"):
            if finding.get(key):
                lines.append(f"- {key.replace('_', ' ').title()}: {finding[key]}")
    elif finding:
        lines.append(str(finding))
    else:
        lines.append("None.")
    lines.extend(
        [
            "",
            "## Resolution",
            "",
            _resolution_markdown(resolution),
            "",
            "## Review",
            "",
            f"- Accepted: `{bool(review.get('accepted'))}`",
            f"- Summary: {_text(review.get('summary')) or 'No review summary provided.'}",
            "",
            "## Follow-Up",
            "",
            _markdown_value((report_content or {}).get("follow_up") or evidence.get("follow_up") or review.get("requested_changes") or "None."),
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _add_dynamic_source_sections(lines: list[str], execution_bundle: dict[str, Any] | None) -> None:
    if not execution_bundle:
        return
    workspace_files = [item for item in _list(execution_bundle.get("workspace_files")) if isinstance(item, dict)]
    local_processes = [item for item in _list(execution_bundle.get("local_processes")) if isinstance(item, dict)]
    local_requests = [item for item in _list(execution_bundle.get("local_requests")) if isinstance(item, dict)]
    if not workspace_files and not local_processes and not local_requests:
        return
    lines.extend(["## Dynamic Source Evidence", ""])
    if workspace_files:
        lines.extend(["### Generated Workspace Files", ""])
        for item in workspace_files:
            lines.append(
                "- "
                f"`{_text(item.get('path')) or 'unknown'}`"
                f" ({_text(item.get('purpose')) or 'no purpose recorded'}, "
                f"{_text(item.get('bytes')) or '0'} bytes)"
            )
        lines.append("")
    if local_processes:
        lines.extend(["### Local Processes", ""])
        for item in local_processes:
            detail = _text(item.get("local_url") or item.get("host_url") or item.get("container_id"))
            lines.append(
                "- "
                f"`{_text(item.get('status')) or 'unknown'}`"
                f" {detail}"
                f" ({_text(item.get('purpose')) or 'no purpose recorded'})"
            )
        lines.append("")
    if local_requests:
        lines.extend(["### Local HTTP Requests", ""])
        for item in local_requests:
            lines.append(
                "- "
                f"`{_text(item.get('method')) or 'GET'}` "
                f"`{_text(item.get('url')) or 'unknown'}` "
                f"exit `{_text(item.get('exit_code')) or 'unknown'}`"
                f" ({_text(item.get('purpose')) or 'no purpose recorded'})"
            )
        lines.append("")


def _report_artifacts(
    report_content: dict[str, Any] | None,
    execution_bundle: dict[str, Any] | None,
    evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for source in (
        (report_content or {}).get("useful_artifacts"),
        (report_content or {}).get("artifacts"),
        (execution_bundle or {}).get("artifacts"),
        evidence.get("artifacts"),
    ):
        candidates.extend(_artifact_candidates_from_source(source))
    candidates.extend(_extract_artifacts(evidence, revision=0))

    by_name: dict[str, dict[str, Any]] = {}
    unnamed: list[dict[str, Any]] = []
    for artifact in candidates:
        if _text(artifact.get("review_status")).lower() == "rejected":
            continue
        name = _text(artifact.get("name"))
        if not name:
            unnamed.append(artifact)
            continue
        current = by_name.get(name)
        if current is None or _artifact_quality_score(artifact) > _artifact_quality_score(current):
            by_name[name] = artifact
    artifacts = list(by_name.values()) + unnamed
    deduplicated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for artifact in artifacts:
        fingerprint = _artifact_fingerprint(artifact)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduplicated.append(artifact)
    return deduplicated


def _artifact_candidates_from_source(source: Any) -> list[dict[str, Any]]:
    if source in (None, "", [], {}):
        return []
    if isinstance(source, dict):
        if any(key in source for key in ("value", "content", "body", "name", "type")):
            normalized = _normalize_artifact(source, revision=0, default_name="artifact")
            return [normalized] if normalized else []
        artifacts: list[dict[str, Any]] = []
        for key, value in source.items():
            normalized = _normalize_artifact(value, revision=0, default_name=_text(key) or "artifact")
            if normalized:
                artifacts.append(normalized)
        return artifacts
    artifacts = []
    for item in _list(source):
        normalized = _normalize_artifact(item, revision=0, default_name="artifact")
        if normalized:
            artifacts.append(normalized)
    return artifacts


def _artifact_quality_score(artifact: dict[str, Any]) -> int:
    value = artifact.get("value")
    if isinstance(value, str):
        return len(value.strip())
    if isinstance(value, dict):
        if _is_descriptor_only_artifact_value(value):
            return 0
        return len(json.dumps(value, sort_keys=True, default=str))
    if isinstance(value, list):
        return len(value)
    return 1 if value not in (None, "", [], {}) else 0


def _resolution_guidance(
    report_content: dict[str, Any] | None,
    evidence: dict[str, Any],
    finding: Any,
    artifacts: list[dict[str, Any]],
) -> Any:
    for source in (report_content or {}, evidence):
        for key in (
            "resolution",
            "remediation",
            "recommended_resolution",
            "developer_guidance",
            "remediation_steps",
            "mitigation",
            "recommendation",
        ):
            if source.get(key) not in (None, "", [], {}):
                return source[key]
    if isinstance(finding, dict):
        for key in ("resolution", "remediation", "recommendation", "mitigation"):
            if finding.get(key) not in (None, "", [], {}):
                return finding[key]

    artifact_hints = []
    for artifact in artifacts:
        artifact_type = _text(artifact.get("type")).lower()
        artifact_name = _text(artifact.get("name")) or "artifact"
        if any(marker in artifact_type for marker in ("remediation", "recommended_policy", "policy", "script")):
            artifact_hints.append(
                f"Use the preserved `{artifact_name}` artifact as a starting point for the fix, then re-test this hypothesis."
            )
    if artifact_hints:
        return artifact_hints

    follow_up = (report_content or {}).get("follow_up") or evidence.get("follow_up")
    if follow_up not in (None, "", [], {}):
        return follow_up
    return "No specific resolution guidance was provided."


def _status_label(status: str) -> str:
    normalized = status.strip().lower().replace("_", "-")
    labels = {
        "finding": "Finding Confirmed",
        "no-finding": "No Finding",
        "inconclusive": "Inconclusive",
        "blocked": "Blocked",
        "skipped": "Skipped",
        "not-executed": "Not Executed",
        "needs-review": "Needs Review",
        "needs-rerun": "Needs Re-Run",
        "rerun-requested": "Re-Run Requested",
        "partial-finding": "Partial Finding",
        "not-applicable": "Not Applicable",
        "error": "Execution Error",
    }
    if normalized in labels:
        return labels[normalized]
    return normalized.replace("-", " ").title() if normalized else "Inconclusive"


def _hypothesis_blockers(
    hypothesis: dict[str, Any],
    engagement: dict[str, Any],
    targets: dict[str, str],
) -> list[str]:
    blockers: list[str] = []
    engagement_settings = engagement.get("engagement") if isinstance(engagement.get("engagement"), dict) else {}
    if not engagement_settings.get("authorization_confirmed"):
        blockers.append("authorization_confirmed is not true in the engagement file")
    if not engagement_settings.get("active_testing_allowed", False):
        blockers.append("active_testing_allowed is not true in the engagement file")
    if _is_state_changing(hypothesis) and not engagement_settings.get("state_changing_tests_allowed", False):
        blockers.append("state_changing_tests_allowed is not true for this state-changing test")
    if not targets:
        blockers.append("no effective target mappings were resolved")
    for role in _needed_roles(hypothesis):
        if not _credential_present(engagement, role):
            blockers.append(f"missing credential material for {role}")
    for item in _needed_safe_data(hypothesis):
        if not _safe_data_present(engagement, item):
            blockers.append(f"missing safe_test_data.{item}")
    return blockers


def _credential_present(engagement: dict[str, Any], role: str) -> bool:
    credentials = engagement.get("credentials") if isinstance(engagement.get("credentials"), dict) else {}
    values = credentials.get(role) if isinstance(credentials.get(role), dict) else {}
    if _text(values.get("token")):
        return True
    return bool(_text(values.get("username")) and _text(values.get("password")))


def _safe_data_present(engagement: dict[str, Any], key: str) -> bool:
    safe_data = engagement.get("safe_test_data") if isinstance(engagement.get("safe_test_data"), dict) else {}
    value = safe_data.get(key)
    if isinstance(value, list):
        return bool(value)
    return bool(_text(value))


def _needed_roles(hypothesis: dict[str, Any]) -> list[str]:
    text = _requirement_text(hypothesis)
    if "no credentials required" in text or "no credential" in text:
        return []
    roles = [role for role in ("admin", "sales", "developer") if _contains_word(text, role)]
    if _enterprise_credentials_needed(text):
        roles.append("enterprise")
    if not roles and _mentions_auth_material(text):
        roles.append("authenticated_user")
    return sorted(set(roles))


def _enterprise_credentials_needed(text: str) -> bool:
    return any(
        phrase in text
        for phrase in (
            "enterprise credential",
            "enterprise credentials",
            "enterprise user",
            "enterprise role",
            "enterprise token",
            "enterprise session",
            "enterprise login",
            "enterprise account credential",
            "enterprise account credentials",
        )
    )


def _needed_safe_data(hypothesis: dict[str, Any]) -> list[str]:
    text = _requirement_text(hypothesis)
    needed: list[str] = []
    if _contains_word(text, "email") or _contains_word(text, "form") or _contains_word(text, "forms"):
        needed.append("email")
    if _contains_word(text, "phone") or _contains_word(text, "sms"):
        needed.append("phone")
    if _contains_word(text, "company"):
        needed.append("company")
    if _contains_word(text, "customer") or _contains_word(text, "customers"):
        needed.append("customer_ids")
    if _contains_word(text, "enterprise"):
        needed.append("enterprise_account_ids")
    if "activation code" in text:
        needed.append("activation_codes")
    return sorted(set(needed))


def _requirement_text(hypothesis: dict[str, Any]) -> str:
    material = {
        "requirements": hypothesis.get("requirements"),
        "preconditions": hypothesis.get("preconditions"),
    }
    return json.dumps(material, sort_keys=True).lower()


def _mentions_auth_material(text: str) -> bool:
    return (
        _contains_word(text, "credential")
        or _contains_word(text, "credentials")
        or "authenticated session" in text
        or "auth token" in text
        or _contains_word(text, "token")
    )


def _contains_word(text: str, word: str) -> bool:
    return bool(re.search(rf"\b{re.escape(word)}\b", text))


def _hypotheses(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in _list(plan.get("test_hypotheses")) if isinstance(item, dict)]


def _has_hypotheses(plan: dict[str, Any] | None) -> bool:
    return bool(plan and _hypotheses(plan))


def _is_state_changing(hypothesis: dict[str, Any]) -> bool:
    text = json.dumps(hypothesis, sort_keys=True).lower()
    return any(marker in text for marker in ("post ", " put ", " delete ", "submit", "create", "modify", "invite"))


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_list(value: Any) -> list[str]:
    return [_text(item) for item in _list(value) if _text(item)]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _hypothesis_id(hypothesis: dict[str, Any]) -> str:
    return _text(hypothesis.get("id")) or "unknown"


def _safe_test_id(test_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", test_id.strip())
    return safe or "unknown"


def _ready_pending_hypotheses(
    plan: dict[str, Any],
    preflight: SecurityTestPreflightResult,
    report_dir: Path,
) -> list[dict[str, Any]]:
    return _pending_hypotheses_for_preflight_items(plan, preflight.ready, report_dir)


def _source_ready_pending_hypotheses(
    plan: dict[str, Any],
    preflight: SecurityTestPreflightResult,
    report_dir: Path,
) -> list[dict[str, Any]]:
    return _pending_hypotheses_for_preflight_items(plan, preflight.source_ready, report_dir)


def _pending_hypotheses_for_preflight_items(
    plan: dict[str, Any],
    items: list[dict[str, Any]],
    report_dir: Path,
) -> list[dict[str, Any]]:
    ready_items = {_text(item.get("id")): item for item in items}
    pending: list[dict[str, Any]] = []
    for hypothesis in _hypotheses(plan):
        test_id = _hypothesis_id(hypothesis)
        ready_item = ready_items.get(test_id)
        if not ready_item:
            continue
        status, reason = _execution_status_for_hypothesis(report_dir, hypothesis)
        ready_item["execution_status"] = status
        ready_item["execution_reason"] = reason
        ready_item["hypothesis_fingerprint"] = hypothesis_fingerprint(hypothesis)
        if status != "current":
            pending.append(hypothesis)
    return pending


def _execution_status_for_hypothesis(report_dir: Path, hypothesis: dict[str, Any]) -> tuple[str, str]:
    test_id = _hypothesis_id(hypothesis)
    report_path = report_dir / "executed_tests" / f"{_safe_test_id(test_id)}.md"
    if not report_path.exists():
        return "pending", "not previously executed"
    metadata = _latest_execution_metadata(report_dir, test_id)
    if metadata is None:
        return "rerun", "previous report is legacy and has no execution metadata"
    if _text(metadata.get("hypothesis_fingerprint")) != hypothesis_fingerprint(hypothesis):
        return "rerun", "hypothesis changed since the previous execution"
    if not bool(metadata.get("review_accepted")):
        return "rerun", "previous execution was not reviewer-accepted"
    return "current", "matching accepted execution already exists"


def _current_executed_test_ids(report_dir: Path) -> set[str]:
    executed_dir = report_dir / "executed_tests"
    if not executed_dir.exists():
        return set()
    current: set[str] = set()
    for path in executed_dir.glob("*.md"):
        metadata = _extract_execution_metadata(path.read_text(encoding="utf-8"))
        if metadata and metadata.get("review_accepted"):
            current.add(path.stem)
    return current


def _disallowed_hosts(command: str, targets: dict[str, str]) -> list[str]:
    allowed_hosts = _target_hosts(targets)
    found_hosts = []
    for raw_url in re.findall(r"https?://[^\s\"'<>),]+", command):
        try:
            host = (urlparse(raw_url).hostname or "").lower()
        except ValueError:
            host = ""
        if host and host not in allowed_hosts:
            found_hosts.append(host)
    return sorted(set(found_hosts))


def _target_hosts(targets: dict[str, str]) -> set[str]:
    hosts: set[str] = set()
    for url in targets.values():
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            host = ""
        if host:
            hosts.add(host)
    return hosts


def _redact_result(result: DockerToolResult, engagement: dict[str, Any]) -> DockerToolResult:
    return DockerToolResult(
        exit_code=result.exit_code,
        stdout=_redact_text(result.stdout, engagement),
        stderr=_redact_text(result.stderr, engagement),
    )


def _redact_text(text: str, engagement: dict[str, Any]) -> str:
    redacted = text
    for secret in _secret_values(engagement):
        redacted = redacted.replace(secret, "[REDACTED]")
    redacted = re.sub(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "[REDACTED_JWT]",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(Authorization:\s*Bearer\s+)([^\s\"']+)",
        r"\1[REDACTED]",
        redacted,
    )
    return redacted


def _secret_values(engagement: dict[str, Any]) -> list[str]:
    credentials = engagement.get("credentials") if isinstance(engagement.get("credentials"), dict) else {}
    values: list[str] = []
    for credential in credentials.values():
        if isinstance(credential, dict):
            for key in ("username", "password", "token"):
                text = _text(credential.get(key))
                if text:
                    values.append(text)
    return sorted(set(values), key=len, reverse=True)


def _truncate(value: str, limit: int = 8000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n[truncated {len(value) - limit} characters]"


def _append_command_log(workspace_dir: Path, command_record: dict[str, Any]) -> None:
    workspace_dir.mkdir(parents=True, exist_ok=True)
    with (workspace_dir / "commands.log").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(command_record, sort_keys=True) + "\n")


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


def _markdown_value(value: Any) -> str:
    if value is None:
        return "None."
    if isinstance(value, str):
        return value.strip() or "None."
    return "```json\n" + json.dumps(value, indent=2, sort_keys=True) + "\n```"


def _resolution_markdown(value: Any) -> str:
    if isinstance(value, str):
        items = _split_inline_numbered_list(value)
        if len(items) > 1:
            return "\n".join(f"{index}. {item}" for index, item in enumerate(items, start=1))
    return _markdown_value(value)


def _split_inline_numbered_list(value: str) -> list[str]:
    text = value.strip()
    if not re.search(r"\s2\.\s+", text):
        return []
    matches = list(re.finditer(r"(?:^|\s)(\d+)\.\s+", text))
    if not matches:
        return []
    items: list[str] = []
    first_item = text[: matches[0].start()].strip()
    if first_item:
        items.append(first_item)
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        item = text[start:end].strip()
        if item:
            items.append(item)
    return items
