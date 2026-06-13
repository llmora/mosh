from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Callable, Protocol

from open_security_harness.config import AppConfig
from open_security_harness.crews.discovery.crew import (
    CREW_CONFIG_PACKAGE,
    CrewAIUnavailable,
    _build_task_with_output_event,
    _llm,
    _load_crewai,
)
from open_security_harness.crews.reporting.reporting import (
    render_final_report,
    validate_final_report_content,
    validate_rendered_report,
)
from open_security_harness.memory import FileMemory
from open_security_harness.models import Event
from open_security_harness.scope import report_dir_name


EXECUTION_METADATA_STARTS = ("<!-- osh-execution", "<!-- appsec-harness-execution")
EXECUTION_METADATA_END = "-->"


@dataclass
class FinalReportState:
    target_url: str
    report_dir: Path
    memory: FileMemory
    bundle: dict[str, Any]
    report_content: dict[str, Any] | None = None
    report_path: Path | None = None
    report_markdown: str = ""
    review: dict[str, Any] | None = None


class FinalReportingCrewRunner(Protocol):
    def run(self, target_url: str, report_dir: Path, memory: FileMemory, bundle: dict[str, Any]) -> Path:
        pass


class FinalReportingOrchestrator:
    def __init__(
        self,
        config: AppConfig,
        output_root: Path = Path("report"),
        event_sink: Callable[[Event], None] | None = None,
        crew_runner: FinalReportingCrewRunner | None = None,
    ) -> None:
        self.config = config
        self.output_root = output_root
        self.event_sink = event_sink
        self.crew_runner = crew_runner or build_final_reporting_crew_runner(config)

    def run(self, url: str) -> Path:
        domain_dir = self.output_root / report_dir_name(url)
        report_dir = domain_dir / "final-report"
        memory = FileMemory(report_dir, event_sink=self.event_sink)
        memory.record_event("orchestrator", "start", "Starting final report generation", {"target": url})
        bundle = build_final_report_bundle(url, domain_dir)
        report_path = self.crew_runner.run(url, report_dir, memory, bundle)
        memory.record_event(
            "orchestrator",
            "complete",
            "Final report generation completed",
            {"report_path": str(report_path)},
        )
        return report_dir


def build_final_reporting_crew_runner(config: AppConfig) -> FinalReportingCrewRunner:
    return CrewAIFinalReportingCrewRunner(config)


class CrewAIFinalReportingCrewRunner:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def run(self, target_url: str, report_dir: Path, memory: FileMemory, bundle: dict[str, Any]) -> Path:
        missing_keys = self.config.missing_llm_api_keys_for_models(
            [self.config.models.reporting.writer, self.config.models.reporting.reviewer]
        )
        if missing_keys:
            raise CrewAIUnavailable(f"Missing LLM API key(s): {', '.join(missing_keys)}.")
        crewai = _load_crewai()
        state = FinalReportState(target_url=target_url, report_dir=report_dir, memory=memory, bundle=bundle)
        writer_crew = _build_writer_crew(crewai, self.config, state)
        writer_crew.crew().kickoff(
            inputs={
                "target_url": target_url,
                "report_bundle": json.dumps(bundle, sort_keys=True),
            }
        )
        if not state.report_path or not state.report_path.exists():
            raise RuntimeError("Final report writer did not write report.md.")

        reviewer_crew = _build_reviewer_crew(crewai, self.config, state)
        reviewer_crew.crew().kickoff(
            inputs={
                "target_url": target_url,
                "report_bundle": json.dumps(bundle, sort_keys=True),
                "generated_report": json.dumps(
                    {
                        "path": str(state.report_path),
                        "bytes": len(state.report_markdown.encode("utf-8")),
                        "markdown": state.report_markdown,
                    },
                    sort_keys=True,
                ),
            }
        )
        if not state.review:
            raise RuntimeError("Final report reviewer did not submit a review.")
        if not bool(state.review.get("accepted")):
            findings = state.review.get("blocking_findings") or []
            summary = _text(state.review.get("summary"))
            detail = findings if findings else summary
            raise RuntimeError(f"Final report reviewer rejected report.md: {detail}")
        return state.report_path


def build_final_report_bundle(target_url: str, domain_dir: Path) -> dict[str, Any]:
    discovery_dir = domain_dir / "discovery"
    planning_dir = domain_dir / "security-test-planning"
    testing_dir = domain_dir / "security-testing"
    plan = _load_structured_security_plan(planning_dir)
    discovery = _load_discovery_summary(discovery_dir)
    testing_memory = _read_json_list(testing_dir / "memory.json")
    execution_bundles = _execution_bundles_by_id(testing_memory)
    executed_tests = _load_executed_tests(testing_dir, plan, execution_bundles)
    preflight = _latest_memory_content(testing_memory, "security_testing_preflight")
    source_artifacts = [
        str(path)
        for path in [
            discovery_dir / "report.md",
            discovery_dir / "memory.json",
            planning_dir / "security_test_plan.md",
            planning_dir / "memory.json",
            testing_dir / "preflight.md",
            testing_dir / "memory.json",
        ]
        if path.exists()
    ]
    return {
        "schema": "osh.final-report-bundle.v1",
        "target_url": target_url,
        "discovery": discovery,
        "security_plan": {
            "title": _text(plan.get("title")) or "Security Test Plan",
            "scope_summary": _text(plan.get("scope_summary")),
        },
        "planned_tests": _hypotheses(plan),
        "engagement": {
            "targets": preflight.get("targets", {}) if isinstance(preflight, dict) else {},
        },
        "blocked_tests": preflight.get("blocked", []) if isinstance(preflight, dict) else [],
        "executed_tests": executed_tests,
        "source_artifacts": source_artifacts,
    }


def _build_writer_crew(crewai: Any, config: AppConfig, state: FinalReportState):
    write_tool = _build_write_final_report_tool(crewai, state)
    agents_path, tasks_path = _write_reporting_subset_configs(
        state.report_dir,
        "writer",
        agent_keys=["writer"],
        task_keys=["write_final_report_task"],
    )

    @crewai.CrewBase
    class FinalReportWriterCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def writer(self):
            return crewai.Agent(
                config=self.agents_config["writer"],
                llm=_llm(crewai, config, config.models.reporting.writer),
                tools=[write_tool],
                allow_delegation=False,
            )

        @crewai.task
        def write_final_report_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["write_final_report_task"],
                agent=self.writer(),
                agent_name="writer",
                task_name="write_final_report_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.writer()],
                tasks=[self.write_final_report_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return FinalReportWriterCrew()


def _build_reviewer_crew(crewai: Any, config: AppConfig, state: FinalReportState):
    review_tool = _build_submit_final_report_review_tool(crewai, state)
    agents_path, tasks_path = _write_reporting_subset_configs(
        state.report_dir,
        "reviewer",
        agent_keys=["reviewer"],
        task_keys=["review_final_report_task"],
    )

    @crewai.CrewBase
    class FinalReportReviewerCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def reviewer(self):
            return crewai.Agent(
                config=self.agents_config["reviewer"],
                llm=_llm(crewai, config, config.models.reporting.reviewer),
                tools=[review_tool],
                allow_delegation=False,
            )

        @crewai.task
        def review_final_report_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["review_final_report_task"],
                agent=self.reviewer(),
                agent_name="reviewer",
                task_name="review_final_report_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.reviewer()],
                tasks=[self.review_final_report_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return FinalReportReviewerCrew()


def _build_write_final_report_tool(crewai: Any, state: FinalReportState):
    class FinalReportInput(crewai.BaseModel):
        report: dict[str, Any] | str = crewai.Field(..., description="Structured final report narrative content.")

    class WriteFinalReportTool(crewai.BaseTool):
        name: str = "write_final_report"
        description: str = "Write final-report/report.md from supported security testing evidence."
        args_schema: type[crewai.BaseModel] = FinalReportInput

        def _run(self, report: Any) -> str:
            content = _coerce_mapping(report)
            errors = validate_final_report_content(state.bundle, content)
            if errors:
                raise ValueError("; ".join(errors))
            markdown = render_final_report(state.target_url, state.bundle, content)
            render_errors = validate_rendered_report(state.bundle, markdown)
            if render_errors:
                raise ValueError("; ".join(render_errors))
            state.report_dir.mkdir(parents=True, exist_ok=True)
            report_path = state.report_dir / "report.md"
            report_path.write_text(markdown, encoding="utf-8")
            state.report_content = content
            state.report_markdown = markdown
            state.report_path = report_path
            state.memory.add_item(
                "final_report",
                {
                    "path": str(report_path),
                    "structured": content,
                    "bytes": len(markdown.encode("utf-8")),
                },
                "writer",
            )
            state.memory.record_event(
                "writer",
                "report_written",
                "Final report writer wrote customer report",
                {"path": str(report_path), "bytes": len(markdown.encode("utf-8"))},
            )
            return json.dumps({"path": str(report_path), "bytes": len(markdown.encode("utf-8"))})

    return WriteFinalReportTool()


def _build_submit_final_report_review_tool(crewai: Any, state: FinalReportState):
    class FinalReportReviewInput(crewai.BaseModel):
        review: dict[str, Any] | str = crewai.Field(..., description="Structured final report review decision.")

    class SubmitFinalReportReviewTool(crewai.BaseTool):
        name: str = "submit_final_report_review"
        description: str = "Submit the reviewer decision for final-report/report.md."
        args_schema: type[crewai.BaseModel] = FinalReportReviewInput

        def _run(self, review: Any) -> str:
            content = _coerce_mapping(review)
            deterministic_errors = validate_rendered_report(state.bundle, state.report_markdown)
            reviewer_blocking = _list(content.get("blocking_findings"))
            blocking = reviewer_blocking + deterministic_errors
            accepted = not blocking
            state.review = {
                "accepted": accepted,
                "reviewer_accepted": bool(content.get("accepted")),
                "summary": _text(content.get("summary")) or "No review summary provided.",
                "blocking_findings": blocking,
            }
            state.memory.add_item("final_report_review", state.review, "reviewer")
            state.memory.record_event(
                "reviewer",
                "review_submitted",
                "Final report reviewer submitted review",
                {"accepted": accepted, "blocking_findings": len(blocking)},
            )
            return json.dumps(state.review, sort_keys=True)

    return SubmitFinalReportReviewTool()


def _write_reporting_subset_configs(
    report_dir: Path,
    name: str,
    agent_keys: list[str],
    task_keys: list[str],
) -> tuple[str, str]:
    config_dir = report_dir / ".crew_config"
    config_dir.mkdir(parents=True, exist_ok=True)
    source_agents = resources.files(CREW_CONFIG_PACKAGE).joinpath("reporting/agents.yaml").read_text(encoding="utf-8")
    source_tasks = resources.files(CREW_CONFIG_PACKAGE).joinpath("reporting/tasks.yaml").read_text(encoding="utf-8")
    agents_path = config_dir / f"{name}_agents.yaml"
    tasks_path = config_dir / f"{name}_tasks.yaml"
    agents_path.write_text(_select_yaml_top_level_blocks(source_agents, agent_keys), encoding="utf-8")
    tasks_path.write_text(_select_yaml_top_level_blocks(source_tasks, task_keys), encoding="utf-8")
    return str(agents_path.resolve()), str(tasks_path.resolve())


def _select_yaml_top_level_blocks(source: str, keys: list[str]) -> str:
    blocks: dict[str, list[str]] = {}
    current_key: str | None = None
    current_block: list[str] = []
    for line in source.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            if current_key is not None:
                blocks[current_key] = current_block
            current_key = line.rstrip()[:-1]
            current_block = [line]
        elif current_key is not None:
            current_block.append(line)
    if current_key is not None:
        blocks[current_key] = current_block
    missing = [key for key in keys if key not in blocks]
    if missing:
        raise KeyError(f"Missing reporting YAML config block(s): {', '.join(missing)}")
    return "\n\n".join("\n".join(blocks[key]).rstrip() for key in keys) + "\n"


def _load_discovery_summary(discovery_dir: Path) -> dict[str, Any]:
    memory = _read_json_list(discovery_dir / "memory.json")
    structured = _latest_memory_content(memory, "llm_report").get("structured", {})
    if not isinstance(structured, dict):
        structured = {}
    key_areas: list[Any] = []
    for key in [
        "key_discovered_areas",
        "discovered_routes",
        "api_endpoints",
        "forms",
        "technologies",
        "third_party_services",
        "authentication_observations",
    ]:
        key_areas.extend(_list(structured.get(key)))
    return {
        "report_path": str(discovery_dir / "report.md"),
        "executive_summary": _text(structured.get("executive_summary")),
        "application_description": _text(structured.get("application_description")),
        "key_areas": key_areas,
    }


def _load_structured_security_plan(planning_dir: Path) -> dict[str, Any]:
    memory = _read_json_list(planning_dir / "memory.json")
    final = _latest_memory_content(memory, "security_test_plan_final").get("structured")
    if isinstance(final, dict):
        return final
    draft = _latest_memory_content(memory, "security_test_plan_draft").get("structured")
    return draft if isinstance(draft, dict) else {}


def _load_executed_tests(
    testing_dir: Path,
    plan: dict[str, Any],
    execution_bundles: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    executed_dir = testing_dir / "executed_tests"
    if not executed_dir.exists():
        return []
    hypotheses = {_text(item.get("id")): item for item in _hypotheses(plan)}
    tests: list[dict[str, Any]] = []
    for report_path in sorted(executed_dir.glob("*.md")):
        markdown = report_path.read_text(encoding="utf-8")
        metadata = _extract_execution_metadata(markdown) or {}
        body = _strip_execution_metadata(markdown)
        test_id = _text(metadata.get("test_id")) or report_path.stem
        hypothesis = hypotheses.get(test_id, {})
        bundle = execution_bundles.get(test_id, {})
        evidence = bundle.get("final_evidence") if isinstance(bundle.get("final_evidence"), dict) else {}
        review = bundle.get("final_review") if isinstance(bundle.get("final_review"), dict) else {}
        status = _canonical_status(_text(metadata.get("status")) or _text(evidence.get("status")) or _extract_status(body))
        review_accepted = bool(metadata.get("review_accepted")) or bool(review.get("accepted"))
        cvss = _cvss_from_known_data(evidence, review, bundle)
        surface = _text(hypothesis.get("surface")) or _extract_scope_value(body, "Surface")
        severity = (
            _text(metadata.get("severity"))
            or _text(metadata.get("priority"))
            or _text(hypothesis.get("priority"))
            or _extract_scope_value(body, "Priority")
            or _extract_qualitative_severity(body)
            or "unknown"
        )
        tests.append(
            {
                "id": test_id,
                "title": _text(hypothesis.get("title")) or _extract_title(body, test_id),
                "surface": surface,
                "affected_area": surface,
                "severity": severity,
                "status": status or "unknown",
                "review_accepted": review_accepted,
                "accepted_finding": review_accepted and status == "finding",
                "cvss": cvss,
                "summary": _extract_section(body, "Summary") or _text(evidence.get("summary")),
                "result": _extract_section(body, "Result") or _text(evidence.get("result")),
                "resolution": _extract_section(body, "Resolution") or _text(evidence.get("resolution")),
                "evidence_summary": _extract_section(body, "Evidence"),
                "commands_summary": _summarize_commands(body),
                "executed_at": _text(metadata.get("executed_at")),
                "plan_revision_id": _text(metadata.get("plan_revision_id")),
                "hypothesis_fingerprint": _text(metadata.get("hypothesis_fingerprint")),
                "report_path": str(report_path),
            }
        )
    return tests


def _extract_execution_metadata(markdown: str) -> dict[str, Any] | None:
    marker = next((candidate for candidate in EXECUTION_METADATA_STARTS if markdown.startswith(candidate)), "")
    if not marker:
        return None
    end = markdown.find(EXECUTION_METADATA_END)
    if end < 0:
        return None
    payload = markdown[len(marker) : end].strip()
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _strip_execution_metadata(markdown: str) -> str:
    marker = next((candidate for candidate in EXECUTION_METADATA_STARTS if markdown.startswith(candidate)), "")
    if not marker:
        return markdown
    end = markdown.find(EXECUTION_METADATA_END)
    if end < 0:
        return markdown
    return markdown[end + len(EXECUTION_METADATA_END) :]


def _execution_bundles_by_id(memory_items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    bundles: dict[str, dict[str, Any]] = {}
    for item in memory_items:
        if item.get("kind") != "security_test_execution_bundle":
            continue
        content = item.get("content") if isinstance(item.get("content"), dict) else {}
        test_id = _text(content.get("test_id"))
        if test_id:
            bundles[test_id] = content
    return bundles


def _latest_memory_content(memory_items: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    for item in reversed(memory_items):
        if item.get("kind") == kind and isinstance(item.get("content"), dict):
            return item["content"]
    return {}


def _read_json_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []


def _hypotheses(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in _list(plan.get("test_hypotheses")) if isinstance(item, dict)]


def _extract_title(markdown: str, fallback_id: str) -> str:
    first_line = markdown.strip().splitlines()[0] if markdown.strip() else ""
    if first_line.startswith("#"):
        title = first_line.lstrip("#").strip()
        return title.split(":", 1)[1].strip() if ":" in title else title
    return fallback_id


def _extract_status(markdown: str) -> str:
    status = _extract_section(markdown, "Status").lower()
    if "finding" in status and "no finding" not in status:
        return "finding"
    if "no finding" in status:
        return "no-finding"
    if "inconclusive" in status:
        return "inconclusive"
    if "failed" in status:
        return "failed"
    return ""


def _extract_scope_value(markdown: str, label: str) -> str:
    scope = _extract_section(markdown, "Scope")
    if not scope:
        return ""
    pattern = re.compile(rf"^-\s*{re.escape(label)}:\s*`?([^`\n]+)`?\s*$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(scope)
    return _text(match.group(1)) if match else ""


def _extract_qualitative_severity(markdown: str) -> str:
    for section_name in ("Summary", "Result"):
        section = _extract_section(markdown, section_name).lower()
        for severity in ("critical", "high", "medium", "low", "informational"):
            if re.search(rf"\b{severity}\b", section):
                return severity
    return ""


def _canonical_status(value: str) -> str:
    normalized = _text(value).lower().replace("_", "-")
    if normalized in ("finding", "confirmed", "finding-confirmed"):
        return "finding"
    if normalized in ("no-finding", "no finding", "not-found", "none"):
        return "no-finding"
    if normalized in ("inconclusive", "failed"):
        return normalized
    return normalized


def _extract_section(markdown: str, heading: str) -> str:
    pattern = re.compile(rf"^## {re.escape(heading)}\s*$", re.MULTILINE)
    match = pattern.search(markdown)
    if not match:
        return ""
    start = match.end()
    next_heading = re.search(r"^##\s+", markdown[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(markdown)
    return markdown[start:end].strip()


def _summarize_commands(markdown: str) -> str:
    section = _extract_section(markdown, "Commands Run")
    if not section or "No commands were recorded." in section:
        return ""
    commands = re.findall(r"^### Command\s+\d+\s*$", section, re.MULTILINE)
    purposes = re.findall(r"^- Purpose:\s*(.+)$", section, re.MULTILINE)
    exit_codes = re.findall(r"^- Exit code:\s*`?([^`\n]+)`?", section, re.MULTILINE)
    lines = [f"{len(commands) or len(exit_codes) or 1} command(s) were recorded in the source executed test report."]
    for index, purpose in enumerate(purposes[:5], start=1):
        exit_code = exit_codes[index - 1] if index - 1 < len(exit_codes) else "not recorded"
        lines.append(f"- Command {index}: {_text(purpose)} (exit code `{_text(exit_code) or 'not recorded'}`)")
    if len(purposes) > 5:
        lines.append(f"- {len(purposes) - 5} additional command(s) are listed in the source report.")
    return "\n".join(lines)


def _cvss_from_known_data(*values: Any) -> Any:
    for value in values:
        if isinstance(value, dict):
            if "cvss" in value:
                return value["cvss"]
            score = value.get("cvss_score")
            vector = value.get("cvss_vector")
            if score or vector:
                return {"score": score, "vector": vector}
            nested = _cvss_from_known_data(*value.values())
            if nested:
                return nested
        elif isinstance(value, list):
            nested = _cvss_from_known_data(*value)
            if nested:
                return nested
    return None


def _coerce_mapping(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
