from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PLAN_SCHEMA_VERSION = "1.0"


def write_security_test_plan(
    report_dir: Path,
    target_url: str,
    plan: dict[str, Any],
    critic_review: dict[str, Any] | None,
    *,
    accepted: bool,
    iterations: int,
) -> str:
    markdown = render_security_test_plan(target_url, plan, critic_review, accepted=accepted, iterations=iterations)
    (report_dir / "security_test_plan.md").write_text(markdown, encoding="utf-8")
    stale_json_report = report_dir / "security_test_plan.json"
    if stale_json_report.exists():
        stale_json_report.unlink()
    return markdown


def render_security_test_plan(
    target_url: str,
    plan: dict[str, Any],
    critic_review: dict[str, Any] | None,
    *,
    accepted: bool,
    iterations: int,
) -> str:
    title = _text(plan.get("title")) or "Security Test Plan"
    lines: list[str] = [f"# {title}", ""]
    lines.extend(
        [
            "## Plan Metadata",
            "",
            f"- Schema version: `{PLAN_SCHEMA_VERSION}`",
            f"- Target URL: `{target_url}`",
            f"- Planner/reviewer accepted: `{str(accepted).lower()}`",
            f"- Planner/reviewer iterations: `{iterations}`",
            "",
        ]
    )
    _add_text_section(lines, "Scope Summary", plan.get("scope_summary"))
    _add_list_section(lines, "Assumptions", plan.get("assumptions"))
    _add_hypotheses(lines, plan.get("test_hypotheses"))
    _add_deferred_opportunities(lines, plan.get("deferred_test_opportunities"))
    _add_list_section(lines, "Not In Scope", plan.get("not_in_scope"))
    _add_list_section(lines, "Open Questions", plan.get("open_questions"))
    _add_critic_review(lines, critic_review)
    return "\n".join(lines).rstrip() + "\n"


def _add_text_section(lines: list[str], heading: str, value: Any) -> None:
    lines.extend([f"## {heading}", ""])
    lines.extend([_text(value) or "No content provided.", ""])


def _add_list_section(lines: list[str], heading: str, value: Any) -> None:
    lines.extend([f"## {heading}", ""])
    items = [item for item in _list(value) if not _is_placeholder_item(item)]
    if not items:
        lines.extend(["No items reported.", ""])
        return
    for item in items:
        if isinstance(item, dict):
            title = _text(
                item.get("title")
                or item.get("name")
                or item.get("requirement")
                or item.get("item")
                or item.get("issue")
                or item.get("suggestion")
                or item.get("id")
            )
            detail = _text(
                item.get("detail")
                or item.get("description")
                or item.get("notes")
                or item.get("required_change")
                or item.get("rationale")
            )
            if not title and not detail:
                continue
            lines.append(f"- **{title or 'Detail'}**")
            if detail:
                lines.append(f"  {detail}")
        else:
            lines.append(f"- {_text(item)}")
    lines.append("")


def _add_hypotheses(lines: list[str], value: Any) -> None:
    hypotheses = [item for item in _list(value) if isinstance(item, dict)]
    lines.extend(["## Test Hypotheses", ""])
    if not hypotheses:
        lines.extend(["No test hypotheses reported.", ""])
        return
    for index, hypothesis in enumerate(hypotheses, start=1):
        hypothesis_id = _text(hypothesis.get("id")) or f"HYP-{index:03d}"
        title = _text(hypothesis.get("title")) or "Untitled hypothesis"
        lines.extend([f"### {hypothesis_id}: {title}", ""])
        lines.extend(
            [
                f"- Surface: `{_text(hypothesis.get('surface')) or 'unknown'}`",
                f"- Priority: `{_text(hypothesis.get('priority')) or 'unknown'}`",
                f"- Status: `{_text(hypothesis.get('status')) or 'planned'}`",
                f"- Execution mode: `{_text(hypothesis.get('execution_mode')) or 'live'}`",
                f"- Evidence sources: `{', '.join(_string_list(hypothesis.get('evidence_sources'))) or 'live'}`",
                f"- Verification strategy: `{_text(hypothesis.get('verification_strategy')) or 'live-verification'}`",
                "",
            ]
        )
        _add_inline_text(lines, "Hypothesis", hypothesis.get("hypothesis"))
        _add_inline_text(lines, "Organisational Risk", hypothesis.get("organisational_risk"))
        _add_inline_text(lines, "Business Value", hypothesis.get("business_value"))
        _add_inline_text(lines, "Expected Secure Behavior", hypothesis.get("expected_secure_behavior"))
        _add_bullets(lines, "Evidence", hypothesis.get("evidence"))
        _add_bullets(lines, "Affected Runtime", _format_structured_items(hypothesis.get("affected_runtime")))
        _add_bullets(lines, "Affected Source", _format_structured_items(hypothesis.get("affected_source")))
        _add_bullets(lines, "Requirements", hypothesis.get("requirements"))
        _add_bullets(lines, "Tools Expected", hypothesis.get("tools_expected"))
        _add_bullets(lines, "Preconditions", hypothesis.get("preconditions"))
        _add_bullets(lines, "Test Steps", hypothesis.get("test_steps"))
        _add_bullets(lines, "Interesting Failure Modes", hypothesis.get("interesting_failure_modes"))
        _add_bullets(lines, "Safety Notes", hypothesis.get("safety_notes"))
        _add_bullets(lines, "Stopping Conditions", hypothesis.get("stopping_conditions"))


def _add_deferred_opportunities(lines: list[str], value: Any) -> None:
    opportunities = [item for item in _list(value) if isinstance(item, dict) and not _is_placeholder_item(item)]
    lines.extend(["## Deferred Test Opportunities", ""])
    if not opportunities:
        lines.extend(["No deferred test opportunities reported.", ""])
        return
    for index, opportunity in enumerate(opportunities, start=1):
        title = _text(opportunity.get("title")) or f"Deferred opportunity {index}"
        lines.extend([f"### {title}", ""])
        surface = _text(opportunity.get("surface"))
        if surface:
            lines.extend([f"- Surface: `{surface}`", ""])
        _add_inline_text(lines, "Organisational Risk", opportunity.get("organisational_risk"))
        _add_inline_text(lines, "Business Value", opportunity.get("business_value"))
        _add_inline_text(lines, "Defer Reason", opportunity.get("defer_reason"))
        _add_bullets(lines, "Evidence", opportunity.get("evidence"))
        _add_bullets(lines, "Requirements To Proceed", opportunity.get("requirements_to_proceed"))
        _add_inline_text(lines, "Suggested Next Step", opportunity.get("suggested_next_step"))


def _add_inline_text(lines: list[str], heading: str, value: Any) -> None:
    text = _text(value)
    if text:
        lines.extend([f"#### {heading}", "", text, ""])


def _add_bullets(lines: list[str], heading: str, value: Any) -> None:
    items = _string_list(value)
    if not items:
        return
    lines.extend([f"#### {heading}", ""])
    for item in items:
        lines.append(f"- {item}")
    lines.append("")


def _add_critic_review(lines: list[str], review: dict[str, Any] | None) -> None:
    lines.extend(["## Reviewer Decision", ""])
    if not review:
        lines.extend(["No reviewer decision recorded.", ""])
        return
    lines.extend(
        [
            f"- Accepted: `{str(bool(review.get('accepted'))).lower()}`",
            f"- Summary: {_text(review.get('summary')) or 'No summary provided.'}",
            "",
        ]
    )
    _add_list_section(lines, "Blocking Reviewer Findings", review.get("blocking_findings"))
    _add_list_section(lines, "Non-Blocking Reviewer Suggestions", review.get("non_blocking_suggestions"))


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _is_placeholder_item(value: Any) -> bool:
    if isinstance(value, dict):
        meaningful_values = [_text(item) for item in value.values()]
        return not meaningful_values or all(_is_placeholder_text(item) for item in meaningful_values)
    return _is_placeholder_text(value)


def _is_placeholder_text(value: Any) -> bool:
    text = _text(value).strip("*`-: ").lower()
    return text in {"", "item", "items", "placeholder", "todo", "tbd", "n/a", "none", "null"}


def _string_list(value: Any) -> list[str]:
    return [_text(item) for item in _list(value) if _text(item) and not _is_placeholder_item(item)]


def _format_structured_items(value: Any) -> list[str]:
    items = []
    for item in _list(value):
        if _is_placeholder_item(item):
            continue
        if isinstance(item, dict):
            path = _text(item.get("path"))
            method = _text(item.get("method"))
            url = _text(item.get("url") or item.get("route") or item.get("full_route"))
            line = _text(item.get("start_line") or item.get("line"))
            end_line = _text(item.get("end_line"))
            if path:
                suffix = f":{line}" if line and line == end_line else f":{line}-{end_line}" if line and end_line else ""
                label = f"{path}{suffix}"
            elif method or url:
                label = f"{method} {url}".strip()
            else:
                label = json.dumps(item, sort_keys=True)
            reason = _text(item.get("reason") or item.get("symbol"))
            items.append(f"{label} ({reason})" if reason else label)
        else:
            items.append(_text(item))
    return [item for item in items if item]


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()
