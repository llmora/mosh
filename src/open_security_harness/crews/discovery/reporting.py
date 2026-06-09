from __future__ import annotations

from pathlib import Path
from typing import Any

from open_security_harness.models import CrawlResult


REPORT_SCHEMA_VERSION = "1.0"

REPORT_SECTION_ORDER = (
    "Executive Summary",
    "Target And Scope",
    "Application Description",
    "Summary Statistics",
    "Key Discovered Areas",
    "Discovered Routes",
    "API Endpoints",
    "Forms",
    "Technology And SBOM Summary",
    "Third-Party Services",
    "Authentication Observations",
    "Confirmed Findings",
    "Inferred Findings",
    "Security Testing Feedback",
    "Discovery Limitations",
    "Recommended Next Steps",
    "Appendix",
)

SECURITY_TESTING_FEEDBACK_HEADING = "Security Testing Feedback"


def write_reports(
    report_dir: Path,
    target_url: str,
    crawl: CrawlResult,
    components: list[dict[str, str]],
    summary: dict[str, Any],
    report_content: dict[str, Any],
) -> str:
    markdown_report = render_markdown_report(target_url, crawl, components, summary, report_content)
    (report_dir / "report.md").write_text(markdown_report, encoding="utf-8")
    stale_json_report = report_dir / "report.json"
    if stale_json_report.exists():
        stale_json_report.unlink()
    return markdown_report


def render_markdown_report(
    target_url: str,
    crawl: CrawlResult,
    components: list[dict[str, str]],
    summary: dict[str, Any],
    report_content: dict[str, Any],
) -> str:
    title = _text(report_content.get("title")) or "Application Discovery Report"
    lines: list[str] = [f"# {title}", ""]
    lines.extend(["## Report Metadata", "", f"- Schema version: `{REPORT_SCHEMA_VERSION}`", f"- Target URL: `{target_url}`", ""])

    _add_text_section(lines, "Executive Summary", report_content.get("executive_summary"))
    _add_items_section(lines, "Target And Scope", report_content.get("target_scope"))
    _add_text_section(lines, "Application Description", report_content.get("application_description"))
    _add_summary_statistics(lines, summary)
    _add_items_section(lines, "Key Discovered Areas", report_content.get("key_discovered_areas"))
    _add_routes_section(lines, report_content.get("discovered_routes"), crawl)
    _add_api_section(lines, report_content.get("api_endpoints"))
    _add_forms_section(lines, report_content.get("forms"))
    _add_components_section(lines, "Technology And SBOM Summary", report_content.get("technologies") or components)
    _add_components_section(lines, "Third-Party Services", report_content.get("third_party_services"))
    _add_items_section(lines, "Authentication Observations", report_content.get("authentication_observations"))
    _add_items_section(lines, "Confirmed Findings", report_content.get("confirmed_findings"))
    _add_items_section(lines, "Inferred Findings", report_content.get("inferred_findings"))
    _add_items_section(lines, SECURITY_TESTING_FEEDBACK_HEADING, report_content.get("security_testing_feedback"))
    _add_items_section(lines, "Discovery Limitations", report_content.get("limitations"))
    _add_actions_section(lines, report_content.get("recommended_next_steps"))
    _add_appendix(lines, report_content.get("appendix"), crawl)

    return "\n".join(lines).rstrip() + "\n"


def update_report_with_security_testing_feedback(report_dir: Path, updates: list[dict[str, Any]]) -> str:
    report_path = report_dir / "report.md"
    existing = report_path.read_text(encoding="utf-8") if report_path.exists() else "# Application Discovery Report\n"
    section = _render_security_testing_feedback_section(updates)
    updated = _replace_markdown_section(existing, SECURITY_TESTING_FEEDBACK_HEADING, section)
    report_path.write_text(updated, encoding="utf-8")
    return updated


def _render_security_testing_feedback_section(updates: list[dict[str, Any]]) -> str:
    lines = [f"## {SECURITY_TESTING_FEEDBACK_HEADING}", ""]
    if not updates:
        lines.extend(["No security-testing feedback has been fed back into discovery.", ""])
        return "\n".join(lines)
    lines.extend(["| Type | Detail | Confidence | Source Test | Evidence |", "|---|---|---|---|---|"])
    for update in updates:
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(update.get("type") or update.get("kind") or update.get("category")),
                    _cell(update.get("detail") or update.get("summary") or update.get("value")),
                    _cell(update.get("confidence")),
                    _cell(update.get("test_id")),
                    _cell("; ".join(_string_list(update.get("evidence") or update.get("source_evidence")))),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def _replace_markdown_section(markdown: str, heading: str, replacement: str) -> str:
    marker = f"## {heading}"
    start = markdown.find(marker)
    if start < 0:
        return markdown.rstrip() + "\n\n" + replacement.rstrip() + "\n"
    next_heading = markdown.find("\n## ", start + len(marker))
    if next_heading < 0:
        return markdown[:start].rstrip() + "\n\n" + replacement.rstrip() + "\n"
    return markdown[:start].rstrip() + "\n\n" + replacement.rstrip() + "\n" + markdown[next_heading:]


def _add_text_section(lines: list[str], heading: str, value: Any) -> None:
    lines.extend([f"## {heading}", ""])
    text = _text(value)
    lines.extend([text or "No content provided.", ""])


def _add_items_section(lines: list[str], heading: str, value: Any) -> None:
    lines.extend([f"## {heading}", ""])
    items = _list(value)
    if not items:
        lines.extend(["No items reported.", ""])
        return
    for item in items:
        if isinstance(item, dict):
            title = _text(item.get("title") or item.get("name") or item.get("finding") or item.get("summary")) or "Item"
            detail = _text(item.get("detail") or item.get("description") or item.get("notes"))
            lines.append(f"- **{title}**")
            if detail:
                lines.append(f"  {detail}")
            confidence = _text(item.get("confidence"))
            evidence = _string_list(item.get("evidence"))
            if confidence:
                lines.append(f"  Confidence: {confidence}")
            if evidence:
                lines.append(f"  Evidence: {'; '.join(evidence)}")
        else:
            lines.append(f"- {_text(item)}")
    lines.append("")


def _add_summary_statistics(lines: list[str], summary: dict[str, Any]) -> None:
    lines.extend(["## Summary Statistics", "", "| Metric | Value |", "|---|---|"])
    for key in sorted(summary):
        lines.append(f"| {_label(key)} | {_cell(summary[key])} |")
    lines.append("")


def _add_routes_section(lines: list[str], value: Any, crawl: CrawlResult) -> None:
    routes = _list(value) or [
        {
            "url": page.url,
            "status": page.status,
            "content_type": page.content_type,
            "notes": page.title or "",
        }
        for page in crawl.pages
    ]
    lines.extend(["## Discovered Routes", "", "| URL | Status | Content Type | Notes | Evidence |", "|---|---:|---|---|---|"])
    if not routes:
        lines.append("| No routes reported. |  |  |  |  |")
    for route in routes:
        if not isinstance(route, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(route.get("url") or route.get("route") or route.get("path")),
                    _cell(route.get("status") or route.get("observed_status")),
                    _cell(route.get("content_type") or route.get("method")),
                    _cell(route.get("notes") or route.get("purpose") or route.get("description")),
                    _cell("; ".join(_string_list(route.get("evidence") or route.get("references")))),
                ]
            )
            + " |"
        )
    lines.append("")


def _add_api_section(lines: list[str], value: Any) -> None:
    endpoints = _list(value)
    lines.extend(["## API Endpoints", "", "| Endpoint | Method | Status | Purpose | Confidence | Evidence |", "|---|---|---|---|---|---|"])
    if not endpoints:
        lines.append("| No API endpoints reported. |  |  |  |  |  |")
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(endpoint.get("endpoint") or endpoint.get("url") or endpoint.get("path")),
                    _cell(endpoint.get("method") or endpoint.get("observed_method") or endpoint.get("inferred_method")),
                    _cell(endpoint.get("status") or endpoint.get("observed_status")),
                    _cell(endpoint.get("purpose") or endpoint.get("description") or endpoint.get("notes")),
                    _cell(endpoint.get("confidence")),
                    _cell("; ".join(_string_list(endpoint.get("evidence") or endpoint.get("references")))),
                ]
            )
            + " |"
        )
    lines.append("")


def _add_forms_section(lines: list[str], value: Any) -> None:
    forms = _list(value)
    lines.extend(["## Forms", "", "| Page | Type | Fields | Method | Notes |", "|---|---|---|---|---|"])
    if not forms:
        lines.append("| No forms reported. |  |  |  |  |")
    for form in forms:
        if not isinstance(form, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(form.get("page") or form.get("url")),
                    _cell(form.get("type") or form.get("purpose")),
                    _cell(", ".join(_string_list(form.get("fields")))),
                    _cell(form.get("method")),
                    _cell(form.get("notes") or form.get("evidence")),
                ]
            )
            + " |"
        )
    lines.append("")


def _add_components_section(lines: list[str], heading: str, value: Any) -> None:
    components = _list(value)
    lines.extend([f"## {heading}", "", "| Name | Type | Version | Confidence | Evidence |", "|---|---|---|---|---|"])
    if not components:
        lines.append("| No components reported. |  |  |  |  |")
    for component in components:
        if not isinstance(component, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(component.get("name") or component.get("component") or component.get("technology")),
                    _cell(component.get("type") or component.get("category")),
                    _cell(component.get("version")),
                    _cell(component.get("confidence")),
                    _cell("; ".join(_string_list(component.get("evidence") or component.get("source")))),
                ]
            )
            + " |"
        )
    lines.append("")


def _add_actions_section(lines: list[str], value: Any) -> None:
    actions = _list(value)
    lines.extend(["## Recommended Next Steps", "", "| Priority | Action | Rationale |", "|---|---|---|"])
    if not actions:
        lines.append("| No recommendations reported. |  |  |")
    for action in actions:
        if not isinstance(action, dict):
            lines.append(f"|  | {_cell(action)} |  |")
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(action.get("priority")),
                    _cell(action.get("action") or action.get("title")),
                    _cell(action.get("rationale") or action.get("reason") or action.get("detail")),
                ]
            )
            + " |"
        )
    lines.append("")


def _add_appendix(lines: list[str], value: Any, crawl: CrawlResult) -> None:
    lines.extend(["## Appendix", ""])
    notes = _list(value)
    if notes:
        lines.extend(["### Notes", ""])
        for note in notes:
            if isinstance(note, dict):
                title = _text(note.get("title") or note.get("name")) or "Note"
                detail = _text(note.get("detail") or note.get("description"))
                lines.append(f"- **{title}**")
                if detail:
                    lines.append(f"  {detail}")
            else:
                lines.append(f"- {_text(note)}")
        lines.append("")
    lines.extend(["### Crawl Reference", "", "| URL | Status | References |", "|---|---:|---|"])
    for page in crawl.pages:
        lines.append(f"| {_cell(page.url)} | {_cell(page.status)} | {_cell('; '.join(page.references[:5]))} |")
    if crawl.out_of_scope:
        lines.extend(["", "### Out Of Scope References", ""])
        for url in crawl.out_of_scope:
            lines.append(f"- `{url}`")
    if crawl.failed:
        lines.extend(["", "### Failed Requests", "", "| URL | Error |", "|---|---|"])
        for failure in crawl.failed:
            lines.append(f"| {_cell(failure.get('url'))} | {_cell(failure.get('error'))} |")
    lines.append("")


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
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _label(key: str) -> str:
    return key.replace("_", " ").title()


def _cell(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    return text.replace("|", "\\|").replace("\n", "<br>")
