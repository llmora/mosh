from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SOURCE_DISCOVERY_REPORT_SCHEMA = "mosh.source-discovery-report.v1"


def write_source_discovery_report(
    report_dir: Path,
    source_index: dict[str, Any],
    report_content: dict[str, Any] | None = None,
) -> str:
    markdown = render_source_discovery_report(source_index, report_content or {})
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.md").write_text(markdown, encoding="utf-8")
    stale_json_report = report_dir / "report.json"
    if stale_json_report.exists():
        stale_json_report.unlink()
    return markdown


def render_source_discovery_report(source_index: dict[str, Any], report_content: dict[str, Any]) -> str:
    source = source_index.get("source") if isinstance(source_index.get("source"), dict) else {}
    inventory = source_index.get("inventory") if isinstance(source_index.get("inventory"), dict) else {}
    summary = source_index.get("summary") if isinstance(source_index.get("summary"), dict) else {}
    component_map = source_index.get("component_map") if isinstance(source_index.get("component_map"), dict) else {}
    gap_analysis = source_index.get("gap_analysis") if isinstance(source_index.get("gap_analysis"), dict) else {}
    title = _text(report_content.get("title")) or "Source Discovery Report"
    lines = [
        f"# {title}",
        "",
        "## Report Metadata",
        "",
        f"- Schema version: `{SOURCE_DISCOVERY_REPORT_SCHEMA}`",
        f"- Source kind: `{_text(source.get('kind')) or 'unknown'}`",
        f"- Source path: `{_text(source.get('path')) or 'unknown'}`",
        f"- Commit SHA: `{_text(source.get('commit_sha')) or 'unknown'}`",
        "",
    ]
    _add_text_section(
        lines,
        "Executive Summary",
        report_content.get("executive_summary")
        or _default_summary(source, summary),
    )
    _add_summary_statistics(lines, summary)
    _add_languages_section(lines, inventory.get("languages"))
    _add_apps_section(lines, inventory.get("apps"))
    _add_component_map_sections(lines, component_map)
    _add_files_section(lines, "Entrypoints", inventory.get("entrypoints"))
    _add_routes_section(lines, inventory.get("routes"))
    _add_dependencies_section(lines, inventory.get("dependencies"))
    _add_config_section(lines, inventory.get("configuration"))
    _add_environment_section(lines, inventory.get("environment_variables"))
    _add_compose_section(lines, inventory.get("compose_topology"))
    _add_items_section(lines, "Auth And Session Candidates", inventory.get("auth") or inventory.get("sessions"))
    _add_items_section(lines, "Data Store Candidates", inventory.get("data_stores"))
    _add_gap_analysis_section(lines, gap_analysis)
    _add_files_section(lines, "Indexed Manifests And Lockfiles", _manifest_lockfile_items(inventory))
    _add_text_section(lines, "Discovery Limitations", report_content.get("limitations") or _default_limitations(source_index))
    _add_actions_section(lines, report_content.get("recommended_next_steps"))
    _add_appendix(lines, source_index)
    return "\n".join(lines).rstrip() + "\n"


def _default_summary(source: dict[str, Any], summary: dict[str, Any]) -> str:
    return (
        f"Source discovery indexed `{summary.get('files_indexed', 0)}` file(s) for "
        f"`{_text(source.get('display_name')) or _text(source.get('path')) or 'the source tree'}` and identified "
        f"`{summary.get('routes_identified', 0)}` route/API candidate(s), "
        f"`{summary.get('dependencies_identified', 0)}` dependency item(s), and "
        f"`{summary.get('configuration_files_identified', 0)}` configuration file(s)."
    )


def _default_limitations(source_index: dict[str, Any]) -> str:
    inventory = source_index.get("inventory") if isinstance(source_index.get("inventory"), dict) else {}
    file_count = len(_list(inventory.get("files")))
    return (
        "This first source discovery increment uses deterministic file inventory, "
        "manifest parsing, and simple framework route patterns. It does not yet "
        f"perform full call-graph, data-flow, or vulnerability scanning. Indexed file count: `{file_count}`."
    )


def _add_text_section(lines: list[str], heading: str, value: Any) -> None:
    lines.extend([f"## {heading}", ""])
    text = _text(value)
    lines.extend([text or "No content provided.", ""])


def _add_summary_statistics(lines: list[str], summary: dict[str, Any]) -> None:
    lines.extend(["## Summary Statistics", "", "| Metric | Value |", "|---|---:|"])
    if not summary:
        lines.append("| No statistics reported. |  |")
    for key in sorted(summary):
        lines.append(f"| {_cell(_label(key))} | {_cell(summary[key])} |")
    lines.append("")


def _add_languages_section(lines: list[str], languages: Any) -> None:
    lines.extend(["## Languages", "", "| Language | Files |", "|---|---:|"])
    if not isinstance(languages, dict) or not languages:
        lines.append("| No languages identified. |  |")
    else:
        for language, count in sorted(languages.items()):
            lines.append(f"| {_cell(language)} | {_cell(count)} |")
    lines.append("")


def _add_files_section(lines: list[str], heading: str, value: Any) -> None:
    files = _list(value)
    lines.extend([f"## {heading}", "", "| Path | Role | Reason | App | Size |", "|---|---|---|---|---:|"])
    if not files:
        lines.append("| No files reported. |  |  |  |  |")
    for file in files[:100]:
        if not isinstance(file, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(file.get("path")),
                    _cell(file.get("role") or file.get("kind")),
                    _cell(file.get("reason")),
                    _cell(file.get("app_id")),
                    _cell(file.get("size")),
                ]
            )
            + " |"
        )
    if len(files) > 100:
        lines.append(f"| {_cell(f'{len(files) - 100} additional file(s) omitted from report.')} |  |  |  |  |")
    lines.append("")


def _add_apps_section(lines: list[str], value: Any) -> None:
    apps = _list(value)
    lines.extend(["## Application Units", "", "| App ID | Type | Root | Frameworks | Entrypoints | Evidence |", "|---|---|---|---|---|---|"])
    if not apps:
        lines.append("| No application units reported. |  |  |  |  |  |")
    for app in apps[:100]:
        if not isinstance(app, dict):
            continue
        entrypoints = [
            _text(entrypoint.get("path"))
            for entrypoint in _list(app.get("entrypoints"))
            if isinstance(entrypoint, dict) and _text(entrypoint.get("path"))
        ]
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(app.get("app_id")),
                    _cell(app.get("type")),
                    _cell(app.get("root")),
                    _cell(", ".join(_string_list(app.get("frameworks")))),
                    _cell(", ".join(entrypoints)),
                    _cell(", ".join(_string_list(app.get("evidence")))),
                ]
            )
            + " |"
        )
    if len(apps) > 100:
        lines.append(f"| {_cell(f'{len(apps) - 100} additional app unit(s) omitted.')} |  |  |  |  |  |")
    lines.append("")


def _add_component_map_sections(lines: list[str], component_map: dict[str, Any]) -> None:
    lines.extend(["## Application Purpose", ""])
    purpose = _text(component_map.get("application_purpose") or component_map.get("purpose"))
    business_domain = _text(component_map.get("business_domain"))
    if purpose:
        lines.append(purpose)
        if business_domain:
            lines.append("")
            lines.append(f"Business domain: `{business_domain}`")
    else:
        lines.append("No model-assisted application purpose submitted.")
    lines.append("")
    _add_component_items_section(lines, "Business Components", component_map.get("key_components"))
    combined = []
    combined.extend(_annotated_items(component_map.get("sensitive_data"), "Sensitive data"))
    combined.extend(_annotated_items(component_map.get("trust_boundaries"), "Trust boundary"))
    combined.extend(_annotated_items(component_map.get("external_integrations"), "External integration"))
    _add_component_items_section(lines, "Sensitive Data And Trust Boundaries", combined)


def _add_component_items_section(lines: list[str], heading: str, value: Any) -> None:
    items = _list(value)
    lines.extend([f"## {heading}", ""])
    if not items:
        lines.extend(["No items reported.", ""])
        return
    for item in items[:100]:
        title, detail, evidence = _item_parts(item)
        lines.append(f"- **{title or 'Item'}**")
        if detail:
            lines.append(f"  {detail}")
        if evidence:
            lines.append(f"  Evidence: {evidence}")
    if len(items) > 100:
        lines.append(f"- {len(items) - 100} additional item(s) omitted from report.")
    lines.append("")


def _add_routes_section(lines: list[str], value: Any) -> None:
    routes = _list(value)
    lines.extend(
        [
            "## Routes And API Candidates",
            "",
            "| Method | Full Route | Scope | Middleware | Local Route | Mount | App | Source | Handler | Resolution | Evidence |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    if not routes:
        lines.append("| No route/API candidates reported. |  |  |  |  |  |  |  |  |  |  |")
    for route in routes[:100]:
        if not isinstance(route, dict):
            continue
        source = f"{_text(route.get('path'))}:{_text(route.get('line'))}"
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(route.get("method")),
                    _cell(route.get("full_route") or route.get("route")),
                    _cell(route.get("scope")),
                    _cell(", ".join(_string_list(route.get("middleware")))),
                    _cell(route.get("route")),
                    _cell(route.get("mount_prefix")),
                    _cell(route.get("app_id")),
                    _cell(source),
                    _cell(route.get("handler") or route.get("framework")),
                    _cell(route.get("route_resolution_source")),
                    _cell(route.get("snippet_hash")),
                ]
            )
            + " |"
        )
    if len(routes) > 100:
        lines.append(f"| {_cell(f'{len(routes) - 100} additional route(s) omitted from report.')} |  |  |  |  |  |  |  |  |  |  |")
    lines.append("")


def _add_dependencies_section(lines: list[str], value: Any) -> None:
    dependencies = _list(value)
    lines.extend(["## Dependency Inventory", "", "| Ecosystem | Name | Version | Scope | Manifest |", "|---|---|---|---|---|"])
    if not dependencies:
        lines.append("| No dependencies parsed from supported manifests. |  |  |  |  |")
    for dependency in dependencies[:150]:
        if not isinstance(dependency, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(dependency.get("ecosystem")),
                    _cell(dependency.get("name")),
                    _cell(dependency.get("version")),
                    _cell(dependency.get("scope")),
                    _cell(dependency.get("manifest")),
                ]
            )
            + " |"
        )
    if len(dependencies) > 150:
        lines.append(f"| {_cell(f'{len(dependencies) - 150} additional dependency item(s) omitted.')} |  |  |  |  |")
    lines.append("")


def _add_config_section(lines: list[str], value: Any) -> None:
    configs = _list(value)
    lines.extend(["## Configuration And Deployment Files", "", "| Path | Kind | Size |", "|---|---|---:|"])
    if not configs:
        lines.append("| No configuration files reported. |  |  |")
    for item in configs[:100]:
        if not isinstance(item, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("path")),
                    _cell(item.get("kind")),
                    _cell(item.get("size")),
                ]
            )
            + " |"
        )
    if len(configs) > 100:
        lines.append(f"| {_cell(f'{len(configs) - 100} additional configuration file(s) omitted.')} |  |  |")
    lines.append("")


def _add_environment_section(lines: list[str], value: Any) -> None:
    items = _list(value)
    lines.extend(["## Environment Variable Inventory", "", "| Name | Source | Path | Line |", "|---|---|---|---:|"])
    if not items:
        lines.append("| No environment variable references reported. |  |  |  |")
    for item in items[:150]:
        if not isinstance(item, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("name")),
                    _cell(item.get("source")),
                    _cell(item.get("path")),
                    _cell(item.get("line")),
                ]
            )
            + " |"
        )
    if len(items) > 150:
        lines.append(f"| {_cell(f'{len(items) - 150} additional environment variable reference(s) omitted.')} |  |  |  |")
    lines.append("")


def _add_compose_section(lines: list[str], value: Any) -> None:
    files = _list(value)
    lines.extend(["## Docker Compose Topology", "", "| File | Service | Image/Build | Ports | Depends On | Environment |", "|---|---|---|---|---|---|"])
    if not files:
        lines.append("| No Docker Compose topology reported. |  |  |  |  |  |")
    rows = 0
    for item in files:
        if not isinstance(item, dict):
            continue
        for service in _list(item.get("services")):
            if not isinstance(service, dict):
                continue
            rows += 1
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(item.get("path")),
                        _cell(service.get("name")),
                        _cell(service.get("image") or service.get("build")),
                        _cell(", ".join(_string_list(service.get("ports")))),
                        _cell(", ".join(_string_list(service.get("depends_on")))),
                        _cell(", ".join(_string_list(service.get("environment")))),
                    ]
                )
                + " |"
            )
            if rows >= 100:
                break
    lines.append("")


def _add_items_section(lines: list[str], heading: str, value: Any) -> None:
    items = _list(value)
    lines.extend([f"## {heading}", ""])
    if not items:
        lines.extend(["No items reported.", ""])
        return
    for item in items[:100]:
        if isinstance(item, dict):
            title = _text(item.get("path") or item.get("route") or item.get("name") or item.get("reason")) or "Item"
            detail = _text(item.get("reason") or item.get("evidence"))
            lines.append(f"- **{title}**")
            if detail:
                lines.append(f"  {detail}")
        else:
            lines.append(f"- {_text(item)}")
    if len(items) > 100:
        lines.append(f"- {len(items) - 100} additional item(s) omitted from report.")
    lines.append("")


def _add_gap_analysis_section(lines: list[str], gap_analysis: dict[str, Any]) -> None:
    lines.extend(["## Discovery Gaps", ""])
    gaps = _list(gap_analysis.get("gaps"))
    limitations = _list(gap_analysis.get("limitations"))
    follow_ups = _list(gap_analysis.get("recommended_follow_up") or gap_analysis.get("follow_up"))
    opportunities = _list(gap_analysis.get("deterministic_tool_opportunities"))
    if not any([gaps, limitations, follow_ups, opportunities]):
        lines.extend(["No model-assisted discovery gaps submitted.", ""])
        return
    for item in gaps[:100]:
        title, detail, evidence = _item_parts(item)
        lines.append(f"- **{title or 'Gap'}**")
        if detail:
            lines.append(f"  {detail}")
        if evidence:
            lines.append(f"  Evidence: {evidence}")
    for item in limitations[:50]:
        lines.append(f"- **Limitation:** {_item_text(item)}")
    for item in follow_ups[:50]:
        lines.append(f"- **Follow-up:** {_item_text(item)}")
    for item in opportunities[:50]:
        lines.append(f"- **Tool opportunity:** {_item_text(item)}")
    lines.append("")


def _add_actions_section(lines: list[str], value: Any) -> None:
    actions = _list(value)
    lines.extend(["## Recommended Next Steps", ""])
    if not actions:
        lines.extend(
            [
                "- Feed this source discovery into security planning.",
                "- Correlate source routes with live discovery when a live URL is available.",
                "- Run engagement security testing once source-backed hypotheses are produced.",
                "",
            ]
        )
        return
    for action in actions:
        lines.append(f"- {_text(action)}")
    lines.append("")


def _add_appendix(lines: list[str], source_index: dict[str, Any]) -> None:
    lines.extend(["## Appendix", "", "### Source Index Schema", "", "```json"])
    lines.append(json.dumps({"schema": source_index.get("schema")}, indent=2, sort_keys=True))
    lines.extend(["```", ""])


def _manifest_lockfile_items(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    files = []
    for file in _list(inventory.get("files")):
        if isinstance(file, dict) and file.get("role") in {"manifest", "lockfile"}:
            files.append(file)
    return files


def _label(value: str) -> str:
    return value.replace("_", " ").title()


def _cell(value: Any) -> str:
    text = _text(value)
    return text.replace("|", "\\|").replace("\n", " ") if text else ""


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _string_list(value: Any) -> list[str]:
    return [_text(item) for item in _list(value) if _text(item)]


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _annotated_items(value: Any, label: str) -> list[Any]:
    annotated = []
    for item in _list(value):
        if isinstance(item, dict):
            copy = dict(item)
            copy.setdefault("type", label)
            annotated.append(copy)
        else:
            annotated.append({"title": label, "detail": item})
    return annotated


def _item_parts(item: Any) -> tuple[str, str, str]:
    if not isinstance(item, dict):
        return _item_text(item), "", ""
    label = _text(item.get("type") or item.get("category"))
    title = _text(item.get("title") or item.get("name") or item.get("component") or item.get("data") or item.get("boundary"))
    if label and title and not title.startswith(label):
        title = f"{label}: {title}"
    detail = _text(item.get("detail") or item.get("description") or item.get("reason") or item.get("summary"))
    evidence = ", ".join(_string_list(item.get("evidence") or item.get("evidence_refs") or item.get("paths")))
    return title, detail, evidence


def _item_text(item: Any) -> str:
    if isinstance(item, dict):
        title, detail, evidence = _item_parts(item)
        text = title or detail or json.dumps(item, sort_keys=True)
        if detail and title:
            text = f"{text} - {detail}"
        if evidence:
            text = f"{text} Evidence: {evidence}"
        return text
    return _text(item)
