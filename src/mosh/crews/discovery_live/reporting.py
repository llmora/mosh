from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mosh.memory import FileMemory
from mosh.models import CrawlResult


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

JAVASCRIPT_DISCOVERY_TOOLS = (
    "katana_docker_crawler",
    "extractify_js_endpoint_discovery",
    "js_static_endpoint_discovery",
    "source_map_discovery",
)

JAVASCRIPT_LIMITATION_REPLACEMENT_MARKERS = (
    "javascript not executed",
    "did not execute javascript",
    "no javascript execution",
    "js bundle not deeply parsed",
    "javascript bundle not deeply parsed",
    "full bundle decompilation",
    "bundle decompilation",
    "string references only",
    "source maps not checked",
    "no source maps available",
    "without accompanying source map",
    "without source map",
)

STATIC_ROUTE_SUFFIXES = (
    ".js",
    ".mjs",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".pdf",
    ".zip",
    ".gz",
)


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


def build_javascript_discovery_summary(memory: FileMemory) -> dict[str, Any]:
    events = _read_json_list(memory.events_path)
    memory_items = _read_json_list(memory.memory_path)
    tools: dict[str, dict[str, Any]] = {
        tool: {"called": False, "completed": False, "failed": 0, "pages": 0} for tool in JAVASCRIPT_DISCOVERY_TOOLS
    }
    javascript_assets = 0

    for event in events:
        if not isinstance(event, dict):
            continue
        action = event.get("action")
        message = _text(event.get("message"))
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        tool = data.get("tool") if isinstance(data.get("tool"), str) else _tool_from_message(message)
        if tool not in tools:
            continue
        if action == "tool_call":
            tools[tool]["called"] = True
            tools[tool]["javascript_assets"] = max(
                int(tools[tool].get("javascript_assets") or 0),
                _safe_int(data.get("javascript_urls")),
            )
            javascript_assets = max(javascript_assets, _safe_int(data.get("javascript_urls")))
        elif action == "tool_result":
            tools[tool]["completed"] = True
            tools[tool]["failed"] = _safe_int(data.get("failed"))
            tools[tool]["pages"] = _safe_int(data.get("pages"))
            if tool == "source_map_discovery":
                tools[tool]["source_maps_found"] = _safe_int(data.get("source_maps_found"))

    source_map_summary = _aggregate_source_map_discovery(memory_items)
    if source_map_summary:
        javascript_assets = max(javascript_assets, _safe_int(source_map_summary.get("javascript_assets")))
        tools["source_map_discovery"]["source_maps_found"] = _safe_int(source_map_summary.get("source_maps_found"))

    return {
        "javascript_assets": javascript_assets,
        "tools": tools,
        "source_maps": source_map_summary,
    }


def apply_javascript_discovery_report_facts(
    report_content: dict[str, Any],
    javascript_summary: dict[str, Any],
) -> dict[str, Any]:
    normalized = copy.deepcopy(report_content)
    if _safe_int(javascript_summary.get("javascript_assets")) <= 0:
        return normalized

    limitations = _list(normalized.get("limitations"))
    filtered = [
        limitation
        for limitation in limitations
        if not _javascript_limitation_replaced_by_facts(limitation, javascript_summary)
    ]
    deterministic_limitation = _javascript_coverage_limitation(javascript_summary)
    if deterministic_limitation and not _has_item_title(filtered, deterministic_limitation["title"]):
        filtered.append(deterministic_limitation)
    normalized["limitations"] = filtered
    return normalized


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
    _add_items_section(lines, SECURITY_TESTING_FEEDBACK_HEADING, report_content.get("testing_feedback"))
    _add_items_section(lines, "Discovery Limitations", report_content.get("limitations"))
    _add_actions_section(lines, report_content.get("recommended_next_steps"))
    _add_appendix(lines, report_content.get("appendix"), crawl)

    return "\n".join(lines).rstrip() + "\n"


def update_report_with_testing_feedback(report_dir: Path, updates: list[dict[str, Any]]) -> str:
    report_path = report_dir / "report.md"
    existing = report_path.read_text(encoding="utf-8") if report_path.exists() else "# Application Discovery Report\n"
    section = _render_testing_feedback_section(updates)
    updated = _replace_markdown_section(existing, SECURITY_TESTING_FEEDBACK_HEADING, section)
    report_path.write_text(updated, encoding="utf-8")
    return updated


def _render_testing_feedback_section(updates: list[dict[str, Any]]) -> str:
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
    routes = _routes_with_crawl_evidence(value, crawl)
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


def _routes_with_crawl_evidence(value: Any, crawl: CrawlResult) -> list[Any]:
    routes = _list(value)
    seen = {_route_key(route) for route in routes if isinstance(route, dict)}
    seen_paths = {_route_path_key(route) for route in routes if isinstance(route, dict)}
    seen.discard("")
    seen_paths.discard("")
    for page in crawl.pages:
        if not _include_crawl_route(page):
            continue
        key = _canonical_url_key(page.url)
        path_key = _path_key(page.url)
        if key in seen or path_key in seen_paths:
            continue
        routes.append(
            {
                "url": page.url,
                "status": page.status,
                "content_type": page.content_type,
                "notes": page.title or _crawl_route_note(page),
                "evidence": page.references[:5],
            }
        )
        seen.add(key)
        seen_paths.add(path_key)
    return routes


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


def _read_json_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _aggregate_source_map_discovery(memory_items: list[dict[str, Any]]) -> dict[str, Any]:
    assets_by_source: dict[str, dict[str, Any]] = {}
    failed_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    start_urls: set[str] = set()
    checked = False
    observed_javascript_assets = 0
    observed_source_maps_found = 0
    observed_sources_with_content = 0

    for item in memory_items:
        if item.get("kind") != "source_map_discovery":
            continue
        content = item.get("content")
        if not isinstance(content, dict):
            continue
        checked = checked or bool(content.get("checked"))
        observed_javascript_assets = max(observed_javascript_assets, _safe_int(content.get("javascript_assets")))
        observed_source_maps_found = max(observed_source_maps_found, _safe_int(content.get("source_maps_found")))
        observed_sources_with_content = max(observed_sources_with_content, _safe_int(content.get("sources_with_content")))
        start_url = _text(content.get("start_url"))
        if start_url:
            start_urls.add(start_url)
        failures = content.get("failed") if isinstance(content.get("failed"), list) else []
        for failure in failures:
            if not isinstance(failure, dict):
                continue
            url = _text(failure.get("url"))
            error = _text(failure.get("error"))
            if error:
                failed_by_key.setdefault((url, error), {"url": url, "error": error})
        content_assets = content.get("assets") if isinstance(content.get("assets"), list) else []
        for asset in content_assets:
            if not isinstance(asset, dict):
                continue
            source = _text(asset.get("source"))
            if not source:
                continue
            aggregate = assets_by_source.setdefault(
                source,
                {
                    "source": source,
                    "checked": 0,
                    "source_maps_found": 0,
                    "source_maps": [],
                },
            )
            aggregate["checked"] = max(_safe_int(aggregate.get("checked")), _safe_int(asset.get("checked")))
            maps_by_url = {
                source_map.get("url"): source_map
                for source_map in aggregate["source_maps"]
                if isinstance(source_map, dict) and isinstance(source_map.get("url"), str)
            }
            asset_source_maps = asset.get("source_maps") if isinstance(asset.get("source_maps"), list) else []
            for source_map in asset_source_maps:
                if not isinstance(source_map, dict):
                    continue
                source_map_url = _text(source_map.get("url"))
                if not source_map_url or source_map_url in maps_by_url:
                    continue
                normalized_map = {
                    "url": source_map_url,
                    "source_root": _text(source_map.get("source_root")),
                    "sources_count": _safe_int(source_map.get("sources_count")),
                    "sources_with_content": _safe_int(source_map.get("sources_with_content")),
                }
                aggregate["source_maps"].append(normalized_map)
                maps_by_url[source_map_url] = normalized_map

    assets = sorted(assets_by_source.values(), key=lambda asset: asset["source"])
    source_maps_found = 0
    sources_with_content = 0
    for asset in assets:
        source_maps = asset.get("source_maps") if isinstance(asset.get("source_maps"), list) else []
        asset["source_maps"] = sorted(source_maps, key=lambda source_map: source_map.get("url", ""))
        asset["source_maps_found"] = len(asset["source_maps"])
        source_maps_found += asset["source_maps_found"]
        sources_with_content += sum(_safe_int(source_map.get("sources_with_content")) for source_map in asset["source_maps"])

    return {
        "start_url": sorted(start_urls)[0] if start_urls else "",
        "start_urls": sorted(start_urls),
        "checked": checked or bool(assets),
        "javascript_assets": max(len(assets), observed_javascript_assets),
        "source_maps_found": max(source_maps_found, observed_source_maps_found),
        "sources_with_content": max(sources_with_content, observed_sources_with_content),
        "assets": assets,
        "failed": sorted(failed_by_key.values(), key=lambda failure: (failure.get("url", ""), failure.get("error", ""))),
    }


def _tool_from_message(message: str) -> str | None:
    for tool in JAVASCRIPT_DISCOVERY_TOOLS:
        if message.startswith(tool):
            return tool
        if f" {tool}" in message:
            return tool
    return None


def _route_key(route: dict[str, Any]) -> str:
    return _canonical_url_key(_text(route.get("url") or route.get("route") or route.get("path")))


def _route_path_key(route: dict[str, Any]) -> str:
    return _path_key(_text(route.get("url") or route.get("route") or route.get("path")))


def _canonical_url_key(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        path = _normalized_path(parsed.path)
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}{query}"
    return _normalized_path(url)


def _path_key(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path if parsed.scheme or parsed.netloc else url
    return _normalized_path(path)


def _normalized_path(path: str) -> str:
    if not path:
        return "/"
    if path != "/":
        path = path.rstrip("/")
    return path or "/"


def _include_crawl_route(page: Any) -> bool:
    url = _text(getattr(page, "url", ""))
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    path = parsed.path or "/"
    lowered_path = path.lower()
    if _route_path_looks_generated(path):
        return False
    if lowered_path.endswith(STATIC_ROUTE_SUFFIXES):
        return False
    if lowered_path.startswith(("/static/", "/assets/")):
        return False
    if any(lowered_path.startswith(prefix) and lowered_path != prefix for prefix in ("/js/", "/css/", "/img/")):
        return False
    return True


def _route_path_looks_generated(path: str) -> bool:
    lowered = path.lower()
    if any(marker in lowered for marker in ("%7b", "%7d", "%5b", "%5d", "{{", "}}", "[object", "this.", "\\u", "\\x")):
        return True
    if any(character in path for character in ("{", "}", "[", "]", "\\", '"', "'")):
        return True
    return False


def _crawl_route_note(page: Any) -> str:
    references = _string_list(getattr(page, "references", []))
    if references:
        return "Discovered from crawler evidence."
    return ""


def _javascript_limitation_replaced_by_facts(limitation: Any, javascript_summary: dict[str, Any]) -> bool:
    text = _limitation_text(limitation).lower()
    if not any(marker in text for marker in JAVASCRIPT_LIMITATION_REPLACEMENT_MARKERS):
        return False
    tools = javascript_summary.get("tools") if isinstance(javascript_summary.get("tools"), dict) else {}
    katana = tools.get("katana_docker_crawler") if isinstance(tools.get("katana_docker_crawler"), dict) else {}
    static = tools.get("js_static_endpoint_discovery") if isinstance(tools.get("js_static_endpoint_discovery"), dict) else {}
    source_maps = javascript_summary.get("source_maps") if isinstance(javascript_summary.get("source_maps"), dict) else {}
    if "javascript" in text and "execut" in text:
        return bool(katana.get("completed")) and _safe_int(katana.get("failed")) == 0
    if "source map" in text:
        source_map_failures = source_maps.get("failed") if isinstance(source_maps.get("failed"), list) else []
        return bool(source_maps.get("checked") or source_map_failures)
    if "bundle" in text or "string references only" in text:
        return bool(static.get("completed"))
    return False


def _javascript_coverage_limitation(javascript_summary: dict[str, Any]) -> dict[str, Any] | None:
    tools = javascript_summary.get("tools") if isinstance(javascript_summary.get("tools"), dict) else {}
    source_maps = javascript_summary.get("source_maps") if isinstance(javascript_summary.get("source_maps"), dict) else {}
    source_map_failures = source_maps.get("failed") if isinstance(source_maps.get("failed"), list) else []
    source_maps_checked = bool(source_maps.get("checked"))
    source_maps_found = _safe_int(source_maps.get("source_maps_found"))
    completed_tools = [
        _human_js_tool_name(tool)
        for tool, state in tools.items()
        if isinstance(state, dict) and bool(state.get("completed"))
    ]
    if source_maps_checked and source_maps_found == 0 and not source_map_failures:
        return {
            "title": "Source Maps Not Available",
            "detail": (
                f"{_sentence_list(completed_tools)} checked the discovered JavaScript assets. "
                "No valid source maps were found, so source-level reconstruction remains limited to runtime observations "
                "and extracted JavaScript evidence."
            ),
            "confidence": "confirmed",
            "evidence": ["source_map_discovery checked JavaScript assets and found 0 source maps"],
        }
    if source_map_failures:
        return {
            "title": "Source Map Discovery Incomplete",
            "detail": (
                f"{_sentence_list(completed_tools)} checked the discovered JavaScript assets, but source-map discovery "
                "reported failures for one or more assets."
            ),
            "confidence": "confirmed",
            "evidence": [str(item.get("error")) for item in source_map_failures if isinstance(item, dict) and item.get("error")],
        }
    return None


def _limitation_text(limitation: Any) -> str:
    if isinstance(limitation, dict):
        return " ".join(
            _text(limitation.get(key))
            for key in ("title", "name", "summary", "detail", "description", "notes")
            if _text(limitation.get(key))
        )
    return _text(limitation)


def _has_item_title(items: list[Any], title: str) -> bool:
    wanted = title.lower()
    for item in items:
        if isinstance(item, dict) and _text(item.get("title")).lower() == wanted:
            return True
        if isinstance(item, str) and item.lower() == wanted:
            return True
    return False


def _human_js_tool_name(tool: str) -> str:
    return {
        "katana_docker_crawler": "Katana runtime crawling",
        "extractify_js_endpoint_discovery": "Extractify string extraction",
        "js_static_endpoint_discovery": "static JavaScript endpoint analysis",
        "source_map_discovery": "source-map discovery",
    }.get(tool, tool)


def _sentence_list(items: list[str]) -> str:
    items = [item for item in items if item]
    if not items:
        return "JavaScript discovery tooling"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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
