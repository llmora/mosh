from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from mosh.engagements import (
    EngagementAsset,
    asset_discovery_dir,
    engagement_dir,
    load_engagement,
)
from mosh.models import utc_now


EVIDENCE_LINKS_SCHEMA = "mosh.evidence-links.v1"
DEFAULT_MAX_LINKS_PER_ASSET_PAIR = 500


@dataclass(frozen=True)
class EvidenceLinkResult:
    links_path: Path
    payload: dict[str, Any]


@dataclass(frozen=True)
class LiveEndpoint:
    asset: EngagementAsset
    url: str
    path: str
    method: str
    status: int | None
    source_kind: str


@dataclass(frozen=True)
class SourceRoute:
    asset: EngagementAsset
    method: str
    route: str
    source_path: str | None
    line: int | None
    handler: str | None
    framework: str | None
    snippet_hash: str | None
    route_resolution_confidence: str | None


def links_path(output_root: Path, engagement_id: str) -> Path:
    return engagement_dir(output_root, engagement_id) / "links.json"


def build_evidence_links(
    output_root: Path,
    engagement_id: str,
    *,
    max_links_per_asset_pair: int = DEFAULT_MAX_LINKS_PER_ASSET_PAIR,
) -> EvidenceLinkResult:
    engagement = load_engagement(output_root, engagement_id)
    live_assets = [asset for asset in engagement.assets if asset.type == "live_url"]
    source_assets = [asset for asset in engagement.assets if asset.type == "source_tree"]
    skipped_assets: list[dict[str, Any]] = []
    link_records: list[dict[str, Any]] = []

    live_by_asset: dict[str, list[LiveEndpoint]] = {}
    for asset in live_assets:
        endpoints = _live_endpoints_from_asset(output_root, engagement.id, asset)
        live_by_asset[asset.id] = endpoints
        if not endpoints:
            skipped_assets.append({"id": asset.id, "reason": "no live discovery endpoints"})

    source_by_asset: dict[str, list[SourceRoute]] = {}
    for asset in source_assets:
        routes = _source_routes_from_asset(output_root, engagement.id, asset)
        source_by_asset[asset.id] = routes
        if not routes:
            skipped_assets.append({"id": asset.id, "reason": "no source discovery routes"})

    pair_summaries: list[dict[str, Any]] = []
    for live_asset in live_assets:
        live_endpoints = live_by_asset.get(live_asset.id, [])
        for source_asset in source_assets:
            source_routes = source_by_asset.get(source_asset.id, [])
            pair_links = _link_asset_pair(
                live_asset,
                live_endpoints,
                source_asset,
                source_routes,
                max_links=max_links_per_asset_pair,
            )
            link_records.extend(pair_links)
            pair_summaries.append(
                {
                    "live_asset_id": live_asset.id,
                    "source_asset_id": source_asset.id,
                    "live_endpoints": len(live_endpoints),
                    "source_routes": len(source_routes),
                    "links": len(pair_links),
                    "capped": len(pair_links) >= max_links_per_asset_pair,
                }
            )

    payload = {
        "schema": EVIDENCE_LINKS_SCHEMA,
        "generated_at": utc_now(),
        "pairs": pair_summaries,
        "links": _dedupe_and_sort_links(link_records),
        "skipped_assets": skipped_assets,
    }
    path = links_path(output_root, engagement.id)
    _write_json(path, payload)
    return EvidenceLinkResult(links_path=path, payload=payload)


def _link_asset_pair(
    live_asset: EngagementAsset,
    live_endpoints: list[LiveEndpoint],
    source_asset: EngagementAsset,
    source_routes: list[SourceRoute],
    *,
    max_links: int,
) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    for source_route in source_routes:
        for live_endpoint in live_endpoints:
            match = _match_route_to_endpoint(source_route, live_endpoint)
            if not match:
                continue
            links.append(_link_record(live_asset, live_endpoint, source_asset, source_route, match))
    links = _dedupe_and_sort_links(links)
    return links[: max(max_links, 0)]


def _match_route_to_endpoint(source_route: SourceRoute, live_endpoint: LiveEndpoint) -> dict[str, Any] | None:
    if not _methods_compatible(source_route.method, live_endpoint.method):
        return None
    source_path = _normalize_path(source_route.route)
    live_path = _normalize_path(live_endpoint.path)
    if not source_path or not live_path:
        return None
    if source_path == live_path:
        return {
            "confidence": "high",
            "score": 1.0,
            "basis": "exact_path",
            "reason": "Source route path exactly matches the observed live endpoint path.",
        }
    if _parameterized_paths_match(source_path, live_path):
        return {
            "confidence": "medium",
            "score": 0.92,
            "basis": "parameterized_path",
            "reason": "Source route and live endpoint paths match after applying route parameter semantics.",
        }
    return None


def _link_record(
    live_asset: EngagementAsset,
    live_endpoint: LiveEndpoint,
    source_asset: EngagementAsset,
    source_route: SourceRoute,
    match: dict[str, Any],
) -> dict[str, Any]:
    source_ref = {
        "asset_id": source_asset.id,
        "kind": "source_route",
        "method": source_route.method,
        "route": source_route.route,
        "path": source_route.source_path,
        "line": source_route.line,
        "handler": source_route.handler,
        "framework": source_route.framework,
        "snippet_hash": source_route.snippet_hash,
        "route_resolution_confidence": source_route.route_resolution_confidence,
    }
    live_ref = {
        "asset_id": live_asset.id,
        "kind": "live_endpoint",
        "method": live_endpoint.method,
        "url": live_endpoint.url,
        "path": live_endpoint.path,
        "status": live_endpoint.status,
        "source_kind": live_endpoint.source_kind,
    }
    identity = "|".join(
        [
            live_asset.id,
            source_asset.id,
            source_route.method,
            source_route.route,
            str(source_route.source_path or ""),
            str(source_route.line or ""),
            live_endpoint.url,
            str(live_endpoint.status or ""),
            str(match["basis"]),
        ]
    )
    return {
        "id": "link_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12],
        "type": "source_route_to_live_endpoint",
        "asset_refs": [source_asset.id, live_asset.id],
        "confidence": match["confidence"],
        "score": match["score"],
        "basis": match["basis"],
        "reason": match["reason"],
        "refs": [source_ref, live_ref],
    }


def _live_endpoints_from_asset(output_root: Path, engagement_id: str, asset: EngagementAsset) -> list[LiveEndpoint]:
    memory = _read_memory(asset_discovery_dir(output_root, engagement_id, asset.id))
    endpoints: list[LiveEndpoint] = []
    seen: set[tuple[str, str, str]] = set()
    for item in memory:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "")
        content = item.get("content") if isinstance(item.get("content"), dict) else {}
        if kind == "crawled_page":
            for url in _urls_from_crawled_page(content, asset.locator):
                endpoint = _live_endpoint(asset, url, content.get("status"), "crawled_page")
                if endpoint and (endpoint.method, endpoint.url, endpoint.path) not in seen:
                    endpoints.append(endpoint)
                    seen.add((endpoint.method, endpoint.url, endpoint.path))
            continue
        if kind in {"discovery_candidate", "candidate", "endpoint", "api_endpoint"}:
            endpoint = _live_endpoint(asset, _text(content.get("url")), content.get("status"), kind)
            if endpoint and (endpoint.method, endpoint.url, endpoint.path) not in seen:
                endpoints.append(endpoint)
                seen.add((endpoint.method, endpoint.url, endpoint.path))
    return sorted(endpoints, key=lambda endpoint: (endpoint.path, endpoint.url, endpoint.method))


def _urls_from_crawled_page(content: dict[str, Any], base_url: str) -> list[str]:
    urls: list[str] = []
    primary_url = _text(content.get("url"))
    if primary_url:
        urls.append(primary_url)
    for field in ("links", "references", "forms"):
        for value in _list(content.get(field)):
            url = _text(value)
            if url:
                urls.append(urljoin(base_url.rstrip("/") + "/", url))
    return urls


def _live_endpoint(
    asset: EngagementAsset,
    raw_url: str,
    status: Any,
    source_kind: str,
) -> LiveEndpoint | None:
    if not raw_url or "${" in raw_url:
        return None
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    path = _normalize_path(parsed.path)
    if not path:
        return None
    return LiveEndpoint(
        asset=asset,
        url=raw_url,
        path=path,
        method="ANY",
        status=_int_or_none(status),
        source_kind=source_kind,
    )


def _source_routes_from_asset(output_root: Path, engagement_id: str, asset: EngagementAsset) -> list[SourceRoute]:
    memory = _read_memory(asset_discovery_dir(output_root, engagement_id, asset.id))
    routes: list[SourceRoute] = []
    source_index = _latest_memory_content(memory, "source_index")
    if source_index:
        inventory = source_index.get("inventory") if isinstance(source_index.get("inventory"), dict) else {}
        routes.extend(_source_routes_from_records(asset, _list(inventory.get("routes"))))
    if not routes:
        resolved = _latest_memory_content(memory, "source_routes_resolved")
        if resolved:
            routes.extend(_source_routes_from_records(asset, _list(resolved.get("routes"))))
    if not routes:
        raw_routes = _latest_memory_content(memory, "source_routes")
        if raw_routes:
            routes.extend(_source_routes_from_records(asset, _list(raw_routes.get("routes"))))
    return _dedupe_source_routes(routes)


def _source_routes_from_records(asset: EngagementAsset, records: list[Any]) -> list[SourceRoute]:
    routes: list[SourceRoute] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        route = _text(item.get("full_route") or item.get("route") or item.get("url") or item.get("endpoint"))
        if not route:
            continue
        routes.append(
            SourceRoute(
                asset=asset,
                method=_normalize_method(item.get("method")),
                route=_normalize_path(route),
                source_path=_optional_text(item.get("path") or item.get("source_path") or item.get("file")),
                line=_int_or_none(item.get("line") or item.get("start_line")),
                handler=_optional_text(item.get("handler")),
                framework=_optional_text(item.get("framework")),
                snippet_hash=_optional_text(item.get("snippet_hash")),
                route_resolution_confidence=_optional_text(item.get("route_resolution_confidence")),
            )
        )
    return routes


def _dedupe_source_routes(routes: list[SourceRoute]) -> list[SourceRoute]:
    seen: set[tuple[str, str, str | None, int | None]] = set()
    deduped: list[SourceRoute] = []
    for route in routes:
        key = (route.method, route.route, route.source_path, route.line)
        if key in seen:
            continue
        deduped.append(route)
        seen.add(key)
    return sorted(deduped, key=lambda route: (route.route, route.method, route.source_path or "", route.line or 0))


def _latest_memory_content(memory: list[Any], kind: str) -> dict[str, Any]:
    for item in reversed(memory):
        if not isinstance(item, dict) or item.get("kind") != kind:
            continue
        content = item.get("content")
        return content if isinstance(content, dict) else {}
    return {}


def _read_memory(discovery_dir: Path) -> list[Any]:
    path = discovery_dir / "memory.json"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(parsed, list):
        raise ValueError(f"{path} must contain a JSON list")
    return parsed


def _normalize_method(value: Any) -> str:
    method = _text(value).upper()
    if not method:
        return "ANY"
    if method == "ALL":
        return "ANY"
    return method


def _methods_compatible(source_method: str, live_method: str) -> bool:
    source_methods = _method_set(source_method)
    live_methods = _method_set(live_method)
    return "ANY" in source_methods or "ANY" in live_methods or bool(source_methods & live_methods)


def _method_set(value: str) -> set[str]:
    methods = {_normalize_method(part) for part in re.split(r"[,|/]", value) if part.strip()}
    return methods or {"ANY"}


def _normalize_path(value: str) -> str:
    text = _text(value).strip()
    if not text:
        return ""
    parsed = urlparse(text)
    path = parsed.path if parsed.scheme and parsed.netloc else text.split("?", 1)[0]
    path = re.sub(r"/+", "/", path.strip())
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def _parameterized_path(path: str) -> str:
    normalized = _normalize_path(path)
    normalized = re.sub(r"\{[^}/]+\}", "{param}", normalized)
    normalized = re.sub(r"<[^>/]+>", "{param}", normalized)
    normalized = re.sub(r":([A-Za-z_][A-Za-z0-9_.-]*)", "{param}", normalized)
    return normalized


def _parameterized_paths_match(source_path: str, live_path: str) -> bool:
    if _parameterized_path(source_path) == _parameterized_path(live_path):
        return True
    return _path_pattern_matches(source_path, live_path) or _path_pattern_matches(live_path, source_path)


def _path_pattern_matches(pattern_path: str, concrete_path: str) -> bool:
    pattern_segments = _normalize_path(pattern_path).strip("/").split("/")
    concrete_segments = _normalize_path(concrete_path).strip("/").split("/")
    if pattern_segments == [""]:
        pattern_segments = []
    if concrete_segments == [""]:
        concrete_segments = []
    if len(pattern_segments) != len(concrete_segments):
        return False
    return all(_segment_matches(pattern, concrete) for pattern, concrete in zip(pattern_segments, concrete_segments))


def _segment_matches(pattern: str, concrete: str) -> bool:
    if _is_parameter_segment(pattern):
        return bool(concrete)
    if _is_parameter_segment(concrete):
        return bool(pattern)
    return pattern == concrete


def _is_parameter_segment(segment: str) -> bool:
    return bool(
        re.fullmatch(r"\{[^/]+\}", segment)
        or re.fullmatch(r"<[^/]+>", segment)
        or re.fullmatch(r":[A-Za-z_][A-Za-z0-9_.-]*", segment)
    )


def _dedupe_and_sort_links(links: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(link["id"]): link for link in links if isinstance(link, dict) and link.get("id")}
    return sorted(
        by_id.values(),
        key=lambda link: (
            -float(link.get("score") or 0),
            str(link.get("asset_refs") or []),
            str(link.get("basis") or ""),
            str(link.get("id") or ""),
        ),
    )


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _optional_text(value: Any) -> str | None:
    text = _text(value).strip()
    return text or None


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return None


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as tmp:
        tmp.write(payload)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
