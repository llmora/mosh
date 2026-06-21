from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable

from mosh.engagements import engagement_dir, engagement_exists, validate_engagement_id
from mosh.models import utc_now


HARNESS_IMPROVEMENTS_SCHEMA = "mosh.harness-improvements.v1"

VALID_IMPACTS = {"critical", "high", "medium", "low", "informational"}
MAX_TITLE_CHARS = 160
MAX_DETAIL_CHARS = 4_000
MAX_EVIDENCE_ITEMS = 20


def harness_improvements_path(output_root: Path, engagement_id: str) -> Path:
    return engagement_dir(output_root, engagement_id) / "harness_improvements.json"


def infer_engagement_location(path: Path) -> tuple[Path, str] | None:
    current = path.resolve()
    candidates = [current, *current.parents]
    for candidate in candidates:
        if re.fullmatch(r"eng_[a-z0-9]{8}", candidate.name):
            return candidate.parent, candidate.name
    return None


def load_harness_improvements(output_root: Path, engagement_id: str) -> dict[str, Any]:
    engagement_id = validate_engagement_id(engagement_id)
    path = harness_improvements_path(output_root, engagement_id)
    if not path.exists():
        return _empty_payload(engagement_id)
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a harness improvements object")
    if parsed.get("schema") != HARNESS_IMPROVEMENTS_SCHEMA:
        raise ValueError(f"{path} has unsupported schema `{parsed.get('schema')}`")
    if parsed.get("engagement_id") != engagement_id:
        raise ValueError(f"{path} contains engagement id `{parsed.get('engagement_id')}`, expected `{engagement_id}`")
    suggestions = parsed.get("suggestions")
    if not isinstance(suggestions, list):
        raise ValueError(f"{path} field suggestions must be a list")
    return {
        "schema": HARNESS_IMPROVEMENTS_SCHEMA,
        "engagement_id": engagement_id,
        "suggestions": [item for item in suggestions if isinstance(item, dict)],
    }


def iter_harness_improvements(output_root: Path, engagement_id: str | None = None) -> Iterable[dict[str, Any]]:
    if engagement_id is not None:
        payload = load_harness_improvements(output_root, engagement_id)
        for suggestion in payload["suggestions"]:
            yield {"engagement_id": engagement_id, **suggestion}
        return

    if not output_root.exists():
        return
    for candidate in sorted(output_root.iterdir()):
        if not candidate.is_dir() or not re.fullmatch(r"eng_[a-z0-9]{8}", candidate.name):
            continue
        path = candidate / "harness_improvements.json"
        if not path.exists():
            continue
        payload = load_harness_improvements(output_root, candidate.name)
        for suggestion in payload["suggestions"]:
            yield {"engagement_id": candidate.name, **suggestion}


def record_harness_improvement(
    output_root: Path,
    engagement_id: str,
    *,
    stage: str,
    agent: str,
    category: str,
    impact: str,
    title: str,
    problem: str,
    suggestion: str,
    evidence: Any = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    engagement_id = validate_engagement_id(engagement_id)
    if not engagement_exists(output_root, engagement_id):
        raise FileNotFoundError(f"Engagement not found: {engagement_id}")
    normalized = _normalized_suggestion(
        category=category,
        impact=impact,
        title=title,
        problem=problem,
        suggestion=suggestion,
        evidence=evidence,
    )
    fingerprint = _fingerprint(normalized)
    suggestion_id = "hi_" + fingerprint.removeprefix("sha256:")[:12]
    now = utc_now()
    occurrence = {
        "stage": _clean_token(stage) or "unknown",
        "agent": _clean_token(agent) or "unknown",
        "source_ref": _clean_optional_text(source_ref, MAX_TITLE_CHARS),
        "recorded_at": now,
    }

    payload = load_harness_improvements(output_root, engagement_id)
    existing = next((item for item in payload["suggestions"] if item.get("fingerprint") == fingerprint), None)
    if existing is None:
        existing = {
            "id": suggestion_id,
            "fingerprint": fingerprint,
            "status": "proposed",
            "category": normalized["category"],
            "impact": normalized["impact"],
            "title": normalized["title"],
            "problem": normalized["problem"],
            "suggestion": normalized["suggestion"],
            "evidence": normalized["evidence"],
            "first_seen_at": now,
            "last_seen_at": now,
            "occurrences": [],
        }
        payload["suggestions"].append(existing)
    else:
        existing["last_seen_at"] = now
        existing["evidence"] = _merge_unique_strings(existing.get("evidence"), normalized["evidence"], MAX_EVIDENCE_ITEMS)

    existing.setdefault("occurrences", [])
    if isinstance(existing["occurrences"], list):
        existing["occurrences"].append(occurrence)
    else:
        existing["occurrences"] = [occurrence]

    payload["suggestions"] = sorted(payload["suggestions"], key=_suggestion_sort_key)
    _write_json(harness_improvements_path(output_root, engagement_id), payload)
    return existing


def _empty_payload(engagement_id: str) -> dict[str, Any]:
    return {
        "schema": HARNESS_IMPROVEMENTS_SCHEMA,
        "engagement_id": engagement_id,
        "suggestions": [],
    }


def _normalized_suggestion(
    *,
    category: str,
    impact: str,
    title: str,
    problem: str,
    suggestion: str,
    evidence: Any,
) -> dict[str, Any]:
    normalized_impact = _normalize_impact(impact)
    normalized = {
        "category": _clean_category(category),
        "impact": normalized_impact,
        "title": _clean_required_text(title, "title", MAX_TITLE_CHARS),
        "problem": _clean_required_text(problem, "problem", MAX_DETAIL_CHARS),
        "suggestion": _clean_required_text(suggestion, "suggestion", MAX_DETAIL_CHARS),
        "evidence": _string_list(evidence)[:MAX_EVIDENCE_ITEMS],
    }
    return normalized


def _fingerprint(value: dict[str, Any]) -> str:
    payload = {
        "category": value["category"],
        "title": _normalize_text_for_fingerprint(value["title"]),
        "problem": _normalize_text_for_fingerprint(value["problem"]),
        "suggestion": _normalize_text_for_fingerprint(value["suggestion"]),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _suggestion_sort_key(value: dict[str, Any]) -> tuple[int, str, str]:
    impact_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    return (
        impact_rank.get(str(value.get("impact")), 5),
        str(value.get("category") or ""),
        str(value.get("title") or ""),
    )


def _clean_required_text(value: str, field: str, limit: int) -> str:
    text = _clean_optional_text(value, limit)
    if not text:
        raise ValueError(f"Harness improvement {field} must not be empty")
    return text


def _clean_optional_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).strip().split())
    if not text:
        return None
    return text[:limit]


def _clean_category(value: str) -> str:
    text = str(value or "other").strip().lower().replace("_", "-")
    text = re.sub(r"[^a-z0-9-]+", "-", text).strip("-")
    return text or "other"


def _clean_token(value: str) -> str:
    text = str(value or "").strip().lower().replace(" ", "-").replace("_", "-")
    return re.sub(r"[^a-z0-9-]+", "-", text).strip("-")


def _normalize_impact(value: str) -> str:
    text = str(value or "medium").strip().lower().replace("_", "-")
    if text == "info":
        text = "informational"
    if text not in VALID_IMPACTS:
        allowed = ", ".join(sorted(VALID_IMPACTS))
        raise ValueError(f"Unsupported harness improvement impact `{value}`. Expected one of: {allowed}.")
    return text


def _normalize_text_for_fingerprint(value: str) -> str:
    return " ".join(str(value).strip().lower().split())


def _string_list(value: Any) -> list[str]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        items = value
    else:
        items = [value]
    strings: list[str] = []
    for item in items:
        text = _clean_optional_text(item, MAX_DETAIL_CHARS)
        if text and text not in strings:
            strings.append(text)
    return strings


def _merge_unique_strings(existing: Any, new: list[str], limit: int) -> list[str]:
    merged = _string_list(existing)
    for item in new:
        if item not in merged:
            merged.append(item)
    return merged[:limit]


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
