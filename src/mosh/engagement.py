from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mosh.scope import normalize_url


ENGAGEMENT_STEER_MAX_CHARS = 8192


def write_engagement_template(report_dir: Path, target_url: str, plan: dict[str, Any]) -> str:
    return write_engagement_template_mapping(report_dir, build_engagement_template(target_url, plan))


def write_engagement_template_mapping(
    report_dir: Path,
    template: dict[str, Any],
    *,
    preserve_existing: bool = True,
    reject_candidate_credentials: bool = True,
) -> str:
    path = report_dir / "engagement_template.yaml"
    existing_template = _simplify_engagement_template(load_engagement_file(path)) if preserve_existing and path.exists() else {}
    validate_engagement_template(template)
    final_template = _simplify_engagement_template(template)
    if reject_candidate_credentials:
        _validate_no_new_secret_values(final_template, existing_template)
    if existing_template:
        final_template = _merge_existing_engagement_values(final_template, existing_template)
    validate_engagement_template(final_template)
    content = _dump_yaml(final_template)
    if path.exists():
        _backup_existing_engagement_template(path)
    path.write_text(content, encoding="utf-8")
    return content


def validate_engagement_template(template: dict[str, Any]) -> None:
    required_keys = {
        "engagement",
        "targets",
        "contacts",
        "limits",
        "credentials",
        "safe_test_data",
    }
    missing = sorted(required_keys - set(template))
    if missing:
        raise ValueError(f"Engagement template is missing required keys: {', '.join(missing)}")
    for key in ("engagement", "targets", "contacts", "limits", "credentials", "safe_test_data"):
        if not isinstance(template.get(key), dict):
            raise ValueError(f"Engagement template field {key} must be a mapping")
    llm = template.get("llm")
    if llm is not None and not isinstance(llm, dict):
        raise ValueError("Engagement template field llm must be a mapping")
    if isinstance(llm, dict):
        steer = llm.get("engagement_steer")
        if steer is not None and not isinstance(steer, str):
            raise ValueError("Engagement template field llm.engagement_steer must be a string or null")
        if isinstance(steer, str) and len(steer) > ENGAGEMENT_STEER_MAX_CHARS:
            raise ValueError(
                "Engagement template field llm.engagement_steer "
                f"must be {ENGAGEMENT_STEER_MAX_CHARS} characters or fewer"
            )


def _backup_existing_engagement_template(path: Path) -> Path:
    backup_dir = path.parent / "engagement_template.backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = backup_dir / f"engagement_template-{timestamp}.yaml"
    counter = 1
    while backup_path.exists():
        backup_path = backup_dir / f"engagement_template-{timestamp}-{counter}.yaml"
        counter += 1
    backup_path.write_bytes(path.read_bytes())
    return backup_path


def _validate_no_new_secret_values(candidate: dict[str, Any], existing: dict[str, Any]) -> None:
    credentials = candidate.get("credentials") if isinstance(candidate.get("credentials"), dict) else {}
    existing_credentials = existing.get("credentials") if isinstance(existing.get("credentials"), dict) else {}
    for role, values in credentials.items():
        if not isinstance(values, dict):
            raise ValueError(f"credentials.{role} must be a mapping")
        existing_values = existing_credentials.get(role) if isinstance(existing_credentials.get(role), dict) else {}
        for field in ("username", "password", "token"):
            candidate_value = _text(values.get(field))
            if not candidate_value:
                continue
            if candidate_value != _text(existing_values.get(field)):
                raise ValueError(f"Refined template must not invent credentials.{role}.{field}")


def render_engagement_template(target_url: str, plan: dict[str, Any]) -> str:
    template = build_engagement_template(target_url, plan)
    return _dump_yaml(template)


def build_engagement_template(target_url: str, plan: dict[str, Any]) -> dict[str, Any]:
    targets = _infer_targets(target_url, plan)
    roles = _infer_credential_roles(plan)
    return {
        "engagement": {
            "authorization_confirmed": True,
            "active_testing_allowed": True,
            "state_changing_tests_allowed": True,
            "notes": None,
        },
        "targets": {
            "production": targets,
            "alternative": {key: None for key in targets},
        },
        "contacts": {
            "escalation": {
                "name": None,
                "email": None,
                "phone": None,
            }
        },
        "limits": {
            "max_requests_per_test": 100,
            "max_rate_per_second": 5,
            "stop_on_sensitive_data": True,
            "evidence_redaction": True,
        },
        "credentials": {
            role: {
                "username": None,
                "password": None,
                "token": None,
            }
            for role in roles
        },
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
        "llm": {
            "engagement_steer": None,
        },
    }


def build_minimal_engagement_template() -> dict[str, Any]:
    return {
        "engagement": {
            "authorization_confirmed": None,
            "active_testing_allowed": None,
            "state_changing_tests_allowed": None,
            "notes": None,
        },
        "targets": {
            "production": {},
            "alternative": {},
        },
        "contacts": {
            "escalation": {
                "name": None,
                "email": None,
                "phone": None,
            }
        },
        "limits": {},
        "credentials": {},
        "safe_test_data": {},
        "llm": {
            "engagement_steer": None,
        },
    }


def engagement_steer(template: dict[str, Any]) -> str:
    llm = template.get("llm") if isinstance(template.get("llm"), dict) else {}
    value = llm.get("engagement_steer") if isinstance(llm, dict) else None
    if not isinstance(value, str):
        return ""
    return value.strip()


def engagement_steer_prompt_value(steer: str | None) -> str:
    value = steer.strip() if isinstance(steer, str) else ""
    if not value:
        return "None provided."
    return value


def load_engagement_steer(path: Path) -> str:
    try:
        return engagement_steer(load_engagement_file(path))
    except FileNotFoundError:
        return ""


def _simplify_engagement_template(template: dict[str, Any]) -> dict[str, Any]:
    return {
        "engagement": _simplify_engagement(template.get("engagement")),
        "targets": _simplify_targets(template.get("targets")),
        "contacts": _simplify_mapping(template.get("contacts")),
        "limits": _simplify_mapping(template.get("limits")),
        "credentials": _simplify_credentials(template.get("credentials")),
        "safe_test_data": _simplify_safe_test_data(template.get("safe_test_data")),
        "llm": _simplify_llm(template.get("llm")),
    }


def _simplify_engagement(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    return {
        "authorization_confirmed": source.get("authorization_confirmed"),
        "active_testing_allowed": source.get("active_testing_allowed"),
        "state_changing_tests_allowed": source.get("state_changing_tests_allowed"),
        "notes": _unwrap_config_value(source.get("notes")),
    }


def _simplify_targets(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    return {
        "production": _simplify_mapping(source.get("production")),
        "alternative": _simplify_mapping(source.get("alternative")),
    }


def _simplify_credentials(value: Any) -> dict[str, dict[str, Any]]:
    source = value if isinstance(value, dict) else {}
    credentials: dict[str, dict[str, Any]] = {}
    for role, role_value in source.items():
        if not isinstance(role_value, dict):
            continue
        credentials[str(role)] = {
            "username": _unwrap_config_value(role_value.get("username")),
            "password": _unwrap_config_value(role_value.get("password")),
            "token": _unwrap_config_value(role_value.get("token")),
        }
    return credentials


def _simplify_safe_test_data(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    safe_data: dict[str, Any] = {}
    for key, item in source.items():
        if key in {"status", "needed_for", "required", "question", "notes"}:
            continue
        safe_data[str(key)] = _unwrap_config_value(item)
    return safe_data


def _simplify_llm(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    return {
        "engagement_steer": _unwrap_config_value(source.get("engagement_steer")),
    }


def _simplify_mapping(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    simplified: dict[str, Any] = {}
    for key, item in source.items():
        if key in {"status", "needed_for", "required", "question"}:
            continue
        simplified[str(key)] = _unwrap_config_value(item)
    return simplified


def _unwrap_config_value(value: Any) -> Any:
    if isinstance(value, dict):
        if "values" in value:
            return value.get("values")
        if "value" in value:
            return value.get("value")
        return _simplify_mapping(value)
    if isinstance(value, list):
        return [_unwrap_config_value(item) for item in value]
    return value


def _merge_existing_engagement_values(generated: Any, existing: Any) -> Any:
    if isinstance(generated, dict) and isinstance(existing, dict):
        merged: dict[str, Any] = {}
        for key in list(generated) + [key for key in existing if key not in generated]:
            merged[key] = _merge_existing_engagement_values(generated.get(key), existing.get(key))
        return merged
    if isinstance(generated, list) and isinstance(existing, list):
        if not _has_user_value(existing):
            return generated
        if not _has_user_value(generated):
            return existing
        return _merge_lists(existing, generated)
    if _has_user_value(existing):
        return existing
    return generated


def _merge_lists(existing: list[Any], generated: list[Any]) -> list[Any]:
    merged: list[Any] = []
    seen: set[str] = set()
    for item in existing + generated:
        marker = json.dumps(item, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(item)
    return merged


def _has_user_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value)
    if isinstance(value, dict):
        return any(_has_user_value(item) for item in value.values())
    return True


def load_engagement_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = _parse_simple_yaml(text)
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain an engagement mapping")
    return parsed


def resolve_target_mapping(engagement: dict[str, Any]) -> dict[str, str]:
    targets = engagement.get("targets") if isinstance(engagement.get("targets"), dict) else {}
    production = targets.get("production") if isinstance(targets.get("production"), dict) else {}
    alternative = targets.get("alternative") if isinstance(targets.get("alternative"), dict) else {}
    keys = sorted(set(production) | set(alternative))
    resolved: dict[str, str] = {}
    for key in keys:
        value = _text(alternative.get(key)) or _text(production.get(key))
        if value:
            resolved[key] = value
    return resolved


def _infer_targets(target_url: str, plan: dict[str, Any]) -> dict[str, str]:
    normalized = normalize_url(target_url)
    urls = _extract_urls(plan)
    api = next((url for url in urls if _hostname(url).startswith("api.") and "/api/private" in url), None)
    api = api or next((url for url in urls if _hostname(url).startswith("api.")), None)
    backoffice = next((url for url in urls if "/backoffice" in url), None)
    return {
        "website": normalized.rstrip("/"),
        "api": _api_base_url(api or _default_api_url(normalized)).rstrip("/"),
        "backoffice": (backoffice or f"{normalized.rstrip('/')}/backoffice").rstrip("/"),
    }


def _api_base_url(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    marker = "/api/private"
    if marker in parsed.path:
        path = parsed.path[: parsed.path.index(marker) + len(marker)]
        return parsed._replace(path=path, params="", query="", fragment="").geturl()
    return url


def _default_api_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if host.startswith("api."):
        return target_url
    return f"{parsed.scheme}://api.{host}/api/private"


def _extract_urls(value: Any) -> list[str]:
    text = json.dumps(value, sort_keys=True)
    return sorted(set(re.findall(r"https?://[^\s\"'<>),]+", text)))


def _hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _infer_credential_roles(plan: dict[str, Any]) -> list[str]:
    roles: list[str] = []
    for hypothesis in _list(plan.get("test_hypotheses")):
        if not isinstance(hypothesis, dict):
            continue
        for role in ("admin", "sales", "developer", "enterprise"):
            if _role_needed(role, hypothesis):
                roles.append(role)
        if _mentions_auth_material(hypothesis):
            roles.append("authenticated_user")
    if not roles:
        roles.append("authenticated_user")
    return sorted(set(roles))


def _role_needed(role: str, hypothesis: dict[str, Any]) -> bool:
    text = _requirement_text(hypothesis)
    if role == "authenticated_user":
        return _mentions_auth_material(hypothesis)
    if role == "enterprise":
        return _enterprise_credentials_needed(text)
    return _contains_word(text, role)


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


def _mentions_auth_material(hypothesis: dict[str, Any]) -> bool:
    text = _requirement_text(hypothesis)
    return (
        _contains_word(text, "credential")
        or _contains_word(text, "credentials")
        or _contains_phrase(text, "authenticated session")
        or _contains_phrase(text, "auth token")
        or _contains_word(text, "token")
    )


def _requirement_text(hypothesis: dict[str, Any]) -> str:
    material = {
        "requirements": hypothesis.get("requirements"),
        "preconditions": hypothesis.get("preconditions"),
    }
    return json.dumps(material, sort_keys=True).lower()


def _contains_word(text: str, word: str) -> bool:
    return bool(re.search(rf"\b{re.escape(word)}\b", text))


def _contains_phrase(text: str, phrase: str) -> bool:
    return phrase in text


def _dump_yaml(value: Any, indent: int = 0) -> str:
    lines = _yaml_lines(value, indent)
    return "\n".join(lines).rstrip() + "\n"


def _yaml_lines(value: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if _is_block_string(item):
                lines.append(f"{pad}{key}: |-")
                lines.extend(_yaml_block_lines(item, indent + 2))
            elif _is_scalar(item):
                lines.append(f"{pad}{key}: {_yaml_scalar(item)}")
            else:
                lines.append(f"{pad}{key}:")
                lines.extend(_yaml_lines(item, indent + 2))
        return lines
    if isinstance(value, list):
        if not value:
            return [f"{pad}[]"]
        lines = []
        for item in value:
            if _is_scalar(item):
                lines.append(f"{pad}- {_yaml_scalar(item)}")
            else:
                lines.append(f"{pad}-")
                lines.extend(_yaml_lines(item, indent + 2))
        return lines
    return [f"{pad}{_yaml_scalar(value)}"]


def _is_block_string(value: Any) -> bool:
    return isinstance(value, str) and "\n" in value


def _yaml_block_lines(value: str, indent: int) -> list[str]:
    pad = " " * indent
    return [f"{pad}{line}" if line else pad for line in value.splitlines()]


def _parse_simple_yaml(text: str) -> Any:
    rows = _yaml_rows(text)
    value, index = _parse_yaml_block(rows, 0, 0)
    if index != len(rows):
        raise ValueError("Unexpected trailing YAML content")
    return value


def _yaml_rows(text: str) -> list[tuple[int, str]]:
    raw_lines = text.splitlines()
    rows: list[tuple[int, str]] = []
    index = 0
    while index < len(raw_lines):
        line = raw_lines[index]
        stripped = line.strip()
        if not stripped or line.lstrip().startswith("#"):
            index += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        key, sep, value = stripped.partition(":")
        if sep and value.strip() in {"|", "|-", "|+"}:
            block_value, index = _parse_yaml_block_scalar(raw_lines, index + 1, indent, value.strip())
            rows.append((indent, f"{key.strip()}: {json.dumps(block_value)}"))
            continue
        rows.append((indent, stripped))
        index += 1
    return rows


def _parse_yaml_block_scalar(
    raw_lines: list[str],
    index: int,
    parent_indent: int,
    marker: str,
) -> tuple[str, int]:
    block_lines: list[str] = []
    content_indent: int | None = None
    while index < len(raw_lines):
        line = raw_lines[index]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if stripped and indent <= parent_indent:
            break
        if stripped and content_indent is None:
            content_indent = indent
        if content_indent is None:
            block_lines.append("")
        elif not stripped:
            block_lines.append("")
        else:
            block_lines.append(line[content_indent:])
        index += 1
    text = "\n".join(block_lines)
    if marker == "|":
        text += "\n"
    return text, index


def _parse_yaml_block(rows: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(rows):
        return {}, index
    current_indent, text = rows[index]
    if current_indent < indent:
        return {}, index
    if text.startswith("-") and current_indent == indent:
        return _parse_yaml_list(rows, index, indent)
    return _parse_yaml_dict(rows, index, indent)


def _parse_yaml_dict(rows: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(rows):
        current_indent, text = rows[index]
        if current_indent < indent or current_indent != indent or text.startswith("-"):
            break
        key, sep, value = text.partition(":")
        if not sep:
            raise ValueError(f"Invalid YAML mapping line: {text}")
        key = key.strip()
        value = value.strip()
        index += 1
        if value:
            result[key] = _parse_yaml_scalar(value)
        else:
            nested, index = _parse_yaml_block(rows, index, indent + 2)
            result[key] = nested
    return result, index


def _parse_yaml_list(rows: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(rows):
        current_indent, text = rows[index]
        if current_indent != indent or not text.startswith("-"):
            break
        rest = text[1:].strip()
        index += 1
        if not rest:
            item, index = _parse_yaml_block(rows, index, indent + 2)
            result.append(item)
            continue
        if ":" in rest:
            key, _, value = rest.partition(":")
            item: dict[str, Any] = {key.strip(): _parse_yaml_scalar(value.strip()) if value.strip() else None}
            if index < len(rows) and rows[index][0] > indent:
                nested, index = _parse_yaml_dict(rows, index, indent + 2)
                item.update(nested)
            result.append(item)
        else:
            result.append(_parse_yaml_scalar(rest))
    return result, index


def _parse_yaml_scalar(value: str) -> Any:
    if value == "[]":
        return []
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        pass
    try:
        return int(value)
    except ValueError:
        return value


def _is_scalar(value: Any) -> bool:
    if value == []:
        return True
    return value is None or isinstance(value, (str, int, float, bool))


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    if value == []:
        return "[]"
    return json.dumps(str(value))


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
