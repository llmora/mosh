from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from appsec_harness.scope import normalize_url


def write_engagement_template(report_dir: Path, target_url: str, plan: dict[str, Any]) -> str:
    content = render_engagement_template(target_url, plan)
    path = report_dir / "engagement_template.yaml"
    path.write_text(content, encoding="utf-8")
    return content


def write_engagement_template_mapping(report_dir: Path, template: dict[str, Any]) -> str:
    validate_engagement_template(template)
    content = _dump_yaml(template)
    (report_dir / "engagement_template.yaml").write_text(content, encoding="utf-8")
    return content


def validate_engagement_template(template: dict[str, Any]) -> None:
    required_keys = {
        "engagement",
        "targets",
        "contacts",
        "limits",
        "credentials",
        "safe_test_data",
        "required_answers",
    }
    missing = sorted(required_keys - set(template))
    if missing:
        raise ValueError(f"Engagement template is missing required keys: {', '.join(missing)}")
    for key in ("engagement", "targets", "contacts", "limits", "credentials", "safe_test_data"):
        if not isinstance(template.get(key), dict):
            raise ValueError(f"Engagement template field {key} must be a mapping")
    if not isinstance(template.get("required_answers"), list):
        raise ValueError("Engagement template field required_answers must be a list")
    _validate_no_secret_values(template)


def _validate_no_secret_values(template: dict[str, Any]) -> None:
    credentials = template.get("credentials") if isinstance(template.get("credentials"), dict) else {}
    for role, values in credentials.items():
        if not isinstance(values, dict):
            raise ValueError(f"credentials.{role} must be a mapping")
        for field in ("username", "password", "token"):
            if _text(values.get(field)):
                raise ValueError(f"Refined template must not invent credentials.{role}.{field}")


def render_engagement_template(target_url: str, plan: dict[str, Any]) -> str:
    template = build_engagement_template(target_url, plan)
    return _dump_yaml(template)


def build_engagement_template(target_url: str, plan: dict[str, Any]) -> dict[str, Any]:
    targets = _infer_targets(target_url, plan)
    roles = _infer_credential_roles(plan)
    hypotheses = [_hypothesis_id(item) for item in _list(plan.get("test_hypotheses")) if isinstance(item, dict)]
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
                "notes": _credential_note(role, plan),
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
        },
        "required_answers": _required_answers(plan, hypotheses),
    }


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
    text = json.dumps(plan, sort_keys=True).lower()
    roles: list[str] = []
    for role in ("admin", "sales", "developer", "enterprise"):
        if role in text:
            roles.append(role)
    if "credential" in text or "authenticated" in text or "token" in text:
        roles.append("authenticated_user")
    if not roles:
        roles.append("authenticated_user")
    return sorted(set(roles))


def _credential_note(role: str, plan: dict[str, Any]) -> str:
    needed_for = [
        _hypothesis_id(item)
        for item in _list(plan.get("test_hypotheses"))
        if isinstance(item, dict) and _role_needed(role, item)
    ]
    if not needed_for and role == "authenticated_user":
        needed_for = [
            _hypothesis_id(item)
            for item in _list(plan.get("test_hypotheses"))
            if isinstance(item, dict) and _mentions_auth_material(item)
        ]
    if not needed_for:
        return "Fill if this role is needed by the selected test plan."
    return f"Required by {', '.join(needed_for)}."


def _role_needed(role: str, hypothesis: dict[str, Any]) -> bool:
    text = _requirement_text(hypothesis)
    if role == "authenticated_user":
        return _mentions_auth_material(hypothesis)
    return _contains_word(text, role)


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


def _required_answers(plan: dict[str, Any], hypotheses: list[str]) -> list[dict[str, Any]]:
    answers = [
        {
            "question": "Provide alternative target URLs only if testing should run against staging or another environment instead of production.",
            "needed_for": ["all"],
        },
        {
            "question": "Provide test credentials and tokens listed in the credentials section where available.",
            "needed_for": hypotheses or ["credentialed tests"],
        },
        {
            "question": "Provide safe test data for forms, customer IDs, enterprise account IDs, and activation codes.",
            "needed_for": _state_changing_hypotheses(plan) or ["state-changing tests"],
        },
    ]
    for question in _list(plan.get("open_questions")):
        text = _text(question)
        if text and not _is_duplicate_required_question(text):
            answers.append({"question": text, "needed_for": ["planning open question"]})
    return answers


def _is_duplicate_required_question(question: str) -> bool:
    lowered = question.lower()
    duplicate_markers = (
        "staging/test environment",
        "agreed testing hours",
        "escalation contacts",
        "source ips",
    )
    return any(marker in lowered for marker in duplicate_markers)


def _contains_word(text: str, word: str) -> bool:
    return bool(re.search(rf"\b{re.escape(word)}\b", text))


def _contains_phrase(text: str, phrase: str) -> bool:
    return phrase in text


def _state_changing_hypotheses(plan: dict[str, Any]) -> list[str]:
    return [
        _hypothesis_id(item)
        for item in _list(plan.get("test_hypotheses"))
        if isinstance(item, dict) and _is_state_changing(item)
    ]


def _is_state_changing(hypothesis: dict[str, Any]) -> bool:
    text = json.dumps(hypothesis, sort_keys=True).lower()
    return any(marker in text for marker in ("post ", " put ", " delete ", "submit", "create", "modify", "invite"))


def _hypothesis_id(hypothesis: dict[str, Any]) -> str:
    return _text(hypothesis.get("id")) or _text(hypothesis.get("title")) or "unknown"


def _dump_yaml(value: Any, indent: int = 0) -> str:
    lines = _yaml_lines(value, indent)
    return "\n".join(lines).rstrip() + "\n"


def _yaml_lines(value: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if _is_scalar(item):
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


def _parse_simple_yaml(text: str) -> Any:
    rows = [
        (len(line) - len(line.lstrip(" ")), line.strip())
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    value, index = _parse_yaml_block(rows, 0, 0)
    if index != len(rows):
        raise ValueError("Unexpected trailing YAML content")
    return value


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
