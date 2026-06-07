from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from appsec_harness.config import AppConfig
from appsec_harness.engagement import load_engagement_file, resolve_target_mapping
from appsec_harness.memory import FileMemory
from appsec_harness.models import Event
from appsec_harness.scope import report_dir_name


@dataclass(frozen=True)
class SecurityTestPreflightResult:
    ready: list[dict[str, Any]]
    blocked: list[dict[str, Any]]
    targets: dict[str, str]


class SecurityTestingOrchestrator:
    def __init__(
        self,
        config: AppConfig,
        output_root: Path = Path("report"),
        event_sink: Callable[[Event], None] | None = None,
    ) -> None:
        self.config = config
        self.output_root = output_root
        self.event_sink = event_sink

    def run(self, url: str, engagement_file: Path) -> Path:
        domain_dir = self.output_root / report_dir_name(url)
        planning_dir = domain_dir / "security-test-planning"
        report_dir = domain_dir / "security-testing"
        memory = FileMemory(report_dir, event_sink=self.event_sink)
        memory.record_event(
            "orchestrator",
            "start",
            "Starting security testing preflight",
            {"target": url, "engagement_file": str(engagement_file)},
        )
        plan = load_security_test_plan(planning_dir)
        engagement = load_engagement_file(engagement_file)
        result = run_security_testing_preflight(plan, engagement)
        markdown = render_preflight_report(url, engagement_file, result)
        (report_dir / "preflight.md").write_text(markdown, encoding="utf-8")
        memory.add_item(
            "security_testing_preflight",
            {
                "ready": result.ready,
                "blocked": result.blocked,
                "targets": result.targets,
            },
            "security_test_coordinator",
        )
        memory.record_event(
            "orchestrator",
            "complete",
            "Security testing preflight completed",
            {
                "ready": len(result.ready),
                "blocked": len(result.blocked),
                "report_dir": str(report_dir),
            },
        )
        return report_dir


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


def run_security_testing_preflight(plan: dict[str, Any], engagement: dict[str, Any]) -> SecurityTestPreflightResult:
    targets = resolve_target_mapping(engagement)
    ready: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for hypothesis in _hypotheses(plan):
        blockers = _hypothesis_blockers(hypothesis, engagement, targets)
        item = {
            "id": _text(hypothesis.get("id")) or "unknown",
            "title": _text(hypothesis.get("title")) or "Untitled test",
            "priority": _text(hypothesis.get("priority")) or "unknown",
            "surface": _text(hypothesis.get("surface")) or "unknown",
            "blockers": blockers,
        }
        if blockers:
            blocked.append(item)
        else:
            ready.append(item)
    return SecurityTestPreflightResult(ready=ready, blocked=blocked, targets=targets)


def render_preflight_report(target_url: str, engagement_file: Path, result: SecurityTestPreflightResult) -> str:
    lines = [
        "# Security Testing Preflight",
        "",
        f"- Target URL: `{target_url}`",
        f"- Engagement file: `{engagement_file}`",
        f"- Ready tests: `{len(result.ready)}`",
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
            lines.append(f"- **{item['id']}**: {item['title']} ({item['priority']})")
    else:
        lines.append("No tests are ready to execute.")
    lines.extend(["", "## Blocked Tests", ""])
    if result.blocked:
        for item in result.blocked:
            lines.append(f"- **{item['id']}**: {item['title']} ({item['priority']})")
            for blocker in item["blockers"]:
                lines.append(f"  - {blocker}")
    else:
        lines.append("No tests are blocked.")
    return "\n".join(lines).rstrip() + "\n"


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
    roles = [role for role in ("admin", "sales", "developer", "enterprise") if _contains_word(text, role)]
    if not roles and _mentions_auth_material(text):
        roles.append("authenticated_user")
    return sorted(set(roles))


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


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
