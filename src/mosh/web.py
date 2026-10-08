"""Small localhost interface for setup and assessment creation."""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Callable
from urllib.parse import parse_qs, quote, urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mosh.config import AppConfig
from mosh.engagement import build_minimal_engagement_template, load_engagement_file, write_engagement_template_mapping, validate_engagement_template
from mosh.engagements import (
    Engagement,
    EngagementAsset,
    asset_discovery_dir,
    attach_asset,
    create_engagement,
    detach_asset,
    engagement_dir,
    engagement_plan_dir,
    load_engagement,
    normalize_asset_locator,
    record_asset_discovery,
)
from mosh.models import Event
from mosh.web_markdown import render_markdown_document


ASSET_TYPES = {
    "live_url": "Live URL",
    "source_tree": "Local source tree",
    "source_repo": "Git repository (HTTPS)",
}
CREDENTIAL_ROLES = {
    "admin": "Admin",
    "sales": "Sales",
    "developer": "Developer",
    "enterprise": "Enterprise",
    "authenticated_user": "Authenticated user",
}
TEST_DATA_FIELDS = {
    "email": "Test email",
    "phone": "Test phone number",
    "company": "Test company",
    "customer_ids": "Customer IDs",
    "enterprise_account_ids": "Enterprise account IDs",
    "activation_codes": "Activation codes",
}
TEST_DATA_LIST_FIELDS = {"customer_ids", "enterprise_account_ids", "activation_codes"}
TESTING_PERMISSION_BLOCKERS = {
    "authorization_confirmed is not true in the engagement file": ("authorization_confirmed", "Authorization confirmed"),
    "active_testing_allowed is not true in the engagement file": ("active_testing_allowed", "Active testing allowed"),
    "state_changing_tests_allowed is not true for this state-changing test": ("state_changing_tests_allowed", "State-changing tests allowed"),
}
KEY_NAMES = {
    "deepseek": "DEEPSEEK_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "custom": "MOSH_LLM_API_KEY",
}
KEY_FIELDS = {
    "deepseek": "deepseek_api_key",
    "openrouter": "openrouter_api_key",
    "custom": "custom_llm_api_key",
}
MAX_BODY_BYTES = 64 * 1024
DISCOVERY_STEPS = {
    "live_url": (
        "Crawling pages, forms and APIs",
        "Identifying technologies and services",
        "Writing discovery report",
    ),
    "source_tree": (
        "Indexing files, routes and API handlers",
        "Inspecting dependencies and configuration",
        "Summarizing components and coverage gaps",
        "Writing discovery report",
    ),
    "source_repo": (
        "Cloning repository and indexing files",
        "Inspecting dependencies and configuration",
        "Summarizing components and coverage gaps",
        "Writing discovery report",
    ),
}
DISCOVERY_STEP_AFTER_TASK = {
    "crawl_application_task": 1,
    "compile_components_task": 2,
    "map_source_task": 1,
    "inspect_dependency_config_task": 2,
    "analyze_discovery_source_gaps_task": 3,
}
DISCOVERY_STEP_FROM_ROLE = {
    "Web Application Discovery Crawler": 0,
    "Application Technology Mapper": 1,
    "Application Discovery Reporter": 2,
    "Source Intake Validator": 0,
    "Source Surface Mapper": 0,
    "Dependency And Configuration Mapper": 1,
    "Source Route Resolver": 2,
    "Source Component Mapper": 2,
    "Source Discovery Gap Analyst": 2,
    "Source Discovery Reporter": 3,
}
PLANNING_STEPS = (
    "Linking discovery evidence",
    "Drafting security test hypotheses",
    "Reviewing and refining the plan",
    "Writing security test plan",
)
PLANNING_STEP_AFTER_EVENT = {
    ("evidence_linker", "complete"): 1,
    ("evidence_linker", "skipped_current"): 1,
    ("planner", "plan_submitted"): 2,
    ("orchestrator", "engagement_template_written"): 3,
}
TESTING_STEPS = ("Running planned checks", "Reviewing evidence", "Writing test report")
TESTING_PROGRESS_PHASES = {
    "test_checks_started": 0,
    "test_evidence_ready": 1,
    "test_review_ready": 2,
    "report_written": 3,
    "report_fallback_written": 3,
}


def _h(value: object) -> str:
    return html.escape(str(value), quote=True)


def _web_testing_blocker(blocker: str) -> str:
    from mosh.crews.testing.crew import _unblock_guidance

    guidance = {
        "authorization_confirmed is not true in the engagement file": "Confirm authorization under Permissions in Scope.",
        "active_testing_allowed is not true in the engagement file": "Allow active testing under Permissions in Scope.",
        "state_changing_tests_allowed is not true for this state-changing test": "Allow state-changing tests under Permissions in Scope.",
        "no effective target mappings were resolved": "Add a target URL under Requested test information in Scope.",
        "live target URL is not available for this assessment": "Add a live URL asset in Scope.",
        "source code is not available for this hypothesis": "Add a source asset in Scope and run discovery.",
    }
    if blocker in guidance:
        return guidance[blocker]
    if blocker.startswith("missing credential material for "):
        role = blocker.removeprefix("missing credential material for ")
        return f"Add {CREDENTIAL_ROLES.get(role, role.replace('_', ' ').title())} credentials in Scope."
    if blocker.startswith("missing safe_test_data."):
        key = blocker.removeprefix("missing safe_test_data.")
        return f"Add {TEST_DATA_FIELDS.get(key, 'test data')} under Safe test data in Scope."
    return _unblock_guidance(blocker)


def _testing_input_for_blocker(blocker: str) -> tuple[str, str] | None:
    if blocker.startswith("missing credential material for "):
        role = blocker.removeprefix("missing credential material for ")
        return ("credential", role) if role in CREDENTIAL_ROLES else None
    if blocker.startswith("missing safe_test_data."):
        key = blocker.removeprefix("missing safe_test_data.")
        return ("data", key) if key in TEST_DATA_FIELDS else None
    if blocker in TESTING_PERMISSION_BLOCKERS:
        return "permission", TESTING_PERMISSION_BLOCKERS[blocker][0]
    if blocker == "no effective target mappings were resolved":
        return "target", ""
    return None


def _stage_step_class(index: int, active_step: int, status: str) -> str:
    if index < active_step:
        return "done"
    if index == active_step and status in {"running", "failed"}:
        return "current" if status == "running" else "failed"
    return "waiting"


def _testing_updating_plan(events: list[Event]) -> bool:
    for event in reversed(events):
        if event.action == "planning_refresh_complete":
            return False
        if event.action == "planning_refresh_start":
            return True
    return False


@dataclass
class WebResponse:
    status: int = 200
    body: str = ""
    content_type: str = "text/html; charset=utf-8"
    location: str | None = None


@dataclass
class AssessmentDraft:
    title: str = ""
    assets: list[tuple[str, str]] = field(default_factory=list)
    authorized: bool = False
    pending_asset: tuple[str, str] | None = None
    check_state: str = ""
    check_message: str = ""
    checked_assets: dict[tuple[str, str], str] = field(default_factory=dict)


@dataclass
class PendingAssessmentAsset:
    kind: str
    locator: str
    state: str = "checking"
    message: str = ""


@dataclass
class DiscoveryRun:
    asset_ids: list[str]
    current_asset_id: str
    completed_ids: set[str] = field(default_factory=set)
    active_step: int = 0
    status: str = "running"
    error: str = ""
    failed_asset_id: str = ""
    events: list[tuple[str, Event]] = field(default_factory=list)


@dataclass
class PlanningRun:
    active_step: int = 0
    status: str = "running"
    error: str = ""
    events: list[Event] = field(default_factory=list)


@dataclass
class TestingRun:
    status: str = "running"
    error: str = ""
    events: list[Event] = field(default_factory=list)


class WebApp:
    def __init__(
        self,
        root: Path,
        *,
        environment_probe: Callable[[], dict[str, bool]] | None = None,
        build_runner: Callable[[], bool] | None = None,
        provider_checker: Callable[[str, str, str], tuple[bool, str]] | None = None,
        asset_checker: Callable[[str, str], tuple[bool, str]] | None = None,
        discovery_runner: Callable[[AppConfig, Path, Engagement, EngagementAsset, Callable[[Event], None]], Path] | None = None,
        planning_runner: Callable[[AppConfig, Path, str, Callable[[Event], None]], Path] | None = None,
        testing_runner: Callable[[AppConfig, Path, str, Callable[[Event], None]], Path] | None = None,
        folder_root: Path | None = None,
    ) -> None:
        self.root = root.resolve()
        self.output_root = self.root / "report"
        self.csrf_token = secrets.token_urlsafe(32)
        self.assessment_draft = AssessmentDraft()
        self._asset_lock = threading.Lock()
        self.assessment_asset_checks: dict[str, PendingAssessmentAsset] = {}
        self.discovery_runs: dict[str, DiscoveryRun] = {}
        self.planning_runs: dict[str, PlanningRun] = {}
        self.testing_runs: dict[str, TestingRun] = {}
        self._run_lock = threading.RLock()
        self.discovery_runner = discovery_runner or self._run_discovery_asset
        self.planning_runner = planning_runner or self._run_planning
        self.testing_runner = testing_runner or self._run_testing
        self.asset_checker = asset_checker or check_asset_reachability
        self.folder_root = (folder_root or Path.home()).resolve()
        self.environment_probe = environment_probe or self._probe_environment
        self.build_runner = build_runner or self._build_tool_images
        self.build_state = "idle"
        self._build_lock = threading.Lock()
        self.provider_checker = provider_checker or check_provider_api
        self.provider_state: dict[str, tuple[str, str]] = {}
        self._provider_lock = threading.Lock()
        self.onboarding_active = not self.setup_ready()

    def handle(
        self,
        method: str,
        target: str,
        fields_data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> WebResponse:
        headers = {key.lower(): value for key, value in (headers or {}).items()}
        host = headers.get("host", "127.0.0.1")
        if not self._local_host(host):
            return WebResponse(403, "Localhost access only", "text/plain; charset=utf-8")
        if method == "POST":
            origin = headers.get("origin")
            if origin and not self._same_origin(origin, host):
                return WebResponse(403, "Invalid origin", "text/plain; charset=utf-8")
            if not fields_data or fields_data.get("csrf") != self.csrf_token:
                return WebResponse(403, "Invalid form token", "text/plain; charset=utf-8")
        parsed = urlsplit(target)
        path = parsed.path
        query = parse_qs(parsed.query)
        step = query.get("step", [""])[0]
        if method == "GET" and path == "/web.css":
            return WebResponse(body=(Path(__file__).with_name("web.css")).read_text(encoding="utf-8"), content_type="text/css; charset=utf-8")
        if method == "GET" and path == "/web.js":
            return WebResponse(body=(Path(__file__).with_name("web.js")).read_text(encoding="utf-8"), content_type="text/javascript; charset=utf-8")
        if self.onboarding_active or not self.setup_ready():
            self.onboarding_active = True
            if method == "GET" and path == "/setup":
                return self._setup_page(step or "environment", provider=query.get("provider", [""])[0])
            if method == "POST" and path.startswith("/setup/"):
                return self._setup_action(path, fields_data or {})
            return self._redirect("/setup")
        if path.startswith("/setup"):
            return self._redirect("/")
        if method == "GET" and path == "/":
            return self._home()
        if method == "POST" and path == "/new/start":
            self.assessment_draft = AssessmentDraft()
            return self._redirect("/new?step=details")
        if method == "GET" and path == "/new":
            return self._assessment_page(step or "details")
        if method == "GET" and path == "/new/folders":
            return self._folder_page(query.get("path", [""])[0])
        if method == "POST" and path.startswith("/new/"):
            return self._assessment_action(path, fields_data or {})
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/folders"):
            return self._folder_page(query.get("path", [""])[0], engagement_id=path.removeprefix("/assessments/").removesuffix("/folders"))
        if method == "POST" and path.startswith("/assessments/") and path.endswith("/select-folder"):
            return self._assessment_select_folder(path.removeprefix("/assessments/").removesuffix("/select-folder"), fields_data or {})
        if method == "POST" and path.startswith("/assessments/") and path.endswith("/assets"):
            return self._assessment_asset_action(path.removeprefix("/assessments/").removesuffix("/assets"), fields_data or {})
        if method == "POST" and path.startswith("/assessments/") and path.endswith("/discovery"):
            return self._discovery_action(path.removeprefix("/assessments/").removesuffix("/discovery"), fields_data or {})
        if method == "POST" and path.startswith("/assessments/") and path.endswith("/planning"):
            return self._planning_action(path.removeprefix("/assessments/").removesuffix("/planning"), fields_data or {})
        if method == "POST" and path.startswith("/assessments/") and path.endswith("/testing"):
            return self._testing_action(path.removeprefix("/assessments/").removesuffix("/testing"), fields_data or {})
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/testing/status"):
            return self._testing_status(
                path.removeprefix("/assessments/").removesuffix("/testing/status"),
                show_logs=query.get("view", [""])[0] == "logs",
            )
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/testing/preflight"):
            return self._testing_report(path.removeprefix("/assessments/").removesuffix("/testing/preflight"), "", preflight=True)
        testing_report_parts = path.split("/")
        if method == "GET" and len(testing_report_parts) == 6 and testing_report_parts[1] == "assessments" and testing_report_parts[3:5] == ["testing", "reports"]:
            return self._testing_report(testing_report_parts[2], testing_report_parts[5])
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/testing"):
            return self._testing_page(
                path.removeprefix("/assessments/").removesuffix("/testing"),
                show_logs=query.get("view", [""])[0] == "logs",
                open_requirements=query.get("details", [""])[0],
            )
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/planning/status"):
            return self._planning_status(
                path.removeprefix("/assessments/").removesuffix("/planning/status"),
                show_logs=query.get("view", [""])[0] == "logs",
            )
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/planning/report"):
            return self._planning_report(path.removeprefix("/assessments/").removesuffix("/planning/report"))
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/planning"):
            return self._planning_page(
                path.removeprefix("/assessments/").removesuffix("/planning"),
                show_logs=query.get("view", [""])[0] == "logs",
            )
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/discovery/status"):
            return self._discovery_status(
                path.removeprefix("/assessments/").removesuffix("/discovery/status"),
                show_logs=query.get("view", [""])[0] == "logs",
            )
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/discovery/refresh"):
            return self._discovery_refresh_page(path.removeprefix("/assessments/").removesuffix("/discovery/refresh"))
        if method == "GET" and path.startswith("/assessments/") and path.endswith("/discovery"):
            return self._discovery_page(path.removeprefix("/assessments/").removesuffix("/discovery"), show_logs=query.get("view", [""])[0] == "logs")
        if method == "POST" and path.startswith("/assessments/") and path.endswith("/guidance"):
            return self._assessment_guidance(path.removeprefix("/assessments/").removesuffix("/guidance"), fields_data or {})
        if method == "POST" and path.startswith("/assessments/") and path.endswith("/credentials"):
            return self._assessment_credentials(path.removeprefix("/assessments/").removesuffix("/credentials"), fields_data or {})
        if method == "POST" and path.startswith("/assessments/") and path.endswith("/test-setup"):
            return self._assessment_test_setup(path.removeprefix("/assessments/").removesuffix("/test-setup"), fields_data or {})
        report_parts = path.split("/")
        if method == "GET" and len(report_parts) == 6 and report_parts[1] == "assessments" and report_parts[3] == "discovery" and report_parts[5] == "report":
            return self._discovery_report(report_parts[2], report_parts[4])
        if method == "GET" and path.startswith("/assessments/"):
            return self._assessment_detail(
                path.removeprefix("/assessments/"),
                hint_mode=query.get("hint", [""])[0],
                credential_mode=query.get("credential", [""])[0],
            )
        return self._page("Not found", "<h1>Page not found</h1>", status=404)

    def setup_ready(self) -> bool:
        try:
            config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
            return not config.missing_llm_settings_for_models(self._model_ids(config))
        except (OSError, ValueError):
            return False

    @staticmethod
    def _model_ids(config: AppConfig) -> list[str]:
        return list(config.model_ids())

    @staticmethod
    def _local_host(host: str) -> bool:
        if not re.fullmatch(r"(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?", host, re.I):
            return False
        port = host.rpartition(":")[2]
        return not port or 1 <= int(port) <= 65535

    @classmethod
    def _same_origin(cls, origin: str, host: str) -> bool:
        parsed = urlsplit(origin)
        return parsed.scheme == "http" and parsed.netloc.lower() == host.lower() and cls._local_host(parsed.netloc)

    @staticmethod
    def _redirect(location: str) -> WebResponse:
        return WebResponse(status=303, location=location)

    def _form(self, action: str, content: str, *, form_class: str = "") -> str:
        return (
            f'<form method="post" action="{_h(action)}" class="{_h(form_class)}">'
            f'<input type="hidden" name="csrf" value="{self.csrf_token}">{content}</form>'
        )

    def _asset_entry_form(self, action: str, folder_url: str) -> str:
        options = "".join(f'<option value="{key}">{_h(label)}</option>' for key, label in ASSET_TYPES.items())
        return self._form(
            action,
            f'<div class="asset-form"><div><label for="asset_type">Asset type</label><select id="asset_type" name="asset_type">{options}</select></div>'
            '<div class="locator remote-locator"><label for="locator">URL</label><input id="locator" name="locator" type="text" required placeholder="https://app.example.test"></div>'
            '<button class="secondary remote-add" type="submit" name="action" value="add">Add asset</button>'
            f'<div class="folder-choice"><label>Folder</label><a class="secondary folder-picker" href="{_h(folder_url)}">'
            '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            '<path d="M3 6.5a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'
            '</svg><span>Choose folder</span></a></div></div>',
            form_class="asset-entry",
        )

    def _page(self, title: str, body: str, *, status: int = 200, refresh: bool = False) -> WebResponse:
        refresh_tag = '<meta http-equiv="refresh" content="3">' if refresh else ""
        markup = (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>{_h(title)} · mosh</title>{refresh_tag}'
            '<link rel="stylesheet" href="/web.css"><script src="/web.js" defer></script></head><body>'
            f'<header class="topbar"><a class="brand" href="/">mosh</a><span class="local">Local only</span></header>'
            f'{body}</body></html>'
        )
        return WebResponse(status=status, body=markup)

    @staticmethod
    def _error(message: str | None) -> str:
        return f'<p class="error" role="alert">{_h(message)}</p>' if message else ""

    @staticmethod
    def _wizard_steps(names: list[str], current: int) -> str:
        items = "".join(
            f'<span class="{("current" if index == current else "done" if index < current else "")}">'
            f'{index + 1}. {_h(name)}</span>'
            for index, name in enumerate(names)
        )
        return f'<nav class="steps" aria-label="Wizard progress">{items}</nav>'

    def _stage_nav(self, engagement: Engagement, current: str) -> str:
        engagement_id = engagement.id
        with self._run_lock:
            discovery_run = self.discovery_runs.get(engagement_id)
            planning_run = self.planning_runs.get(engagement_id)
            testing_run = self.testing_runs.get(engagement_id)
            testing_updating_plan = bool(testing_run and testing_run.status == "running" and _testing_updating_plan(testing_run.events))
        supported = [asset for asset in engagement.assets if asset.type in DISCOVERY_STEPS]
        discovered = [
            asset for asset in supported
            if (asset_discovery_dir(self.output_root, engagement_id, asset.id) / "report.md").is_file()
        ]
        if discovery_run and discovery_run.status == "running":
            discovery_state = "running"
        elif discovery_run and discovery_run.status == "failed":
            discovery_state = "attention"
        elif supported and len(discovered) == len(supported):
            discovery_state = "done"
        else:
            discovery_state = "waiting"
        plan_path = engagement_plan_dir(self.output_root, engagement_id) / "plan.md"
        if planning_run and planning_run.status == "running":
            planning_state = "running"
        elif planning_run and planning_run.status == "failed":
            planning_state = "attention"
        elif plan_path.is_file() and self._planning_current(engagement):
            planning_state = "done"
        elif plan_path.is_file():
            planning_state = "attention"
        else:
            planning_state = "waiting"
        if testing_run and testing_run.status == "running":
            testing_state = "running"
        elif testing_run and testing_run.status == "failed":
            testing_state = "attention"
        else:
            preflight, completed = self._testing_snapshot(engagement_id)
            if preflight is None and not completed:
                testing_state = "waiting"
            elif not completed or preflight is None or preflight.get("blocked") or self._testing_pending_count(engagement_id, preflight) or not self._planning_current(engagement) or not self._testing_plan_matches(engagement_id, preflight):
                testing_state = "attention"
            else:
                testing_state = "done"
        states = {
            "scope": "done" if engagement.assets else "waiting",
            "discovery": discovery_state,
            "planning": planning_state,
            "testing": testing_state,
        }
        labels = {"done": "Complete", "running": "In progress", "attention": "Needs attention", "waiting": "Not started"}
        marks = {"done": "✓", "running": "", "attention": "!", "waiting": "○"}
        items = []
        for key, label in (("scope", "Scope"), ("discovery", "Discovery"), ("planning", "Planning"), ("testing", "Testing")):
            state = states[key]
            url = f"/assessments/{engagement_id}" + (f"/{key}" if key != "scope" else "")
            active = ' aria-current="step"' if current == key else ""
            state_label = "Updating plan" if key == "testing" and testing_updating_plan else labels[state]
            items.append(
                f'<a class="stage-item {state}{" active" if current == key else ""}" href="{_h(url)}"'
                f' aria-label="{label}, {state_label}"{active}>'
                f'<span class="stage-mark" aria-hidden="true">{marks[state]}</span>{label}</a>'
            )
        for label in ("Report",):
            items.append(f'<span class="stage-item future" aria-disabled="true"><span class="stage-mark" aria-hidden="true">○</span>{label}</span>')
        return f'<nav class="stage-nav" aria-label="Assessment stages">{"".join(items)}</nav>'

    @staticmethod
    def _log_console(entries: str, *, open_logs: bool) -> str:
        content = f'<ol data-preserve-scroll>{entries}</ol>' if entries else '<p class="empty">No events yet.</p>'
        if not open_logs:
            content = '<p class="empty">Loading logs…</p>'
        return (
            f'<details class="log-console" data-live-logs data-logs-loaded="{"true" if open_logs else "false"}"{" open" if open_logs else ""}>'
            '<summary><span class="log-show">Detailed logs</span><span class="log-hide">Hide logs</span></summary>'
            f'<div class="log-console-content">{content}</div></details>'
        )

    @staticmethod
    def _log_time(event: dict) -> str:
        timestamp = str(event.get("timestamp", ""))
        return f'<time title="{_h(timestamp)}">{_h(timestamp.replace("T", " ")[:19])}</time>'

    def _setup_page(self, step: str, error: str | None = None, *, provider: str = "") -> WebResponse:
        if step == "review":
            return self._redirect("/setup?step=model")
        if step not in {"environment", "model", "provider"}:
            return self._redirect("/setup")
        if step != "environment" and not self._environment_ready():
            return self._redirect("/setup")
        if step == "environment":
            checks = self.environment_probe()
            if checks["uv"] and checks["docker"] and not checks["images"] and self.build_state in {"idle", "done"}:
                self._start_build()
            with self._build_lock:
                build_state = self.build_state
            if build_state == "done" and not checks["images"]:
                checks = self.environment_probe()
            image_status = (
                ("ready", "Ready") if checks["images"] else
                ("building", "Building tools") if build_state == "running" else
                ("failed", "Build failed") if build_state == "failed" else
                ("missing", "Needs attention")
            )
            statuses = {
                name: (("ready", "Ready") if ready else ("missing", "Needs attention"))
                for name, ready in checks.items()
            }
            statuses["images"] = image_status
            rows = "".join(
                f'<div class="check"><div><strong>{_h(label)}</strong><small>{_h(note)}</small></div>'
                f'<span class="{statuses[name][0]}">{statuses[name][1]}</span></div>'
                for name, label, note in [
                    ("uv", "Python and uv", "Python dependencies"),
                    ("docker", "Docker", "Local container runtime"),
                    ("images", "Tool images", "Discovery and security tools"),
                ]
            )
            build = (
                self._form("/setup/build", '<button class="secondary" type="submit">Retry build</button>')
                if checks["uv"] and checks["docker"] and not checks["images"] and build_state == "failed" else ""
            )
            build_note = '<p class="hint">Install uv and Docker to run assessment tools.</p>' if not checks["uv"] or not checks["docker"] else ""
            if build_state == "running" and not checks["images"]:
                build_note = '<p class="hint">The Docker build may take a few minutes. Continue will be available when the tools are ready.</p>'
            if build_state == "failed" and not checks["images"]:
                build_note = '<p class="error" role="alert">Build failed. Run <code>./scripts/setup.sh --force-docker</code> in a terminal to see the error.</p>'
            continue_control = (
                '<a class="primary" href="/setup?step=model">Continue</a>'
                if all(checks.values()) else
                '<button class="primary" type="button" disabled>Continue</button>'
            )
            content = (
                '<h1>Set up mosh</h1><p class="intro">Check the local environment before connecting providers.</p>'
                + self._wizard_steps(["Environment", "Providers"], 0)
                + self._error(error)
                + f'<section class="panel"><h2>Environment</h2>{rows}{build_note}</section>'
                + f'<div class="actions">{build}{continue_control}</div>'
            )
            return self._page("Set up mosh", f'<main class="wizard">{content}</main>', refresh=build_state == "running" and not checks["images"])
        if step == "model":
            try:
                config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
                missing = config.missing_llm_settings_for_models(self._model_ids(config))
            except (OSError, ValueError) as exc:
                config = None
                missing = ["Configuration error"]
                error = str(exc)
            descriptions = {
                "deepseek": ("DeepSeek", "Direct access to DeepSeek models."),
                "openrouter": ("OpenRouter", "Access to configured models through OpenRouter."),
                "custom": ("Custom endpoint", "An OpenAI-compatible URL. API key optional."),
            }
            rows = "".join(
                self._provider_row(name, *descriptions[name], config)
                for name in descriptions
            )
            with self._provider_lock:
                checking = any(state == "checking" for state, _ in self.provider_state.values())
            finish_control = (
                self._form("/setup/finish", '<button class="primary" type="submit">Finish setup</button>')
                if not missing and not checking else
                '<button class="primary" type="button" disabled>Finish setup</button>'
            )
            missing_note = (
                '<p class="hint">Connect a provider to finish setup.</p>' if missing and not error else ""
            )
            legacy_custom_note = (
                '<p class="hint">This custom endpoint currently handles all models. To use providers together, assign at least one model with a custom/ prefix in mosh.yaml.</p>'
                if config and config.custom_llm_base_url and not config.has_explicit_custom_models()
                else ""
            )
            content = (
                '<h1>Connect providers</h1><p class="intro">Choose a provider and check its API access.</p>'
                + self._wizard_steps(["Environment", "Providers"], 1)
                + self._error(error)
                + f'<section class="panel"><h2>Providers</h2>{rows}{missing_note}{legacy_custom_note}</section>'
                + f'<div class="actions"><a class="text-link" href="/setup">Back</a>{finish_control}</div>'
            )
            return self._page("Connect providers", f'<main class="wizard">{content}</main>', refresh=checking)
        if step == "provider":
            if provider not in KEY_NAMES:
                return self._redirect("/setup?step=model")
            try:
                config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
            except (OSError, ValueError) as exc:
                return self._setup_page("model", str(exc))
            if provider == "custom":
                base_url = config.custom_llm_base_url or ""
                inputs = (
                    '<label for="base_url">Endpoint URL</label>'
                    f'<input id="base_url" name="base_url" type="url" maxlength="2048" required value="{_h(base_url)}" placeholder="http://localhost:11434/v1">'
                    '<label for="api_key">API key <span class="optional">Optional</span></label>'
                    '<input id="api_key" name="api_key" type="password" autocomplete="new-password">'
                    '<p class="hint">Connect checks the endpoint’s model list. It does not run the configured model.</p>'
                )
            else:
                inputs = (
                    '<label for="api_key">API key</label>'
                    '<input id="api_key" name="api_key" type="password" required autocomplete="new-password">'
                )
            form = self._form(
                "/setup/provider",
                f'<input type="hidden" name="provider" value="{provider}">{inputs}'
                '<div class="actions"><a class="text-link" href="/setup?step=model">Back</a><button class="primary" type="submit">Connect</button></div>',
            )
            title = "Custom endpoint" if provider == "custom" else provider.title()
            content = (
                f'<h1>{_h(title)}</h1><p class="intro">Add provider access for mosh.</p>'
                + self._wizard_steps(["Environment", "Providers"], 1)
                + self._error(error)
                + f'<section class="panel"><h2>{_h(title)}</h2>{form}</section>'
            )
            return self._page(title, f'<main class="wizard">{content}</main>')

    def _provider_row(self, name: str, label: str, description: str, config: AppConfig | None) -> str:
        configured = bool(config.custom_llm_base_url if name == "custom" else getattr(config, KEY_FIELDS[name])) if config else False
        with self._provider_lock:
            state, message = self.provider_state.get(name, ("", ""))
            another_check = any(value[0] == "checking" for value in self.provider_state.values())
        if state == "checking":
            action = '<span class="checking" role="status">Checking API</span>'
        elif configured:
            action = f'<span class="ready">{"Verified" if state == "verified" else "Configured"}</span>'
        elif another_check:
            action = '<span>Waiting for check</span>'
        elif state == "failed":
            action = f'<div class="provider-action"><span class="failed" role="alert">{_h(message)}</span><a class="secondary" href="/setup?step=provider&amp;provider={name}">Retry</a></div>'
        else:
            action = f'<a class="secondary" href="/setup?step=provider&amp;provider={name}">Connect</a>'
        return f'<div class="provider-row"><div><strong>{_h(label)}</strong><small>{_h(description)}</small></div>{action}</div>'

    def _setup_action(self, path: str, form: dict[str, str]) -> WebResponse:
        if path == "/setup/build":
            checks = self.environment_probe()
            if checks["uv"] and checks["docker"] and not checks["images"] and self.build_state != "running":
                self._start_build()
            return self._redirect("/setup")
        if path in {"/setup/provider", "/setup/finish"} and not self._environment_ready():
            return self._redirect("/setup")
        if path == "/setup/provider":
            provider = form.get("provider", "")
            if provider not in KEY_NAMES:
                return self._redirect("/setup?step=model")
            try:
                config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
            except (OSError, ValueError) as exc:
                return self._setup_page("model", str(exc))
            key = form.get("api_key", "").strip()
            if len(key) > 4096 or (key and not key.isprintable()) or (provider != "custom" and not key):
                return self._setup_page("provider", "Enter a valid API key.", provider=provider)
            base_url = ""
            if provider == "custom":
                base_url = form.get("base_url", "").strip()
                if not _valid_endpoint_url(base_url):
                    return self._setup_page("provider", "Enter an http or https endpoint URL without credentials or a query string.", provider=provider)
            with self._provider_lock:
                checking = any(state == "checking" for state, _ in self.provider_state.values())
            if checking:
                return self._setup_page("model", "Wait for the current API check to finish.")
            self._start_provider_check(provider, key, base_url)
            return self._redirect("/setup?step=model")
        if path == "/setup/finish":
            with self._provider_lock:
                if any(state == "checking" for state, _ in self.provider_state.values()):
                    return self._redirect("/setup?step=model")
            try:
                config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
                missing = config.missing_llm_settings_for_models(self._model_ids(config))
                if missing:
                    return self._setup_page("model", "Additional provider access is needed: " + ", ".join(missing))
            except (OSError, ValueError) as exc:
                return self._setup_page("model", str(exc))
            self.onboarding_active = False
            return self._redirect("/")
        return self._page("Not found", "<h1>Page not found</h1>", status=404)

    def _start_provider_check(self, provider: str, key: str, base_url: str) -> None:
        with self._provider_lock:
            if any(state == "checking" for state, _ in self.provider_state.values()):
                return
            self.provider_state[provider] = ("checking", "")

        def run() -> None:
            try:
                valid, message = self.provider_checker(provider, key, base_url)
            except Exception:
                valid, message = False, "Could not reach the API. Try again."
            if valid:
                try:
                    settings: dict[str, str | None] = (
                        {"MOSH_LLM_BASE_URL": base_url, "MOSH_LLM_API_KEY": key or None}
                        if provider == "custom" else {KEY_NAMES[provider]: key}
                    )
                    _write_env_settings(self.root / ".env", settings)
                except Exception:
                    valid, message = False, "Could not save provider access."
            with self._provider_lock:
                self.provider_state[provider] = ("verified", "") if valid else ("failed", message)

        threading.Thread(target=run, daemon=True, name="mosh-provider-check").start()

    def _environment_ready(self) -> bool:
        checks = self.environment_probe()
        return all(checks[name] for name in ("uv", "docker", "images"))

    def _probe_environment(self) -> dict[str, bool]:
        uv = shutil.which("uv") is not None
        docker = shutil.which("docker") is not None
        if docker:
            docker = _command_ok(["docker", "info"])
        images = docker and all(
            _command_ok(["docker", "image", "inspect", name])
            for name in ("mosh-discovery-tools:latest", "mosh-security-tools:latest")
        )
        return {"uv": uv, "docker": docker, "images": images}

    def _build_tool_images(self) -> bool:
        script = self.root / "scripts" / "setup.sh"
        if not script.is_file():
            script = Path(__file__).resolve().parents[2] / "scripts" / "setup.sh"
        try:
            result = subprocess.run(
                [str(script)],
                cwd=script.parent.parent,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3600,
                check=False,
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _start_build(self) -> None:
        with self._build_lock:
            if self.build_state == "running":
                return
            self.build_state = "running"

        def run() -> None:
            try:
                result = self.build_runner()
                if result:
                    result = self.environment_probe()["images"]
            except Exception:
                result = False
            with self._build_lock:
                self.build_state = "done" if result else "failed"

        threading.Thread(target=run, daemon=True, name="mosh-tool-build").start()

    def _home(self) -> WebResponse:
        entries = []
        for path in sorted(self.output_root.glob("eng_*/engagement.json"), reverse=True):
            try:
                engagement = load_engagement(self.output_root, path.parent.name)
            except (OSError, ValueError):
                continue
            entries.append(
                f'<a class="engagement-row" href="/assessments/{_h(engagement.id)}">'
                f'<strong>{_h(engagement.title or engagement.id)}</strong>'
                f'<span>{len(engagement.assets)} asset(s)</span></a>'
            )
        new_form = self._form("/new/start", '<button class="primary" type="submit"><span class="button-plus" aria-hidden="true">+</span>New assessment</button>')
        body = (
            '<main class="home"><div class="home-heading"><div><h1>Assessments</h1>'
            '<p class="intro">Create an assessment and add its assets before running discovery.</p></div>'
            + new_form + '</div>'
            + ('<section class="engagement-list">' + "".join(entries) + "</section>" if entries else '<p class="empty">No assessments yet.</p>')
            + '</main>'
        )
        return self._page("Assessments", body)

    def _assessment_page(self, step: str, error: str | None = None) -> WebResponse:
        if step not in {"details", "assets", "review"}:
            return self._redirect("/new?step=details")
        draft = self.assessment_draft
        with self._asset_lock:
            assets = list(draft.assets)
            checked_assets = dict(draft.checked_assets)
            pending_asset = draft.pending_asset
            check_state = draft.check_state
            check_message = draft.check_message
            authorized = draft.authorized
        if step != "details" and not draft.title:
            return self._redirect("/new?step=details")
        if step == "review" and (not assets or not authorized or check_state):
            return self._redirect("/new?step=assets")
        cancel = self._form("/new/cancel", '<button class="text-link" type="submit">Cancel</button>')
        header = f'<div class="wizard-heading"><div><h1>New assessment</h1><p class="intro">Define the scope before discovery.</p></div>{cancel}</div>'
        progress = self._wizard_steps(["Details", "Assets", "Review"], {"details": 0, "assets": 1, "review": 2}[step])
        if step == "details":
            form = self._form(
                "/new/details",
                f'<label for="title">Assessment name</label><input id="title" name="title" type="text" maxlength="120" required value="{_h(draft.title)}" placeholder="Example app">'
                '<div class="actions"><button class="primary" type="submit">Continue</button></div>',
            )
            content = '<section class="panel"><h2>Details</h2><p class="hint">Choose a name you will recognize in reports.</p>' + form + '</section>'
        elif step == "assets":
            add = self._asset_entry_form("/new/add", "/new/folders")
            rows = self._asset_rows(assets, checked_assets, removable=True)
            check_notice = ""
            if pending_asset and check_state == "checking":
                label = "website" if pending_asset[0] == "live_url" else "repository"
                check_notice = f'<p class="asset-check checking" role="status">Checking {label} reachability… <code>{_h(pending_asset[1])}</code></p>'
            elif pending_asset and check_state == "failed":
                check_notice = (
                    f'<div class="asset-check-failed"><p class="error" role="alert">{_h(check_message)} <code>{_h(pending_asset[1])}</code></p>'
                    + self._form("/new/retry", '<button class="secondary" type="submit">Retry check</button>')
                    + self._form("/new/add-anyway", '<button class="secondary" type="submit">Add anyway</button>')
                    + self._form("/new/dismiss-check", '<button class="text-link" type="submit">Dismiss</button>')
                    + '</div>'
                )
            next_form = self._form(
                "/new/assets-next",
                '<label class="authorization"><input type="checkbox" name="authorized" value="yes" required'
                + (' checked' if authorized else '')
                + '> I have permission to assess these assets.</label>'
                '<div class="actions"><a class="text-link" href="/new?step=details">Back</a><button class="primary" type="submit">Review assets</button></div>',
            )
            content = (
                '<section class="panel"><h2>Assets</h2><p class="hint">Adding a website or repository checks reachability. No discovery starts yet.</p>'
                + add
                + check_notice + '<h3>Added assets</h3>' + (rows or '<p class="empty">Add at least one asset.</p>')
                + '</section>' + next_form
            )
        else:
            rows = self._asset_rows(assets, checked_assets, removable=False)
            missing_folder = any(kind == "source_tree" and not Path(locator).is_dir() for kind, locator in assets)
            finish = (
                '<div class="actions"><a class="text-link" href="/new?step=assets">Back</a><button class="primary" type="button" disabled>Create assessment</button></div>'
                if missing_folder else
                self._form("/new/finish", '<div class="actions"><a class="text-link" href="/new?step=assets">Back</a><button class="primary" type="submit">Create assessment</button></div>')
            )
            missing_note = '<p class="error" role="alert">A local folder is missing. Go back and choose an existing folder.</p>' if missing_folder else ''
            content = f'<section class="panel"><h2>{_h(draft.title)}</h2><p class="hint">{len(assets)} asset(s) · Authorization confirmed</p>{rows}</section>{missing_note}{finish}'
        return self._page("New assessment", f'<main class="wizard">{header}{progress}{self._error(error)}{content}</main>', refresh=step == "assets" and check_state == "checking")

    def _asset_rows(self, assets: list[tuple[str, str]], checked: dict[tuple[str, str], str], *, removable: bool) -> str:
        rows = []
        for index, (kind, locator) in enumerate(assets):
            if kind == "source_tree":
                status = "Folder found" if Path(locator).is_dir() else "Folder missing"
            else:
                status = checked.get((kind, locator), "Not verified")
            status_class = "failed" if status in {"Folder missing", "Not verified"} else "ready"
            remove = self._form("/new/remove", f'<input type="hidden" name="index" value="{index}"><button class="text-link" type="submit">Remove</button>') if removable else ""
            rows.append(
                f'<div class="asset-row"><span class="type">{_h(ASSET_TYPES[kind])}</span>'
                f'<code>{_h(locator)}</code><span class="asset-status {status_class}">{_h(status)}</span>{remove}</div>'
            )
        return "".join(rows)

    def _folder_path(self, value: str) -> Path:
        folder = Path(value).expanduser().resolve() if value else self.folder_root
        if not folder.is_relative_to(self.folder_root) or not folder.is_dir():
            raise ValueError("Choose an existing folder within the browse location.")
        return folder

    def _folder_page(self, path: str, *, engagement_id: str | None = None) -> WebResponse:
        if engagement_id:
            try:
                load_engagement(self.output_root, engagement_id)
            except (OSError, ValueError):
                return self._assessment_detail(engagement_id)
        elif not self.assessment_draft.title:
            return self._redirect("/new?step=details")
        folder_url = f"/assessments/{engagement_id}/folders" if engagement_id else "/new/folders"
        back_url = f"/assessments/{engagement_id}" if engagement_id else "/new?step=assets"
        select_url = f"/assessments/{engagement_id}/select-folder" if engagement_id else "/new/select-folder"
        try:
            folder = self._folder_path(path)
            children = []
            for child in folder.iterdir():
                if child.name.startswith(".") or child.is_symlink() or not child.is_dir():
                    continue
                resolved = child.resolve()
                if resolved.is_relative_to(self.folder_root):
                    children.append(resolved)
            children.sort(key=lambda child: child.name.casefold())
        except (OSError, RuntimeError, ValueError):
            return self._page("Choose folder", f'<main class="wizard"><h1>Choose a folder</h1><p class="error" role="alert">This folder cannot be opened.</p><a class="text-link" href="{_h(folder_url)}">Browse from the start</a></main>')
        parent = (
            f'<a class="text-link" href="{_h(folder_url)}?path={quote(str(folder.parent), safe="")}">← Parent folder</a>'
            if folder != self.folder_root else ""
        )
        entries = "".join(
            f'<a class="folder-row" href="{_h(folder_url)}?path={quote(str(child), safe="")}"><span>{_h(child.name)}</span><span aria-hidden="true">›</span></a>'
            for child in children
        )
        select = self._form(
            select_url,
            f'<input type="hidden" name="path" value="{_h(folder)}"><button class="primary" type="submit">Use this folder</button>',
        )
        content = (
            '<main class="wizard"><h1>Choose a folder</h1>'
            f'<p class="intro">Browse folders under {_h(self.folder_root)}.</p>'
            '<section class="panel"><div class="folder-heading">'
            f'<code>{_h(folder)}</code>{select}</div>{parent}'
            + (f'<div class="folder-list">{entries}</div>' if entries else '<p class="empty">No subfolders here.</p>')
            + f'</section><div class="actions"><a class="text-link" href="{_h(back_url)}">Back to assets</a></div></main>'
        )
        return self._page("Choose folder", content)

    def _assessment_action(self, path: str, form: dict[str, str]) -> WebResponse:
        draft = self.assessment_draft
        if path == "/new/cancel":
            self.assessment_draft = AssessmentDraft()
            return self._redirect("/")
        if path == "/new/details":
            title = form.get("title", "").strip()
            if not title or len(title) > 120:
                return self._assessment_page("details", "Enter an assessment name of 1–120 characters.")
            draft.title = title
            return self._redirect("/new?step=assets")
        if path == "/new/add":
            kind = form.get("asset_type", "")
            if kind not in ASSET_TYPES:
                return self._assessment_page("assets", "Choose a supported asset type.")
            try:
                locator = normalize_asset_locator(form.get("locator", ""), kind)
            except (OSError, ValueError) as exc:
                return self._assessment_page("assets", str(exc))
            with self._asset_lock:
                busy = bool(draft.check_state)
                duplicate = (kind, locator) in draft.assets
            if busy:
                return self._assessment_page("assets", "Resolve the current asset check first.")
            if duplicate:
                return self._assessment_page("assets", "That asset is already added.")
            if kind == "source_tree":
                with self._asset_lock:
                    draft.assets.append((kind, locator))
                    draft.authorized = False
            else:
                self._start_asset_check(draft, kind, locator)
            return self._redirect("/new?step=assets")
        if path == "/new/select-folder":
            try:
                if not form.get("path"):
                    raise ValueError("Folder path is required")
                locator = normalize_asset_locator(str(self._folder_path(form.get("path", ""))), "source_tree")
            except (OSError, ValueError):
                return self._assessment_page("assets", "Choose an existing folder from the folder browser.")
            with self._asset_lock:
                busy = bool(draft.check_state)
                duplicate = ("source_tree", locator) in draft.assets
                if not busy and not duplicate:
                    draft.assets.append(("source_tree", locator))
                    draft.authorized = False
            if busy:
                return self._assessment_page("assets", "Resolve the current asset check first.")
            if duplicate:
                return self._assessment_page("assets", "That asset is already added.")
            return self._redirect("/new?step=assets")
        if path in {"/new/retry", "/new/add-anyway", "/new/dismiss-check"}:
            with self._asset_lock:
                if draft.check_state != "failed" or not draft.pending_asset:
                    return self._redirect("/new?step=assets")
                kind, locator = draft.pending_asset
                if path == "/new/add-anyway":
                    draft.assets.append((kind, locator))
                    draft.authorized = False
                if path != "/new/retry":
                    draft.pending_asset = None
                    draft.check_state = ""
                    draft.check_message = ""
            if path == "/new/retry":
                self._start_asset_check(draft, kind, locator)
            return self._redirect("/new?step=assets")
        if path == "/new/remove":
            try:
                index = int(form.get("index", ""))
                if index < 0:
                    raise ValueError
                with self._asset_lock:
                    removed = draft.assets.pop(index)
                    draft.checked_assets.pop(removed, None)
                    draft.authorized = False
            except (ValueError, IndexError):
                return self._assessment_page("assets", "Choose an asset to remove.")
            return self._redirect("/new?step=assets")
        if path == "/new/assets-next":
            with self._asset_lock:
                asset_count = len(draft.assets)
                checking = bool(draft.check_state)
            if checking:
                return self._assessment_page("assets", "Resolve the current asset check first.")
            if not asset_count:
                return self._assessment_page("assets", "Add at least one asset.")
            if form.get("authorized") != "yes":
                return self._assessment_page("assets", "Confirm that you have permission to assess these assets.")
            with self._asset_lock:
                draft.authorized = True
            return self._redirect("/new?step=review")
        if path == "/new/finish":
            with self._asset_lock:
                assets = list(draft.assets)
                ready = bool(draft.title and assets and draft.authorized and not draft.check_state)
            if not ready:
                return self._redirect("/new?step=details")
            try:
                for kind, locator in assets:
                    normalize_asset_locator(locator, kind)
                engagement = create_engagement(self.output_root, title=draft.title)
                for kind, locator in assets:
                    attach_asset(self.output_root, engagement.id, locator, asset_type=kind)
            except (OSError, ValueError) as exc:
                return self._assessment_page("review", str(exc))
            self.assessment_draft = AssessmentDraft()
            return self._redirect(f"/assessments/{engagement.id}")
        return self._page("Not found", "<h1>Page not found</h1>", status=404)

    def _start_asset_check(self, draft: AssessmentDraft, kind: str, locator: str) -> None:
        with self._asset_lock:
            draft.pending_asset = (kind, locator)
            draft.check_state = "checking"
            draft.check_message = ""

        def run() -> None:
            try:
                reachable, message = self.asset_checker(kind, locator)
            except Exception:
                reachable, message = False, "Could not check this asset. Try again."
            with self._asset_lock:
                if reachable:
                    draft.assets.append((kind, locator))
                    draft.checked_assets[(kind, locator)] = message or "Reachable when added"
                    draft.authorized = False
                    draft.pending_asset = None
                    draft.check_state = ""
                    draft.check_message = ""
                else:
                    draft.check_state = "failed"
                    draft.check_message = message

        threading.Thread(target=run, daemon=True, name="mosh-asset-check").start()

    def _assessment_select_folder(self, engagement_id: str, form: dict[str, str]) -> WebResponse:
        try:
            if not form.get("path"):
                raise ValueError
            locator = str(self._folder_path(form["path"]))
        except (OSError, RuntimeError, ValueError):
            return self._assessment_detail(engagement_id, asset_error="Choose an existing folder from the folder browser.")
        return self._assessment_asset_action(engagement_id, {"action": "add", "asset_type": "source_tree", "locator": locator})

    def _assessment_asset_action(self, engagement_id: str, form: dict[str, str]) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._assessment_detail(engagement_id)
        with self._run_lock:
            stage_running = any(run.status == "running" for run in self.discovery_runs.values()) or any(
                run.status == "running" for run in self.planning_runs.values()
            ) or any(
                run.status == "running" for run in self.testing_runs.values()
            )
        if stage_running:
            return self._assessment_detail(engagement_id, asset_error="Wait for the current stage to finish before changing assets.")
        action = form.get("action", "")
        detail_url = f"/assessments/{engagement_id}"
        try:
            if action == "add":
                kind = form.get("asset_type", "")
                if kind not in ASSET_TYPES:
                    raise ValueError("Choose a supported asset type.")
                locator = normalize_asset_locator(form.get("locator", ""), kind)
                with self._asset_lock:
                    if engagement_id in self.assessment_asset_checks:
                        raise ValueError("Resolve the current asset check first.")
                    if any(asset.type == kind and asset.locator == locator for asset in engagement.assets):
                        raise ValueError("That asset is already attached.")
                    if kind == "source_tree":
                        attach_asset(self.output_root, engagement_id, locator, asset_type=kind)
                if kind != "source_tree":
                    if not self._start_assessment_asset_check(engagement_id, kind, locator):
                        raise ValueError("Resolve the current asset check first.")
            elif action == "remove":
                with self._asset_lock:
                    detach_asset(self.output_root, engagement_id, form.get("asset_id", ""))
            elif action in {"retry", "add-anyway", "dismiss"}:
                with self._asset_lock:
                    pending = self.assessment_asset_checks.get(engagement_id)
                    if not pending or pending.state != "failed":
                        return self._redirect(detail_url)
                    if action == "add-anyway":
                        attach_asset(self.output_root, engagement_id, pending.locator, asset_type=pending.kind)
                    if action != "retry":
                        self.assessment_asset_checks.pop(engagement_id, None)
                if action == "retry":
                    self._start_assessment_asset_check(engagement_id, pending.kind, pending.locator)
            else:
                raise ValueError("Choose a valid asset action.")
        except (OSError, ValueError) as exc:
            return self._assessment_detail(engagement_id, asset_error=str(exc))
        return self._redirect(detail_url)

    def _start_assessment_asset_check(self, engagement_id: str, kind: str, locator: str) -> bool:
        pending = PendingAssessmentAsset(kind, locator)
        with self._asset_lock:
            current = self.assessment_asset_checks.get(engagement_id)
            if current and current.state == "checking":
                return False
            self.assessment_asset_checks[engagement_id] = pending

        def run() -> None:
            try:
                reachable, message = self.asset_checker(kind, locator)
            except Exception:
                reachable, message = False, "Could not check this asset. Try again."
            with self._asset_lock:
                if self.assessment_asset_checks.get(engagement_id) is not pending:
                    return
                if reachable:
                    try:
                        attach_asset(self.output_root, engagement_id, locator, asset_type=kind)
                    except (OSError, ValueError) as exc:
                        reachable, message = False, str(exc)
                if reachable:
                    self.assessment_asset_checks.pop(engagement_id, None)
                else:
                    pending.state = "failed"
                    pending.message = message

        threading.Thread(target=run, daemon=True, name="mosh-assessment-asset-check").start()
        return True

    @staticmethod
    def _run_discovery_asset(
        config: AppConfig,
        output_root: Path,
        engagement: Engagement,
        asset: EngagementAsset,
        event_sink: Callable[[Event], None],
    ) -> Path:
        from mosh.cli import _run_asset_discovery

        args = SimpleNamespace(max_pages=200, max_depth=config.max_depth)
        return _run_asset_discovery(config, output_root, engagement, asset, args, event_sink=event_sink)

    def _discovery_action(self, engagement_id: str, form: dict[str, str]) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._assessment_detail(engagement_id)
        action = form.get("action", "")
        supported = [asset for asset in engagement.assets if asset.type in DISCOVERY_STEPS]
        supported_ids = {asset.id for asset in supported}
        due = [asset.id for asset in supported if not (asset_discovery_dir(self.output_root, engagement_id, asset.id) / "report.md").is_file()]
        with self._run_lock:
            if any(run.status == "running" for run in self.discovery_runs.values()) or any(
                run.status == "running" for run in self.planning_runs.values()
            ) or any(
                run.status == "running" for run in self.testing_runs.values()
            ):
                return self._discovery_page(engagement_id, error="A stage is already running. Wait for it to finish.")
            if action == "refresh" and form.get("confirmed") != "yes":
                return self._discovery_refresh_page(engagement_id)
            previous = self.discovery_runs.get(engagement_id)
            if action == "start":
                asset_ids = due
            elif action == "retry" and previous and previous.status == "failed":
                asset_ids = list(dict.fromkeys(asset_id for asset_id in [previous.failed_asset_id, *due] if asset_id in supported_ids))
            elif action == "refresh":
                asset_ids = [asset.id for asset in supported]
            else:
                return self._discovery_page(engagement_id, error="Choose a valid discovery action.")
            if not asset_ids:
                return self._discovery_page(engagement_id, error="No assets need discovery.")
            run = DiscoveryRun(asset_ids=asset_ids, current_asset_id=asset_ids[0])
            self.discovery_runs[engagement_id] = run
        threading.Thread(target=self._run_discovery, args=(engagement_id, run), daemon=True, name="mosh-web-discovery").start()
        return self._redirect(f"/assessments/{engagement_id}/discovery")

    def _run_discovery(self, engagement_id: str, run: DiscoveryRun) -> None:
        def event_sink(asset_id: str, event: Event) -> None:
            with self._run_lock:
                run.events.append((asset_id, event))
                if event.action == "agent_output":
                    task = str(event.data.get("task", ""))
                    run.active_step = max(run.active_step, DISCOVERY_STEP_AFTER_TASK.get(task, 0))
                elif event.action == "agent_started":
                    role = str(event.data.get("agent_role", ""))
                    run.active_step = max(run.active_step, DISCOVERY_STEP_FROM_ROLE.get(role, 0))

        try:
            config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
            for asset_id in run.asset_ids:
                with self._run_lock:
                    run.current_asset_id = asset_id
                    run.active_step = 0
                engagement = load_engagement(self.output_root, engagement_id)
                asset = next((item for item in engagement.assets if item.id == asset_id), None)
                if asset is None:
                    raise ValueError(f"Asset {asset_id} is no longer attached.")
                report_dir = self.discovery_runner(
                    config, self.output_root, engagement, asset,
                    lambda event, current_id=asset_id: event_sink(current_id, event),
                )
                if not (report_dir / "report.md").is_file():
                    raise RuntimeError("Discovery did not write a report.")
                record_asset_discovery(self.output_root, engagement_id, asset_id, report_dir)
                with self._run_lock:
                    run.completed_ids.add(asset_id)
            with self._run_lock:
                run.status = "complete"
                run.current_asset_id = ""
        except Exception as exc:
            with self._run_lock:
                run.status = "failed"
                run.failed_asset_id = run.current_asset_id
                run.error = str(exc) or "Discovery failed."

    @staticmethod
    def _run_planning(config: AppConfig, output_root: Path, engagement_id: str, event_sink: Callable[[Event], None]) -> Path:
        from mosh.crews.planning.crew import SecurityTestPlanningOrchestrator

        return SecurityTestPlanningOrchestrator(config, output_root=output_root, event_sink=event_sink).run(engagement_id)

    def _planning_current(self, engagement: Engagement) -> bool:
        from mosh.crews.planning.crew import _engagement_plan_is_current

        return _engagement_plan_is_current(self.output_root, engagement, engagement_plan_dir(self.output_root, engagement.id))

    def _planning_action(self, engagement_id: str, form: dict[str, str]) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._planning_page(engagement_id)
        if form.get("action") not in {"start", "retry"}:
            return self._planning_page(engagement_id, error="Choose a valid planning action.")
        supported = [asset for asset in engagement.assets if asset.type in DISCOVERY_STEPS]
        missing = [asset for asset in supported if not (asset_discovery_dir(self.output_root, engagement_id, asset.id) / "report.md").is_file()]
        if not supported or missing:
            return self._planning_page(engagement_id, error="Complete discovery for all supported assets before planning.")
        with self._run_lock:
            if any(run.status == "running" for run in self.discovery_runs.values()) or any(
                run.status == "running" for run in self.planning_runs.values()
            ) or any(
                run.status == "running" for run in self.testing_runs.values()
            ):
                return self._planning_page(engagement_id, error="A stage is already running. Wait for it to finish.")
            if self._planning_current(engagement):
                return self._redirect(f"/assessments/{engagement_id}/planning")
            run = PlanningRun()
            self.planning_runs[engagement_id] = run
        threading.Thread(target=self._run_planning_task, args=(engagement_id, run), daemon=True, name="mosh-web-planning").start()
        return self._redirect(f"/assessments/{engagement_id}/planning")

    def _run_planning_task(self, engagement_id: str, run: PlanningRun) -> None:
        def event_sink(event: Event) -> None:
            with self._run_lock:
                run.events.append(event)
                run.active_step = max(run.active_step, PLANNING_STEP_AFTER_EVENT.get((event.agent, event.action), 0))

        try:
            config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
            report_dir = self.planning_runner(config, self.output_root, engagement_id, event_sink)
            if not (report_dir / "plan.md").is_file():
                raise RuntimeError("Planning did not write a security test plan.")
            with self._run_lock:
                run.active_step = len(PLANNING_STEPS)
                run.status = "complete"
        except Exception as exc:
            with self._run_lock:
                run.status = "failed"
                run.error = str(exc) or "Planning failed."

    def _planning_report(self, engagement_id: str) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
            report = (engagement_plan_dir(self.output_root, engagement_id) / "plan.md").read_text(encoding="utf-8")
        except (OSError, ValueError):
            return self._page("Not found", '<main class="home"><h1>Security test plan not found</h1></main>', status=404)
        body = (
            f'<main class="home"><a class="text-link" href="/assessments/{_h(engagement_id)}/planning">← Back to planning</a>'
            f'<h1>Security test plan</h1><p class="intro">{_h(engagement.title or engagement.id)}</p>'
            f'{render_markdown_document(report)}</main>'
        )
        return self._page("Security test plan", body)

    def _planning_page(self, engagement_id: str, *, show_logs: bool = False, error: str | None = None) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._page("Not found", '<main class="home"><h1>Assessment not found</h1></main>', status=404)
        section, _ = self._planning_section(engagement, show_logs=show_logs, error=error)
        body = f'<main class="home">{section}</main>'
        return self._page("Planning", body)

    def _planning_status(self, engagement_id: str, *, show_logs: bool) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return WebResponse(404, '{"error":"Assessment not found"}', "application/json; charset=utf-8")
        section, running = self._planning_section(engagement, show_logs=show_logs, error=None)
        return WebResponse(body=json.dumps({"html": section, "poll": running}), content_type="application/json; charset=utf-8")

    def _planning_section(self, engagement: Engagement, *, show_logs: bool, error: str | None) -> tuple[str, bool]:
        engagement_id = engagement.id
        planning_url = f"/assessments/{engagement_id}/planning"
        report_path = engagement_plan_dir(self.output_root, engagement_id) / "plan.md"
        with self._run_lock:
            current = self.planning_runs.get(engagement_id)
            testing_run_started = engagement_id in self.testing_runs
            run = PlanningRun(
                active_step=current.active_step, status=current.status, error=current.error,
                events=list(current.events) if show_logs else [],
            ) if current else None
        running = bool(run and run.status == "running")
        failed = bool(run and run.status == "failed")
        report_ready = report_path.is_file()
        current_plan = report_ready and not running and self._planning_current(engagement)
        testing_started = testing_run_started or self._testing_dir(engagement_id).exists()
        supported = [asset for asset in engagement.assets if asset.type in DISCOVERY_STEPS]
        ready = bool(supported) and all(
            (asset_discovery_dir(self.output_root, engagement_id, asset.id) / "report.md").is_file()
            for asset in supported
        )
        if running:
            summary = "Planning in progress"
        elif failed:
            summary = "Planning needs attention"
        elif report_ready and current_plan:
            summary = "Planning complete"
        elif report_ready:
            summary = "Plan needs updating"
        elif ready:
            summary = "Discovery is complete. Ready to build a security test plan."
        else:
            summary = "Complete discovery before planning."
        if running or not ready:
            action = ""
        elif failed:
            action = self._form(planning_url, '<button class="primary" type="submit" name="action" value="retry">Retry planning</button>')
        elif report_ready and current_plan:
            action = (
                f'<a class="primary" href="/assessments/{_h(engagement_id)}/testing">Continue to testing</a>'
                if not testing_started else f'<a class="primary" href="{_h(planning_url)}/report">View plan</a>'
            )
        else:
            label = "Update plan" if report_ready else "Start planning"
            action = self._form(planning_url, f'<button class="primary" type="submit" name="action" value="start">{label}</button>')
        steps = ""
        if run:
            items = "".join(
                f'<li class="{_stage_step_class(index, run.active_step, run.status)}">{_h(label)}</li>'
                for index, label in enumerate(PLANNING_STEPS)
            )
            steps = f'<ol class="discovery-steps">{items}</ol>'
        logs = ""
        if show_logs:
            if run:
                events = [event.to_dict() for event in run.events]
            else:
                try:
                    stored = json.loads((engagement_plan_dir(self.output_root, engagement_id) / "events.json").read_text(encoding="utf-8"))
                    events = stored if isinstance(stored, list) else []
                except (OSError, ValueError):
                    events = []
            entries = "".join(
                f'<li>{self._log_time(event)}<span class="log-source">{_h(event.get("agent", ""))}</span>'
                f'<span class="log-message">{_h(event.get("message", ""))}</span></li>'
                for event in events if isinstance(event, dict)
            )
            logs = self._log_console(entries, open_logs=True)
        elif run or (engagement_plan_dir(self.output_root, engagement_id) / "events.json").is_file():
            logs = self._log_console("", open_logs=False)
        previous_report = f'<a class="text-link" href="{_h(planning_url)}/report">Previous plan</a>' if report_ready and not current_plan else ""
        if report_ready and current_plan and not testing_started:
            previous_report = f'<a class="text-link" href="{_h(planning_url)}/report">View plan</a>'
        poll_url = planning_url + "/status" + ("?view=logs" if show_logs else "")
        poll_attrs = f' data-poll-url="{_h(poll_url)}" data-poll-ms="2000"' if running else ""
        section = (
            f'<section id="planning-status" class="panel discovery" data-status-url="{_h(planning_url)}/status"{poll_attrs}>{self._stage_nav(engagement, "planning")}<div class="discovery-heading"><div><h2>Planning</h2>'
            f'<p class="discovery-summary">{_h(summary)}</p></div>{action}</div>'
            + self._error(error) + (self._error(run.error[:500]) if failed else "")
            + '<p class="field-help">Planning examines the discovered assets, identifies potential security issues, and turns them into testable hypotheses with checks tailored to this assessment. It writes the plan; security tests run later.</p>'
            + steps
            + (f'<div class="discovery-footer">{previous_report}</div>' if previous_report else "")
            + logs + '</section>'
        )
        return section, running

    def _testing_dir(self, engagement_id: str) -> Path:
        return engagement_dir(self.output_root, engagement_id) / "security-testing"

    def _testing_snapshot(self, engagement_id: str) -> tuple[dict | None, bool]:
        testing_dir = self._testing_dir(engagement_id)
        try:
            memory = json.loads((testing_dir / "memory.json").read_text(encoding="utf-8"))
            events = json.loads((testing_dir / "events.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, False
        preflight = None
        if isinstance(memory, list):
            preflight = next(
                (item.get("content") for item in reversed(memory) if isinstance(item, dict) and item.get("kind") == "testing_preflight"),
                None,
            )
        complete = isinstance(events, list) and any(
            isinstance(event, dict) and event.get("agent") == "orchestrator" and event.get("action") == "complete"
            for event in events
        )
        return preflight if isinstance(preflight, dict) else None, complete

    def _testing_plan_matches(self, engagement_id: str, preflight: dict) -> bool:
        from mosh.crews.testing.crew import plan_revision_id

        try:
            return preflight.get("plan_revision_id") == plan_revision_id(self._testing_plan(engagement_id))
        except (OSError, ValueError, RuntimeError):
            return False

    def _testing_plan(self, engagement_id: str) -> dict:
        from mosh.conversation import active_directives
        from mosh.crews.testing.crew import _apply_testing_conversation_directives, load_security_test_plan

        plan = load_security_test_plan(engagement_plan_dir(self.output_root, engagement_id))
        directives = active_directives(self.output_root, engagement_id, stage="testing")
        return _apply_testing_conversation_directives(plan, directives) if directives else plan

    def _testing_readiness(self, engagement: Engagement, template: dict):
        from mosh.crews.testing.crew import _current_executed_test_ids, run_testing_preflight
        from mosh.source_assets import first_source_asset, readable_source_root

        plan = self._testing_plan(engagement.id)
        source = first_source_asset(engagement.assets)
        result = run_testing_preflight(
            plan,
            template,
            live_target_available=any(asset.type == "live_url" for asset in engagement.assets),
            source_available=bool(source and readable_source_root(self.output_root, engagement.id, source)),
            completed_test_ids=_current_executed_test_ids(self._testing_dir(engagement.id)),
        )
        return plan, result

    def _planned_tests(self, engagement: Engagement, *, progress_events: list[Event] | None = None, run_active: bool = False, run_failed: bool = False, open_requirements: str = "") -> str:
        from mosh.crews.testing.crew import (
            _execution_status_for_hypothesis,
            _hypotheses,
            _safe_test_id,
        )

        try:
            template_path = engagement_dir(self.output_root, engagement.id) / "engagement_template.yaml"
            template = load_engagement_file(template_path) if template_path.exists() else build_minimal_engagement_template()
            plan, result = self._testing_readiness(engagement, template)
        except (OSError, ValueError, RuntimeError):
            return '<p class="field-help">Planned test readiness is unavailable. Review the plan and engagement settings.</p>'
        statuses = {str(item["id"]): (label, item) for label, items in (
            ("blocked", result.blocked), ("deferred", result.deferred), ("ready", result.ready)
        ) for item in items}
        counts = {"ready": 0, "blocked": 0, "deferred": 0, "complete": 0, "rerun": 0}
        rows = []
        dialogs = []
        report_dir = self._testing_dir(engagement.id)
        testing_url = f"/assessments/{engagement.id}/testing"
        hypotheses = _hypotheses(plan)
        with self._run_lock:
            can_edit = not any(run.status == "running" for runs in (self.discovery_runs, self.planning_runs, self.testing_runs) for run in runs.values())
        phases = {}
        for event in progress_events or []:
            test_id = event.data.get("test_id")
            if test_id and event.action in TESTING_PROGRESS_PHASES:
                phases[str(test_id)] = TESTING_PROGRESS_PHASES[event.action]
        for index, hypothesis in enumerate(hypotheses):
            test_id = str(hypothesis.get("id") or "unknown")
            status, item = statuses.get(test_id, ("blocked", {"blockers": ["No preflight result for this test."]}))
            reason = ""
            report_path = report_dir / "executed_tests" / f"{_safe_test_id(test_id)}.md"
            report_link = (
                f'<a class="text-link" href="{_h(testing_url)}/reports/{quote(report_path.stem)}">View report</a>'
                if report_path.is_file() else ""
            )
            phase = phases.get(test_id)
            if status == "ready":
                execution, reason = _execution_status_for_hypothesis(report_dir, hypothesis)
                if phase is not None and phase < len(TESTING_STEPS) and run_active:
                    status, reason = "running", ""
                elif phase is not None and phase < len(TESTING_STEPS) and execution != "current":
                    status, reason = "rerun", "The test stopped before its report was complete."
                elif execution == "current":
                    status = "complete"
                elif execution == "rerun":
                    status = "rerun"
            counts["ready" if status == "running" else status] += 1
            label = {"ready": "Ready", "blocked": "Blocked", "deferred": "Deferred", "complete": "Complete", "rerun": "Needs rerun", "running": "Running"}[status]
            blockers = item.get("blockers", []) if status in {"blocked", "deferred"} else []
            details = ''.join(f'<li>{_h(_web_testing_blocker(str(blocker)))}</li>' for blocker in blockers)
            if reason and status == "rerun":
                details = f'<li>{_h(reason)}</li>'
            action = ""
            if status == "blocked" and can_edit:
                inputs = list(dict.fromkeys(
                    value for blocker in blockers if (value := _testing_input_for_blocker(str(blocker)))
                ))
                if inputs:
                    dialog_id = f"test-requirements-{index}"
                    action = f'<button class="text-link" type="button" data-open-requirements="{dialog_id}">Add required details</button>'
                    dialogs.append(self._testing_requirement_dialog(
                        engagement.id, test_id, str(hypothesis.get("title") or "Untitled test"), dialog_id,
                        inputs, blockers, open_requirements == test_id,
                    ))
                elif any("scope" in str(blocker).lower() or "asset" in str(blocker).lower() for blocker in blockers):
                    action = f'<a class="text-link" href="/assessments/{_h(engagement.id)}#assets">Review scope</a>'
            steps = ""
            if phase is not None:
                shown_phase = len(TESTING_STEPS) if status == "complete" else phase
                step_rows = ''.join(
                    f'<li class="{_stage_step_class(index, shown_phase, "failed" if run_failed or not run_active else "running")}">{_h(label)}</li>'
                    for index, label in enumerate(TESTING_STEPS)
                )
                steps = f'<ol class="discovery-steps testing-steps">{step_rows}</ol>'
            rows.append(
                f'<li class="planned-test"><div class="planned-test-main"><span><strong>{_h(test_id)}</strong> {_h(hypothesis.get("title") or "Untitled test")}</span>'
                f'<span class="planned-test-status {status}">{_h(label)}</span></div>'
                + (f'<ul class="planned-test-details">{details}</ul>' if details else '')
                + steps
                + (f'<div class="planned-test-link">{report_link}{" · " if report_link and action else ""}{action}</div>' if report_link or action else '') + '</li>'
            )
        summary = f'{counts["ready"]} ready · {counts["blocked"]} blocked · {counts["deferred"]} deferred'
        if counts["complete"] or counts["rerun"]:
            summary += f' · {counts["complete"]} complete · {counts["rerun"]} need rerun'
        count = len(hypotheses)
        intro = (
            f'<p class="testing-intro">Planning identified {count} security {"test" if count == 1 else "tests"} from the discovered assets. '
            'Review them below. Some may need access, permission, or safe test data before they can run.</p>'
        )
        guide = (
            '<details class="testing-status-guide"><summary>What do these statuses mean?</summary><dl>'
            '<div><dt>Ready</dt><dd>Can run with the information already provided.</dd></div>'
            '<div><dt>Running</dt><dd>Checks or report writing are underway.</dd></div>'
            '<div><dt>Blocked</dt><dd>Needs a prerequisite before it can run.</dd></div>'
            '<div><dt>Needs rerun</dt><dd>An earlier run needs repeating because the plan changed or its result was not accepted.</dd></div>'
            '<div><dt>Complete</dt><dd>The test has run and a result has been produced for the current plan.</dd></div>'
            '<div><dt>Deferred</dt><dd>Cannot run within the current scope or setup.</dd></div>'
            '</dl></details>'
        )
        return f'{intro}{guide}<div class="planned-tests"><h3>Planned tests</h3><p class="field-help">{summary}</p><ul>{"".join(rows)}</ul></div>{"".join(dialogs)}'

    def _testing_requirement_dialog(
        self, engagement_id: str, test_id: str, title: str, dialog_id: str,
        inputs: list[tuple[str, str]], blockers: list[str], auto_open: bool,
    ) -> str:
        base = f"/assessments/{engagement_id}"
        hidden = f'<input type="hidden" name="return_to" value="testing"><input type="hidden" name="test_id" value="{_h(test_id)}">'
        forms = []
        for kind, key in inputs:
            if kind == "credential":
                fields = (
                    f'<h3>{_h(CREDENTIAL_ROLES[key])} credentials</h3>'
                    f'<input type="hidden" name="role" value="{_h(key)}">'
                    '<p class="field-help">Enter a token or a username and password. Saved values are never shown here.</p>'
                    '<label>Username<input name="username" type="text" maxlength="256" autocomplete="off"></label>'
                    '<label>Password<input name="password" type="password" maxlength="4096" autocomplete="new-password"></label>'
                    '<span class="field-help">or</span>'
                    '<label>Token<input name="token" type="password" maxlength="4096" autocomplete="off"></label>'
                    '<button class="secondary" type="submit" name="action" value="save">Save credentials</button>'
                )
                forms.append(self._form(base + "/credentials", hidden + fields, form_class="testing-requirement-form"))
            elif kind == "permission":
                label = next(label for field, label in TESTING_PERMISSION_BLOCKERS.values() if field == key)
                fields = (
                    f'<h3>{_h(label)}</h3><p class="field-help">Only approve testing you have authorized.</p>'
                    f'<input type="hidden" name="permission_key" value="{_h(key)}">'
                    f'<label>{_h(label)}<select name="permission_value" required>'
                    '<option value="" selected>Choose</option><option value="yes">Yes</option><option value="no">No</option>'
                    '</select></label><button class="secondary" type="submit" name="action" value="save-permission">Save permission</button>'
                )
                forms.append(self._form(base + "/test-setup", hidden + fields, form_class="testing-requirement-form"))
            elif kind == "data":
                fields = (
                    f'<h3>{_h(TEST_DATA_FIELDS[key])}</h3><input type="hidden" name="data_key" value="{_h(key)}">'
                    f'<label>{_h(TEST_DATA_FIELDS[key])}<textarea name="data_value" rows="3" maxlength="4096" required></textarea></label>'
                    + ('<p class="field-help">Enter one value per line.</p>' if key in TEST_DATA_LIST_FIELDS else '')
                    + '<button class="secondary" type="submit" name="action" value="save-data">Save test data</button>'
                )
                forms.append(self._form(base + "/test-setup", hidden + fields, form_class="testing-requirement-form"))
            elif kind == "target":
                fields = (
                    '<h3>Target URL</h3><p class="field-help">Enter an approved target for this assessment.</p>'
                    '<label>Target name<input name="target_name" type="text" maxlength="64" value="website" required></label>'
                    '<label>Target URL<input name="target_url" type="url" maxlength="2048" placeholder="https://app.example.test" required></label>'
                    '<button class="secondary" type="submit" name="action" value="save-target">Save target</button>'
                )
                forms.append(self._form(base + "/test-setup", hidden + fields, form_class="testing-requirement-form"))
        reasons = ''.join(f'<li>{_h(_web_testing_blocker(str(blocker)))}</li>' for blocker in blockers)
        scope_link = (
            f'<a class="text-link" href="{_h(base)}#assets">Review scope</a>'
            if any(_testing_input_for_blocker(str(blocker)) is None and "scope" in str(blocker).lower() for blocker in blockers)
            else ""
        )
        return (
            f'<dialog id="{dialog_id}" class="testing-requirements" aria-labelledby="{dialog_id}-title"{" data-auto-open" if auto_open else ""}>'
            f'<div class="testing-requirements-heading"><div><h2 id="{dialog_id}-title">Add details for {_h(test_id)}</h2><p>{_h(title)}</p></div>'
            '<button class="text-link" type="button" data-close-requirements aria-label="Close details">Close</button></div>'
            f'<ul class="planned-test-details">{reasons}</ul>'
            '<p class="field-help">These details are saved in Scope. Saving does not start testing.</p>'
            + ''.join(forms) + (f'<p>{scope_link}</p>' if scope_link else '') + '</dialog>'
        )

    def _testing_pending_count(self, engagement_id: str, preflight: dict) -> int:
        from mosh.crews.testing.crew import _latest_execution_metadata

        report_dir = self._testing_dir(engagement_id)
        pending = 0
        for item in preflight.get("ready", []):
            if not isinstance(item, dict):
                continue
            try:
                metadata = _latest_execution_metadata(report_dir, str(item.get("id", "")))
            except (OSError, ValueError):
                metadata = None
            if not metadata or not metadata.get("review_accepted") or metadata.get("hypothesis_fingerprint") != item.get("hypothesis_fingerprint"):
                pending += 1
        return pending

    @staticmethod
    def _run_testing(config: AppConfig, output_root: Path, engagement_id: str, event_sink: Callable[[Event], None]) -> Path:
        from mosh.crews.testing.crew import SecurityTestingOrchestrator

        return SecurityTestingOrchestrator(config, output_root=output_root, event_sink=event_sink).run(engagement_id)

    def _testing_action(self, engagement_id: str, form: dict[str, str]) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._testing_page(engagement_id)
        if form.get("action") != "start":
            return self._testing_page(engagement_id, error="Choose a valid testing action.")
        if not (engagement_plan_dir(self.output_root, engagement_id) / "plan.md").is_file() or not self._planning_current(engagement):
            return self._testing_page(engagement_id, error="Complete or update planning before testing.")
        with self._run_lock:
            if any(run.status == "running" for run in self.discovery_runs.values()) or any(
                run.status == "running" for run in self.planning_runs.values()
            ) or any(run.status == "running" for run in self.testing_runs.values()):
                return self._testing_page(engagement_id, error="A stage is already running. Wait for it to finish.")
            preflight, completed = self._testing_snapshot(engagement_id)
            if completed and preflight is not None and not preflight.get("blocked") and not self._testing_pending_count(engagement_id, preflight) and self._testing_plan_matches(engagement_id, preflight):
                return self._redirect(f"/assessments/{engagement_id}/testing")
            run = TestingRun()
            self.testing_runs[engagement_id] = run
        threading.Thread(target=self._run_testing_task, args=(engagement_id, run), daemon=True, name="mosh-web-testing").start()
        return self._redirect(f"/assessments/{engagement_id}/testing")

    def _run_testing_task(self, engagement_id: str, run: TestingRun) -> None:
        def event_sink(event: Event) -> None:
            with self._run_lock:
                run.events.append(event)

        try:
            config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
            report_dir = self.testing_runner(config, self.output_root, engagement_id, event_sink)
            if not (report_dir / "preflight.md").is_file():
                raise RuntimeError("Testing did not write a preflight report.")
            with self._run_lock:
                run.status = "complete"
        except Exception as exc:
            with self._run_lock:
                run.status = "failed"
                run.error = str(exc) or "Testing failed."

    def _testing_report(self, engagement_id: str, report_id: str, *, preflight: bool = False) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
            testing_dir = self._testing_dir(engagement_id)
            if preflight:
                report_path = testing_dir / "preflight.md"
                title = "Testing preflight"
            else:
                report_path = next(path for path in (testing_dir / "executed_tests").glob("*.md") if path.stem == report_id)
                title = f"Test {report_id}"
            report = report_path.read_text(encoding="utf-8")
        except (OSError, ValueError, StopIteration):
            return self._page("Not found", '<main class="home"><h1>Testing report not found</h1></main>', status=404)
        if not preflight:
            from mosh.crews.testing.crew import _strip_execution_metadata

            report = _strip_execution_metadata(report)
        body = (
            f'<main class="home"><a class="text-link" href="/assessments/{_h(engagement_id)}/testing">← Back to testing</a>'
            f'<h1>{_h(title)}</h1><p class="intro">{_h(engagement.title or engagement.id)}</p>'
            f'{render_markdown_document(report)}</main>'
        )
        return self._page(title, body)

    def _testing_page(self, engagement_id: str, *, show_logs: bool = False, error: str | None = None, open_requirements: str = "") -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._page("Not found", '<main class="home"><h1>Assessment not found</h1></main>', status=404)
        section, _ = self._testing_section(engagement, show_logs=show_logs, error=error, open_requirements=open_requirements)
        return self._page("Testing", f'<main class="home">{section}</main>')

    def _testing_status(self, engagement_id: str, *, show_logs: bool) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return WebResponse(404, '{"error":"Assessment not found"}', "application/json; charset=utf-8")
        section, running = self._testing_section(engagement, show_logs=show_logs, error=None)
        return WebResponse(body=json.dumps({"html": section, "poll": running}), content_type="application/json; charset=utf-8")

    def _testing_section(self, engagement: Engagement, *, show_logs: bool, error: str | None, open_requirements: str = "") -> tuple[str, bool]:
        engagement_id = engagement.id
        testing_url = f"/assessments/{engagement_id}/testing"
        testing_dir = self._testing_dir(engagement_id)
        with self._run_lock:
            current = self.testing_runs.get(engagement_id)
            run = TestingRun(status=current.status, error=current.error, events=list(current.events) if show_logs else []) if current else None
            execution_started = bool(current and any(event.action == "execution_start" for event in current.events))
            updating_plan = bool(current and _testing_updating_plan(current.events))
            progress_events = [event for event in current.events if event.action in TESTING_PROGRESS_PHASES] if current else []
        running = bool(run and run.status == "running")
        failed = bool(run and run.status == "failed")
        plan_ready = (engagement_plan_dir(self.output_root, engagement_id) / "plan.md").is_file() and self._planning_current(engagement)
        preflight, completed = self._testing_snapshot(engagement_id)
        blocked = preflight.get("blocked", []) if preflight else []
        deferred = preflight.get("deferred", []) if preflight else []
        pending = self._testing_pending_count(engagement_id, preflight) if preflight else 0
        plan_matches = bool(preflight and self._testing_plan_matches(engagement_id, preflight))
        if running:
            if updating_plan:
                summary = "Tests finished. Updating discovery and the security test plan from test results."
            elif execution_started:
                summary = "Executing and reviewing ready security tests"
            else:
                summary = "Checking test readiness"
        elif failed:
            summary = "Testing needs attention"
        elif not plan_ready:
            summary = "Complete or update planning before testing."
        elif completed and preflight and plan_matches and not blocked and not pending:
            summary = "Testing complete"
        elif completed and preflight and not plan_matches:
            summary = "The plan or testing guidance changed after the last run. Run testing for the updated inputs."
        elif completed and blocked:
            summary = f"Testing finished with {len(blocked)} blocked test(s)"
        elif completed and pending:
            summary = f"Testing finished with {pending} test(s) needing another run"
        elif preflight:
            summary = "The previous testing run did not finish. Review the preflight and retry."
        else:
            summary = "Ready to run security tests."
        action = ""
        if plan_ready and not running and not (completed and preflight and plan_matches and not blocked and not pending):
            label = "Retry testing" if failed or (preflight and not completed) else "Run remaining tests" if completed else "Start testing"
            action = self._form(testing_url, f'<button class="primary" type="submit" name="action" value="start">{label}</button>')
        results = ""
        if plan_ready:
            results += self._planned_tests(engagement, progress_events=progress_events, run_active=running, run_failed=failed, open_requirements=open_requirements)
        if (testing_dir / "preflight.md").is_file():
            results += f'<p class="testing-preflight-link"><a class="text-link" href="{_h(testing_url)}/preflight">View preflight</a></p>'
        logs = ""
        if show_logs:
            if run:
                events = [event.to_dict() for event in run.events]
            else:
                try:
                    stored = json.loads((testing_dir / "events.json").read_text(encoding="utf-8"))
                    events = stored if isinstance(stored, list) else []
                except (OSError, ValueError):
                    events = []
            entries = "".join(
                f'<li>{self._log_time(event)}<span class="log-source">{_h(event.get("agent", ""))}</span>'
                f'<span class="log-message">{_h(event.get("message", ""))}</span></li>'
                for event in events if isinstance(event, dict)
            )
            logs = self._log_console(entries, open_logs=True)
        elif run or (testing_dir / "events.json").is_file():
            logs = self._log_console("", open_logs=False)
        poll_url = testing_url + "/status" + ("?view=logs" if show_logs else "")
        poll_attrs = f' data-poll-url="{_h(poll_url)}" data-poll-ms="2000"' if running else ""
        section = (
            f'<section id="testing-status" class="panel discovery" data-status-url="{_h(testing_url)}/status"{poll_attrs}>'
            f'{self._stage_nav(engagement, "testing")}<div class="discovery-heading"><div><h2>Testing</h2>'
            f'<p class="discovery-summary">{_h(summary)}</p></div>{action}</div>'
            + self._error(error) + (self._error(run.error[:500]) if failed else "")
            + results + logs + '</section>'
        )
        return section, running

    def _discovery_report(self, engagement_id: str, asset_id: str) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
            asset = next(item for item in engagement.assets if item.id == asset_id)
            report = (asset_discovery_dir(self.output_root, engagement_id, asset_id) / "report.md").read_text(encoding="utf-8")
        except (OSError, ValueError, StopIteration):
            return self._page("Not found", '<main class="home"><h1>Discovery report not found</h1></main>', status=404)
        body = (
            f'<main class="home"><a class="text-link" href="/assessments/{_h(engagement_id)}/discovery">← Back to discovery</a>'
            f'<h1>Discovery report</h1><p class="intro">{_h(ASSET_TYPES.get(asset.type, asset.type))} · {_h(asset.locator)}</p>'
            f'{render_markdown_document(report)}</main>'
        )
        return self._page("Discovery report", body)

    def _discovery_page(self, engagement_id: str, *, show_logs: bool = False, error: str | None = None) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._page("Not found", '<main class="home"><h1>Assessment not found</h1></main>', status=404)
        section, _ = self._discovery_section(engagement, show_logs=show_logs, error=error)
        body = f'<main class="home">{section}</main>'
        return self._page("Discovery", body)

    def _discovery_refresh_page(self, engagement_id: str) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._page("Not found", '<main class="home"><h1>Assessment not found</h1></main>', status=404)
        assets = [asset for asset in engagement.assets if asset.type in DISCOVERY_STEPS]
        discovery_url = f"/assessments/{engagement_id}/discovery"
        if not assets or any(not (asset_discovery_dir(self.output_root, engagement_id, asset.id) / "report.md").is_file() for asset in assets):
            return self._redirect(discovery_url)
        count = len(assets)
        form = self._form(
            discovery_url,
            '<input type="hidden" name="confirmed" value="yes">'
            '<button class="primary" type="submit" name="action" value="refresh">Refresh discovery</button>',
        )
        body = (
            f'<main class="home"><a class="text-link" href="{_h(discovery_url)}">← Back to discovery</a>'
            '<h1>Refresh discovery?</h1><section class="panel discovery">'
            f'<p>This will run discovery again for all {count} attached asset{"s" if count != 1 else ""}.</p>'
            '<p>Current discovery reports and logs may be replaced as each asset finishes. Any existing plan may need updating afterward.</p>'
            f'<div class="actions"><a class="text-link" href="{_h(discovery_url)}">Cancel</a>{form}</div>'
            '</section></main>'
        )
        return self._page("Confirm refresh", body)

    def _discovery_status(self, engagement_id: str, *, show_logs: bool) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return WebResponse(404, '{"error":"Assessment not found"}', "application/json; charset=utf-8")
        section, running = self._discovery_section(engagement, show_logs=show_logs, error=None)
        return WebResponse(body=json.dumps({"html": section, "poll": running}), content_type="application/json; charset=utf-8")

    def _discovery_section(self, engagement: Engagement, *, show_logs: bool, error: str | None) -> tuple[str, bool]:
        engagement_id = engagement.id
        detail_url = f"/assessments/{engagement_id}"
        discovery_url = detail_url + "/discovery"
        with self._run_lock:
            current = self.discovery_runs.get(engagement_id)
            planning_run = self.planning_runs.get(engagement_id)
            run = DiscoveryRun(
                asset_ids=list(current.asset_ids), current_asset_id=current.current_asset_id,
                completed_ids=set(current.completed_ids), active_step=current.active_step,
                status=current.status, error=current.error, failed_asset_id=current.failed_asset_id,
                events=list(current.events) if show_logs else [],
            ) if current else None
        supported = [asset for asset in engagement.assets if asset.type in DISCOVERY_STEPS]
        due = [asset for asset in supported if not (asset_discovery_dir(self.output_root, engagement_id, asset.id) / "report.md").is_file()]
        running = bool(run and run.status == "running")
        run_failed = bool(run and run.status == "failed" and any(asset.id == run.failed_asset_id for asset in supported))
        if running:
            position = run.asset_ids.index(run.current_asset_id) + 1 if run.current_asset_id in run.asset_ids else 1
            summary = f"Discovering asset {position} of {len(run.asset_ids)}"
        elif run_failed:
            summary = "Discovery needs attention"
        elif supported and not due:
            summary = "Discovery complete" if len(supported) == len(engagement.assets) else "Discovery complete for supported assets"
        elif due:
            summary = f"{len(due)} asset(s) ready for discovery"
        elif engagement.assets:
            summary = "Discovery is not available for these assets"
        else:
            summary = "Add an asset to begin discovery"
        action = ""
        if not running and supported:
            if run_failed:
                action = self._form(discovery_url, '<button class="primary" type="submit" name="action" value="retry">Retry remaining</button>')
            elif due:
                label = "Start discovery" if len(due) == len(supported) else "Discover remaining"
                action = self._form(discovery_url, f'<button class="primary" type="submit" name="action" value="start">{label}</button>')
        rows = []
        for asset in engagement.assets:
            report_ready = (asset_discovery_dir(self.output_root, engagement_id, asset.id) / "report.md").is_file()
            active = bool(run and run.current_asset_id == asset.id and run.status == "running")
            asset_failed = bool(run and run.failed_asset_id == asset.id and run.status == "failed")
            if asset.type not in DISCOVERY_STEPS:
                status = "Not supported"
                status_class = "waiting"
            elif active:
                status = "In progress"
                status_class = "running"
            elif asset_failed:
                status = "Needs attention"
                status_class = "failed"
            elif run and run.status == "running" and asset.id in run.asset_ids and asset.id not in run.completed_ids:
                status = "Waiting"
                status_class = "waiting"
            elif report_ready:
                status = "Complete"
                status_class = "complete"
            else:
                status = "Waiting" if running and run and asset.id in run.asset_ids else "Not started"
                status_class = "waiting"
            report_label = "Previous report" if asset_failed else "View report"
            report_link = (
                f'<a class="text-link" href="{_h(detail_url)}/discovery/{_h(asset.id)}/report">{report_label}</a>'
                if report_ready and not active and not (running and run and asset.id in run.asset_ids and asset.id not in run.completed_ids) else ""
            )
            steps = ""
            if active or asset_failed:
                step_items = "".join(
                    f'<li class="{_stage_step_class(index, run.active_step, run.status)}">{_h(label)}</li>'
                    for index, label in enumerate(DISCOVERY_STEPS[asset.type])
                )
                steps = f'<ol class="discovery-steps">{step_items}</ol>'
            rows.append(
                '<div class="discovery-asset">'
                f'<div class="discovery-asset-line"><div><strong>{_h(ASSET_TYPES.get(asset.type, asset.type))}</strong><code>{_h(asset.locator)}</code></div>'
                f'<span class="discovery-status {status_class}">{status}</span>{report_link}</div>{steps}</div>'
            )
        logs = ""
        if show_logs:
            entries = []
            for asset in engagement.assets:
                if run and asset.id in run.asset_ids:
                    events = [event.to_dict() for event_asset_id, event in run.events if event_asset_id == asset.id]
                else:
                    path = asset_discovery_dir(self.output_root, engagement_id, asset.id) / "events.json"
                    try:
                        stored = json.loads(path.read_text(encoding="utf-8"))
                        events = stored if isinstance(stored, list) else []
                    except (OSError, ValueError):
                        events = []
                for event in events:
                    if isinstance(event, dict):
                        entries.append(
                            f'<li>{self._log_time(event)}'
                            f'<span class="log-source">{_h(ASSET_TYPES.get(asset.type, asset.type))} · {_h(event.get("agent", ""))}</span>'
                            f'<span class="log-message">{_h(event.get("message", ""))}</span></li>'
                        )
            logs = self._log_console("".join(entries), open_logs=True)
        elif run or any((asset_discovery_dir(self.output_root, engagement_id, asset.id) / "events.json").exists() for asset in supported):
            logs = self._log_console("", open_logs=False)
        refresh = f'<a class="text-link" href="{_h(discovery_url)}/refresh">Refresh discovery</a>' if supported and not due and not running and not (planning_run and planning_run.status == "running") else ""
        failure = self._error(run.error[:500]) if run_failed else ""
        poll_url = discovery_url + "/status"
        if show_logs:
            poll_url += "?view=logs"
        poll_attrs = f' data-poll-url="{_h(poll_url)}" data-poll-ms="2000"' if running else ""
        section = (
            f'<section id="discovery-status" class="panel discovery" data-status-url="{_h(discovery_url)}/status"{poll_attrs}>{self._stage_nav(engagement, "discovery")}<div class="discovery-heading"><div><h2>Discovery</h2>'
            f'<p class="discovery-summary">{_h(summary)}</p></div>{action}</div>'
            + self._error(error) + failure
            + ("<p class=\"field-help\">Discovery may contact attached live targets and configured model providers.</p>" if not running and due else "")
            + "".join(rows)
            + (f'<div class="discovery-footer">{refresh}</div>' if refresh else "")
            + logs + '</section>'
        )
        return section, running

    def _assessment_guidance(self, engagement_id: str, form: dict[str, str]) -> WebResponse:
        try:
            load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._assessment_detail(engagement_id)
        with self._run_lock:
            if any(run.status == "running" for run in self.testing_runs.values()):
                return self._assessment_detail(engagement_id, error="Wait for testing to finish before changing guidance.")
        template_path = self.output_root / engagement_id / "engagement_template.yaml"
        try:
            template = load_engagement_file(template_path) if template_path.exists() else build_minimal_engagement_template()
            hints = list(template.get("hints", []))
            action = form.get("action", "")
            if action == "save-notes":
                notes = form.get("notes", "")
                template["llm"] = {**(template.get("llm") or {}), "engagement_steer": notes or None}
                notice = "General guidance saved. It will be used by the next analysis run."
            elif action == "save-hint":
                title, body = form.get("title", ""), form.get("text", "")
                index_value = form.get("index", "")
                if index_value:
                    index = int(index_value)
                    if not 0 <= index < len(hints):
                        raise ValueError("Choose a hint to edit.")
                    hints[index] = {"title": title, "text": body}
                else:
                    if len(hints) >= 30:
                        raise ValueError("Provide at most 30 hints.")
                    hints.append({"title": title, "text": body})
                template["hints"] = hints
                notice = "Hint saved."
            elif action.startswith("delete:"):
                index = int(action.split(":", 1)[1])
                if not 0 <= index < len(hints):
                    raise ValueError("Choose a hint to delete.")
                hints.pop(index)
                template["hints"] = hints
                notice = "Hint deleted."
            else:
                raise ValueError("Choose a valid action.")
            validate_engagement_template(template)
            write_engagement_template_mapping(template_path.parent, template, preserve_existing=False, reject_candidate_credentials=False)
            return self._assessment_detail(engagement_id, notice=notice)
        except (ValueError, OSError) as exc:
            if form.get("action") == "save-hint":
                index_value = form.get("index", "")
                hint_mode = f"edit:{index_value}" if index_value else "new"
                hint_draft = {"title": form.get("title", ""), "text": form.get("text", "")}
                return self._assessment_detail(engagement_id, hint_mode=hint_mode, hint_draft=hint_draft, error=str(exc))
            return self._assessment_detail(engagement_id, notes_draft=form.get("notes") if form.get("action") == "save-notes" else None, error=str(exc))

    def _assessment_credentials(self, engagement_id: str, form: dict[str, str]) -> WebResponse:
        try:
            load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._assessment_detail(engagement_id)
        with self._run_lock:
            if any(run.status == "running" for runs in (self.discovery_runs, self.planning_runs, self.testing_runs) for run in runs.values()):
                message = "Wait for the current stage to finish before changing credentials."
                return self._scope_edit_result(engagement_id, form, error=message, credential_error=message)
        template_path = engagement_dir(self.output_root, engagement_id) / "engagement_template.yaml"
        role = form.get("role", "")
        action = form.get("action", "")
        credentials = {}
        try:
            template = load_engagement_file(template_path) if template_path.exists() else build_minimal_engagement_template()
            credentials = dict(template.get("credentials") or {})
            if action == "save":
                if role not in credentials and role not in CREDENTIAL_ROLES:
                    raise ValueError("Choose an account role.")
                username = form.get("username", "").strip()
                password = form.get("password", "")
                token = form.get("token", "")
                if len(username) > 256 or len(password) > 4096 or len(token) > 4096:
                    raise ValueError("Credential values are too long.")
                if token.strip() and (username or password.strip()):
                    raise ValueError("Enter a token or a username and password, not both.")
                if not token.strip() and not (username and password.strip()):
                    raise ValueError("Enter a token or both a username and password.")
                credentials[role] = {
                    "username": username or None,
                    "password": password or None,
                    "token": token or None,
                }
                notice = f"Credentials saved for {CREDENTIAL_ROLES.get(role, role)}."
            elif action == "remove":
                if role not in credentials:
                    raise ValueError("Choose an account role to remove.")
                if form.get("confirmed") != "yes":
                    return self._assessment_detail(engagement_id, credential_mode=f"remove:{role}")
                del credentials[role]
                notice = f"Credentials removed for {CREDENTIAL_ROLES.get(role, role)}."
            else:
                raise ValueError("Choose a valid credential action.")
            template["credentials"] = credentials
            validate_engagement_template(template)
            write_engagement_template_mapping(template_path.parent, template, preserve_existing=False, reject_candidate_credentials=False)
            return self._scope_edit_result(engagement_id, form, credential_notice=notice)
        except ValueError as exc:
            mode = f"edit:{role}" if action == "save" and role in credentials else "new" if action == "save" else f"remove:{role}" if action == "remove" else ""
            return self._scope_edit_result(engagement_id, form, error=str(exc), credential_mode=mode, credential_error=str(exc))
        except OSError:
            message = "Could not save credentials. Try again."
            return self._scope_edit_result(engagement_id, form, error=message, credential_error=message)

    def _scope_edit_result(self, engagement_id: str, form: dict[str, str], *, error: str | None = None, **scope_options) -> WebResponse:
        if form.get("return_to") == "testing":
            test_id = form.get("test_id", "")
            if error:
                return self._testing_page(engagement_id, error=error, open_requirements=test_id)
            return self._redirect(f"/assessments/{engagement_id}/testing?details={quote(test_id, safe='')}")
        return self._assessment_detail(engagement_id, **scope_options)

    def _assessment_test_setup(self, engagement_id: str, form: dict[str, str]) -> WebResponse:
        try:
            load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._assessment_detail(engagement_id)
        with self._run_lock:
            if any(run.status == "running" for runs in (self.discovery_runs, self.planning_runs, self.testing_runs) for run in runs.values()):
                message = "Wait for the current stage to finish before changing test setup."
                return self._scope_edit_result(engagement_id, form, error=message, setup_error=message)
        template_path = engagement_dir(self.output_root, engagement_id) / "engagement_template.yaml"
        try:
            template = load_engagement_file(template_path) if template_path.exists() else build_minimal_engagement_template()
            action = form.get("action")
            if action == "save-permissions":
                settings = dict(template.get("engagement") or {})
                for key in ("authorization_confirmed", "active_testing_allowed", "state_changing_tests_allowed"):
                    choice = form.get(key)
                    if choice not in {"unset", "yes", "no"}:
                        raise ValueError("Choose a value for each testing permission.")
                    settings[key] = {"unset": None, "yes": True, "no": False}[choice]
                template["engagement"] = settings
                notice = "Testing permissions saved."
            elif action == "save-permission":
                key = form.get("permission_key", "")
                choice = form.get("permission_value", "")
                if key not in {field for field, _ in TESTING_PERMISSION_BLOCKERS.values()} or choice not in {"yes", "no"}:
                    raise ValueError("Choose Yes or No for a testing permission.")
                settings = dict(template.get("engagement") or {})
                settings[key] = choice == "yes"
                template["engagement"] = settings
                notice = "Testing permission saved."
            elif action == "save-target":
                name = form.get("target_name", "").strip()
                url = form.get("target_url", "").strip()
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
                    raise ValueError("Use a target name of up to 64 letters, numbers, hyphens, or underscores.")
                if not _valid_endpoint_url(url):
                    raise ValueError("Enter an http or https target URL without credentials, a query, or a fragment.")
                targets = dict(template.get("targets") or {})
                alternative = dict(targets.get("alternative") or {})
                alternative[name] = url
                targets["alternative"] = alternative
                template["targets"] = targets
                notice = f"Target {name} saved."
            elif action == "save-data":
                key = form.get("data_key", "")
                value = form.get("data_value", "").strip()
                if key not in TEST_DATA_FIELDS:
                    raise ValueError("Choose a test data field.")
                if not value or len(value) > 4096 or "\x00" in value:
                    raise ValueError("Enter a test value of up to 4,096 characters.")
                if key in TEST_DATA_LIST_FIELDS:
                    parsed = [line.strip() for line in value.splitlines() if line.strip()]
                    if len(parsed) > 100:
                        raise ValueError("Provide at most 100 values, one per line.")
                else:
                    if "\n" in value or "\r" in value:
                        raise ValueError("Enter one value for this field.")
                    parsed = value
                data = dict(template.get("safe_test_data") or {})
                data[key] = parsed
                template["safe_test_data"] = data
                notice = f"{TEST_DATA_FIELDS[key]} saved."
            else:
                raise ValueError("Choose a valid test setup action.")
            validate_engagement_template(template)
            write_engagement_template_mapping(template_path.parent, template, preserve_existing=False, reject_candidate_credentials=False)
            return self._scope_edit_result(engagement_id, form, setup_notice=notice)
        except ValueError as exc:
            return self._scope_edit_result(engagement_id, form, error=str(exc), setup_error=str(exc))
        except OSError:
            message = "Could not save test setup. Try again."
            return self._scope_edit_result(engagement_id, form, error=message, setup_error=message)

    def _testing_setup_section(self, engagement: Engagement, template: dict, error: str | None, notice: str | None, credential_mode: str, credential_error: str | None, credential_notice: str | None) -> str:
        engagement_id = engagement.id
        settings = template.get("engagement") if isinstance(template.get("engagement"), dict) else {}
        targets = template.get("targets") if isinstance(template.get("targets"), dict) else {}
        production = targets.get("production") if isinstance(targets.get("production"), dict) else {}
        alternative = targets.get("alternative") if isinstance(targets.get("alternative"), dict) else {}
        data = template.get("safe_test_data") if isinstance(template.get("safe_test_data"), dict) else {}
        action_url = f"/assessments/{engagement_id}/test-setup"
        permission_count = sum(settings.get(key) is not None for key in ("authorization_confirmed", "active_testing_allowed", "state_changing_tests_allowed"))
        target_count = sum(bool(alternative.get(name) or production.get(name)) for name in set(production) | set(alternative))
        data_count = sum(bool(data.get(key)) for key in TEST_DATA_FIELDS)
        permission_fields = []
        for key, label in (
            ("authorization_confirmed", "Authorization confirmed"),
            ("active_testing_allowed", "Active testing allowed"),
            ("state_changing_tests_allowed", "State-changing tests allowed"),
        ):
            current = settings.get(key)
            selected = "yes" if current is True else "no" if current is False else "unset"
            options = "".join(f'<option value="{choice}"{" selected" if choice == selected else ""}>{name}</option>' for choice, name in (("unset", "Not set"), ("yes", "Yes"), ("no", "No")))
            permission_fields.append(f'<label for="setup-{key}">{label}</label><select id="setup-{key}" name="{key}">{options}</select>')
        permissions = self._form(action_url, "".join(permission_fields) + '<button class="secondary" type="submit" name="action" value="save-permissions">Save permissions</button>')
        names = sorted(set(production) | set(alternative))
        target_rows = "".join(
            f'<div class="setup-row"><strong>{_h(name)}</strong><span>{_h(alternative.get(name) or production.get(name) or "Not set")}</span></div>'
            for name in names
        )
        target_form = self._form(action_url,
            '<label for="setup-target-name">Target name</label><input id="setup-target-name" name="target_name" type="text" maxlength="64" placeholder="website" required>'
            '<label for="setup-target-url">Target URL</label><input id="setup-target-url" name="target_url" type="url" maxlength="2048" placeholder="https://app.example.test" required>'
            '<p class="field-help">Use an existing target name to replace its test URL, or add a new name.</p>'
            '<button class="secondary" type="submit" name="action" value="save-target">Save target</button>')
        data_rows = "".join(
            f'<div class="setup-row"><strong>{_h(label)}</strong><span>{"Provided" if data.get(key) else "Not set"}</span></div>'
            for key, label in TEST_DATA_FIELDS.items()
        )
        data_options = "".join(f'<option value="{_h(key)}">{_h(label)}</option>' for key, label in TEST_DATA_FIELDS.items())
        data_form = self._form(action_url,
            f'<label for="setup-data-key">Test data type</label><select id="setup-data-key" name="data_key">{data_options}</select>'
            '<label for="setup-data-value">Value</label><textarea id="setup-data-value" name="data_value" rows="3" maxlength="4096" required></textarea>'
            '<p class="field-help">For IDs or activation codes, enter one value per line. Saving replaces the chosen field; saved values are not shown here.</p>'
            '<button class="secondary" type="submit" name="action" value="save-data">Save test data</button>')
        requests = []
        if (engagement_plan_dir(self.output_root, engagement_id) / "plan.md").is_file() and self._planning_current(engagement):
            try:
                _, readiness = self._testing_readiness(engagement, template)
                for item in readiness.blocked:
                    for blocker in item.get("blockers", []):
                        if blocker.startswith("missing credential material for "):
                            name = blocker.removeprefix("missing credential material for ").replace("_", " ").title()
                            request = f"{name} credentials"
                        elif blocker.startswith("missing safe_test_data."):
                            key = blocker.removeprefix("missing safe_test_data.")
                            request = TEST_DATA_FIELDS.get(key, "Test data")
                        else:
                            request = {
                                "authorization_confirmed is not true in the engagement file": "Authorization confirmation",
                                "active_testing_allowed is not true in the engagement file": "Active testing permission",
                                "state_changing_tests_allowed is not true for this state-changing test": "State-changing test permission",
                                "no effective target mappings were resolved": "Target URL",
                            }.get(blocker)
                        if request and request not in requests:
                            requests.append(request)
                request_note = ('<p class="field-help">Needed for planned tests:</p><ul class="requested-inputs">'
                                + ''.join(f'<li>{_h(request)}</li>' for request in requests) + '</ul>') if requests else '<p class="field-help">The current plan requests no additional test information.</p>'
            except (OSError, ValueError, RuntimeError):
                request_note = '<p class="field-help">Test requirements will appear after the plan is available.</p>'
        else:
            request_note = '<p class="field-help">Planning will identify any required test information. You can return here to add it.</p>'
        return (
            '<section class="panel testing-setup" id="test-setup"><h2>Requested test information</h2>'
            '<p class="field-help">Planned tests may need credentials, permission, a target URL, or safe test data. Add only what is requested here.</p>'
            + self._error(error) + (f'<p class="save-notice" role="status">{_h(notice)}</p>' if notice else '')
            + request_note
            + self._credential_section(engagement_id, template, credential_mode, credential_error, credential_notice)
            + f'<details><summary>Permissions <small>{permission_count} of 3 set</small></summary><p class="field-help">Only allow actions you have approved for this assessment.</p>' + permissions + '</details>'
            + f'<details><summary>Target URLs <small>{target_count} configured</small></summary>' + (target_rows or '<p class="empty">No target URLs set.</p>') + target_form + '</details>'
            + f'<details><summary>Safe test data <small>{data_count} provided</small></summary>' + data_rows + data_form + '</details></section>'
        )

    def _credential_section(self, engagement_id: str, template: dict, mode: str, error: str | None, notice: str | None) -> str:
        credentials = template.get("credentials") if isinstance(template.get("credentials"), dict) else {}
        detail_url = f"/assessments/{engagement_id}"
        action_url = detail_url + "/credentials"
        rows = []
        for role, values in credentials.items():
            if not isinstance(values, dict):
                continue
            ready = bool(values.get("token") or (values.get("username") and values.get("password")))
            label = CREDENTIAL_ROLES.get(role, role)
            encoded_role = quote(role, safe="")
            rows.append(
                '<div class="credential-row">'
                f'<span><strong>{_h(label)}</strong><small>{"Ready" if ready else "Needs credentials"}</small></span>'
                f'<span class="hint-actions"><a class="text-link" href="{_h(detail_url)}?credential=edit:{encoded_role}">{"Replace" if ready else "Add"}</a>'
                f'<a class="text-link" href="{_h(detail_url)}?credential=remove:{encoded_role}">Remove</a></span></div>'
            )
        editor = ""
        if mode == "new":
            available = [(role, label) for role, label in CREDENTIAL_ROLES.items() if role not in credentials]
            if available:
                options = "".join(f'<option value="{_h(role)}">{_h(label)}</option>' for role, label in available)
                role_field = f'<label for="credential-role">Account role</label><select id="credential-role" name="role">{options}</select>'
                editor = self._credential_form(action_url, role_field, "Add credentials")
        elif mode.startswith("edit:"):
            role = mode.removeprefix("edit:")
            if role in credentials:
                role_field = f'<input type="hidden" name="role" value="{_h(role)}"><p class="field-help">{_h(CREDENTIAL_ROLES.get(role, role))}</p>'
                editor = self._credential_form(action_url, role_field, "Replace credentials")
        elif mode.startswith("remove:"):
            role = mode.removeprefix("remove:")
            if role in credentials:
                editor = (
                    '<div class="credential-editor"><h3>Remove credentials?</h3>'
                    f'<p>This removes {_h(CREDENTIAL_ROLES.get(role, role))} credentials from the active assessment. Local template backups may still contain earlier values.</p>'
                    + self._form(action_url,
                        f'<input type="hidden" name="role" value="{_h(role)}"><input type="hidden" name="confirmed" value="yes">'
                        f'<div class="actions"><a class="text-link" href="{_h(detail_url)}">Cancel</a><button class="secondary" type="submit" name="action" value="remove">Remove credentials</button></div>')
                    + '</div>'
                )
        add = f'<a class="secondary" href="{_h(detail_url)}?credential=new">+ Add credentials</a>' if not editor and any(role not in credentials for role in CREDENTIAL_ROLES) else ""
        return (
            '<div class="credentials"><h2>Test credentials</h2>'
            '<p class="field-help">Add an account by role when a planned test needs it. Enter a token or a username and password. Saved values are hidden here.</p>'
            + self._error(error) + (f'<p class="save-notice" role="status">{_h(notice)}</p>' if notice else '')
            + ("".join(rows) or '<p class="empty">No test credentials added.</p>') + editor + add + '</div>'
        )

    def _credential_form(self, action_url: str, role_field: str, label: str) -> str:
        return (
            f'<div class="credential-editor"><h3>{label}</h3>'
            '<p class="field-help">Saving replaces the credentials for this role. Enter the full new token or username and password.</p>'
            + self._form(action_url,
                role_field
                + '<label for="credential-username">Username</label><input id="credential-username" name="username" type="text" maxlength="256" autocomplete="off">'
                '<label for="credential-password">Password</label><input id="credential-password" name="password" type="password" maxlength="4096" autocomplete="new-password">'
                '<p class="field-help">or</p>'
                '<label for="credential-token">Token</label><input id="credential-token" name="token" type="password" maxlength="4096" autocomplete="off">'
                f'<div class="actions"><a class="text-link" href="{_h(action_url.removesuffix("/credentials"))}">Cancel</a><button class="primary" type="submit" name="action" value="save">{label}</button></div>')
            + '</div>'
        )

    def _assessment_detail(self, engagement_id: str, *, hint_mode: str = "", credential_mode: str = "", hint_draft=None, notes_draft=None, error=None, notice=None, asset_error=None, credential_error=None, credential_notice=None, setup_error=None, setup_notice=None) -> WebResponse:
        try:
            engagement = load_engagement(self.output_root, engagement_id)
        except (OSError, ValueError):
            return self._page("Not found", "<main class=\"home\"><h1>Assessment not found</h1></main>", status=404)
        template_path = self.output_root / engagement_id / "engagement_template.yaml"
        try:
            template = load_engagement_file(template_path) if template_path.exists() else build_minimal_engagement_template()
        except (OSError, ValueError):
            return self._page("Guidance unavailable", '<main class="home"><h1>Assessment guidance could not be loaded</h1><p>The existing configuration has not been changed.</p></main>', status=400)
        notes = notes_draft if notes_draft is not None else (template.get("llm") or {}).get("engagement_steer") or ""
        hints = template.get("hints", [])
        guidance_url = f"/assessments/{engagement_id}/guidance"
        detail_url = f"/assessments/{engagement_id}"
        notes_form = self._form(guidance_url,
            f'<label for="general-guidance">General guidance</label><p class="field-help">Describe overall priorities, goals, or context that should guide the assessment.</p>'
            f'<textarea id="general-guidance" name="notes" rows="4" maxlength="8192" placeholder="For example, focus on account boundaries and payment workflows.">{_h(notes)}</textarea>'
            '<div class="actions"><button class="secondary" type="submit" name="action" value="save-notes">Save guidance</button></div>')
        hint_rows = "".join(
            f'<div class="hint-row"><span class="hint-title">{_h(hint["title"])}</span><div class="hint-actions">'
            f'<a class="text-link" href="{_h(detail_url)}?hint=edit:{i}">Edit</a>'
            + self._form(guidance_url, f'<button class="text-link" type="submit" name="action" value="delete:{i}">Delete</button>')
            + '</div></div>' for i, hint in enumerate(hints)
        )
        editor = ""
        if hint_mode == "new" or hint_mode.startswith("edit:"):
            index_value = ""
            if hint_mode == "new":
                hint = {"title": "", "text": ""}
                editor_title = "Add hint"
            else:
                try:
                    index = int(hint_mode.split(":", 1)[1])
                    if not 0 <= index < len(hints):
                        raise ValueError
                    index_value = str(index)
                    hint = hints[index]
                    editor_title = "Edit hint"
                except ValueError:
                    hint = None
                    error = "Choose a hint to edit."
            if hint is not None:
                hint = hint_draft if hint_draft is not None else hint
                editor = (
                    f'<div class="hint-editor"><h4>{editor_title}</h4>'
                    + self._form(guidance_url,
                        f'<input type="hidden" name="index" value="{index_value}">'
                        f'<label for="hint-title">Title</label><input id="hint-title" type="text" name="title" maxlength="120" required value="{_h(hint["title"])}" placeholder="For example, Shared accounts">'
                        f'<label for="hint-text">What should we check?</label><textarea id="hint-text" name="text" rows="4" required placeholder="Describe what you know or suspect.">{_h(hint["text"])}</textarea>'
                        f'<div class="actions"><a class="text-link" href="{_h(detail_url)}">Cancel</a><button class="primary" type="submit" name="action" value="save-hint">Save hint</button></div>')
                    + '</div>'
                )
        add_hint = f'<a class="secondary" href="{_h(detail_url)}?hint=new">+ Add hint</a>' if len(hints) < 30 and not editor else ""
        assets_url = f"/assessments/{engagement_id}/assets"
        asset_rows = "".join(
            f'<div class="asset-row"><span class="type">{_h(ASSET_TYPES.get(asset.type, asset.type))}</span><code>{_h(asset.locator)}</code>'
            + self._form(assets_url, f'<input type="hidden" name="asset_id" value="{_h(asset.id)}"><button class="text-link" type="submit" name="action" value="remove">Remove</button>')
            + '</div>' for asset in engagement.assets
        )
        with self._asset_lock:
            current_check = self.assessment_asset_checks.get(engagement_id)
            pending = PendingAssessmentAsset(current_check.kind, current_check.locator, current_check.state, current_check.message) if current_check else None
        check_notice = ""
        if pending and pending.state == "checking":
            label = "website" if pending.kind == "live_url" else "repository"
            check_notice = f'<p class="asset-check checking" role="status">Checking {label} reachability… <code>{_h(pending.locator)}</code></p>'
        elif pending and pending.state == "failed":
            check_notice = (
                f'<div class="asset-check-failed"><p class="error" role="alert">{_h(pending.message)} <code>{_h(pending.locator)}</code></p>'
                + self._form(assets_url, '<button class="secondary" type="submit" name="action" value="retry">Retry check</button>')
                + self._form(assets_url, '<button class="secondary" type="submit" name="action" value="add-anyway">Add anyway</button>')
                + self._form(assets_url, '<button class="text-link" type="submit" name="action" value="dismiss">Dismiss</button>')
                + '</div>'
            )
        assets_section = (
            '<section class="panel assessment-assets" id="assets"><h2>Assets</h2>'
            + (asset_rows or '<p class="empty">No assets attached yet.</p>')
            + ('<p class="field-help asset-removal-note">Removing an asset takes it out of future runs. Existing generated files stay on disk.</p>' if engagement.assets else '')
            + '<h3>Add asset</h3>' + self._error(asset_error)
            + self._asset_entry_form(assets_url, f"/assessments/{engagement_id}/folders")
            + check_notice + '</section>'
        )
        body = (
            f'<main class="home"><a class="text-link" href="/">← All assessments</a><h1>{_h(engagement.title or engagement.id)}</h1>'
            + self._stage_nav(engagement, "scope")
            + assets_section
            + f'<section class="panel guidance"><h2>Assessment guidance (optional)</h2>'
            '<p class="guidance-intro">Mosh discovers each asset automatically from its content, so guidance is optional. Use this space to highlight key functionality, note relevant account roles, or point to sections worth reviewing. This guidance steers the security test for this assessment. You can edit it or add hints as the assessment progresses.</p>'
            f'{self._error(error)}' + (f'<p class="save-notice" role="status">{_h(notice)}</p>' if notice else '')
            + notes_form
            + '<div class="hints-section"><h3>Hints</h3><p class="field-help">Add facts or questions worth checking. Hints are leads, not confirmed findings; they guide analysis but do not provide test access. Add credentials and other required information below.</p>'
            + (hint_rows or '<p class="empty">No hints yet.</p>') + editor + add_hint + '</div></section>'
            + self._testing_setup_section(engagement, template, setup_error, setup_notice, credential_mode, credential_error, credential_notice)
            + '</main>'
        )
        return self._page(engagement.title or engagement.id, body, refresh=bool(pending and pending.state == "checking"))


def _command_ok(command: list[str]) -> bool:
    try:
        return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _valid_endpoint_url(value: str) -> bool:
    if not value or len(value) > 2048 or not value.isprintable() or any(char.isspace() for char in value):
        return False
    try:
        parsed = urlsplit(value)
        return bool(
            parsed.scheme in {"http", "https"}
            and parsed.hostname
            and parsed.port != 0
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def check_provider_api(provider: str, key: str, base_url: str) -> tuple[bool, str]:
    """Check API access without calling a model or exposing response details."""
    urls = {
        "deepseek": "https://api.deepseek.com/models",
        "openrouter": "https://openrouter.ai/api/v1/key",
    }
    if provider == "custom":
        if not _valid_endpoint_url(base_url):
            return False, "Enter a valid endpoint URL."
        url = base_url.rstrip("/") + "/models"
    elif provider in urls:
        url = urls[provider]
    else:
        return False, "Unsupported provider."
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    request = Request(url, headers=headers)
    try:
        with build_opener(_NoRedirect).open(request, timeout=8) as response:
            payload = response.read(64 * 1024 + 1)
    except HTTPError as exc:
        if exc.code in {401, 403}:
            return False, "API key was rejected." if key else "This endpoint requires an API key."
        if 300 <= exc.code < 400:
            return False, "API redirected the check. Verify the endpoint URL."
        return False, f"API check failed (HTTP {exc.code})."
    except (OSError, URLError):
        return False, "Could not reach the API. Try again."
    if len(payload) > 64 * 1024:
        return False, "API response was too large."
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        return False, "API did not return a model or key response."
    if not isinstance(data, dict) or not isinstance(data.get("data"), dict if provider == "openrouter" else list):
        return False, "API did not return a model or key response."
    return True, ""


def check_asset_reachability(kind: str, locator: str) -> tuple[bool, str]:
    """Check a website or HTTPS Git repository without starting discovery."""
    try:
        locator = normalize_asset_locator(locator, kind)
    except (OSError, ValueError):
        return False, "Enter a valid asset URL."
    if kind == "live_url":
        opener = build_opener(_NoRedirect)
        for method in ("HEAD", "GET"):
            headers = {"Range": "bytes=0-0"} if method == "GET" else {}
            request = Request(locator, headers=headers, method=method)
            try:
                with opener.open(request, timeout=8) as response:
                    status = response.status
            except HTTPError as exc:
                status = exc.code
            except (OSError, URLError):
                return False, "Could not reach this website."
            if method == "HEAD" and status in {405, 501}:
                continue
            if 200 <= status < 400:
                return True, "Reachable when added" if status < 300 else "Redirects when added"
            if status in {401, 403}:
                return True, "Reachable · access restricted"
            return False, f"Website returned HTTP {status}."
    if kind == "source_repo":
        git_env = os.environ.copy()
        git_env.update({
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ASKPASS": os.devnull,
            "GCM_INTERACTIVE": "Never",
        })
        try:
            result = subprocess.run(
                ["git", "-c", "credential.helper=", "-c", "http.followRedirects=false", "ls-remote", "--symref", locator, "HEAD"],
                cwd=tempfile.gettempdir(), env=git_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=8, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False, "Could not reach this repository."
        return (True, "Repository reachable when added") if result.returncode == 0 else (False, "Could not reach this repository. It may require authentication.")
    return False, "Choose a website or Git repository (HTTPS) to check."


def _write_env_settings(path: Path, settings: dict[str, str | None]) -> None:
    if any(key not in {*KEY_NAMES.values(), "MOSH_LLM_BASE_URL"} for key in settings):
        raise ValueError("Unsupported setting")
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = {key: f"{key}={_h_env(value)}" for key, value in settings.items() if value is not None}
    updated = []
    for line in lines:
        match = re.match(r"\s*(?:export\s+)?([A-Z_]+)\s*=", line)
        if match and match.group(1) in settings:
            replacement = remaining.pop(match.group(1), None)
            if replacement is not None:
                updated.append(replacement)
            continue
        updated.append(line)
    updated.extend(remaining.values())
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".mosh-env-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("\n".join(updated) + "\n")
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _h_env(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def make_handler(app: WebApp) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._send(app.handle("GET", self.path, headers=dict(self.headers)))

        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY_BYTES or self.headers.get_content_type() != "application/x-www-form-urlencoded":
                self._send(WebResponse(400, "Invalid form body", "text/plain; charset=utf-8"))
                return
            parsed = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"), keep_blank_values=True)
            if any(len(values) != 1 for values in parsed.values()):
                self._send(WebResponse(400, "Duplicate form field", "text/plain; charset=utf-8"))
                return
            self._send(app.handle("POST", self.path, {key: values[0] for key, values in parsed.items()}, dict(self.headers)))

        def _send(self, response: WebResponse) -> None:
            body = response.body.encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            if response.location:
                self.send_header("Location", response.location)
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mosh-web", description="Run the mosh localhost interface")
    parser.add_argument("--port", type=int, default=8765, help="Local port (default: 8765)")
    parser.add_argument("--project-root", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    app = WebApp(args.project_root)
    with HTTPServer(("127.0.0.1", args.port), make_handler(app)) as server:
        print(f"mosh web: http://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
