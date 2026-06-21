from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from mosh.config import AppConfig
from mosh.engagements import asset_discovery_dir, engagement_dir, engagement_exists, load_engagement
from mosh.models import utc_now


CONVERSATION_SCHEMA = "mosh.conversation.v1"
DIRECTIVES_SCHEMA = "mosh.conversation-directives.v1"
CHAT_CONTEXT_SCHEMA = "mosh.engagement-chat-context.v1"

CONTEXT_TEXT_LIMIT = 6_000
CONTEXT_MEMORY_ITEMS_LIMIT = 80
CONTEXT_EXECUTED_REPORTS_LIMIT = 100
CHAT_MAX_OUTPUT_TOKENS = 2_048
LLM_CONTEXT_TEXT_LIMIT = 1_000
LLM_CONTEXT_SHORT_TEXT_LIMIT = 350
LLM_CONTEXT_ITEMS_LIMIT = 25
LLM_CONTEXT_HYPOTHESES_LIMIT = 20
LLM_CONTEXT_EXECUTED_TESTS_LIMIT = 12
EXECUTION_METADATA_START = "<!-- mosh-execution"
EXECUTION_METADATA_END = "-->"
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
    "unknown": 5,
}
DIRECTIVE_DEFAULT_STAGES = {
    "scope_override": ["discovery", "planning", "testing", "reporting"],
    "additional_discovery_fact": ["discovery", "planning", "reporting"],
    "planning_focus": ["planning", "reporting"],
    "test_instruction": ["planning", "testing"],
    "tool_request": ["discovery", "planning", "testing"],
    "execution_constraint": ["testing"],
    "engagement_template_update_suggestion": ["testing"],
    "report_correction": ["reporting"],
    "engagement_context": ["planning", "testing", "reporting"],
}
VALID_DIRECTIVE_KINDS = set(DIRECTIVE_DEFAULT_STAGES)

STAGE_DIRECTIVE_KINDS: dict[str, set[str]] = {
    "discovery": {
        "scope_override",
        "additional_discovery_fact",
        "tool_request",
    },
    "planning": {
        "scope_override",
        "additional_discovery_fact",
        "planning_focus",
        "test_instruction",
        "tool_request",
        "engagement_context",
    },
    "testing": {
        "scope_override",
        "test_instruction",
        "tool_request",
        "execution_constraint",
        "engagement_template_update_suggestion",
        "engagement_context",
    },
    "reporting": {
        "scope_override",
        "report_correction",
        "planning_focus",
        "additional_discovery_fact",
        "engagement_context",
    },
}


@dataclass(frozen=True)
class ConversationMessage:
    id: str
    role: str
    content: str
    timestamp: str = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"schema": CONVERSATION_SCHEMA, **asdict(self)}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ConversationMessage":
        return cls(
            id=str(value.get("id") or ""),
            role=str(value.get("role") or ""),
            content=str(value.get("content") or ""),
            timestamp=str(value.get("timestamp") or utc_now()),
            metadata=value.get("metadata") if isinstance(value.get("metadata"), dict) else {},
        )


@dataclass(frozen=True)
class ConversationDirective:
    id: str
    kind: str
    instruction: str
    source_message_id: str
    stages: list[str]
    target: dict[str, Any] = field(default_factory=dict)
    status: str = "active"
    confidence: str = "heuristic"
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ConversationDirective":
        stages = [str(item) for item in _list(value.get("stages")) if str(item)]
        return cls(
            id=str(value.get("id") or ""),
            kind=str(value.get("kind") or ""),
            instruction=str(value.get("instruction") or ""),
            source_message_id=str(value.get("source_message_id") or ""),
            stages=stages,
            target=value.get("target") if isinstance(value.get("target"), dict) else {},
            status=str(value.get("status") or "active"),
            confidence=str(value.get("confidence") or "heuristic"),
            created_at=str(value.get("created_at") or utc_now()),
        )


@dataclass(frozen=True)
class EngagementChatResult:
    response: str
    directives: list[dict[str, Any]]
    artifact_refs: list[str] = field(default_factory=list)
    user_message: dict[str, Any] | None = None
    assistant_message: dict[str, Any] | None = None


class EngagementChatRunner(Protocol):
    def respond(
        self,
        *,
        engagement_id: str,
        user_message: ConversationMessage,
        context: dict[str, Any],
    ) -> EngagementChatResult:
        pass


class LocalEngagementChatRunner:
    """Deterministic first-pass chat runner.

    This keeps the product usable and testable without requiring live LLM calls.
    Crew stages still receive the extracted directives in their model context.
    """

    def respond(
        self,
        *,
        engagement_id: str,
        user_message: ConversationMessage,
        context: dict[str, Any],
    ) -> EngagementChatResult:
        directives = [directive.to_dict() for directive in extract_directives(user_message.content, user_message.id)]
        answer, refs = _answer_from_context(context, user_message.content)
        lines: list[str] = []
        if answer:
            lines.append(answer)
        if directives:
            if lines:
                lines.append("")
            lines.append(_render_recorded_directives(directives))
        if not lines:
            lines.append(
                "I recorded the message, but I do not have enough matching engagement context yet to answer it or extract an actionable directive."
            )
        return EngagementChatResult(response="\n".join(lines).strip(), directives=directives, artifact_refs=refs)


class LLMEngagementChatRunner:
    def __init__(
        self,
        config: AppConfig,
        *,
        completion: Callable[[list[dict[str, str]]], str] | None = None,
        fallback_runner: EngagementChatRunner | None = None,
    ) -> None:
        self.config = config
        self.completion = completion
        self.fallback_runner = fallback_runner or LocalEngagementChatRunner()

    def respond(
        self,
        *,
        engagement_id: str,
        user_message: ConversationMessage,
        context: dict[str, Any],
    ) -> EngagementChatResult:
        model = self.config.models.chat.assistant
        missing_settings = self.config.missing_llm_settings_for_models([model])
        if missing_settings:
            fallback = self.fallback_runner.respond(
                engagement_id=engagement_id,
                user_message=user_message,
                context=context,
            )
            return EngagementChatResult(
                response=(
                    "LLM chat is unavailable because "
                    f"{', '.join(missing_settings)} is not configured. "
                    "Using local engagement context fallback.\n\n"
                    f"{fallback.response}"
                ),
                directives=fallback.directives,
                artifact_refs=fallback.artifact_refs,
            )

        messages = _build_llm_chat_messages(context, user_message)
        raw_response = ""
        last_error: Exception | None = None
        try:
            for attempt in range(2):
                raw_response = self._complete(messages)
                try:
                    result = _parse_llm_chat_result(raw_response, user_message, context)
                    if _looks_like_incomplete_chat_answer(result.response):
                        raise ValueError("chat model answer appears incomplete")
                    return _merge_heuristic_directives(result, user_message)
                except Exception as exc:
                    last_error = exc
                    if attempt == 0:
                        messages = _build_llm_chat_repair_messages(messages, raw_response, exc)
                        continue
                    raise
        except Exception as exc:
            fallback = self.fallback_runner.respond(
                engagement_id=engagement_id,
                user_message=user_message,
                context=context,
            )
            reason = last_error or exc
            return EngagementChatResult(
                response=(
                    "The chat model response could not be used "
                    f"({type(reason).__name__}: {reason}). "
                    "Using local engagement context fallback.\n\n"
                    f"{fallback.response}"
                ),
                directives=fallback.directives,
                artifact_refs=fallback.artifact_refs,
            )

    def _complete(self, messages: list[dict[str, str]]) -> str:
        if self.completion:
            return self.completion(messages)
        from mosh.crews.discovery_live.crew import _llm, _load_crewai

        crewai = _load_crewai()
        response = _llm(
            crewai,
            self.config,
            self.config.models.chat.assistant,
            max_tokens=CHAT_MAX_OUTPUT_TOKENS,
        ).call(messages)
        return _text(response)


class EngagementChatOrchestrator:
    def __init__(
        self,
        output_root: Path = Path("report"),
        config: AppConfig | None = None,
        runner: EngagementChatRunner | None = None,
    ) -> None:
        self.output_root = output_root
        self.runner = runner or (
            LLMEngagementChatRunner(config) if config is not None else LocalEngagementChatRunner()
        )

    def ask(self, engagement_id: str, message: str) -> EngagementChatResult:
        if not engagement_exists(self.output_root, engagement_id):
            raise FileNotFoundError(f"Engagement not found: {engagement_id}")
        content = message.strip()
        if not content:
            raise ValueError("Chat message cannot be empty")
        user_message = append_message(self.output_root, engagement_id, "user", content)
        context = build_engagement_chat_context(self.output_root, engagement_id)
        result = self.runner.respond(
            engagement_id=engagement_id,
            user_message=user_message,
            context=context,
        )
        persisted_directives = add_directives(self.output_root, engagement_id, result.directives)
        assistant_message = append_message(
            self.output_root,
            engagement_id,
            "assistant",
            result.response,
            metadata={
                "directive_ids": [directive["id"] for directive in persisted_directives],
                "artifact_refs": result.artifact_refs,
            },
        )
        return EngagementChatResult(
            response=result.response,
            directives=persisted_directives,
            artifact_refs=result.artifact_refs,
            user_message=user_message.to_dict(),
            assistant_message=assistant_message.to_dict(),
        )


def conversation_dir(output_root: Path, engagement_id: str) -> Path:
    return engagement_dir(output_root, engagement_id) / "conversation"


def messages_path(output_root: Path, engagement_id: str) -> Path:
    return conversation_dir(output_root, engagement_id) / "messages.jsonl"


def directives_path(output_root: Path, engagement_id: str) -> Path:
    return conversation_dir(output_root, engagement_id) / "directives.json"


def append_message(
    output_root: Path,
    engagement_id: str,
    role: str,
    content: str,
    *,
    metadata: dict[str, Any] | None = None,
) -> ConversationMessage:
    normalized_role = role.strip().lower()
    if normalized_role not in {"user", "assistant", "system"}:
        raise ValueError(f"Unsupported conversation role `{role}`")
    if not content.strip():
        raise ValueError("Conversation message cannot be empty")
    root = conversation_dir(output_root, engagement_id)
    root.mkdir(parents=True, exist_ok=True)
    message = ConversationMessage(
        id=_new_id("msg"),
        role=normalized_role,
        content=content.strip(),
        metadata=metadata or {},
    )
    with messages_path(output_root, engagement_id).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(message.to_dict(), sort_keys=True) + "\n")
    return message


def load_messages(output_root: Path, engagement_id: str) -> list[dict[str, Any]]:
    path = messages_path(output_root, engagement_id)
    if not path.exists():
        return []
    messages: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        parsed = json.loads(line)
        if not isinstance(parsed, dict):
            raise ValueError(f"{path}:{line_number}: conversation message must be a JSON object")
        messages.append(ConversationMessage.from_dict(parsed).to_dict())
    return messages


def load_directives(output_root: Path, engagement_id: str) -> list[dict[str, Any]]:
    path = directives_path(output_root, engagement_id)
    if not path.exists():
        return []
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(parsed, list):
        values = parsed
    elif isinstance(parsed, dict):
        values = parsed.get("directives", [])
    else:
        raise ValueError(f"{path} must contain a directive list")
    return [
        ConversationDirective.from_dict(item).to_dict()
        for item in values
        if isinstance(item, dict)
    ]


def save_directives(output_root: Path, engagement_id: str, directives: list[dict[str, Any]]) -> None:
    path = directives_path(output_root, engagement_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    cleaned = [ConversationDirective.from_dict(item).to_dict() for item in directives if isinstance(item, dict)]
    _write_json(path, {"schema": DIRECTIVES_SCHEMA, "directives": cleaned})


def add_directives(
    output_root: Path,
    engagement_id: str,
    directives: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not directives:
        return []
    existing = load_directives(output_root, engagement_id)
    existing_fingerprints = {_directive_duplicate_fingerprint(item) for item in existing}
    added: list[dict[str, Any]] = []
    for item in directives:
        if not isinstance(item, dict):
            continue
        directive = ConversationDirective.from_dict({**item, "id": item.get("id") or _new_id("dir")}).to_dict()
        fingerprint = _directive_duplicate_fingerprint(directive)
        if fingerprint in existing_fingerprints:
            continue
        existing_fingerprints.add(fingerprint)
        existing.append(directive)
        added.append(directive)
    if added:
        save_directives(output_root, engagement_id, existing)
    return added


def active_directives(
    output_root: Path,
    engagement_id: str,
    *,
    stage: str | None = None,
) -> list[dict[str, Any]]:
    directives = [item for item in load_directives(output_root, engagement_id) if item.get("status") == "active"]
    if stage is None:
        return directives
    allowed_kinds = STAGE_DIRECTIVE_KINDS.get(stage, set())
    return [
        item
        for item in directives
        if item.get("kind") in allowed_kinds or stage in _list(item.get("stages")) or "all" in _list(item.get("stages"))
    ]


def directives_fingerprint(directives: list[dict[str, Any]]) -> str:
    normalized = [
        {
            "id": item.get("id"),
            "kind": item.get("kind"),
            "instruction": item.get("instruction"),
            "source_message_id": item.get("source_message_id"),
            "stages": sorted(str(stage) for stage in _list(item.get("stages"))),
            "target": item.get("target") if isinstance(item.get("target"), dict) else {},
            "status": item.get("status"),
        }
        for item in directives
        if isinstance(item, dict)
    ]
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def active_directives_fingerprint(output_root: Path, engagement_id: str, *, stage: str) -> str:
    return directives_fingerprint(active_directives(output_root, engagement_id, stage=stage))


def extract_directives(message: str, source_message_id: str) -> list[ConversationDirective]:
    text = message.strip()
    if not text:
        return []
    lowered = text.lower()
    pure_question = _looks_like_pure_question(text)
    directives: list[ConversationDirective] = []
    urls = _extract_urls(text)
    paths = _extract_paths(text)
    hypothesis_ids = _extract_hypothesis_ids(text)

    if not pure_question and _looks_like_scope_exclusion(lowered):
        targets = _target_records(urls, paths) or [{"text": text}]
        for target in targets:
            directives.append(
                _directive(
                    kind="scope_override",
                    instruction=text,
                    source_message_id=source_message_id,
                    stages=["discovery", "planning", "testing", "reporting"],
                    target={**target, "action": "exclude"},
                )
            )
    elif not pure_question and _looks_like_scope_inclusion(lowered):
        targets = _target_records(urls, paths) or [{"text": text}]
        for target in targets:
            directives.append(
                _directive(
                    kind="scope_override",
                    instruction=text,
                    source_message_id=source_message_id,
                    stages=["discovery", "planning", "testing", "reporting"],
                    target={**target, "action": "include"},
                )
            )

    has_scope_directive = any(directive.kind == "scope_override" for directive in directives)
    if not pure_question and not has_scope_directive and _looks_like_discovery_fact(lowered):
        for target in _target_records(urls, paths) or [{"text": text}]:
            directives.append(
                _directive(
                    kind="additional_discovery_fact",
                    instruction=text,
                    source_message_id=source_message_id,
                    stages=["discovery", "planning", "reporting"],
                    target=target,
                )
            )

    if not pure_question and _looks_like_planning_focus(lowered):
        directives.append(
            _directive(
                kind="planning_focus",
                instruction=text,
                source_message_id=source_message_id,
                stages=["planning", "reporting"],
                target={"hypothesis_ids": hypothesis_ids} if hypothesis_ids else {},
            )
        )

    tools = _extract_requested_tools(text)
    if tools:
        for tool in tools:
            directives.append(
                _directive(
                    kind="tool_request",
                    instruction=text,
                    source_message_id=source_message_id,
                    stages=["discovery", "planning", "testing"],
                    target={"tool": tool, "hypothesis_ids": hypothesis_ids},
                )
            )

    if (hypothesis_ids and not pure_question) or _looks_like_test_instruction(lowered):
        target = {"hypothesis_ids": hypothesis_ids} if hypothesis_ids else {}
        directives.append(
            _directive(
                kind="test_instruction",
                instruction=text,
                source_message_id=source_message_id,
                stages=["planning", "testing"],
                target=target,
            )
        )

    if not pure_question and _looks_like_execution_constraint(lowered):
        directives.append(
            _directive(
                kind="execution_constraint",
                instruction=text,
                source_message_id=source_message_id,
                stages=["testing"],
                target={"hypothesis_ids": hypothesis_ids} if hypothesis_ids else {},
            )
        )

    if not pure_question and _looks_like_template_suggestion(lowered):
        directives.append(
            _directive(
                kind="engagement_template_update_suggestion",
                instruction=text,
                source_message_id=source_message_id,
                stages=["testing"],
                target={"hypothesis_ids": hypothesis_ids} if hypothesis_ids else {},
            )
        )

    if not pure_question and _looks_like_report_correction(lowered):
        directives.append(
            _directive(
                kind="report_correction",
                instruction=text,
                source_message_id=source_message_id,
                stages=["reporting"],
                target={"hypothesis_ids": hypothesis_ids} if hypothesis_ids else {},
            )
        )

    if not pure_question and _looks_like_design_clarification(lowered):
        directives.append(
            _directive(
                kind="engagement_context",
                instruction=text,
                source_message_id=source_message_id,
                stages=["planning", "testing", "reporting"],
                target={"clarification": True},
            )
        )

    if not pure_question and _looks_like_engagement_context(lowered) and not directives:
        directives.append(
            _directive(
                kind="engagement_context",
                instruction=text,
                source_message_id=source_message_id,
                stages=["planning", "testing", "reporting"],
                target={},
            )
        )

    return _dedupe_directives(directives)


def build_engagement_chat_context(output_root: Path, engagement_id: str) -> dict[str, Any]:
    engagement = load_engagement(output_root, engagement_id)
    root = engagement_dir(output_root, engagement.id)
    planning_dir = root / "plan"
    testing_dir = root / "security-testing"
    final_report_dir = root / "final-report"
    return {
        "schema": CHAT_CONTEXT_SCHEMA,
        "engagement": {
            "id": engagement.id,
            "title": engagement.title,
            "assets": [
                {
                    "id": asset.id,
                    "type": asset.type,
                    "locator": asset.locator,
                    "label": asset.label,
                    "metadata": asset.metadata,
                }
                for asset in engagement.assets
            ],
        },
        "conversation": {
            "messages": load_messages(output_root, engagement.id)[-20:],
            "active_directives": active_directives(output_root, engagement.id),
        },
        "discovery": [
            {
                "asset_id": asset.id,
                "asset_type": asset.type,
                "path": str(asset_discovery_dir(output_root, engagement.id, asset.id)),
                "report": _read_text(asset_discovery_dir(output_root, engagement.id, asset.id) / "report.md"),
                "memory": _compact_memory(asset_discovery_dir(output_root, engagement.id, asset.id) / "memory.json"),
            }
            for asset in engagement.assets
            if asset_discovery_dir(output_root, engagement.id, asset.id).exists()
        ],
        "planning": {
            "path": str(planning_dir),
            "report": _read_text(planning_dir / "plan.md"),
            "memory": _compact_memory(planning_dir / "memory.json"),
            "structured_plan": _latest_structured_plan(planning_dir / "memory.json"),
        },
        "engagement_template": {
            "path": str(root / "engagement_template.yaml"),
            "content": _read_text(root / "engagement_template.yaml"),
        },
        "testing": {
            "path": str(testing_dir),
            "preflight": _read_text(testing_dir / "preflight.md"),
            "preflight_state": _latest_memory_content(testing_dir / "memory.json", "testing_preflight"),
            "memory": _compact_memory(testing_dir / "memory.json"),
            "executed_tests": _executed_test_context(testing_dir),
        },
        "final_report": {
            "path": str(final_report_dir / "report.md"),
            "content": _read_text(final_report_dir / "report.md"),
        },
    }


def _directive(
    *,
    kind: str,
    instruction: str,
    source_message_id: str,
    stages: list[str],
    target: dict[str, Any],
) -> ConversationDirective:
    return ConversationDirective(
        id=_new_id("dir"),
        kind=kind,
        instruction=instruction,
        source_message_id=source_message_id,
        stages=stages,
        target={key: value for key, value in target.items() if value not in (None, "", [], {})},
    )


def _dedupe_directives(directives: list[ConversationDirective]) -> list[ConversationDirective]:
    seen: set[str] = set()
    result: list[ConversationDirective] = []
    for directive in directives:
        fingerprint = _directive_duplicate_fingerprint(directive.to_dict())
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(directive)
    return result


def _directive_duplicate_fingerprint(directive: dict[str, Any]) -> str:
    return json.dumps(
        {
            "kind": directive.get("kind"),
            "instruction": directive.get("instruction"),
            "source_message_id": directive.get("source_message_id"),
            "target": directive.get("target"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _looks_like_scope_exclusion(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "out of scope",
            "out-of-scope",
            "not in scope",
            "not in-scope",
            "exclude ",
            "excluded from scope",
            "should not be tested",
            "do not test",
            "don't test",
        )
    )


def _looks_like_scope_inclusion(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "in scope",
            "in-scope",
            "include in scope",
            "should be tested",
        )
    ) and not _looks_like_scope_exclusion(lowered)


def _looks_like_discovery_fact(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "discovery missed",
            "not identified",
            "additional discovery",
            "additional information",
            "endpoint",
            "graphql",
            "api route",
            "url is",
            "there is a",
        )
    )


def _looks_like_planning_focus(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "focus",
            "prioritise",
            "prioritize",
            "testing did not include",
            "important for the user",
            "important for us",
            "include testing",
            "include a test",
            "point the testing",
            "test the",
        )
    )


def _looks_like_test_instruction(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "when testing",
            "during testing",
            "test should",
            "should use",
            "run against",
            "validate",
            "verify",
        )
    )


def _looks_like_execution_constraint(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "do not run",
            "don't run",
            "avoid running",
            "limit requests",
            "rate limit",
            "read only",
            "read-only",
            "no state changing",
            "stop if",
        )
    )


def _looks_like_template_suggestion(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "credential",
            "token",
            "safe test data",
            "safe_test_data",
            "target mapping",
            "engagement template",
            "authorization",
            "authorisation",
        )
    )


def _looks_like_report_correction(lowered: str) -> bool:
    return "report" in lowered and any(marker in lowered for marker in ("correct", "correction", "should say", "wrong", "not accurate"))


def _looks_like_design_clarification(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "intentional",
            "by design",
            "expected",
            "supposed to",
            "that's fine",
            "that is fine",
            "not a bug",
            "not an issue",
            "not a finding",
            "false positive",
            "acceptable",
            "works without authentication",
            "work without authentication",
            "production users are anonymous",
        )
    )


def _looks_like_engagement_context(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "business",
            "context",
            "user flow",
            "workflow",
            "domain",
            "customer",
            "intentional",
            "by design",
        )
    )


def _extract_urls(text: str) -> list[str]:
    return sorted(set(re.findall(r"https?://[^\s\"'<>),]+", text)))


def _extract_paths(text: str) -> list[str]:
    candidates = re.findall(r"(?<!https:)(?<!http:)(/[A-Za-z0-9_./{}?=&:%+-]+)", text)
    return sorted(set(candidate.rstrip(".,;:") for candidate in candidates if len(candidate) > 1))


def _extract_hypothesis_ids(text: str) -> list[str]:
    return sorted(set(re.findall(r"\b[A-Z][A-Z0-9_]+-\d+\b", text)))


def _extract_requested_tools(text: str) -> list[str]:
    lowered = text.lower()
    known_tools = {
        "dirb": ("dirb", "directory brute", "bruteforce", "brute force"),
        "katana": ("katana",),
        "js-endpoint-extractor": ("js endpoint", "javascript endpoint", "js-endpoint-extractor"),
        "extractify": ("extractify",),
    }
    requested: list[str] = []
    if "run" not in lowered and "use" not in lowered and "tool" not in lowered:
        return []
    for tool, markers in known_tools.items():
        if any(marker in lowered for marker in markers):
            requested.append(tool)
    return requested


def _target_records(urls: list[str], paths: list[str]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    records.extend({"url": url} for url in urls)
    records.extend({"path": path} for path in paths)
    return records


def _build_llm_chat_messages(context: dict[str, Any], user_message: ConversationMessage) -> list[dict[str, str]]:
    llm_context = _llm_chat_context(context, user_message.content)
    return [
        {
            "role": "system",
            "content": (
                "You are the Mosh engagement chat assistant. Answer naturally and concisely using only the provided "
                "engagement context. Do not dump raw grep-like excerpts. Cite artifact paths in artifact_refs. "
                "If the user gives steering feedback, record it as directives. If the user clarifies intended "
                "application behavior, record an engagement_context directive and explain how that changes the next "
                "steps. Keep credentials and permissions in the engagement template; suggest exact fields instead of "
                "inventing secrets. Complete every list you introduce; do not end the answer after a colon. "
                "Use only real mosh CLI commands: testing a specific hypothesis is "
                "`uv run mosh test <engagement_id> --hypothesis <HYPOTHESIS_ID>`. Never suggest "
                "`mosh test <HYPOTHESIS_ID>`. "
                "Return only one JSON object with keys: answer, artifact_refs, directives. "
                "directives must be a list of objects with kind, instruction, stages, and target."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(llm_context, sort_keys=True),
        },
    ]


def _llm_chat_context(context: dict[str, Any], question: str) -> dict[str, Any]:
    structured_answer = _structured_answer_from_context(context, question)
    facts: dict[str, Any] = {}
    if structured_answer:
        facts = {
            "deterministic_answer": structured_answer[0],
            "artifact_refs": structured_answer[1],
        }
    return {
        "schema": "mosh.engagement-chat-llm-context.v1",
        "user_message": question,
        "question_facts": facts,
        "engagement": context.get("engagement", {}),
        "valid_cli_commands": _llm_valid_cli_commands(context),
        "recent_messages": _compact_recent_messages((context.get("conversation") or {}).get("messages")),
        "active_directives": _llm_directive_summaries((context.get("conversation") or {}).get("active_directives")),
        "stage_status": _stage_status_snapshot(context),
        "retrieved_artifact_excerpts": _llm_retrieved_artifact_excerpts(context, question),
        "planning": _llm_planning_summary(context),
        "testing": {
            "path": (context.get("testing") or {}).get("path"),
            "preflight_state": _llm_preflight_summary((context.get("testing") or {}).get("preflight_state")),
            "executed_tests": _llm_executed_test_summaries(context),
        },
        "discovery": _llm_discovery_summaries(context),
        "final_report": {
            "path": (context.get("final_report") or {}).get("path"),
            "available": bool((context.get("final_report") or {}).get("content")),
            "report_excerpt": _truncate(_text((context.get("final_report") or {}).get("content")), LLM_CONTEXT_TEXT_LIMIT),
        },
    }


def _build_llm_chat_repair_messages(
    messages: list[dict[str, str]],
    raw_response: str,
    error: Exception,
) -> list[dict[str, str]]:
    return [
        *messages,
        {
            "role": "assistant",
            "content": _truncate(raw_response, 4_000) if raw_response else "",
        },
        {
            "role": "user",
            "content": (
                f"The previous response could not be used: {type(error).__name__}: {error}. "
                "Return one valid JSON object with a complete answer, artifact_refs, and directives. "
                "If you introduce next steps, include the actual steps."
            ),
        },
    ]


def _llm_valid_cli_commands(context: dict[str, Any]) -> list[str]:
    engagement = context.get("engagement") if isinstance(context.get("engagement"), dict) else {}
    engagement_id = _text(engagement.get("id")) or "<engagement_id>"
    return [
        f"uv run mosh discover {engagement_id}",
        f"uv run mosh plan {engagement_id}",
        f"uv run mosh test {engagement_id}",
        f"uv run mosh test {engagement_id} --hypothesis <HYPOTHESIS_ID>",
        f"uv run mosh report {engagement_id}",
        f"uv run mosh chat {engagement_id}",
    ]


def _compact_recent_messages(value: Any) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = []
    for item in _list(value)[-8:]:
        if not isinstance(item, dict):
            continue
        messages.append(
            {
                "role": _text(item.get("role")),
                "content": _truncate(_text(item.get("content")), 500),
            }
        )
    return messages


def _llm_directive_summaries(value: Any) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for item in _list(value)[-LLM_CONTEXT_ITEMS_LIMIT:]:
        if not isinstance(item, dict):
            continue
        summaries.append(
            {
                "id": item.get("id"),
                "kind": item.get("kind"),
                "instruction": _truncate(_text(item.get("instruction")), LLM_CONTEXT_SHORT_TEXT_LIMIT),
                "stages": _string_list(item.get("stages")),
                "target": _llm_compact_value(item.get("target"), LLM_CONTEXT_SHORT_TEXT_LIMIT),
            }
        )
    return summaries


def _stage_status_snapshot(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "available_stages": _available_context_stages(context),
        "preflight_counts": _preflight_counts(context),
        "confirmed_findings": len(_accepted_findings_from_context(context)),
        "executed_tests": len(_list((context.get("testing") or {}).get("executed_tests"))),
    }


def _llm_retrieved_artifact_excerpts(context: dict[str, Any], question: str) -> list[dict[str, str]]:
    return [
        {
            "path": snippet["ref"],
            "excerpt": snippet["text"],
        }
        for snippet in _matching_context_snippets(context, question)[:5]
    ]


def _llm_planning_summary(context: dict[str, Any]) -> dict[str, Any]:
    planning = context.get("planning") if isinstance(context.get("planning"), dict) else {}
    structured = planning.get("structured_plan") if isinstance(planning.get("structured_plan"), dict) else {}
    hypotheses = _list(
        structured.get("test_hypotheses")
        or structured.get("hypotheses")
        or structured.get("tests")
    )
    return {
        "path": planning.get("path"),
        "report_excerpt": _truncate(_text(planning.get("report")), LLM_CONTEXT_TEXT_LIMIT),
        "hypotheses": [
            _llm_hypothesis_summary(item)
            for item in hypotheses[:LLM_CONTEXT_HYPOTHESES_LIMIT]
            if isinstance(item, dict)
        ],
    }


def _llm_hypothesis_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "title": _truncate(_text(item.get("title")), LLM_CONTEXT_SHORT_TEXT_LIMIT),
        "priority": item.get("priority") or item.get("severity"),
        "surface": item.get("surface"),
        "execution_mode": item.get("execution_mode"),
        "status": item.get("status"),
        "requirements": [
            _truncate(_text(requirement), 150)
            for requirement in _list(item.get("requirements"))[:4]
            if _text(requirement)
        ],
    }


def _llm_preflight_summary(value: Any) -> dict[str, Any]:
    state = value if isinstance(value, dict) else {}
    return {
        "ready": [
            _llm_preflight_item(item)
            for item in _list(state.get("ready"))[:LLM_CONTEXT_ITEMS_LIMIT]
            if isinstance(item, dict)
        ],
        "blocked": [
            _llm_preflight_item(item)
            for item in _list(state.get("blocked"))[:LLM_CONTEXT_ITEMS_LIMIT]
            if isinstance(item, dict)
        ],
        "deferred": [
            _llm_preflight_item(item)
            for item in _list(state.get("deferred"))[:LLM_CONTEXT_ITEMS_LIMIT]
            if isinstance(item, dict)
        ],
    }


def _llm_preflight_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "title": _truncate(_text(item.get("title")), LLM_CONTEXT_SHORT_TEXT_LIMIT),
        "priority": item.get("priority"),
        "blockers": [
            _truncate(_text(blocker), LLM_CONTEXT_SHORT_TEXT_LIMIT)
            for blocker in _list(item.get("blockers"))[:8]
            if _text(blocker)
        ],
    }


def _llm_executed_test_summaries(context: dict[str, Any]) -> list[dict[str, Any]]:
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    summaries: list[dict[str, Any]] = []
    for item in _list(testing.get("executed_tests"))[:LLM_CONTEXT_EXECUTED_TESTS_LIMIT]:
        if not isinstance(item, dict):
            continue
        summaries.append(
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "status": item.get("status"),
                "review_accepted": item.get("review_accepted"),
                "severity": item.get("severity"),
                "summary": _truncate(_text(item.get("summary")), 220),
                "result": _truncate(_text(item.get("result")), 220),
                "path": item.get("path"),
            }
        )
    return summaries


def _llm_discovery_summaries(context: dict[str, Any]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for item in _list(context.get("discovery"))[:LLM_CONTEXT_ITEMS_LIMIT]:
        if not isinstance(item, dict):
            continue
        memory = item.get("memory") if isinstance(item.get("memory"), list) else []
        report = next(
            (
                memory_item.get("content")
                for memory_item in reversed(memory)
                if isinstance(memory_item, dict) and memory_item.get("kind") in {"llm_report", "summary", "source_index"}
            ),
            {},
        )
        summaries.append(
            {
                "asset_id": item.get("asset_id"),
                "asset_type": item.get("asset_type"),
                "path": item.get("path"),
                "summary": _llm_compact_value(report, LLM_CONTEXT_TEXT_LIMIT),
                "report_excerpt": _truncate(_text(item.get("report")), LLM_CONTEXT_TEXT_LIMIT),
            }
        )
    return summaries


def _llm_compact_value(value: Any, limit: int) -> Any:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, str):
        return _truncate(value, limit)
    try:
        return _truncate(json.dumps(value, sort_keys=True), limit)
    except TypeError:
        return _truncate(_text(value), limit)


def _parse_llm_chat_result(
    raw_response: str,
    user_message: ConversationMessage,
    context: dict[str, Any],
) -> EngagementChatResult:
    engagement_id = _context_engagement_id(context)
    try:
        parsed = _extract_json_object(raw_response)
    except ValueError:
        plain_answer = _plain_text_model_answer(raw_response)
        if not plain_answer or _looks_jsonish(raw_response):
            raise
        return EngagementChatResult(
            response=_repair_invalid_cli_commands(plain_answer, engagement_id),
            directives=[],
            artifact_refs=_artifact_refs_for_question(context, user_message.content),
        )
    answer = _text(parsed.get("answer"))
    if not answer:
        raise ValueError("chat model response JSON did not contain a non-empty `answer`")
    answer = _repair_invalid_cli_commands(answer, engagement_id)
    artifact_refs = _string_list(parsed.get("artifact_refs"))
    if not artifact_refs:
        facts = _structured_answer_from_context(context, user_message.content)
        artifact_refs = facts[1] if facts else []
    directives = [
        directive
        for directive in (
            _normalize_llm_directive(item, user_message)
            for item in _list(parsed.get("directives"))
            if isinstance(item, dict)
        )
        if directive is not None
    ]
    return EngagementChatResult(response=answer, directives=directives, artifact_refs=artifact_refs)


def _context_engagement_id(context: dict[str, Any]) -> str:
    engagement = context.get("engagement") if isinstance(context.get("engagement"), dict) else {}
    return _text(engagement.get("id")) or "<engagement_id>"


def _repair_invalid_cli_commands(answer: str, engagement_id: str) -> str:
    def replace(match: re.Match[str]) -> str:
        prefix = match.group("prefix")
        test_id = match.group("test_id")
        return f"{prefix}mosh test {engagement_id} --hypothesis {test_id}"

    return re.sub(
        r"(?P<prefix>(?:uv run\s+)?)mosh\s+test\s+(?P<test_id>[A-Z][A-Z0-9_]+-\d+)(?!\s+--hypothesis)",
        replace,
        answer,
    )


def _plain_text_model_answer(raw_response: str) -> str:
    text = raw_response.strip()
    if not text:
        return ""
    if text.startswith("```"):
        text = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _looks_jsonish(raw_response: str) -> bool:
    text = raw_response.lstrip()
    return text.startswith("{") or text.startswith("[") or text.startswith("```json")


def _artifact_refs_for_question(context: dict[str, Any], question: str) -> list[str]:
    structured = _structured_answer_from_context(context, question)
    if structured:
        return structured[1]
    return [snippet["ref"] for snippet in _matching_context_snippets(context, question)[:5]]


def _looks_like_incomplete_chat_answer(answer: str) -> bool:
    text = answer.strip()
    if not text:
        return True
    lowered = text.lower()
    if lowered.endswith(("the next steps are:", "next steps are:", "the steps are:", "steps are:")):
        return True
    return bool(text.endswith(":") and re.search(r"\b(next steps|steps|actions|tasks|items|following)\b", lowered))


def _merge_heuristic_directives(
    result: EngagementChatResult,
    user_message: ConversationMessage,
) -> EngagementChatResult:
    heuristic = [directive.to_dict() for directive in extract_directives(user_message.content, user_message.id)]
    if not heuristic:
        return result
    model_keys = {_directive_intent_key(directive) for directive in result.directives}
    heuristic = [
        directive
        for directive in heuristic
        if _directive_intent_key(directive) not in model_keys
    ]
    if not heuristic:
        return result
    return EngagementChatResult(
        response=result.response,
        directives=_dedupe_directive_dicts([*result.directives, *heuristic]),
        artifact_refs=result.artifact_refs,
    )


def _directive_intent_key(directive: dict[str, Any]) -> str:
    return json.dumps(
        {
            "kind": directive.get("kind"),
            "instruction": directive.get("instruction"),
            "source_message_id": directive.get("source_message_id"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _dedupe_directive_dicts(directives: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in directives:
        if not isinstance(item, dict):
            continue
        fingerprint = _directive_duplicate_fingerprint(item)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(item)
    return result


def _extract_json_object(raw_response: str) -> dict[str, Any]:
    text = raw_response.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("chat model did not return JSON")
        parsed = json.loads(text[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("chat model response must be a JSON object")
    return parsed


def _normalize_llm_directive(value: dict[str, Any], user_message: ConversationMessage) -> dict[str, Any] | None:
    kind = _text(value.get("kind")).lower().replace("-", "_")
    if kind not in VALID_DIRECTIVE_KINDS:
        return None
    stages = [str(item) for item in _list(value.get("stages")) if _text(item)]
    if not stages:
        stages = DIRECTIVE_DEFAULT_STAGES[kind]
    target = value.get("target") if isinstance(value.get("target"), dict) else {}
    directive = ConversationDirective(
        id=_text(value.get("id")) or _new_id("dir"),
        kind=kind,
        instruction=_text(value.get("instruction")) or user_message.content,
        source_message_id=user_message.id,
        stages=stages,
        target=target,
        status=_text(value.get("status")) or "active",
        confidence=_text(value.get("confidence")) or "model",
    )
    return directive.to_dict()


def _string_list(value: Any) -> list[str]:
    return [_text(item) for item in _list(value) if _text(item)]


def _answer_from_context(context: dict[str, Any], message: str) -> tuple[str, list[str]]:
    if not _looks_like_question(message):
        return "", []
    structured_answer = _structured_answer_from_context(context, message)
    if structured_answer:
        return structured_answer
    hypothesis_ids = _extract_hypothesis_ids(message)
    if hypothesis_ids and "block" in message.lower():
        answer = _blocked_hypothesis_answer(context, hypothesis_ids[0])
        if answer:
            return answer

    snippets = _matching_context_snippets(context, message)
    if snippets:
        refs = [snippet["ref"] for snippet in snippets]
        lines = ["Relevant engagement context:"]
        for snippet in snippets[:5]:
            lines.append(f"- `{snippet['ref']}`: {snippet['text']}")
        return "\n".join(lines), refs

    stages = _available_context_stages(context)
    stage_text = ", ".join(stages) if stages else "no completed stage artifacts"
    return f"I do not have a precise matching artifact for that question yet. Available context: {stage_text}.", []


def _looks_like_question(message: str) -> bool:
    stripped = message.strip().lower()
    return stripped.endswith("?") or stripped.split(" ", 1)[0] in {
        "what",
        "why",
        "how",
        "which",
        "where",
        "when",
        "who",
        "list",
        "show",
        "summarize",
        "summarise",
    }


def _looks_like_pure_question(message: str) -> bool:
    if not _looks_like_question(message):
        return False
    lowered = message.lower()
    directive_markers = (
        "mark",
        "record",
        "treat",
        "consider",
        "please",
        "should",
        "do not",
        "don't",
        "exclude",
        "include",
        "use ",
        "run ",
        "focus",
    )
    return not any(marker in lowered for marker in directive_markers)


def _structured_answer_from_context(context: dict[str, Any], message: str) -> tuple[str, list[str]] | None:
    lowered = message.lower()
    hypothesis_ids = _extract_hypothesis_ids(message)
    if hypothesis_ids and "block" in lowered:
        return _blocked_hypothesis_structured_answer(context, hypothesis_ids[0])
    if _asks_highest_finding(lowered):
        return _highest_finding_answer(context)
    if _asks_blocked_tests(lowered):
        return _blocked_tests_answer(context)
    if _asks_findings(lowered):
        return _findings_answer(context)
    if _asks_stage_status(lowered):
        return _stage_status_answer(context)
    return None


def _asks_highest_finding(lowered: str) -> bool:
    return "finding" in lowered and any(marker in lowered for marker in ("highest", "most severe", "top", "worst", "critical"))


def _asks_blocked_tests(lowered: str) -> bool:
    return "block" in lowered and any(marker in lowered for marker in ("test", "currently", "current", "what", "which", "list"))


def _asks_findings(lowered: str) -> bool:
    return "finding" in lowered and any(marker in lowered for marker in ("list", "show", "what", "which", "all"))


def _asks_stage_status(lowered: str) -> bool:
    return any(marker in lowered for marker in ("status", "state", "progress")) and any(
        marker in lowered for marker in ("engagement", "stage", "assessment", "current")
    )


def _highest_finding_answer(context: dict[str, Any]) -> tuple[str, list[str]]:
    findings = _accepted_findings_from_context(context)
    if not findings:
        return ("No reviewer-accepted findings are recorded yet.", _existing_refs(_testing_refs(context)))
    findings.sort(key=_finding_sort_key)
    highest = findings[0]
    same_severity = [
        finding
        for finding in findings[1:]
        if _severity_rank(finding.get("severity")) == _severity_rank(highest.get("severity"))
    ]
    lines = [
        f"Highest confirmed finding: `{highest['id']}` ({_severity_label(highest.get('severity'))}).",
        "",
        _text(highest.get("title")) or "Untitled finding.",
    ]
    summary = _text(highest.get("summary") or highest.get("result"))
    if summary:
        lines.extend(["", f"Summary: {summary}"])
    if same_severity:
        peers = ", ".join(f"`{finding['id']}`" for finding in same_severity[:5])
        lines.extend(["", f"Other finding(s) at the same severity: {peers}."])
    report_path = _text(highest.get("path"))
    if report_path:
        lines.extend(["", f"Source: `{report_path}`"])
    return "\n".join(lines), [report_path] if report_path else []


def _blocked_tests_answer(context: dict[str, Any]) -> tuple[str, list[str]]:
    blocked = _blocked_tests_from_context(context)
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    preflight_ref = str(Path(_text(testing.get("path")) or "security-testing") / "preflight.md")
    if not blocked:
        counts = _preflight_counts(context)
        detail = ""
        if counts:
            detail = f" Ready: `{counts.get('ready', 0)}`. Deferred: `{counts.get('deferred', 0)}`."
        return (f"No tests are currently blocked.{detail}", [preflight_ref] if _text(testing.get("preflight")) else [])
    lines = [f"Currently blocked: `{len(blocked)}` test(s).", ""]
    for item in blocked:
        lines.append(f"- `{item['id']}`: {item['title']} ({_text(item.get('priority')) or 'unknown'})")
        for blocker in _list(item.get("blockers")):
            blocker_text = _text(blocker)
            if blocker_text:
                lines.append(f"  - {blocker_text}")
                guidance = _unblock_guidance(blocker_text)
                if guidance != blocker_text:
                    lines.append(f"    Update: {guidance}")
    lines.extend(["", f"Source: `{preflight_ref}`"])
    return "\n".join(lines), [preflight_ref]


def _blocked_hypothesis_structured_answer(context: dict[str, Any], hypothesis_id: str) -> tuple[str, list[str]] | None:
    blocked = [item for item in _blocked_tests_from_context(context) if item.get("id") == hypothesis_id]
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    preflight_ref = str(Path(_text(testing.get("path")) or "security-testing") / "preflight.md")
    if not blocked:
        return None
    item = blocked[0]
    lines = [f"`{hypothesis_id}` is currently blocked: {item['title']}.", ""]
    blockers = [blocker for blocker in _list(item.get("blockers")) if _text(blocker)]
    if blockers:
        lines.append("Blockers:")
        for blocker in blockers:
            blocker_text = _text(blocker)
            lines.append(f"- {blocker_text}")
            guidance = _unblock_guidance(blocker_text)
            if guidance != blocker_text:
                lines.append(f"  Update: {guidance}")
    lines.extend(["", f"Source: `{preflight_ref}`"])
    return "\n".join(lines), [preflight_ref]


def _findings_answer(context: dict[str, Any]) -> tuple[str, list[str]]:
    findings = _accepted_findings_from_context(context)
    if not findings:
        return ("No reviewer-accepted findings are recorded yet.", _existing_refs(_testing_refs(context)))
    findings.sort(key=_finding_sort_key)
    lines = [f"Confirmed findings: `{len(findings)}`.", ""]
    refs: list[str] = []
    for finding in findings:
        path = _text(finding.get("path"))
        if path:
            refs.append(path)
        lines.append(
            f"- `{finding['id']}` ({_severity_label(finding.get('severity'))}): "
            f"{_text(finding.get('title')) or 'Untitled finding'}"
        )
    return "\n".join(lines), refs


def _stage_status_answer(context: dict[str, Any]) -> tuple[str, list[str]]:
    stages = _available_context_stages(context)
    counts = _preflight_counts(context)
    findings = _accepted_findings_from_context(context)
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    executed = _list(testing.get("executed_tests"))
    lines = ["Engagement status:"]
    lines.append(f"- Completed context available: {', '.join(stages) if stages else 'none'}.")
    if counts:
        lines.append(
            "- Testing preflight: "
            f"`{counts.get('ready', 0)}` ready, "
            f"`{counts.get('blocked', 0)}` blocked, "
            f"`{counts.get('deferred', 0)}` deferred."
        )
    if executed:
        lines.append(f"- Executed test reports: `{len(executed)}`.")
    lines.append(f"- Confirmed findings: `{len(findings)}`.")
    refs = _existing_refs(_testing_refs(context) + _planning_refs(context))
    if refs:
        lines.extend(["", "Sources:"])
        lines.extend(f"- `{ref}`" for ref in refs[:5])
    return "\n".join(lines), refs


def _accepted_findings_from_context(context: dict[str, Any]) -> list[dict[str, Any]]:
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    findings: list[dict[str, Any]] = []
    for item in _list(testing.get("executed_tests")):
        if not isinstance(item, dict):
            continue
        status = _canonical_status(item.get("status") or (item.get("metadata") or {}).get("status"))
        if status != "finding":
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        if item.get("review_accepted") is False or metadata.get("review_accepted") is False:
            continue
        findings.append(item)
    return findings


def _blocked_tests_from_context(context: dict[str, Any]) -> list[dict[str, Any]]:
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    preflight = testing.get("preflight_state") if isinstance(testing.get("preflight_state"), dict) else {}
    blocked = preflight.get("blocked") if isinstance(preflight.get("blocked"), list) else []
    return [item for item in blocked if isinstance(item, dict)]


def _preflight_counts(context: dict[str, Any]) -> dict[str, int]:
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    preflight = testing.get("preflight_state") if isinstance(testing.get("preflight_state"), dict) else {}
    if not preflight:
        return {}
    return {
        "ready": len(_list(preflight.get("ready"))),
        "blocked": len(_list(preflight.get("blocked"))),
        "deferred": len(_list(preflight.get("deferred"))),
    }


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, str]:
    return (_severity_rank(finding.get("severity")), _text(finding.get("id")))


def _severity_rank(value: Any) -> int:
    return SEVERITY_ORDER.get(_text(value).lower().replace("_", "-"), SEVERITY_ORDER["unknown"])


def _severity_label(value: Any) -> str:
    text = _text(value) or "unknown"
    return text.lower().replace("_", "-")


def _canonical_status(value: Any) -> str:
    text = _text(value).lower().replace("_", "-")
    if text in {"finding", "no-finding", "inconclusive", "failed"}:
        return text
    if "no finding" in text:
        return "no-finding"
    if "finding" in text:
        return "finding"
    if "failed" in text:
        return "failed"
    if "inconclusive" in text:
        return "inconclusive"
    return text


def _testing_refs(context: dict[str, Any]) -> list[str]:
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    refs = []
    if _text(testing.get("preflight")):
        refs.append(str(Path(_text(testing.get("path")) or "security-testing") / "preflight.md"))
    refs.extend(_text(item.get("path")) for item in _list(testing.get("executed_tests")) if isinstance(item, dict))
    return refs


def _planning_refs(context: dict[str, Any]) -> list[str]:
    planning = context.get("planning") if isinstance(context.get("planning"), dict) else {}
    refs = []
    if _text(planning.get("report")):
        refs.append(str(Path(_text(planning.get("path")) or "plan") / "plan.md"))
    return refs


def _existing_refs(refs: list[str]) -> list[str]:
    return [ref for ref in refs if ref]


def _unblock_guidance(blocker: str) -> str:
    guidance = {
        "authorization_confirmed is not true in the engagement file": (
            "set `engagement.authorization_confirmed` to `true` after confirming authorization."
        ),
        "active_testing_allowed is not true in the engagement file": (
            "set `engagement.active_testing_allowed` to `true` once active testing is approved."
        ),
        "state_changing_tests_allowed is not true for this state-changing test": (
            "set `engagement.state_changing_tests_allowed` to `true` if state-changing tests are approved."
        ),
        "no effective target mappings were resolved": (
            "add at least one non-empty URL under `targets.production` or `targets.alternative`."
        ),
        "live target URL is not available for this assessment": "attach or map a live URL target.",
        "source code is not available for this hypothesis": "attach a source tree asset and run source discovery.",
    }
    if blocker in guidance:
        return guidance[blocker]
    if blocker.startswith("missing credential material for "):
        role = blocker.removeprefix("missing credential material for ").strip()
        return f"add `credentials.{role}.token` or both `credentials.{role}.username` and `credentials.{role}.password`."
    if blocker.startswith("missing safe_test_data."):
        key = blocker.removeprefix("missing safe_test_data.").strip()
        return f"add a non-empty `safe_test_data.{key}` value."
    if blocker.startswith("dependency `"):
        return "run the dependency test first and ensure its accepted execution report is current."
    return blocker


def _blocked_hypothesis_answer(context: dict[str, Any], hypothesis_id: str) -> tuple[str, list[str]] | None:
    preflight = _text(((context.get("testing") or {}).get("preflight")))
    if not preflight:
        return None
    lines = preflight.splitlines()
    matches = [index for index, line in enumerate(lines) if hypothesis_id in line]
    if not matches:
        return None
    start = max(0, matches[0] - 2)
    end = min(len(lines), matches[0] + 6)
    excerpt = " ".join(line.strip() for line in lines[start:end] if line.strip())
    ref = str(((context.get("testing") or {}).get("path") or "security-testing") + "/preflight.md")
    return f"`{hypothesis_id}` appears in the testing preflight: {excerpt}", [ref]


def _matching_context_snippets(context: dict[str, Any], message: str) -> list[dict[str, str]]:
    terms = _query_terms(message)
    if not terms:
        return []
    snippets: list[dict[str, str]] = []
    for ref, text in _context_text_sources(context):
        lowered = text.lower()
        score = sum(1 for term in terms if term in lowered)
        if score <= 0:
            continue
        snippets.append({"ref": ref, "text": _matching_excerpt(text, terms), "score": str(score)})
    snippets.sort(key=lambda item: int(item["score"]), reverse=True)
    return snippets[:8]


def _query_terms(message: str) -> list[str]:
    stop = {
        "about",
        "after",
        "around",
        "engagement",
        "what",
        "where",
        "which",
        "with",
        "from",
        "that",
        "this",
        "there",
        "were",
        "have",
        "does",
        "did",
        "the",
        "and",
        "for",
        "why",
        "how",
        "was",
    }
    return [
        term
        for term in re.findall(r"[A-Za-z0-9_/-]{4,}", message.lower())
        if term not in stop
    ][:8]


def _context_text_sources(context: dict[str, Any]) -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []
    for discovery in _list(context.get("discovery")):
        if not isinstance(discovery, dict):
            continue
        ref = f"{discovery.get('path')}/report.md"
        sources.append((ref, _text(discovery.get("report"))))
        sources.append((f"{discovery.get('path')}/memory.json", json.dumps(discovery.get("memory"), sort_keys=True)))
    planning = context.get("planning") if isinstance(context.get("planning"), dict) else {}
    sources.append((f"{planning.get('path')}/plan.md", _text(planning.get("report"))))
    sources.append((f"{planning.get('path')}/memory.json", json.dumps(planning.get("memory"), sort_keys=True)))
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    sources.append((f"{testing.get('path')}/preflight.md", _text(testing.get("preflight"))))
    for executed in _list(testing.get("executed_tests")):
        if isinstance(executed, dict):
            sources.append((_text(executed.get("path")), _text(executed.get("content"))))
    final_report = context.get("final_report") if isinstance(context.get("final_report"), dict) else {}
    sources.append((_text(final_report.get("path")), _text(final_report.get("content"))))
    conversation = context.get("conversation") if isinstance(context.get("conversation"), dict) else {}
    sources.append(("conversation/directives.json", json.dumps(conversation.get("active_directives"), sort_keys=True)))
    return [(ref, text) for ref, text in sources if ref and text]


def _matching_excerpt(text: str, terms: list[str]) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    lowered = compact.lower()
    indexes = [lowered.find(term) for term in terms if lowered.find(term) >= 0]
    start = max(0, min(indexes) - 120) if indexes else 0
    end = min(len(compact), start + 360)
    excerpt = compact[start:end].strip()
    if start > 0:
        excerpt = "..." + excerpt
    if end < len(compact):
        excerpt += "..."
    return excerpt


def _available_context_stages(context: dict[str, Any]) -> list[str]:
    stages: list[str] = []
    if context.get("discovery"):
        stages.append("discovery")
    planning = context.get("planning") if isinstance(context.get("planning"), dict) else {}
    if planning.get("report") or planning.get("memory"):
        stages.append("planning")
    testing = context.get("testing") if isinstance(context.get("testing"), dict) else {}
    if testing.get("preflight") or testing.get("memory") or testing.get("executed_tests"):
        stages.append("testing")
    final_report = context.get("final_report") if isinstance(context.get("final_report"), dict) else {}
    if final_report.get("content"):
        stages.append("final-report")
    return stages


def _render_recorded_directives(directives: list[dict[str, Any]]) -> str:
    lines = ["Recorded engagement directive" + ("s" if len(directives) != 1 else "") + ":"]
    for directive in directives:
        stages = ", ".join(_list(directive.get("stages")))
        lines.append(f"- `{directive.get('kind')}` for {stages}: {directive.get('instruction')}")
    lines.append("Relevant future crew stages will include these directives in their context.")
    return "\n".join(lines)


def _executed_test_context(testing_dir: Path) -> list[dict[str, Any]]:
    executed_dir = testing_dir / "executed_tests"
    if not executed_dir.exists():
        return []
    results: list[dict[str, Any]] = []
    for path in sorted(executed_dir.glob("*.md"))[:CONTEXT_EXECUTED_REPORTS_LIMIT]:
        full_text = path.read_text(encoding="utf-8")
        metadata = _extract_execution_metadata(full_text) or {}
        body = _strip_execution_metadata(full_text)
        content = _truncate(full_text, CONTEXT_TEXT_LIMIT)
        status = _canonical_status(metadata.get("status") or _extract_section(body, "Status"))
        priority = (
            _text(metadata.get("severity"))
            or _text(metadata.get("priority"))
            or _extract_scope_value(body, "Priority")
            or "unknown"
        )
        results.append(
            {
                "id": _text(metadata.get("test_id")) or path.stem,
                "path": str(path),
                "metadata": metadata,
                "title": _extract_markdown_title(body) or path.stem,
                "status": status or "unknown",
                "review_accepted": bool(metadata.get("review_accepted")),
                "severity": priority,
                "surface": _extract_scope_value(body, "Surface"),
                "summary": _extract_section(body, "Summary"),
                "result": _extract_section(body, "Result"),
                "content": content,
            }
        )
    return results


def _latest_structured_plan(path: Path) -> dict[str, Any]:
    content = _latest_memory_content(path, "security_test_plan_final")
    structured = content.get("structured") if isinstance(content.get("structured"), dict) else {}
    if structured:
        return _compact_value(structured)
    content = _latest_memory_content(path, "security_test_plan_draft")
    structured = content.get("structured") if isinstance(content.get("structured"), dict) else {}
    return _compact_value(structured) if structured else {}


def _latest_memory_content(path: Path, kind: str) -> dict[str, Any]:
    items = _read_json(path, [])
    if not isinstance(items, list):
        return {}
    for item in reversed(items):
        if not isinstance(item, dict) or item.get("kind") != kind:
            continue
        content = item.get("content")
        return content if isinstance(content, dict) else {}
    return {}


def _compact_memory(path: Path) -> list[dict[str, Any]]:
    items = _read_json(path, [])
    if not isinstance(items, list):
        return []
    compact: list[dict[str, Any]] = []
    for item in items[-CONTEXT_MEMORY_ITEMS_LIMIT:]:
        if not isinstance(item, dict):
            continue
        compact.append(
            {
                "kind": item.get("kind"),
                "source": item.get("source"),
                "timestamp": item.get("timestamp"),
                "content": _compact_value(item.get("content")),
            }
        )
    return compact


def _compact_value(value: Any) -> Any:
    if isinstance(value, str):
        return _truncate(value, CONTEXT_TEXT_LIMIT)
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 80:
                compact["_omitted_keys"] = len(value) - 80
                break
            compact[str(key)] = _compact_value(item)
        return compact
    if isinstance(value, list):
        compact_list = [_compact_value(item) for item in value[:80]]
        if len(value) > 80:
            compact_list.append({"_omitted_items": len(value) - 80})
        return compact_list
    return value


def _extract_execution_metadata(markdown: str) -> dict[str, Any] | None:
    if not markdown.startswith(EXECUTION_METADATA_START):
        return None
    end = markdown.find(EXECUTION_METADATA_END)
    if end < 0:
        return None
    payload = markdown[len(EXECUTION_METADATA_START) : end].strip()
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _strip_execution_metadata(markdown: str) -> str:
    if not markdown.startswith(EXECUTION_METADATA_START):
        return markdown
    end = markdown.find(EXECUTION_METADATA_END)
    if end < 0:
        return markdown
    return markdown[end + len(EXECUTION_METADATA_END) :].lstrip()


def _extract_markdown_title(markdown: str) -> str:
    match = re.search(r"^#\s+(.+)$", markdown, flags=re.MULTILINE)
    if not match:
        return ""
    return match.group(1).strip()


def _extract_scope_value(markdown: str, label: str) -> str:
    pattern = rf"^\s*-\s*{re.escape(label)}:\s*`?([^`\n]+)`?\s*$"
    match = re.search(pattern, markdown, flags=re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else ""


def _extract_section(markdown: str, heading: str) -> str:
    pattern = rf"^##\s+{re.escape(heading)}\s*$"
    match = re.search(pattern, markdown, flags=re.IGNORECASE | re.MULTILINE)
    if not match:
        return ""
    start = match.end()
    next_heading = re.search(r"^##\s+", markdown[start:], flags=re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(markdown)
    return re.sub(r"\s+", " ", markdown[start:end]).strip()


def _read_text(path: Path, limit: int = CONTEXT_TEXT_LIMIT) -> str:
    if not path.exists():
        return ""
    return _truncate(path.read_text(encoding="utf-8"), limit)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _write_json(path: Path, data: Any) -> None:
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


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit].rstrip() + f"\n[mosh: truncated {len(value) - limit} characters]"


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


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
