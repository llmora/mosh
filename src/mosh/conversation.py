from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from mosh.engagements import asset_discovery_dir, engagement_dir, engagement_exists, load_engagement
from mosh.models import utc_now


CONVERSATION_SCHEMA = "mosh.conversation.v1"
DIRECTIVES_SCHEMA = "mosh.conversation-directives.v1"
CHAT_CONTEXT_SCHEMA = "mosh.engagement-chat-context.v1"

CONTEXT_TEXT_LIMIT = 6_000
CONTEXT_MEMORY_ITEMS_LIMIT = 80
CONTEXT_EXECUTED_REPORTS_LIMIT = 100

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


class EngagementChatOrchestrator:
    def __init__(
        self,
        output_root: Path = Path("report"),
        runner: EngagementChatRunner | None = None,
    ) -> None:
        self.output_root = output_root
        self.runner = runner or LocalEngagementChatRunner()

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

    if not pure_question and _looks_like_engagement_context(lowered) and not directives:
        directives.append(
            _directive(
                kind="engagement_context",
                instruction=text,
                source_message_id=source_message_id,
                stages=["planning", "reporting"],
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
        },
        "engagement_template": {
            "path": str(root / "engagement_template.yaml"),
            "content": _read_text(root / "engagement_template.yaml"),
        },
        "testing": {
            "path": str(testing_dir),
            "preflight": _read_text(testing_dir / "preflight.md"),
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


def _looks_like_engagement_context(lowered: str) -> bool:
    return any(marker in lowered for marker in ("business", "context", "user flow", "workflow", "domain", "customer"))


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


def _answer_from_context(context: dict[str, Any], message: str) -> tuple[str, list[str]]:
    if not _looks_like_question(message):
        return "", []
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
        text = _read_text(path)
        results.append(
            {
                "id": path.stem,
                "path": str(path),
                "content": text,
            }
        )
    return results


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
