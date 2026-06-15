from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mosh.memory import FileMemory

try:
    from crewai.events import (  # type: ignore[import-untyped]
        BaseEventListener,
        CrewKickoffStartedEvent,
        CrewKickoffCompletedEvent,
        AgentExecutionStartedEvent,
        AgentExecutionCompletedEvent,
        TaskStartedEvent,
        TaskCompletedEvent,
        ToolUsageEvent,
        LLMCallStartedEvent,
        LLMCallCompletedEvent,
    )

    _CREWAI_EVENTS_AVAILABLE = True
except ModuleNotFoundError:
    BaseEventListener = object  # type: ignore[misc,assignment]
    CrewKickoffStartedEvent = None  # type: ignore[misc,assignment]
    CrewKickoffCompletedEvent = None  # type: ignore[misc,assignment]
    AgentExecutionStartedEvent = None  # type: ignore[misc,assignment]
    AgentExecutionCompletedEvent = None  # type: ignore[misc,assignment]
    TaskStartedEvent = None  # type: ignore[misc,assignment]
    TaskCompletedEvent = None  # type: ignore[misc,assignment]
    ToolUsageEvent = None  # type: ignore[misc,assignment]
    LLMCallStartedEvent = None  # type: ignore[misc,assignment]
    LLMCallCompletedEvent = None  # type: ignore[misc,assignment]
    _CREWAI_EVENTS_AVAILABLE = False


def _require_crewai_events() -> None:
    if not _CREWAI_EVENTS_AVAILABLE:
        raise RuntimeError(
            "CrewAI events system is not available. "
            "Install project dependencies with `pip install -e .` "
            "and ensure crewai>=1.14.7 is installed."
        )


class MoshCrewAIEventListener(BaseEventListener):  # type: ignore[misc]
    """Persists all CrewAI internal events to FileMemory-backed files on disk.

    Events are buffered in memory during crew execution and flushed to disk
    when the crew completes.  This avoids slow read-modify-write cycles on
    ``events.json`` from blocking the agent pipeline.
    """

    def __init__(self, memory: FileMemory) -> None:
        super().__init__()
        self._memory = memory
        self._usage_path = memory.report_dir / "usage.json"
        self._event_buffer: list[dict[str, Any]] = []
        self._usage_buffer: list[dict[str, Any]] = []

    def _record(self, agent: str, action: str, message: str, data: dict[str, Any] | None = None) -> None:
        from mosh.models import Event

        event = Event(agent=agent, action=action, message=message, data=data or {})
        self._event_buffer.append(event.to_dict())
        if self._memory.event_sink:
            self._memory.event_sink(event)

    def _flush(self) -> None:
        if not self._event_buffer and not self._usage_buffer:
            return
        self._memory.report_dir.mkdir(parents=True, exist_ok=True)
        if self._event_buffer:
            _append_json_list(self._memory.report_dir / "events.json", self._event_buffer)
            self._event_buffer.clear()
        if self._usage_buffer:
            _append_json_list(self._usage_path, self._usage_buffer)
            self._usage_buffer.clear()

    def setup_listeners(self, crewai_event_bus: Any) -> None:
        @crewai_event_bus.on(CrewKickoffStartedEvent)
        def on_crew_started(source: Any, event: Any) -> None:
            self._record(
                "crewai",
                "crew_started",
                "Crew started",
                {
                    "crew_name": _safe_attr(event, "crew_name"),
                    "inputs": _truncate_dict(_safe_attr(event, "inputs"), 300),
                },
            )

        @crewai_event_bus.on(CrewKickoffCompletedEvent)
        def on_crew_completed(source: Any, event: Any) -> None:
            raw_usage = _safe_attr(event, "total_usage")
            usage = _safe_usage_dict(raw_usage)
            self._record(
                "crewai",
                "crew_completed",
                "Crew completed",
                {
                    "crew_name": _safe_attr(event, "crew_name"),
                    "total_usage": usage,
                    "output": _truncate(str(_safe_attr(event, "output", "")), 500),
                },
            )
            self._flush()

        @crewai_event_bus.on(AgentExecutionStartedEvent)
        def on_agent_started(source: Any, event: Any) -> None:
            agent_role = _safe_attr(_safe_attr(event, "agent"), "role", "")
            self._record(
                "crewai",
                "agent_started",
                "Agent execution started",
                {"agent_role": str(agent_role)},
            )

        @crewai_event_bus.on(AgentExecutionCompletedEvent)
        def on_agent_completed(source: Any, event: Any) -> None:
            agent_role = _safe_attr(_safe_attr(event, "agent"), "role", "")
            self._record(
                "crewai",
                "agent_completed",
                "Agent execution completed",
                {
                    "agent_role": str(agent_role),
                    "output": _truncate(str(_safe_attr(event, "output", "")), 500),
                },
            )

        @crewai_event_bus.on(TaskStartedEvent)
        def on_task_started(source: Any, event: Any) -> None:
            self._record(
                "crewai",
                "task_started",
                "Task started",
                {"task_name": _task_label(event)},
            )

        @crewai_event_bus.on(TaskCompletedEvent)
        def on_task_completed(source: Any, event: Any) -> None:
            self._record(
                "crewai",
                "task_completed",
                "Task completed",
                {
                    "task_name": _task_label(event),
                    "output": _truncate(str(_safe_attr(event, "output", "")), 500),
                },
            )

        @crewai_event_bus.on(ToolUsageEvent)
        def on_tool_used(source: Any, event: Any) -> None:
            self._record(
                "crewai",
                "tool_used",
                f"Tool used: {_safe_attr(event, 'tool_name', '')}",
                {
                    "tool_name": _safe_attr(event, "tool_name", ""),
                    "tool_input": _truncate(str(_safe_attr(event, "tool_args", "")), 300),
                },
            )

        @crewai_event_bus.on(LLMCallStartedEvent)
        def on_llm_call_started(source: Any, event: Any) -> None:
            self._record(
                "crewai",
                "llm_call_started",
                "LLM call started",
                {
                    "model": _safe_attr(event, "model", ""),
                    "agent_role": _safe_attr(event, "agent_role", ""),
                },
            )

        @crewai_event_bus.on(LLMCallCompletedEvent)
        def on_llm_call_completed(source: Any, event: Any) -> None:
            usage = _safe_attr(event, "usage")
            prompt_tokens = _usage_field(usage, "prompt_tokens")
            completion_tokens = _usage_field(usage, "completion_tokens")
            total_tokens = _usage_field(usage, "total_tokens")
            self._record(
                "crewai",
                "llm_call_completed",
                "LLM call completed",
                {
                    "model": _safe_attr(event, "model", ""),
                    "agent_role": _safe_attr(event, "agent_role", ""),
                    "tokens_prompt": prompt_tokens,
                    "tokens_completion": completion_tokens,
                    "tokens_total": total_tokens,
                },
            )
            model = _safe_attr(event, "model", "")
            if model:
                self._usage_buffer.append({
                    "model": model,
                    "agent_role": _safe_attr(event, "agent_role", ""),
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": total_tokens,
                })


def _task_label(event: Any) -> str:
    task = _safe_attr(event, "task")
    if task:
        if isinstance(task, dict):
            return task.get("name") or task.get("description", "")[:120] or "unknown"
        task_name = _safe_attr(task, "name") or _safe_attr(task, "description", "")
        if task_name:
            return str(task_name)[:120]
    description = _safe_attr(event, "description", "")
    return str(description)[:120] or "unknown"


def _safe_attr(obj: Any, name: str, default: Any = "") -> Any:
    return getattr(obj, name, default)


def _usage_field(usage: Any, name: str, default: int = 0) -> int:
    if usage is None:
        return default
    if isinstance(usage, dict):
        return int(usage.get(name, default))
    return int(_safe_attr(usage, name, default))


def _safe_usage_dict(usage: Any) -> dict[str, int]:
    if usage is None:
        return {}
    if isinstance(usage, dict):
        return {str(k): int(v) for k, v in usage.items() if isinstance(v, (int, float))}
    return {
        "prompt_tokens": int(_safe_attr(usage, "prompt_tokens", 0)),
        "completion_tokens": int(_safe_attr(usage, "completion_tokens", 0)),
        "total_tokens": int(_safe_attr(usage, "total_tokens", 0)),
    }


def _truncate(value: str, limit: int = 500) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _truncate_dict(value: Any, limit: int = 300) -> Any:
    if isinstance(value, dict):
        return {k: _truncate(str(v), limit) for k, v in value.items()}
    return _truncate(str(value), limit)


def _append_json_list(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: list[dict[str, Any]] = []
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            existing = data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            existing = []
    existing.extend(items)
    payload = json.dumps(existing, indent=2, sort_keys=True) + "\n"
    path.write_text(payload, encoding="utf-8")
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mosh.memory import FileMemory

try:
    from crewai.events import (  # type: ignore[import-untyped]
        BaseEventListener,
        CrewKickoffStartedEvent,
        CrewKickoffCompletedEvent,
        AgentExecutionStartedEvent,
        AgentExecutionCompletedEvent,
        TaskStartedEvent,
        TaskCompletedEvent,
        ToolUsageEvent,
        LLMCallStartedEvent,
        LLMCallCompletedEvent,
    )

    _CREWAI_EVENTS_AVAILABLE = True
except ModuleNotFoundError:
    BaseEventListener = object  # type: ignore[misc,assignment]
    CrewKickoffStartedEvent = None  # type: ignore[misc,assignment]
    CrewKickoffCompletedEvent = None  # type: ignore[misc,assignment]
    AgentExecutionStartedEvent = None  # type: ignore[misc,assignment]
    AgentExecutionCompletedEvent = None  # type: ignore[misc,assignment]
    TaskStartedEvent = None  # type: ignore[misc,assignment]
    TaskCompletedEvent = None  # type: ignore[misc,assignment]
    ToolUsageEvent = None  # type: ignore[misc,assignment]
    LLMCallStartedEvent = None  # type: ignore[misc,assignment]
    LLMCallCompletedEvent = None  # type: ignore[misc,assignment]
    _CREWAI_EVENTS_AVAILABLE = False


def _require_crewai_events() -> None:
    if not _CREWAI_EVENTS_AVAILABLE:
        raise RuntimeError(
            "CrewAI events system is not available. "
            "Install project dependencies with `pip install -e .` "
            "and ensure crewai>=1.14.7 is installed."
        )


class MoshCrewAIEventListener(BaseEventListener):  # type: ignore[misc]
    """Persists all CrewAI internal events to FileMemory-backed files on disk.

    Events are buffered in memory during crew execution and flushed to disk
    when the crew completes.  This avoids slow read-modify-write cycles on
    ``events.json`` from blocking the agent pipeline.
    """

    def __init__(self, memory: FileMemory) -> None:
        super().__init__()
        self._memory = memory
        self._usage_path = memory.report_dir / "usage.json"
        self._event_buffer: list[dict[str, Any]] = []
        self._usage_buffer: list[dict[str, Any]] = []

    def _record(self, agent: str, action: str, message: str, data: dict[str, Any] | None = None) -> None:
        from mosh.models import Event

        event = Event(agent=agent, action=action, message=message, data=data or {})
        self._event_buffer.append(event.to_dict())
        if self._memory.event_sink:
            self._memory.event_sink(event)

    def _flush(self) -> None:
        if not self._event_buffer and not self._usage_buffer:
            return
        self._memory.report_dir.mkdir(parents=True, exist_ok=True)
        if self._event_buffer:
            _append_json_list(self._memory.report_dir / "events.json", self._event_buffer)
            self._event_buffer.clear()
        if self._usage_buffer:
            _append_json_list(self._usage_path, self._usage_buffer)
            self._usage_buffer.clear()

    def setup_listeners(self, crewai_event_bus: Any) -> None:
        @crewai_event_bus.on(CrewKickoffStartedEvent)
        def on_crew_started(source: Any, event: Any) -> None:
            self._record(
                "crewai",
                "crew_started",
                "Crew started",
                {
                    "crew_name": _safe_attr(event, "crew_name"),
                    "inputs": _truncate_dict(_safe_attr(event, "inputs"), 300),
                },
            )

        @crewai_event_bus.on(CrewKickoffCompletedEvent)
        def on_crew_completed(source: Any, event: Any) -> None:
            raw_usage = _safe_attr(event, "total_usage")
            usage = _safe_usage_dict(raw_usage)
            self._record(
                "crewai",
                "crew_completed",
                "Crew completed",
                {
                    "crew_name": _safe_attr(event, "crew_name"),
                    "total_usage": usage,
                    "output": _truncate(str(_safe_attr(event, "output", "")), 500),
                },
            )
            self._flush()

        @crewai_event_bus.on(AgentExecutionStartedEvent)
        def on_agent_started(source: Any, event: Any) -> None:
            agent_role = _safe_attr(_safe_attr(event, "agent"), "role", "")
            self._record(
                "crewai",
                "agent_started",
                "Agent execution started",
                {"agent_role": str(agent_role)},
            )

        @crewai_event_bus.on(AgentExecutionCompletedEvent)
        def on_agent_completed(source: Any, event: Any) -> None:
            agent_role = _safe_attr(_safe_attr(event, "agent"), "role", "")
            self._record(
                "crewai",
                "agent_completed",
                "Agent execution completed",
                {
                    "agent_role": str(agent_role),
                    "output": _truncate(str(_safe_attr(event, "output", "")), 500),
                },
            )

        @crewai_event_bus.on(TaskStartedEvent)
        def on_task_started(source: Any, event: Any) -> None:
            self._record(
                "crewai",
                "task_started",
                "Task started",
                {"task_name": _task_label(event)},
            )

        @crewai_event_bus.on(TaskCompletedEvent)
        def on_task_completed(source: Any, event: Any) -> None:
            self._record(
                "crewai",
                "task_completed",
                "Task completed",
                {
                    "task_name": _task_label(event),
                    "output": _truncate(str(_safe_attr(event, "output", "")), 500),
                },
            )

        @crewai_event_bus.on(ToolUsageEvent)
        def on_tool_used(source: Any, event: Any) -> None:
            tool_input = _truncate(str(_safe_attr(event, "tool_args", "")), 300)
            self._record(
                "crewai",
                "tool_used",
                f"Tool used: {_safe_attr(event, 'tool_name', '')}",
                {
                    "tool_name": _safe_attr(event, "tool_name", ""),
                    "tool_input": _redact_secrets(tool_input),
                },
            )

        @crewai_event_bus.on(LLMCallStartedEvent)
        def on_llm_call_started(source: Any, event: Any) -> None:
            self._record(
                "crewai",
                "llm_call_started",
                "LLM call started",
                {
                    "model": _safe_attr(event, "model", ""),
                    "agent_role": _safe_attr(event, "agent_role", ""),
                },
            )

        @crewai_event_bus.on(LLMCallCompletedEvent)
        def on_llm_call_completed(source: Any, event: Any) -> None:
            usage = _safe_attr(event, "usage")
            prompt_tokens = _usage_field(usage, "prompt_tokens")
            completion_tokens = _usage_field(usage, "completion_tokens")
            total_tokens = _usage_field(usage, "total_tokens")
            self._record(
                "crewai",
                "llm_call_completed",
                "LLM call completed",
                {
                    "model": _safe_attr(event, "model", ""),
                    "agent_role": _safe_attr(event, "agent_role", ""),
                    "tokens_prompt": prompt_tokens,
                    "tokens_completion": completion_tokens,
                    "tokens_total": total_tokens,
                },
            )
            model = _safe_attr(event, "model", "")
            if model:
                self._usage_buffer.append({
                    "model": model,
                    "agent_role": _safe_attr(event, "agent_role", ""),
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": total_tokens,
                })


def _task_label(event: Any) -> str:
    task = _safe_attr(event, "task")
    if task:
        if isinstance(task, dict):
            return task.get("name") or task.get("description", "")[:120] or "unknown"
        task_name = _safe_attr(task, "name") or _safe_attr(task, "description", "")
        if task_name:
            return str(task_name)[:120]
    description = _safe_attr(event, "description", "")
    return str(description)[:120] or "unknown"


def _safe_attr(obj: Any, name: str, default: Any = "") -> Any:
    return getattr(obj, name, default)


def _usage_field(usage: Any, name: str, default: int = 0) -> int:
    if usage is None:
        return default
    if isinstance(usage, dict):
        return int(usage.get(name, default))
    return int(_safe_attr(usage, name, default))


def _safe_usage_dict(usage: Any) -> dict[str, int]:
    if usage is None:
        return {}
    if isinstance(usage, dict):
        return {str(k): int(v) for k, v in usage.items() if isinstance(v, (int, float))}
    return {
        "prompt_tokens": int(_safe_attr(usage, "prompt_tokens", 0)),
        "completion_tokens": int(_safe_attr(usage, "completion_tokens", 0)),
        "total_tokens": int(_safe_attr(usage, "total_tokens", 0)),
    }


def _truncate(value: str, limit: int = 500) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _truncate_dict(value: Any, limit: int = 300) -> Any:
    if isinstance(value, dict):
        return {k: _truncate(str(v), limit) for k, v in value.items()}
    return _truncate(str(value), limit)


def _append_json_list(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: list[dict[str, Any]] = []
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            existing = data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            existing = []
    existing.extend(items)
    payload = json.dumps(existing, indent=2, sort_keys=True) + "\n"
    path.write_text(payload, encoding="utf-8")


_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_BEARER_AUTH_RE = re.compile(
    r"(?i)(Authorization:\s*Bearer\s+)([^\s\"']+)"
)


def _redact_secrets(text: str) -> str:
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    text = _BEARER_AUTH_RE.sub(r"\1[REDACTED]", text)
    return text
