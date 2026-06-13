from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from mmosh.models import Event, MemoryItem


EventSink = Callable[[Event], None]


class FileMemory:
    def __init__(self, report_dir: Path, event_sink: EventSink | None = None) -> None:
        self.report_dir = report_dir
        self.event_sink = event_sink
        self.events_path = report_dir / "events.json"
        self.memory_path = report_dir / "memory.json"
        self._lock = threading.RLock()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self._write_json(self.events_path, [])
        self._write_json(self.memory_path, [])

    def record_event(
        self,
        agent: str,
        action: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> Event:
        with self._lock:
            event = Event(agent=agent, action=action, message=message, data=data or {})
            events = self._read_list(self.events_path)
            events.append(event.to_dict())
            self._write_json(self.events_path, events)
        if self.event_sink:
            self.event_sink(event)
        return event

    def add_item(self, kind: str, content: dict[str, Any], source: str) -> MemoryItem:
        with self._lock:
            item = MemoryItem(kind=kind, content=content, source=source)
            items = self._read_list(self.memory_path)
            items.append(item.to_dict())
            self._write_json(self.memory_path, items)
        self.record_event(
            source,
            "memory_write",
            f"Added {kind} to shared memory",
            {"kind": kind, "content": content},
        )
        return item

    @staticmethod
    def _read_list(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(f"{path} must contain a JSON list")
        return data

    @staticmethod
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
