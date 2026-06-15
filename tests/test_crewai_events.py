from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from mosh.memory import FileMemory


def _crewai_events_available() -> bool:
    try:
        import crewai.events
        return True
    except ModuleNotFoundError:
        return False


class MoshCrewAIEventListenerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.report_dir = Path(self.tmp.name)
        self.memory = FileMemory(self.report_dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_listener_initialization(self):
        from mosh.crews.events import MoshCrewAIEventListener

        listener = MoshCrewAIEventListener(self.memory)
        self.assertIsNotNone(listener)
        self.assertEqual(listener._memory, self.memory)
        self.assertEqual(listener._usage_path, self.report_dir / "usage.json")
        self.assertEqual(listener._event_buffer, [])
        self.assertEqual(listener._usage_buffer, [])

    def test_listener_has_setup_listeners_method(self):
        from mosh.crews.events import MoshCrewAIEventListener

        listener = MoshCrewAIEventListener(self.memory)
        self.assertTrue(hasattr(listener, "setup_listeners"))

    def test_setup_listeners_registers_handlers(self):
        from mosh.crews.events import MoshCrewAIEventListener

        listener = MoshCrewAIEventListener(self.memory)
        bus = MagicMock()
        listener.setup_listeners(bus)
        self.assertEqual(bus.on.call_count, 9)

    def test_record_buffers_events_not_writes_to_disk(self):
        from mosh.crews.events import MoshCrewAIEventListener

        listener = MoshCrewAIEventListener(self.memory)
        events_path = self.report_dir / "events.json"
        initial_events = json.loads(events_path.read_text(encoding="utf-8"))

        listener._record("crewai", "test_action", "test message", {"key": "value"})

        after_record = json.loads(events_path.read_text(encoding="utf-8"))
        self.assertEqual(len(after_record), len(initial_events))
        self.assertEqual(len(listener._event_buffer), 1)

    def test_flush_writes_buffered_events_to_disk(self):
        from mosh.crews.events import MoshCrewAIEventListener

        listener = MoshCrewAIEventListener(self.memory)
        events_path = self.report_dir / "events.json"

        listener._record("crewai", "action_1", "message 1", {})
        listener._record("crewai", "action_2", "message 2", {})
        listener._flush()

        events = json.loads(events_path.read_text(encoding="utf-8"))
        buffered = [e for e in events if e.get("agent") == "crewai"]
        self.assertEqual(len(buffered), 2)
        self.assertEqual(listener._event_buffer, [])

    def test_flush_preserves_existing_events(self):
        from mosh.crews.events import MoshCrewAIEventListener

        listener = MoshCrewAIEventListener(self.memory)
        events_path = self.report_dir / "events.json"
        initial_count = len(json.loads(events_path.read_text(encoding="utf-8")))

        listener._record("crewai", "new_action", "new", {})
        listener._flush()

        events = json.loads(events_path.read_text(encoding="utf-8"))
        self.assertEqual(len(events), initial_count + 1)

    def test_flush_writes_usage_buffer(self):
        from mosh.crews.events import MoshCrewAIEventListener

        listener = MoshCrewAIEventListener(self.memory)
        usage_path = self.report_dir / "usage.json"

        listener._usage_buffer.append(
            {"model": "m1", "agent_role": "a1", "prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
        )
        listener._usage_buffer.append(
            {"model": "m2", "agent_role": "a2", "prompt_tokens": 200, "completion_tokens": 100, "total_tokens": 300}
        )
        listener._flush()

        self.assertTrue(usage_path.exists())
        usage = json.loads(usage_path.read_text(encoding="utf-8"))
        self.assertEqual(len(usage), 2)
        self.assertEqual(usage[0]["total_tokens"], 150)
        self.assertEqual(listener._usage_buffer, [])

    def test_flush_with_corrupted_existing_json(self):
        from mosh.crews.events import MoshCrewAIEventListener

        listener = MoshCrewAIEventListener(self.memory)
        usage_path = self.report_dir / "usage.json"
        usage_path.write_text("not valid json", encoding="utf-8")

        listener._usage_buffer.append(
            {"model": "m1", "agent_role": "a1", "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 50}
        )
        listener._flush()

        usage = json.loads(usage_path.read_text(encoding="utf-8"))
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0]["total_tokens"], 50)

    @unittest.skipUnless(_crewai_events_available(), "crewai>=1.14.7 required")
    def test_crew_started_event_handler_buffers_then_flushes(self):
        from mosh.crews.events import (
            MoshCrewAIEventListener,
            CrewKickoffStartedEvent,
            CrewKickoffCompletedEvent,
        )

        handlers: dict[str, object] = {}

        class CapturingBus:
            def on(self, event_class):
                def decorator(fn):
                    handlers[event_class.__name__] = fn
                    return fn
                return decorator

        listener = MoshCrewAIEventListener(self.memory)
        bus = CapturingBus()
        listener.setup_listeners(bus)

        start_handler = handlers["CrewKickoffStartedEvent"]
        start_handler(MagicMock(), MagicMock(crew_name="test-crew"))
        self.assertEqual(len(listener._event_buffer), 1)

        done_handler = handlers["CrewKickoffCompletedEvent"]
        done_handler(MagicMock(), MagicMock(crew_name="test-crew"))
        self.assertEqual(len(listener._event_buffer), 0)

        events = json.loads((self.report_dir / "events.json").read_text(encoding="utf-8"))
        crew_events = [e for e in events if e.get("agent") == "crewai"]
        self.assertEqual(len(crew_events), 2)


if __name__ == "__main__":
    unittest.main()
