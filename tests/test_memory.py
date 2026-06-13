from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from mosh.memory import FileMemory


class FileMemoryTests(unittest.TestCase):
    def test_records_events_and_memory_items_as_json_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            events = []
            memory = FileMemory(Path(directory), event_sink=events.append)

            memory.record_event("agent", "start", "Starting")
            memory.add_item("finding", {"url": "https://example.com"}, "agent")

            stored_events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            stored_memory = json.loads((Path(directory) / "memory.json").read_text(encoding="utf-8"))

            self.assertEqual(len(stored_events), 2)
            self.assertEqual(len(stored_memory), 1)
            self.assertEqual(stored_memory[0]["kind"], "finding")
            self.assertEqual(len(events), 2)

    def test_concurrent_event_writes_keep_json_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            memory = FileMemory(Path(directory))

            def write_events(worker: int) -> None:
                for index in range(25):
                    memory.record_event("agent", "event", "Concurrent write", {"worker": worker, "index": index})

            threads = [threading.Thread(target=write_events, args=(worker,)) for worker in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            stored_events = json.loads((Path(directory) / "events.json").read_text(encoding="utf-8"))
            self.assertEqual(len(stored_events), 200)


if __name__ == "__main__":
    unittest.main()
