from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mosh.crews.harness_improvements import build_harness_improvement_tool
from mosh.engagements import create_engagement
from mosh.harness_improvements import (
    harness_improvements_path,
    iter_harness_improvements,
    load_harness_improvements,
    record_harness_improvement,
)
from mosh.memory import FileMemory


class FakeCrewAI:
    BaseModel = object
    BaseTool = object

    @staticmethod
    def Field(default=None, description: str = ""):
        return default


class HarnessImprovementTests(unittest.TestCase):
    def test_record_harness_improvement_upserts_by_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)

            first = record_harness_improvement(
                output_root,
                engagement.id,
                stage="testing",
                agent="executor",
                category="Tooling",
                impact="high",
                title="Add JWT claim diff tool",
                problem="JWT claims had to be decoded and compared manually.",
                suggestion="Add a bounded JWT decode and claim diff helper.",
                evidence=["AUTH-001"],
                source_ref="AUTH-001",
            )
            second = record_harness_improvement(
                output_root,
                engagement.id,
                stage="testing",
                agent="reviewer",
                category="tooling",
                impact="high",
                title="Add JWT claim diff tool",
                problem="JWT claims had to be decoded and compared manually.",
                suggestion="Add a bounded JWT decode and claim diff helper.",
                evidence=["AUTH-002"],
                source_ref="AUTH-002",
            )

            payload = load_harness_improvements(output_root, engagement.id)

            self.assertEqual(first["id"], second["id"])
            self.assertEqual(payload["schema"], "mosh.harness-improvements.v1")
            self.assertEqual(len(payload["suggestions"]), 1)
            suggestion = payload["suggestions"][0]
            self.assertEqual(suggestion["category"], "tooling")
            self.assertEqual(suggestion["impact"], "high")
            self.assertEqual(suggestion["evidence"], ["AUTH-001", "AUTH-002"])
            self.assertEqual(len(suggestion["occurrences"]), 2)
            self.assertEqual(suggestion["occurrences"][0]["stage"], "testing")
            self.assertEqual(suggestion["occurrences"][1]["agent"], "reviewer")

    def test_iter_harness_improvements_scans_engagements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            first = create_engagement(output_root)
            second = create_engagement(output_root)

            for engagement in [first, second]:
                record_harness_improvement(
                    output_root,
                    engagement.id,
                    stage="planning",
                    agent="planner",
                    category="prompt",
                    impact="medium",
                    title="Clarify deferred opportunity guidance",
                    problem="Planner mixed harness gaps with deferred tests.",
                    suggestion="Add prompt guidance separating harness feedback from test opportunities.",
                )

            suggestions = list(iter_harness_improvements(output_root))

            self.assertEqual({item["engagement_id"] for item in suggestions}, {first.id, second.id})
            self.assertEqual(len(suggestions), 2)

    def test_record_tool_writes_canonical_file_and_memory_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            report_dir = output_root / engagement.id / "security-testing"
            memory = FileMemory(report_dir)
            tool = build_harness_improvement_tool(FakeCrewAI, memory, stage="testing", agent="executor")

            result = json.loads(
                tool._run(
                    category="tooling",
                    impact="medium",
                    title="Add token parser",
                    problem="Token parsing required repeated shell snippets.",
                    suggestion="Provide a bounded token parser helper.",
                    evidence=["AUTH-001"],
                    source_ref="AUTH-001",
                )
            )

            payload = load_harness_improvements(output_root, engagement.id)
            memory_items = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))

            self.assertEqual(result["id"], payload["suggestions"][0]["id"])
            self.assertTrue(harness_improvements_path(output_root, engagement.id).exists())
            ref = next(item for item in memory_items if item["kind"] == "harness_improvement_ref")
            self.assertEqual(ref["content"]["id"], result["id"])
            self.assertEqual(set(ref["content"]), {"fingerprint", "id", "path"})


if __name__ == "__main__":
    unittest.main()
