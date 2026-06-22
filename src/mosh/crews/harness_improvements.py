from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mosh.harness_improvements import infer_engagement_location, record_harness_improvement
from mosh.memory import FileMemory


def build_harness_improvement_tool(crewai: Any, memory: FileMemory, *, stage: str, agent: str):
    class HarnessImprovementInput(crewai.BaseModel):
        category: str = crewai.Field(
            ...,
            description="Short category such as tooling, prompt, workflow, stage, output, or documentation.",
        )
        impact: str = crewai.Field(
            default="medium",
            description="Expected impact: critical, high, medium, low, or informational.",
        )
        title: str = crewai.Field(..., description="Short human-readable improvement title.")
        problem: str = crewai.Field(..., description="Observed harness limitation or repeated manual work.")
        suggestion: str = crewai.Field(..., description="Concrete improvement proposal for the mosh harness.")
        evidence: list[str] | str | None = crewai.Field(
            default=None,
            description="Optional short evidence, such as missing command output, blocked parser, or repeated task.",
        )
        source_ref: str | None = crewai.Field(
            default=None,
            description="Optional local reference such as a hypothesis ID, task name, route, or artifact path.",
        )

    class RecordHarnessImprovementTool(crewai.BaseTool):
        name: str = "record_harness_improvement"
        description: str = (
            "Record an internal mosh harness improvement suggestion for human review. "
            "Use this for missing tools, prompt improvements, workflow/stage improvements, "
            "or repeated manual work in the harness; do not use it for application vulnerabilities "
            "or normal engagement blockers."
        )
        args_schema: type[crewai.BaseModel] = HarnessImprovementInput

        def _run(
            self,
            category: str,
            title: str,
            problem: str,
            suggestion: str,
            impact: str = "medium",
            evidence: Any = None,
            source_ref: str | None = None,
        ) -> str:
            location = infer_engagement_location(memory.report_dir)
            if location is None:
                raise RuntimeError(
                    "Cannot infer engagement from report directory; "
                    "harness improvements are only available for engagement-backed stages."
                )
            output_root, engagement_id = location
            recorded = record_harness_improvement(
                output_root,
                engagement_id,
                stage=stage,
                agent=agent,
                category=category,
                impact=impact,
                title=title,
                problem=problem,
                suggestion=suggestion,
                evidence=evidence,
                source_ref=source_ref,
            )
            path = output_root / engagement_id / "harness_improvements.json"
            memory.add_item(
                "harness_improvement_ref",
                {
                    "id": recorded["id"],
                    "fingerprint": recorded["fingerprint"],
                    "path": str(path),
                },
                agent,
            )
            return json.dumps(
                {
                    "id": recorded["id"],
                    "fingerprint": recorded["fingerprint"],
                    "path": str(path),
                    "occurrences": len(recorded.get("occurrences") or []),
                },
                sort_keys=True,
            )

    return RecordHarnessImprovementTool()
