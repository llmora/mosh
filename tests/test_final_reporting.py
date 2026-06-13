from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from open_security_harness.config import AppConfig
from open_security_harness.crews.reporting.crew import (
    CrewAIFinalReportingCrewRunner,
    FinalReportState,
    _build_submit_final_report_review_tool,
    _build_write_final_report_tool,
    build_final_report_bundle,
)
from open_security_harness.crews.reporting.reporting import render_final_report
from open_security_harness.crews.security_testing.crew import (
    _with_execution_metadata_mapping,
    render_executed_test_report,
)
from open_security_harness.memory import FileMemory
from open_security_harness.scope import report_dir_name


class FakeCrewAI:
    BaseModel = object
    BaseTool = object

    @staticmethod
    def Field(default=None, description: str = ""):
        return default


class FakeRuntimeCrewAI(FakeCrewAI):
    class Process:
        sequential = "sequential"

    class LLM:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

    class Agent:
        def __init__(self, config, llm, tools, allow_delegation) -> None:
            self.config = config
            self.llm = llm
            self.tools = tools
            self.allow_delegation = allow_delegation

    class Task:
        def __init__(self, config, agent, callback=None) -> None:
            self.config = config
            self.agent = agent
            self.callback = callback

    class Crew:
        def __init__(self, agents, tasks, process, verbose) -> None:
            self.agents = agents
            self.tasks = tasks
            self.process = process
            self.verbose = verbose

        def kickoff(self, inputs):
            for task in self.tasks:
                for tool in task.agent.tools:
                    if tool.name == "write_final_report":
                        tool._run(
                            {
                                "executive_summary": "The engagement found one accepted finding.",
                                "detailed_findings": [
                                    {
                                        "id": "AUTH-001",
                                        "impact": "Unauthenticated users can access private API data.",
                                        "remediation": "Require authentication before returning private data.",
                                    }
                                ],
                            }
                        )
                    elif tool.name == "submit_final_report_review":
                        tool._run({"accepted": True, "summary": "Report matches the bundle.", "blocking_findings": []})
            return None

    @staticmethod
    def CrewBase(cls):
        if isinstance(getattr(cls, "agents_config", None), str):
            cls.agents_config = FakeRuntimeCrewAI._load_config_blocks(cls.agents_config)
        if isinstance(getattr(cls, "tasks_config", None), str):
            cls.tasks_config = FakeRuntimeCrewAI._load_config_blocks(cls.tasks_config)
        return cls

    @staticmethod
    def _load_config_blocks(path: str) -> dict[str, str]:
        blocks: dict[str, list[str]] = {}
        current_key: str | None = None
        current_block: list[str] = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                if current_key is not None:
                    blocks[current_key] = current_block
                current_key = line.rstrip()[:-1]
                current_block = []
            elif current_key is not None:
                current_block.append(line)
        if current_key is not None:
            blocks[current_key] = current_block
        return {key: "\n".join(value) for key, value in blocks.items()}

    @staticmethod
    def agent(fn):
        return fn

    @staticmethod
    def task(fn):
        return fn

    @staticmethod
    def crew(fn):
        return fn


class FinalReportingTests(unittest.TestCase):
    def test_reporting_crew_writes_and_reviews_customer_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)
            report_dir = domain_dir / "final-report"
            memory = FileMemory(report_dir)
            runner = CrewAIFinalReportingCrewRunner(AppConfig(openrouter_api_key="test-key"))

            with patch("open_security_harness.crews.reporting.crew._load_crewai", return_value=FakeRuntimeCrewAI):
                report_path = runner.run("https://example.test", report_dir, memory, bundle)

            markdown = report_path.read_text(encoding="utf-8")
            self.assertIn("# Open Security Harness Security Assessment Report", markdown)
            self.assertIn("## Executive Summary", markdown)
            self.assertIn("### At A Glance", markdown)
            self.assertIn("### What Was Tested", markdown)
            self.assertIn("### Overall Security Posture", markdown)
            self.assertIn("### Remediation Priorities", markdown)
            self.assertIn("## Engagement Overview", markdown)
            self.assertIn("## Summary of Findings", markdown)
            self.assertIn("| ID | Title | Severity | Status | Affected Area | Remediation Priority |", markdown)
            self.assertIn("## Key Discovery Areas", markdown)
            self.assertIn("## Detailed Findings", markdown)
            self.assertIn("## Tests With No Finding / Inconclusive", markdown)
            self.assertIn("## Appendix", markdown)
            self.assertIn("AUTH-001", markdown)
            self.assertIn("Critical", markdown)
            self.assertIn("CVSS: `Not scored`", markdown)
            self.assertNotIn("### HDR-001:", markdown)
            memory_items = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))
            self.assertTrue(any(item["kind"] == "final_report_review" for item in memory_items))

    def test_final_report_bundle_promotes_only_accepted_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)

        executed = bundle["executed_tests"]
        findings = [item for item in executed if item["accepted_finding"]]
        self.assertEqual([item["id"] for item in findings], ["AUTH-001"])
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertIsNone(findings[0]["cvss"])

    def test_final_report_bundle_reads_legacy_execution_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test", legacy_metadata=True)
            bundle = build_final_report_bundle("https://example.test", domain_dir)

        findings = [item for item in bundle["executed_tests"] if item["accepted_finding"]]
        self.assertEqual([item["id"] for item in findings], ["AUTH-001"])
        self.assertEqual(findings[0]["status"], "finding")
        self.assertEqual(findings[0]["review_accepted"], True)

    def test_final_report_bundle_uses_executed_report_priority_when_plan_no_longer_has_test(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            planning_memory = domain_dir / "security-test-planning" / "memory.json"
            plan_items = json.loads(planning_memory.read_text(encoding="utf-8"))
            plan_items[0]["content"]["structured"]["test_hypotheses"] = [
                item
                for item in plan_items[0]["content"]["structured"]["test_hypotheses"]
                if item["id"] != "AUTH-001"
            ]
            planning_memory.write_text(json.dumps(plan_items), encoding="utf-8")

            bundle = build_final_report_bundle("https://example.test", domain_dir)

        auth = next(item for item in bundle["executed_tests"] if item["id"] == "AUTH-001")
        self.assertEqual(auth["severity"], "critical")
        self.assertEqual(auth["surface"], "authentication")

    def test_writer_tool_rejects_unsupported_cvss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)
            report_dir = domain_dir / "final-report"
            state = FinalReportState(
                target_url="https://example.test",
                report_dir=report_dir,
                memory=FileMemory(report_dir),
                bundle=bundle,
            )
            tool = _build_write_final_report_tool(FakeCrewAI, state)

            with self.assertRaisesRegex(ValueError, "unsupported CVSS"):
                tool._run(
                    {
                        "detailed_findings": [
                            {
                                "id": "AUTH-001",
                                "cvss": {"score": "9.8", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                            }
                        ]
                    }
                )

    def test_writer_tool_rejects_complete_markdown_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)
            report_dir = domain_dir / "final-report"
            state = FinalReportState(
                target_url="https://example.test",
                report_dir=report_dir,
                memory=FileMemory(report_dir),
                bundle=bundle,
            )
            tool = _build_write_final_report_tool(FakeCrewAI, state)

            with self.assertRaisesRegex(ValueError, "structured narrative fields"):
                tool._run({"report": "# Complete Report\n\nThis bypasses the deterministic renderer."})

    def test_rendered_report_does_not_trust_writer_headline_severity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)
            bundle["executed_tests"][0]["severity"] = "unknown"

            markdown = render_final_report(
                "https://example.test",
                bundle,
                {"headline_risks": ["Critical AUTH-001 authentication failure"]},
            )

        headline_section = markdown.split("### Headline Risks", 1)[1].split("### Findings By Severity", 1)[0]
        self.assertIn("severity not classified", headline_section)
        self.assertNotIn("Critical", headline_section)

    def test_outcome_breakdown_counts_inconclusive_even_when_review_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            _write_executed_report(
                domain_dir / "security-testing" / "executed_tests",
                "XSS-001",
                "Search form reflected input",
                "inconclusive",
                False,
            )
            bundle = build_final_report_bundle("https://example.test", domain_dir)

            markdown = render_final_report("https://example.test", bundle, {})

        outcome_section = markdown.split("### Outcome Breakdown", 1)[1].split("## Key Discovery Areas", 1)[0]
        self.assertIn("| Inconclusive | 1 |", outcome_section)
        self.assertIn("| Reviewer-Rejected Finding | 0 |", outcome_section)

    def test_review_tool_does_not_fail_on_unstructured_false_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)
            report_dir = domain_dir / "final-report"
            state = FinalReportState(
                target_url="https://example.test",
                report_dir=report_dir,
                memory=FileMemory(report_dir),
                bundle=bundle,
                report_markdown=render_final_report("https://example.test", bundle, {}),
            )
            tool = _build_submit_final_report_review_tool(FakeCrewAI, state)

            tool._run({"accepted": False, "blocking_findings": []})

        self.assertTrue(state.review["accepted"])
        self.assertFalse(state.review["reviewer_accepted"])


def _write_report_inputs(root: Path, target_url: str, legacy_metadata: bool = False) -> Path:
    domain_dir = root / "report" / report_dir_name(target_url)
    discovery_dir = domain_dir / "discovery"
    planning_dir = domain_dir / "security-test-planning"
    testing_dir = domain_dir / "security-testing"
    executed_dir = testing_dir / "executed_tests"
    discovery_dir.mkdir(parents=True)
    planning_dir.mkdir(parents=True)
    executed_dir.mkdir(parents=True)

    discovery_dir.joinpath("report.md").write_text("# Discovery\n", encoding="utf-8")
    discovery_dir.joinpath("memory.json").write_text(
        json.dumps(
            [
                {
                    "kind": "llm_report",
                    "content": {
                        "structured": {
                            "executive_summary": "Discovery found an API surface.",
                            "key_discovered_areas": [{"title": "Private API", "detail": "/api/private"}],
                        }
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    discovery_dir.joinpath("events.json").write_text("[]", encoding="utf-8")

    plan = {
        "title": "Security Test Plan",
        "scope_summary": "Test private API and headers.",
        "test_hypotheses": [
            {
                "id": "AUTH-001",
                "title": "Private API requires authentication",
                "surface": "authentication",
                "priority": "critical",
            },
            {
                "id": "HDR-001",
                "title": "Security headers are present",
                "surface": "headers",
                "priority": "medium",
            },
        ],
    }
    planning_dir.joinpath("memory.json").write_text(
        json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]),
        encoding="utf-8",
    )
    planning_dir.joinpath("security_test_plan.md").write_text("# Security Test Plan\n", encoding="utf-8")

    _write_executed_report(executed_dir, "AUTH-001", "Private API requires authentication", "finding", True, legacy_metadata)
    _write_executed_report(executed_dir, "HDR-001", "Security headers are present", "no-finding", True, legacy_metadata)
    testing_dir.joinpath("preflight.md").write_text("# Preflight\n", encoding="utf-8")
    testing_dir.joinpath("memory.json").write_text(
        json.dumps(
            [
                {
                    "kind": "security_testing_preflight",
                    "content": {"ready": [{"id": "AUTH-001"}, {"id": "HDR-001"}], "blocked": [], "targets": {}},
                },
                {
                    "kind": "security_test_execution_bundle",
                    "content": {
                        "test_id": "AUTH-001",
                        "final_evidence": {
                            "status": "finding",
                            "summary": "Private API returned data without authentication.",
                            "result": "Authentication was not enforced.",
                        },
                        "final_review": {"accepted": True},
                    },
                },
                {
                    "kind": "security_test_execution_bundle",
                    "content": {
                        "test_id": "HDR-001",
                        "final_evidence": {"status": "no-finding", "summary": "Headers present."},
                        "final_review": {"accepted": True},
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    return domain_dir


def _write_executed_report(
    executed_dir: Path,
    test_id: str,
    title: str,
    status: str,
    accepted: bool,
    legacy_metadata: bool = False,
) -> None:
    markdown = render_executed_test_report(
        target_url="https://example.test",
        hypothesis={
            "id": test_id,
            "title": title,
            "priority": "critical" if status == "finding" else "medium",
            "surface": "authentication" if test_id == "AUTH-001" else "headers",
        },
        evidence={
            "status": status,
            "summary": f"{title} summary.",
            "result": f"{title} result.",
        },
        review={"accepted": accepted, "summary": "Accepted."},
        commands=[],
        report_content={
            "status": status,
            "summary": f"{title} summary.",
            "result": f"{title} result.",
            "resolution": "Fix the affected control." if status == "finding" else "No remediation required.",
        },
    )
    metadata = {
        "schema": "appsec-harness.security-test-execution.v1" if legacy_metadata else "osh.security-test-execution.v1",
        "test_id": test_id,
        "status": status,
        "review_accepted": accepted,
        "report_path": str(executed_dir / f"{test_id}.md"),
        "executed_at": "2026-06-13T06:40:12+00:00",
    }
    if legacy_metadata:
        with_metadata = f"<!-- appsec-harness-execution\n{json.dumps(metadata, sort_keys=True)}\n-->\n\n{markdown}"
    else:
        with_metadata = _with_execution_metadata_mapping(markdown, metadata)
    executed_dir.joinpath(f"{test_id}.md").write_text(with_metadata, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
