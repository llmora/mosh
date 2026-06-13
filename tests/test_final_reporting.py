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
from open_security_harness.crews.reporting.reporting import render_final_report, validate_rendered_report
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
                                "executive_summary": "The engagement found one confirmed finding.",
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
            self.assertIn("| Report Context | Details |", markdown)
            self.assertNotIn("| Executive Question | Answer |", markdown)
            self.assertIn("This assessment reviewed `https://example.test`.", markdown)
            self.assertIn("The application provides the following business capability:", markdown)
            self.assertNotIn("| Field | Value |", markdown)
            self.assertIn("### What Was Tested", markdown)
            self.assertIn("The assessment covered `https://example.test` and the areas of the service most relevant", markdown)
            self.assertIn("Example is a private API used for customer account operations.", markdown)
            self.assertIn("### Overall Security Posture", markdown)
            self.assertIn("### Remediation Priorities", markdown)
            self.assertIn("The engagement confirmed 1 finding", markdown)
            self.assertIn("The assessment confirmed 1 finding.", markdown)
            self.assertNotIn("accepted finding", markdown.lower())
            self.assertNotIn("accepted findings", markdown.lower())
            self.assertIn("Engagement timeline", markdown)
            self.assertIn("13th June 2026 06:00 UTC", markdown)
            self.assertIn("Discovery: `13th June 2026`", markdown)
            self.assertIn("Security test planning: `13th June 2026`", markdown)
            self.assertNotIn("Discovery: `13th June 2026 06:00 UTC`", markdown)
            self.assertIn("Final reporting:", markdown)
            self.assertIn("## Engagement Overview", markdown)
            self.assertIn("The engagement assessed `https://example.test` using the target mappings", markdown)
            self.assertIn("The recorded engagement activity ran from", markdown)
            self.assertIn("Scope and limitations:", markdown)
            self.assertIn("Testing approach:", markdown)
            self.assertIn("Lifecycle detail:", markdown)
            self.assertIn("## Summary of Findings", markdown)
            self.assertIn("The findings table is intended for prioritization.", markdown)
            self.assertIn("| ID | Title | Severity | Status | Affected Area | Remediation Priority |", markdown)
            self.assertIn("## Key Discovery Areas", markdown)
            self.assertIn("Discovery provides the context for interpreting the findings.", markdown)
            self.assertIn("## Detailed Findings", markdown)
            self.assertIn("## Tests With No Finding / Inconclusive", markdown)
            self.assertIn("They are not confirmed vulnerabilities", markdown)
            self.assertIn("## Appendix", markdown)
            self.assertIn("AUTH-001", markdown)
            self.assertIn("Critical", markdown)
            self.assertIn("CVSS: `Not scored`", markdown)
            self.assertIn("Technical fix guidance:", markdown)
            self.assertIn("Expected corrected behavior:", markdown)
            self.assertIn("Regression check:", markdown)
            self.assertNotIn("Recommended remediation plan:", markdown)
            self.assertNotIn("Assign an owner for `AUTH-001`", markdown)
            self.assertNotIn("### HDR-001:", markdown)
            memory_items = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))
            self.assertTrue(any(item["kind"] == "final_report_review" for item in memory_items))

    def test_rendered_report_fences_unclosed_markdown_from_source_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)
            bundle["executed_tests"][0]["resolution"] = (
                "Update the API authorization guard:\n\n"
                "```python\n"
                "if not request.user:\n"
                "    return deny()\n"
            )

            markdown = render_final_report("https://example.test", bundle, {})

        self.assertIn("````text\nUpdate the API authorization guard:", markdown)
        self.assertIn("```python", markdown)
        self.assertEqual(validate_rendered_report(bundle, markdown), [])

    def test_findings_table_is_sorted_by_severity_and_remediation_priority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)
            bundle["executed_tests"].extend(
                [
                    {
                        "id": "AAA-LOW",
                        "title": "Low severity finding",
                        "status": "finding",
                        "accepted_finding": True,
                        "review_accepted": True,
                        "severity": "low",
                        "surface": "headers",
                        "report_path": "AAA-LOW.md",
                    },
                    {
                        "id": "ZZZ-HIGH",
                        "title": "High severity finding",
                        "status": "finding",
                        "accepted_finding": True,
                        "review_accepted": True,
                        "severity": "high",
                        "surface": "api",
                        "report_path": "ZZZ-HIGH.md",
                    },
                ]
            )

            markdown = render_final_report("https://example.test", bundle, {})

        findings_table = markdown.split("### Findings Table", 1)[1].split("### Severity Counts", 1)[0]
        self.assertLess(findings_table.index("| AUTH-001 |"), findings_table.index("| ZZZ-HIGH |"))
        self.assertLess(findings_table.index("| ZZZ-HIGH |"), findings_table.index("| AAA-LOW |"))

    def test_executive_summary_long_plain_text_is_split_into_paragraphs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)

            markdown = render_final_report(
                "https://example.test",
                bundle,
                {
                    "what_was_tested": (
                        "The assessment covered the customer account API, authentication boundary, administrative workflows, and browser-facing controls. "
                        "Testing focused on the places where customer data could be exposed or modified without the expected authorization checks. "
                        "The review also considered exposed application routes, forms, headers, and API behavior observed during discovery. "
                        "These areas were selected because they carry the highest business risk for the service."
                    ),
                    "overall_security_posture": (
                        "The assessment confirmed an authentication weakness affecting private API access. "
                        "The finding should be treated as a priority because it concerns access to customer account data. "
                        "Other completed tests did not confirm additional vulnerabilities, but inconclusive areas should be revisited if new credentials or evidence become available. "
                        "The overall posture therefore depends on correcting the confirmed access-control behavior and retesting the affected path."
                    ),
                },
            )

        what_was_tested = markdown.split("### What Was Tested", 1)[1].split("### Overall Security Posture", 1)[0]
        posture = markdown.split("### Overall Security Posture", 1)[1].split("### Headline Risks", 1)[0]
        self.assertIn("\n\nTesting focused on", what_was_tested)
        self.assertIn("\n\nOther completed tests", posture)

    def test_long_source_detail_is_not_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain_dir = _write_report_inputs(Path(directory), "https://example.test")
            bundle = build_final_report_bundle("https://example.test", domain_dir)
            bundle["executed_tests"][0]["evidence_summary"] = " ".join(
                f"Evidence sentence {index}." for index in range(300)
            )

            markdown = render_final_report("https://example.test", bundle, {})

        self.assertIn("Evidence sentence 0.", markdown)
        self.assertIn("Evidence sentence 299.", markdown)
        self.assertNotIn("truncated", markdown.lower())
        self.assertNotIn("raw executed test report", markdown)

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
        self.assertIn("| Inconclusive / more evidence needed | 1 |", outcome_section)
        self.assertIn("| Rejected by review | 0 |", outcome_section)

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
    final_report_dir = domain_dir / "final-report"
    executed_dir = testing_dir / "executed_tests"
    discovery_dir.mkdir(parents=True)
    planning_dir.mkdir(parents=True)
    executed_dir.mkdir(parents=True)
    final_report_dir.mkdir(parents=True)

    discovery_dir.joinpath("report.md").write_text("# Discovery\n", encoding="utf-8")
    discovery_dir.joinpath("memory.json").write_text(
        json.dumps(
            [
                {
                    "kind": "llm_report",
                    "content": {
                        "structured": {
                            "executive_summary": "Discovery found an API surface.",
                            "application_description": "Example is a private API used for customer account operations.",
                            "key_discovered_areas": [{"title": "Private API", "detail": "/api/private"}],
                        }
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    discovery_dir.joinpath("events.json").write_text(
        json.dumps(
            [
                {
                    "agent": "orchestrator",
                    "action": "complete",
                    "message": "Discovery completed",
                    "timestamp": "2026-06-13T06:00:00+00:00",
                    "data": {},
                }
            ]
        ),
        encoding="utf-8",
    )

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
    planning_dir.joinpath("events.json").write_text(
        json.dumps(
            [
                {
                    "agent": "orchestrator",
                    "action": "complete",
                    "message": "Planning completed",
                    "timestamp": "2026-06-13T06:10:00+00:00",
                    "data": {},
                }
            ]
        ),
        encoding="utf-8",
    )

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
    final_report_dir.joinpath("events.json").write_text(
        json.dumps(
            [
                {
                    "agent": "orchestrator",
                    "action": "start",
                    "message": "Starting final report generation",
                    "timestamp": "2026-06-13T06:50:00+00:00",
                    "data": {},
                }
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
