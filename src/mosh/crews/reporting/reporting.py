from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any


FINAL_REPORT_SCHEMA_VERSION = "osh.final-report.v1"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational", "unknown"]
REMEDIATION_PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Not recorded": 3}


def render_final_report(target_url: str, bundle: dict[str, Any], report_content: dict[str, Any]) -> str:
    findings = _accepted_findings(bundle)
    finding_ids = {_text(item.get("id")) for item in findings}
    other_tests = [
        item
        for item in _list(bundle.get("executed_tests"))
        if isinstance(item, dict) and _text(item.get("id")) not in finding_ids
    ]
    severity_counts = _severity_counts(findings)
    outcome_counts = _outcome_counts(bundle)
    lines = [
        "# Open Security Harness Security Assessment Report",
        "",
    ]
    lines.extend(_report_metadata_lines(target_url, bundle))
    lines.extend(
        [
            "",
            "## Executive Summary",
            "",
            "### At A Glance",
            "",
        ]
    )
    lines.extend(_at_a_glance_lines(target_url, bundle, findings, severity_counts, outcome_counts))
    lines.extend(
        [
            "",
            "### What Was Tested",
            "",
            _executive_summary_block(
                _text(report_content.get("what_was_tested")) or _default_what_was_tested(target_url, bundle),
                1800,
            ),
            "",
            "### Overall Security Posture",
            "",
            _executive_summary_block(
                _text(report_content.get("overall_security_posture"))
                or _text(report_content.get("executive_summary"))
                or _default_security_posture(findings, outcome_counts),
                1800,
            ),
            "",
            "### Headline Risks",
            "",
        ]
    )
    lines.extend(_headline_risk_lines(report_content, findings))
    lines.extend(
        [
            "",
            "### Findings By Severity",
            "",
            "Severity counts apply only to confirmed findings. Tests that produced no finding, were inconclusive, or failed are counted separately later in the report.",
            "",
        ]
    )
    lines.extend(_severity_count_table(severity_counts))
    lines.extend(
        [
            "",
            "### Remediation Priorities",
            "",
        ]
    )
    lines.extend(_remediation_priority_lines(findings))
    lines.extend(
        [
            "",
            "## Engagement Overview",
            "",
        ]
    )
    lines.extend(_engagement_overview_lines(target_url, bundle, report_content))
    lines.extend(["", "## Summary of Findings", ""])
    lines.extend(_summary_of_findings_intro(findings, outcome_counts))
    lines.extend(
        [
            "",
            "### Findings Table",
            "",
            "The table below lists confirmed findings only. Appendix entries for no-finding, inconclusive, failed, or reviewer-rejected tests are intentionally kept out of this table.",
            "",
        ]
    )
    lines.extend(_finding_summary_table(findings))
    lines.extend(
        [
            "",
            "### Severity Counts",
            "",
            "This distribution helps prioritize confirmed remediation work. It does not include tests where no vulnerability was confirmed.",
            "",
        ]
    )
    lines.extend(_severity_count_table(severity_counts))
    lines.extend(
        [
            "",
            "### Outcome Breakdown",
            "",
            "This table accounts for every executed test report, including tests that did not become confirmed findings.",
            "",
        ]
    )
    lines.extend(_outcome_count_table(outcome_counts))
    lines.extend(
        [
            "",
            "## Key Discovery Areas",
            "",
        ]
    )
    lines.extend(_key_discovery_intro(bundle))
    lines.append("")
    lines.extend(_key_discovery_lines(bundle))
    lines.extend(
        [
            "",
            "## Detailed Findings",
            "",
        ]
    )
    if findings:
        for finding in findings:
            lines.extend(_detailed_finding_lines(finding, report_content))
    else:
        lines.append("No confirmed findings were recorded in the executed security tests.")
    lines.extend(
        [
            "",
            "## Tests With No Finding / Inconclusive",
            "",
            "The following tests are included for transparency and traceability. They are not confirmed vulnerabilities and are not mixed into the detailed findings.",
            "",
        ]
    )
    if other_tests:
        lines.extend(_other_test_table(other_tests))
    else:
        lines.append("No no-finding, inconclusive, failed, or reviewer-rejected tests were recorded.")
    lines.extend(
        [
            "",
            "## Appendix",
            "",
            "### Methodology",
            "",
            _safe_markdown_block(_text(report_content.get("methodology")) or _default_methodology(), 1600),
            "",
            "### Tools Used",
            "",
        ]
    )
    lines.extend(_tools_used_lines(bundle))
    lines.extend(
        [
            "",
            "### Evidence Index",
            "",
        ]
    )
    lines.extend(_evidence_index_lines(bundle))
    lines.extend(
        [
            "",
            "### Raw Report References",
            "",
            f"- Report schema: `{FINAL_REPORT_SCHEMA_VERSION}`",
            "- CVSS values are included only when present in source execution evidence.",
        ]
    )
    for artifact in _list(bundle.get("source_artifacts")):
        lines.append(f"- `{artifact}`")
    return "\n".join(lines).rstrip() + "\n"


def validate_final_report_content(bundle: dict[str, Any], report_content: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    report_value = report_content.get("report")
    if isinstance(report_value, str) and report_value.lstrip().startswith("#"):
        errors.append("write_final_report accepts structured narrative fields, not a complete Markdown report.")
    valid_finding_ids = {item["id"] for item in _accepted_findings(bundle)}
    for item in _writer_finding_items(report_content):
        if not isinstance(item, dict):
            errors.append("Each finding narrative in report content must be an object.")
            continue
        finding_id = _text(item.get("id"))
        if finding_id and finding_id not in valid_finding_ids:
            errors.append(f"Report content references unsupported finding `{finding_id}`.")
        if _has_cvss(item) and not _bundle_finding_has_cvss(bundle, finding_id):
            errors.append(f"Report content includes unsupported CVSS data for `{finding_id}`.")
    return errors


def validate_rendered_report(bundle: dict[str, Any], markdown: str) -> list[str]:
    errors: list[str] = []
    required_sections = [
        "## Executive Summary",
        "## Engagement Overview",
        "## Summary of Findings",
        "## Key Discovery Areas",
        "## Detailed Findings",
        "## Tests With No Finding / Inconclusive",
        "## Appendix",
    ]
    for section in required_sections:
        if section not in markdown:
            errors.append(f"Required final report section `{section}` is missing.")
    for finding in _accepted_findings(bundle):
        if finding["id"] not in markdown:
            errors.append(f"Confirmed finding `{finding['id']}` is missing from the final report.")
    for test in _list(bundle.get("executed_tests")):
        if test.get("accepted_finding"):
            continue
        detailed_marker = f"### {test.get('id')}:"
        if detailed_marker in markdown:
            errors.append(f"Non-finding test `{test.get('id')}` appears in detailed findings.")
    if _markdown_has_unclosed_backticks(markdown):
        errors.append("Rendered report contains unclosed Markdown backticks or code fences.")
    return errors


def _accepted_findings(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in _list(bundle.get("executed_tests"))
        if isinstance(item, dict) and bool(item.get("accepted_finding"))
    ]


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = _severity(finding.get("severity"))
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _report_metadata_lines(target_url: str, bundle: dict[str, Any]) -> list[str]:
    report_period = _timeline_period(bundle) or "not recorded"
    return [
        "| Report Context | Details |",
        "| --- | --- |",
        f"| Assessment target | `{target_url}` |",
        "| Assessment type | Web application security assessment |",
        f"| Engagement timeline | `{report_period}` |",
        "| Prepared with | Open Security Harness (`osh`) |",
    ]


def _at_a_glance_lines(
    target_url: str,
    bundle: dict[str, Any],
    findings: list[dict[str, Any]],
    severity_counts: dict[str, int],
    outcome_counts: dict[str, int],
) -> list[str]:
    app_context = _application_context(bundle)
    highest = _highest_severity(severity_counts).title()
    completed = len(_list(bundle.get("executed_tests")))
    no_finding = outcome_counts.get("no finding", 0)
    inconclusive = outcome_counts.get("inconclusive", 0)
    timeline = _timeline_period(bundle)
    lines = [
        f"This assessment reviewed `{target_url}`. {app_context}",
        "",
        (
            f"The engagement confirmed {len(findings)} {_plural('finding', len(findings))} across "
            f"{completed} completed {_plural('test outcome', completed)}. "
            f"The highest confirmed qualitative severity is {highest}."
        ),
        "",
        (
            f"{no_finding} {_plural('test', no_finding)} completed with no finding, and "
            f"{inconclusive} {_plural('test', inconclusive)} require more evidence "
            "before they can be confirmed or ruled out."
        ),
    ]
    if timeline:
        lines.extend(["", f"The engagement timeline covered {timeline}, including discovery, planning, security testing, and final reporting."])
    return lines


def _outcome_counts(bundle: dict[str, Any]) -> dict[str, int]:
    counts = {
        "findings": 0,
        "no finding": 0,
        "inconclusive": 0,
        "failed": 0,
        "reviewer-rejected finding": 0,
        "unknown": 0,
    }
    for test in _list(bundle.get("executed_tests")):
        if not isinstance(test, dict):
            continue
        if test.get("accepted_finding"):
            counts["findings"] += 1
            continue
        status = _status(test.get("status"))
        if status in ("no-finding", "no finding"):
            counts["no finding"] += 1
        elif status == "inconclusive":
            counts["inconclusive"] += 1
        elif status == "failed":
            counts["failed"] += 1
        elif status == "finding" and not test.get("review_accepted"):
            counts["reviewer-rejected finding"] += 1
        else:
            counts["unknown"] += 1
    return counts


def _severity_count_table(severity_counts: dict[str, int]) -> list[str]:
    lines = ["| Severity | Count |", "| --- | ---: |"]
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity.title()} | {severity_counts.get(severity, 0)} |")
    return lines


def _outcome_count_table(outcome_counts: dict[str, int]) -> list[str]:
    labels = {
        "findings": "Findings",
        "no finding": "Completed with no finding",
        "inconclusive": "Inconclusive / more evidence needed",
        "failed": "Could not be completed",
        "reviewer-rejected finding": "Rejected by review",
        "unknown": "Unclassified outcome",
    }
    lines = ["| Test Outcome | Count | What It Means |", "| --- | ---: | --- |"]
    explanations = {
        "findings": "A vulnerability was confirmed and included in the report.",
        "no finding": "The test completed and did not confirm a vulnerability.",
        "inconclusive": "The test did not gather enough evidence to confirm or rule out the issue.",
        "failed": "The test could not complete successfully.",
        "reviewer-rejected finding": "A possible finding was not confirmed by review.",
        "unknown": "The test outcome could not be classified from the available evidence.",
    }
    for outcome in ["findings", "no finding", "inconclusive", "failed", "reviewer-rejected finding", "unknown"]:
        lines.append(f"| {labels[outcome]} | {outcome_counts.get(outcome, 0)} | {explanations[outcome]} |")
    return lines


def _remediation_priority_lines(findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return ["No remediation priorities were generated because no confirmed findings were recorded."]
    lines = ["| Priority | Finding | Recommended Owner Action |", "| --- | --- | --- |"]
    for finding in _sort_findings_by_remediation_priority(findings):
        severity = _severity(finding.get("severity")).title()
        action = "Address immediately" if _severity(finding.get("severity")) in ("critical", "high") else "Schedule remediation"
        if _severity(finding.get("severity")) == "unknown":
            action = "Triage severity and remediation owner"
        lines.append(
            f"| {severity} | `{_text(finding.get('id'))}` - {_escape_table(_text(finding.get('title')))} | {action} |"
        )
    return lines


def _finding_summary_table(findings: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| ID | Title | Severity | Status | Affected Area | Remediation Priority |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    if findings:
        for finding in _sort_findings_by_remediation_priority(findings):
            lines.append(
                f"| {finding['id']} | {_escape_table(_text(finding.get('title')))} | "
                f"{_severity(finding.get('severity')).title()} | {_status(finding.get('status')).title()} | "
                f"{_escape_table(_affected_area(finding))} | {_remediation_priority(finding)} |"
            )
    else:
        lines.append("| - | No confirmed findings | - | - | - | - |")
    return lines


def _sort_findings_by_remediation_priority(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.index(_severity(finding.get("severity"))),
            REMEDIATION_PRIORITY_ORDER.get(_remediation_priority(finding), len(REMEDIATION_PRIORITY_ORDER)),
            _text(finding.get("id")),
        ),
    )


def _key_discovery_lines(bundle: dict[str, Any]) -> list[str]:
    discovery = bundle.get("discovery") if isinstance(bundle.get("discovery"), dict) else {}
    areas = _list(discovery.get("key_areas"))
    if not areas:
        return ["No key discovery areas were recorded."]
    lines: list[str] = []
    for area in areas[:12]:
        if isinstance(area, dict):
            title = _text(area.get("title")) or _text(area.get("url")) or _text(area.get("endpoint")) or "Discovery item"
            detail = _text(area.get("detail")) or _text(area.get("purpose")) or _text(area.get("notes"))
            lines.append(f"- **{title}:** {detail}" if detail else f"- **{title}**")
        else:
            lines.append(f"- {_text(area)}")
    return lines


def _summary_of_findings_intro(findings: list[dict[str, Any]], outcome_counts: dict[str, int]) -> list[str]:
    if findings:
        highest = _highest_severity(_severity_counts(findings)).title()
        return [
            f"The assessment confirmed {len(findings)} {_plural('finding', len(findings))}. The highest confirmed qualitative severity is {highest}.",
            "",
            "The findings table is intended for prioritization. Detailed evidence, reproduction notes, remediation guidance, and retest guidance are provided in the Detailed Findings section.",
        ]
    executed = sum(outcome_counts.values())
    return [
        f"The assessment completed {executed} test outcome(s), and no confirmed findings were recorded.",
        "",
        "Tests that did not produce a confirmed finding are still listed later in the report so the scope and limitations remain visible.",
    ]


def _key_discovery_intro(bundle: dict[str, Any]) -> list[str]:
    discovery = bundle.get("discovery") if isinstance(bundle.get("discovery"), dict) else {}
    application_description = _text(discovery.get("application_description"))
    if application_description:
        return [
            "Discovery provides the context for interpreting the findings. The items below are the application areas, routes, APIs, forms, technologies, or exposed surfaces that shaped the security test plan.",
            "",
            f"Application context: {application_description}",
        ]
    return [
        "Discovery provides the context for interpreting the findings. The items below are the application areas, routes, APIs, forms, technologies, or exposed surfaces that shaped the security test plan.",
    ]


def _detailed_finding_lines(finding: dict[str, Any], report_content: dict[str, Any]) -> list[str]:
    writer_detail = _writer_detail_for(report_content, finding["id"])
    impact = _text(writer_detail.get("impact")) or _text(finding.get("impact")) or _text(finding.get("result"))
    if not impact:
        impact = "Impact was not separately recorded in the source evidence."
    remediation = (
        _text(writer_detail.get("remediation_guidance"))
        or _text(writer_detail.get("remediation"))
        or _text(finding.get("resolution"))
        or "No remediation guidance was recorded for this finding."
    )
    evidence = _text(writer_detail.get("evidence")) or _text(finding.get("evidence_summary")) or "See source executed test report."
    reproduction = (
        _text(writer_detail.get("reproduction_summary"))
        or _text(finding.get("reproduction_summary"))
        or _text(finding.get("commands_summary"))
        or "See the source executed test report for recorded commands and observations."
    )
    severity = _severity(finding.get("severity")).title()
    severity_rationale = f"Based on planned priority `{_text(finding.get('severity')) or 'unknown'}` and review-confirmed execution status."
    retest_guidance = (
        _text(writer_detail.get("verification_guidance"))
        or _text(writer_detail.get("retest_guidance"))
        or "Rerun `osh test-security` for the affected test and then `osh report` after remediation."
    )
    references = _references(writer_detail, finding)
    cvss = _cvss_label(finding.get("cvss"))
    lines = [
        f"### {finding['id']}: {_text(finding.get('title')) or 'Untitled finding'}",
        "",
        f"- Severity: `{severity}`",
        f"- Severity rationale: {severity_rationale}",
        f"- Status: `{_status(finding.get('status')).title()}`",
        f"- CVSS: `{cvss}`",
        f"- Affected target/component: {_affected_area(finding)}",
        f"- Source report: `{_text(finding.get('report_path')) or 'not recorded'}`",
        "",
        "**Summary**",
        "",
        _safe_markdown_block(_text(writer_detail.get("summary")) or _text(finding.get("summary")) or "No summary recorded.", 1200),
        "",
        "**Evidence**",
        "",
        _safe_markdown_block(evidence, 2000),
        "",
        "**Reproduction Summary**",
        "",
        _safe_markdown_block(reproduction, 1200),
        "",
        "**Impact**",
        "",
        _safe_markdown_block(impact, 1200),
        "",
        "**Remediation Guidance**",
        "",
    ]
    lines.extend(_remediation_guidance_lines(finding, remediation))
    lines.extend(
        [
        "",
        "**Verification / Retest Guidance**",
        "",
        _safe_markdown_block(retest_guidance, 1000),
        "",
        "**References**",
        "",
        references,
        "",
        ]
    )
    return lines


def _other_test_table(tests: list[dict[str, Any]]) -> list[str]:
    lines = ["| ID | Test | Status | Review Outcome | Source Report |", "| --- | --- | --- | --- | --- |"]
    for test in tests:
        lines.append(
            f"| {_text(test.get('id')) or 'unknown'} | {_escape_table(_text(test.get('title')))} | "
            f"{_status(test.get('status')).title()} | "
            f"{'confirmed for reporting' if test.get('review_accepted') else 'not confirmed for reporting'} | "
            f"`{_text(test.get('report_path')) or 'not recorded'}` |"
        )
    return lines


def _remediation_guidance_lines(finding: dict[str, Any], remediation: str) -> list[str]:
    affected_area = _affected_area(finding)
    source_guidance = _clean_remediation_text(remediation)
    lines = [
        "Technical fix guidance:",
        "",
        _safe_markdown_block(source_guidance, 1800),
        "",
        "Expected corrected behavior:",
        "",
        f"The affected control in `{affected_area}` should prevent the vulnerable behavior described in the evidence while preserving legitimate use of the feature.",
        "",
        "Regression check:",
        "",
        "Add a focused automated test around the affected route, API, role, or component so the corrected behavior is enforced by the codebase.",
    ]
    if not remediation or remediation == "No remediation guidance was recorded for this finding.":
        lines[2] = (
            f"No source-specific fix was recorded. Change the implementation behind `{affected_area}` so the request, role, "
            "header, session, or component behavior shown in the evidence is no longer possible."
        )
    return lines


def _engagement_overview_lines(target_url: str, bundle: dict[str, Any], report_content: dict[str, Any]) -> list[str]:
    lines = [
        (
            f"The engagement assessed `{target_url}` using the target mappings and constraints recorded for the assessment. "
            "Discovery, planning, execution, review, and final reporting are treated as one engagement lifecycle so the report reflects the full assessment period rather than only the command execution window."
        ),
        "",
    ]
    timeline = _timeline_period(bundle)
    if timeline:
        lines.extend(
            [
                f"The recorded engagement activity ran from {timeline}.",
                "",
            ]
        )
    target_description = _target_mapping_sentence(bundle)
    if target_description:
        lines.extend([target_description, ""])
    else:
        lines.extend(["No alternative target mappings were recorded for this engagement.", ""])
    limitations = _scope_limitations_text(bundle, report_content)
    lines.extend(
        [
            f"Scope and limitations: {limitations}",
            "",
            "Testing approach:",
            "",
            _safe_markdown_block(_text(report_content.get("testing_approach")) or _default_testing_approach(bundle), 1800),
            "",
            "Lifecycle detail:",
            "",
        ]
    )
    lines.extend(_timestamp_lines(bundle))
    return lines


def _target_mapping_sentence(bundle: dict[str, Any]) -> str:
    engagement = bundle.get("engagement") if isinstance(bundle.get("engagement"), dict) else {}
    targets = engagement.get("targets") if isinstance(engagement.get("targets"), dict) else {}
    pairs = [(str(name), str(value)) for name, value in targets.items() if _text(value) and str(name).lower() != "notes"]
    if not pairs:
        return ""
    fragments = [f"{name} mapped to `{value}`" for name, value in pairs]
    sentence = "Effective target mappings used during the engagement: " + _join_human(fragments) + "."
    notes = _text(targets.get("notes"))
    if notes:
        sentence += f" Additional target notes: {notes}"
    return sentence


def _scope_limitations_text(bundle: dict[str, Any], report_content: dict[str, Any]) -> str:
    parts: list[str] = []
    blocked = _list(bundle.get("blocked_tests"))
    if blocked:
        parts.append(f"{len(blocked)} planned test(s) were blocked or not ready for execution")
    limitations = _text(report_content.get("limitations")) or _text(report_content.get("scope_and_limitations"))
    if limitations:
        parts.append(limitations)
    return "; ".join(parts) + "." if parts else "No additional scope limitations were recorded."


def _scope_limitations_lines(bundle: dict[str, Any], report_content: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    blocked = _list(bundle.get("blocked_tests"))
    if blocked:
        lines.append(f"- Blocked tests not executed: `{len(blocked)}`")
    limitations = _text(report_content.get("limitations"))
    if limitations:
        lines.append(f"- {limitations}")
    if not lines:
        lines.append("No additional scope limitations were recorded.")
    return lines


def _default_what_was_tested(target_url: str, bundle: dict[str, Any]) -> str:
    surfaces = _assessed_surface_labels(bundle)
    target_sentence = f"The assessment covered `{target_url}` and the areas of the service most relevant to customer, administrative, and operational risk."
    if surfaces:
        return (
            f"{target_sentence}\n\n"
            f"Testing focused on {', '.join(surfaces[:-1]) + ', and ' + surfaces[-1] if len(surfaces) > 1 else surfaces[0]}. "
            "The objective was to identify security issues that could affect customer data, administrative control, authentication boundaries, exposed APIs, or operational resilience."
        )
    return (
        f"{target_sentence}\n\n"
        "The objective was to identify security issues that could affect customer data, administrative control, authentication boundaries, exposed APIs, or operational resilience."
    )


def _default_security_posture(findings: list[dict[str, Any]], outcome_counts: dict[str, int]) -> str:
    if findings:
        highest = _highest_severity(_severity_counts(findings))
        immediate = sum(1 for finding in findings if _severity(finding.get("severity")) in ("critical", "high"))
        return (
            f"The assessment confirmed `{len(findings)}` {_plural('finding', len(findings))}, with `{highest.title()}` as the highest recorded qualitative severity.\n\n"
            f"`{immediate}` {_plural('finding', immediate)} are Critical or High and should be prioritized for remediation planning, owner assignment, and retesting."
        )
    executed = sum(outcome_counts.values())
    return (
        f"No confirmed findings were recorded across `{executed}` executed test outcome(s).\n\n"
        "Any inconclusive or failed tests should still be reviewed to decide whether additional evidence or access is needed."
    )


def _default_testing_approach(bundle: dict[str, Any]) -> str:
    planned = len(_list(bundle.get("planned_tests")))
    executed = len(_list(bundle.get("executed_tests")))
    return (
        "The assessment started with discovery to identify relevant routes, APIs, forms, authentication areas, technologies, and exposed surfaces.\n\n"
        "Those observations were converted into a security test plan. Ready tests were executed with the configured engagement constraints, and the final report was assembled from reviewed execution evidence.\n\n"
        f"This report includes `{executed}` executed test report(s) from `{planned}` planned test hypothesis/hypotheses."
    )


def _default_methodology() -> str:
    return (
        "The report is assembled from Open Security Harness discovery, security planning, "
        "preflight, execution, and review artifacts. Findings are included only when "
        "the executed test outcome is a finding and the review stage confirms it for reporting."
    )


def _writer_detail_for(report_content: dict[str, Any], finding_id: str) -> dict[str, Any]:
    for item in _writer_finding_items(report_content):
        if isinstance(item, dict) and _text(item.get("id")) == finding_id:
            return item
    return {}


def _writer_finding_items(report_content: dict[str, Any]) -> list[Any]:
    items: list[Any] = []
    narratives = report_content.get("finding_narratives")
    if isinstance(narratives, dict):
        for finding_id, narrative in narratives.items():
            if isinstance(narrative, dict):
                merged = {"id": finding_id}
                merged.update(narrative)
                items.append(merged)
            else:
                items.append({"id": finding_id, "summary": narrative})
    else:
        items.extend(_list(narratives))
    items.extend(_list(report_content.get("detailed_findings")))
    return items


def _bundle_finding_has_cvss(bundle: dict[str, Any], finding_id: str) -> bool:
    for finding in _accepted_findings(bundle):
        if finding.get("id") == finding_id:
            return bool(finding.get("cvss"))
    return False


def _has_cvss(item: dict[str, Any]) -> bool:
    return any(key in item for key in ("cvss", "cvss_score", "cvss_vector"))


def _headline_risk_lines(report_content: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    if findings:
        lines = []
        for finding in findings[:5]:
            severity = _severity(finding.get("severity"))
            severity_label = "severity not classified" if severity == "unknown" else f"{severity.title()} severity"
            lines.append(f"- `{finding['id']}`: {_text(finding.get('title')) or 'Untitled finding'} ({severity_label})")
        return lines
    return ["- No headline risks were recorded because no findings were confirmed."]


def _effective_target_lines(bundle: dict[str, Any]) -> list[str]:
    engagement = bundle.get("engagement") if isinstance(bundle.get("engagement"), dict) else {}
    targets = engagement.get("targets") if isinstance(engagement.get("targets"), dict) else {}
    if not targets:
        return ["No effective target mappings were recorded."]
    return [f"- {name}: `{value}`" for name, value in targets.items()]


def _timestamp_lines(bundle: dict[str, Any]) -> list[str]:
    timeline = bundle.get("timeline") if isinstance(bundle.get("timeline"), dict) else {}
    if not timeline:
        return ["No lifecycle dates were recorded in the source reports."]
    lines = []
    if _text(timeline.get("started_at")):
        lines.append(f"- Engagement started: `{_human_date(_text(timeline.get('started_at')))}`")
    if _text(timeline.get("completed_at")):
        lines.append(f"- Latest recorded activity: `{_human_date(_text(timeline.get('completed_at')))}`")
    stages = _list(timeline.get("stages"))
    if stages:
        lines.append("- Lifecycle stages:")
        for stage in stages:
            if not isinstance(stage, dict):
                continue
            stage_name = _text(stage.get("name")) or "Stage"
            stage_period = _format_date_period(_text(stage.get("started_at")), _text(stage.get("completed_at")))
            lines.append(f"  - {stage_name}: `{stage_period or 'not recorded'}`")
    return lines or ["No lifecycle dates were recorded in the source reports."]


def _timeline_period(bundle: dict[str, Any]) -> str:
    timeline = bundle.get("timeline") if isinstance(bundle.get("timeline"), dict) else {}
    started = _text(timeline.get("started_at"))
    completed = _text(timeline.get("completed_at"))
    if started or completed:
        return _format_period(started, completed)
    timestamps = [_text(test.get("executed_at")) for test in _list(bundle.get("executed_tests")) if isinstance(test, dict)]
    timestamps = [item for item in timestamps if item]
    return _format_period(min(timestamps), max(timestamps)) if timestamps else ""


def _format_period(started: str, completed: str) -> str:
    started_label = _human_timestamp(started)
    completed_label = _human_timestamp(completed)
    if started_label and completed_label and started_label != completed_label:
        return f"{started_label} to {completed_label}"
    return started_label or completed_label


def _format_date_period(started: str, completed: str) -> str:
    started_label = _human_date(started)
    completed_label = _human_date(completed)
    if started_label and completed_label and started_label != completed_label:
        return f"{started_label} to {completed_label}"
    return started_label or completed_label


def _human_timestamp(value: str) -> str:
    if not value:
        return ""
    normalized = value.strip()
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return normalized
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return f"{_ordinal(parsed.day)} {parsed.strftime('%B %Y %H:%M')} UTC"


def _human_date(value: str) -> str:
    if not value:
        return ""
    normalized = value.strip()
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return normalized
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return f"{_ordinal(parsed.day)} {parsed.strftime('%B %Y')}"


def _ordinal(day: int) -> str:
    if 10 <= day % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
    return f"{day}{suffix}"


def _application_context(bundle: dict[str, Any]) -> str:
    discovery = bundle.get("discovery") if isinstance(bundle.get("discovery"), dict) else {}
    context = _text(discovery.get("application_description")) or _text(discovery.get("executive_summary"))
    if context:
        return f"The application provides the following business capability: {_readable_paragraphs(context)}"
    return "Discovery did not record a separate business description for the application."


def _assessed_surface_labels(bundle: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for item in _list(bundle.get("executed_tests")) + _list(bundle.get("planned_tests")):
        if not isinstance(item, dict):
            continue
        surface = _surface_label(_text(item.get("surface")) or _text(item.get("affected_area")))
        if surface and surface not in seen:
            seen.add(surface)
            labels.append(surface)
    return labels[:6]


def _surface_label(value: str) -> str:
    normalized = value.lower().replace("_", "-").strip()
    labels = {
        "api": "APIs",
        "authentication": "authentication and session controls",
        "auth": "authentication and session controls",
        "forms": "user-input forms",
        "form": "user-input forms",
        "headers": "browser-facing security headers",
        "header": "browser-facing security headers",
        "cors": "cross-origin browser access controls",
        "spa": "single-page application behavior",
        "infrastructure": "hosting and access-control boundaries",
        "infra": "hosting and access-control boundaries",
    }
    return labels.get(normalized, value)


def _tools_used_lines(bundle: dict[str, Any]) -> list[str]:
    tools = set()
    for test in _list(bundle.get("executed_tests")):
        if not isinstance(test, dict):
            continue
        for tool in _list(test.get("tools_used")):
            name = _text(tool)
            if name:
                tools.add(name)
    lines = ["- Open Security Harness"]
    lines.extend(f"- {tool}" for tool in sorted(tools))
    return lines


def _evidence_index_lines(bundle: dict[str, Any]) -> list[str]:
    lines = ["| Artifact | Path |", "| --- | --- |"]
    for test in _list(bundle.get("executed_tests")):
        if not isinstance(test, dict):
            continue
        lines.append(f"| Executed test `{_text(test.get('id')) or 'unknown'}` | `{_text(test.get('report_path'))}` |")
    if len(lines) == 2:
        lines.append("| No executed test reports | - |")
    return lines


def _affected_area(finding: dict[str, Any]) -> str:
    return _text(finding.get("affected_area")) or _text(finding.get("surface")) or _text(finding.get("component")) or "not separately recorded"


def _remediation_priority(finding: dict[str, Any]) -> str:
    severity = _severity(finding.get("severity"))
    if severity in ("critical", "high"):
        return "High"
    if severity == "medium":
        return "Medium"
    if severity in ("low", "informational"):
        return "Low"
    return "Not recorded"


def _references(writer_detail: dict[str, Any], finding: dict[str, Any]) -> str:
    refs = _list(writer_detail.get("references")) + _list(finding.get("references"))
    labels = [_text(ref) for ref in refs if _text(ref)]
    if labels:
        return "\n".join(f"- {label}" for label in labels)
    return "No OWASP, ASVS, CWE, or external references were recorded in the source evidence."


def _clean_remediation_text(value: str) -> str:
    text = value.strip()
    text = re.sub(r"(?m)^\s*\d+\.\s+(#{1,6}\s+)", r"\1", text)
    text = re.sub(r"(?m)^\s*\d+\.\s+", "- ", text)
    text = re.sub(r"(?ms)\n+### If No Finding Was Present\n.*$", "", text)
    return text or value


def _safe_markdown_block(value: str, _max_chars: int) -> str:
    text = value.strip()
    if _markdown_has_unclosed_backticks(text):
        return _fenced_text_block(text)
    return text


def _executive_summary_block(value: str, max_chars: int) -> str:
    text = value.strip()
    if _is_plain_narrative(text):
        text = _readable_paragraphs(text)
    return _safe_markdown_block(text, max_chars)


def _is_plain_narrative(value: str) -> bool:
    if "\n\n" in value:
        return False
    markdown_markers = (
        r"^\s*[-*+]\s+",
        r"^\s*\d+\.\s+",
        r"^\s*#{1,6}\s+",
        r"^\s*\|",
        r"^\s*`{3,}",
    )
    return not any(re.search(pattern, value, flags=re.MULTILINE) for pattern in markdown_markers)


def _fenced_text_block(value: str) -> str:
    max_run = max((len(run) for run in re.findall(r"`+", value)), default=3)
    fence = "`" * max(4, max_run + 1)
    return f"{fence}text\n{value.rstrip()}\n{fence}"


def _markdown_has_unclosed_backticks(value: str) -> bool:
    outside_lines: list[str] = []
    fence_len: int | None = None
    for line in value.splitlines():
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if fence_len is not None:
            if indent <= 3 and re.fullmatch(rf"`{{{fence_len},}}\s*", stripped):
                fence_len = None
            continue
        if indent <= 3:
            opening = re.match(r"(`{3,})(?:[^`]*)$", stripped)
            if opening:
                fence_len = len(opening.group(1))
                continue
        outside_lines.append(line)
    if fence_len is not None:
        return True

    outside_text = "\n".join(outside_lines)
    inline_counts: dict[int, int] = {}
    for run in re.findall(r"(?<!`)`{1,2}(?!`)", outside_text):
        inline_counts[len(run)] = inline_counts.get(len(run), 0) + 1
    return any(count % 2 for count in inline_counts.values())


def _cvss_label(value: Any) -> str:
    if not value:
        return "Not scored"
    if isinstance(value, dict):
        score = _text(value.get("score"))
        vector = _text(value.get("vector"))
        if score and vector:
            return f"{score} {vector}"
        return score or vector or "Not scored"
    return _text(value) or "Not scored"


def _highest_severity(severity_counts: dict[str, int]) -> str:
    for severity in SEVERITY_ORDER:
        if severity_counts.get(severity, 0):
            return severity
    return "unknown"


def _severity(value: Any) -> str:
    normalized = _text(value).lower()
    return normalized if normalized in SEVERITY_ORDER else "unknown"


def _status(value: Any) -> str:
    normalized = _text(value).lower().replace("_", "-")
    if normalized in ("finding", "confirmed", "finding-confirmed"):
        return "finding"
    if normalized in ("no-finding", "no finding", "not-found", "none"):
        return "no-finding"
    if normalized in ("inconclusive", "failed"):
        return normalized
    return normalized or "unknown"


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|") or "Untitled"


def _plural(label: str, count: int) -> str:
    return label if count == 1 else f"{label}s"


def _join_human(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _readable_paragraphs(value: str) -> str:
    text = " ".join(value.split())
    if len(text) <= 260:
        return text
    raw_sentences = [sentence.strip() for sentence in text.split(". ") if sentence.strip()]
    sentences = [sentence if sentence.endswith((".", "!", "?")) else f"{sentence}." for sentence in raw_sentences]
    paragraphs: list[str] = []
    current: list[str] = []
    current_length = 0
    for sentence in sentences:
        if current and current_length + len(sentence) > 240:
            paragraphs.append(" ".join(current))
            current = []
            current_length = 0
        current.append(sentence)
        current_length += len(sentence) + 1
    if current:
        paragraphs.append(" ".join(current))
    return "\n\n".join(paragraphs)
