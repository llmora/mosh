from __future__ import annotations

from typing import Any


FINAL_REPORT_SCHEMA_VERSION = "osh.final-report.v1"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational", "unknown"]


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
            _text(report_content.get("what_was_tested")) or _default_what_was_tested(target_url, bundle),
            "",
            "### Overall Security Posture",
            "",
            _text(report_content.get("overall_security_posture"))
            or _text(report_content.get("executive_summary"))
            or _default_security_posture(findings, outcome_counts),
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
            "### Target URL",
            "",
            f"`{target_url}`",
            "",
            "### Effective Target Mappings",
            "",
        ]
    )
    lines.extend(_effective_target_lines(bundle))
    lines.extend(
        [
            "",
            "### Dates And Run Timestamps",
            "",
        ]
    )
    lines.extend(_timestamp_lines(bundle))
    lines.extend(
        [
            "",
            "### Scope And Limitations",
            "",
        ]
    )
    lines.extend(_scope_limitations_lines(bundle, report_content))
    lines.extend(
        [
            "",
            "### Testing Approach",
            "",
            _text(report_content.get("testing_approach")) or _default_testing_approach(bundle),
            "",
            "## Summary of Findings",
            "",
            "### Findings Table",
            "",
        ]
    )
    lines.extend(_finding_summary_table(findings))
    lines.extend(
        [
            "",
            "### Severity Counts",
            "",
        ]
    )
    lines.extend(_severity_count_table(severity_counts))
    lines.extend(
        [
            "",
            "### Outcome Breakdown",
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
        lines.append("No accepted findings were recorded in the executed security tests.")
    lines.extend(
        [
            "",
            "## Tests With No Finding / Inconclusive",
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
            _text(report_content.get("methodology")) or _default_methodology(),
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
            errors.append(f"Accepted finding `{finding['id']}` is missing from the final report.")
    for test in _list(bundle.get("executed_tests")):
        if test.get("accepted_finding"):
            continue
        detailed_marker = f"### {test.get('id')}:"
        if detailed_marker in markdown:
            errors.append(f"Non-finding test `{test.get('id')}` appears in detailed findings.")
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
    timestamps = [_text(test.get("executed_at")) for test in _list(bundle.get("executed_tests")) if isinstance(test, dict)]
    timestamps = [item for item in timestamps if item]
    report_period = f"{min(timestamps)} to {max(timestamps)}" if timestamps else "not recorded"
    return [
        "| Field | Value |",
        "| --- | --- |",
        f"| Target | `{target_url}` |",
        f"| Report Type | Web application security assessment |",
        f"| Test Execution Window | `{report_period}` |",
        f"| Report Generator | Open Security Harness (`osh`) |",
    ]


def _at_a_glance_lines(
    target_url: str,
    bundle: dict[str, Any],
    findings: list[dict[str, Any]],
    severity_counts: dict[str, int],
    outcome_counts: dict[str, int],
) -> list[str]:
    return [
        "| Metric | Value |",
        "| --- | --- |",
        f"| Target | `{target_url}` |",
        f"| Executed Tests | `{len(_list(bundle.get('executed_tests')))}` |",
        f"| Accepted Findings | `{len(findings)}` |",
        f"| Highest Qualitative Severity | `{_highest_severity(severity_counts).title()}` |",
        f"| No-Finding Tests | `{outcome_counts.get('no finding', 0)}` |",
        f"| Inconclusive Tests | `{outcome_counts.get('inconclusive', 0)}` |",
    ]


def _outcome_counts(bundle: dict[str, Any]) -> dict[str, int]:
    counts = {
        "accepted findings": 0,
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
            counts["accepted findings"] += 1
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
    lines = ["| Outcome | Count |", "| --- | ---: |"]
    for outcome in ["accepted findings", "no finding", "inconclusive", "failed", "reviewer-rejected finding", "unknown"]:
        lines.append(f"| {outcome.title()} | {outcome_counts.get(outcome, 0)} |")
    return lines


def _remediation_priority_lines(findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return ["No remediation priorities were generated because no accepted findings were recorded."]
    lines = ["| Priority | Finding | Recommended Owner Action |", "| --- | --- | --- |"]
    for finding in sorted(findings, key=lambda item: SEVERITY_ORDER.index(_severity(item.get("severity")))):
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
        for finding in findings:
            lines.append(
                f"| {finding['id']} | {_escape_table(_text(finding.get('title')))} | "
                f"{_severity(finding.get('severity')).title()} | {_status(finding.get('status')).title()} | "
                f"{_escape_table(_affected_area(finding))} | {_remediation_priority(finding)} |"
            )
    else:
        lines.append("| - | No accepted findings | - | - | - | - |")
    return lines


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
    severity_rationale = f"Based on planned priority `{_text(finding.get('severity')) or 'unknown'}` and accepted execution status."
    retest_guidance = (
        _text(writer_detail.get("verification_guidance"))
        or _text(writer_detail.get("retest_guidance"))
        or "Rerun `osh test-security` for the affected test and then `osh report` after remediation."
    )
    references = _references(writer_detail, finding)
    cvss = _cvss_label(finding.get("cvss"))
    return [
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
        _excerpt(_text(writer_detail.get("summary")) or _text(finding.get("summary")) or "No summary recorded.", 1200),
        "",
        "**Evidence**",
        "",
        _excerpt(evidence, 2000),
        "",
        "**Reproduction Summary**",
        "",
        _excerpt(reproduction, 1200),
        "",
        "**Impact**",
        "",
        _excerpt(impact, 1200),
        "",
        "**Remediation Guidance**",
        "",
        _excerpt(remediation, 1600),
        "",
        "**Verification / Retest Guidance**",
        "",
        _excerpt(retest_guidance, 1000),
        "",
        "**References**",
        "",
        references,
        "",
    ]


def _other_test_table(tests: list[dict[str, Any]]) -> list[str]:
    lines = ["| ID | Test | Status | Review | Source Report |", "| --- | --- | --- | --- | --- |"]
    for test in tests:
        lines.append(
            f"| {_text(test.get('id')) or 'unknown'} | {_escape_table(_text(test.get('title')))} | "
            f"{_status(test.get('status')).title()} | "
            f"{'accepted' if test.get('review_accepted') else 'not accepted'} | "
            f"`{_text(test.get('report_path')) or 'not recorded'}` |"
        )
    return lines


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
    planned = len(_list(bundle.get("planned_tests")))
    executed = len(_list(bundle.get("executed_tests")))
    return (
        f"Open Security Harness tested `{target_url}` using discovery context, "
        f"`{planned}` planned security test(s), and `{executed}` executed test report(s)."
    )


def _default_security_posture(findings: list[dict[str, Any]], outcome_counts: dict[str, int]) -> str:
    if findings:
        highest = _highest_severity(_severity_counts(findings))
        return (
            f"The engagement produced `{len(findings)}` accepted finding(s). "
            f"The highest recorded qualitative severity is `{highest.title()}`."
        )
    executed = sum(outcome_counts.values())
    return f"No accepted findings were recorded across `{executed}` executed test outcome(s)."


def _default_testing_approach(bundle: dict[str, Any]) -> str:
    planned = len(_list(bundle.get("planned_tests")))
    executed = len(_list(bundle.get("executed_tests")))
    return (
        "The assessment used discovery output to build a security test plan, ran ready tests through "
        f"the security-testing workflow, and assembled this report from `{executed}` executed test "
        f"report(s) out of `{planned}` planned test hypothesis/hypotheses."
    )


def _default_methodology() -> str:
    return (
        "The report is assembled from Open Security Harness discovery, security planning, "
        "preflight, execution, and review artifacts. Accepted findings are included only when "
        "the executed test outcome is a finding and the review accepted it."
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
    return ["- No accepted headline risks were recorded."]


def _effective_target_lines(bundle: dict[str, Any]) -> list[str]:
    engagement = bundle.get("engagement") if isinstance(bundle.get("engagement"), dict) else {}
    targets = engagement.get("targets") if isinstance(engagement.get("targets"), dict) else {}
    if not targets:
        return ["No effective target mappings were recorded."]
    return [f"- {name}: `{value}`" for name, value in targets.items()]


def _timestamp_lines(bundle: dict[str, Any]) -> list[str]:
    timestamps = [_text(test.get("executed_at")) for test in _list(bundle.get("executed_tests")) if isinstance(test, dict)]
    timestamps = [item for item in timestamps if item]
    if not timestamps:
        return ["No execution timestamps were recorded in the source reports."]
    return [
        f"- First recorded test execution: `{min(timestamps)}`",
        f"- Latest recorded test execution: `{max(timestamps)}`",
    ]


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


def _excerpt(value: str, max_chars: int) -> str:
    text = value.strip()
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars].rstrip()
    last_break = max(truncated.rfind("\n\n"), truncated.rfind(". "), truncated.rfind("\n"))
    if last_break > max_chars * 0.6:
        truncated = truncated[:last_break].rstrip()
    return f"{truncated}\n\n_Source detail truncated; see the raw executed test report for full evidence._"
