from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from appsec_harness.models import CrawlResult


def write_reports(
    report_dir: Path,
    target_url: str,
    crawl: CrawlResult,
    components: list[dict[str, str]],
    summary: dict[str, Any],
    markdown_report: str,
    agent_report: dict[str, Any] | None = None,
) -> None:
    payload = {
        "target_url": target_url,
        "summary": summary,
        "agent_report": agent_report or {},
        "report_markdown": _normalize_markdown(markdown_report),
        "crawl": crawl.to_dict(),
        "components": components,
    }
    (report_dir / "report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (report_dir / "report.md").write_text(
        _normalize_markdown(markdown_report),
        encoding="utf-8",
    )


def _normalize_markdown(markdown_report: str) -> str:
    return markdown_report.rstrip() + "\n"
