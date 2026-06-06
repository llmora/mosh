from __future__ import annotations

import argparse
import sys
from pathlib import Path

from appsec_harness.config import AppConfig
from appsec_harness.models import Event
from appsec_harness.orchestrator import DiscoveryOrchestrator


def main(argv: list[str] | None = None) -> int:
    config = AppConfig.from_env()
    parser = argparse.ArgumentParser(prog="appsec-harness")
    parser.add_argument("url", help="Target application URL to discover")
    parser.add_argument("--max-pages", type=int, default=200, help=argparse.SUPPRESS)
    parser.add_argument("--max-depth", type=int, default=config.max_depth, help=argparse.SUPPRESS)
    parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    orchestrator = DiscoveryOrchestrator(
        config,
        output_root=Path(args.output_root),
        event_sink=_print_event,
    )
    try:
        report_dir = orchestrator.run(args.url, max_pages=args.max_pages, max_depth=args.max_depth)
    except Exception as exc:
        print(f"appsec-harness failed: {exc}", file=sys.stderr)
        return 1
    print(f"Report written to {report_dir}")
    return 0


def _print_event(event: Event) -> None:
    print(f"[{event.timestamp}] {event.agent}: {event.message}")


if __name__ == "__main__":
    raise SystemExit(main())
