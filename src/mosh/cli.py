from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mosh.config import AppConfig
from mosh.models import Event
from mosh.crews.discovery.crew import DiscoveryOrchestrator
from mosh.crews.reporting.crew import FinalReportingOrchestrator
from mosh.crews.source_discovery.crew import SourceDiscoveryOrchestrator
from mosh.scope import report_dir_name
from mosh.crews.security_planning.crew import SecurityTestPlanningOrchestrator
from mosh.crews.security_testing.crew import (
    SecurityTestPreflightResult,
    SecurityTestingOrchestrator,
    render_blocked_tests_cli_summary,
)


def main(argv: list[str] | None = None) -> int:
    argv = _normalize_url_shorthand(argv)
    try:
        config = AppConfig.from_env()
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(prog="mosh")
    subcommands = parser.add_subparsers(dest="command", required=True)

    discover_parser = subcommands.add_parser("discover", help="Run the discovery crew")
    discover_parser.add_argument("url", help="Target application URL to discover")
    discover_parser.add_argument("--max-pages", type=int, default=200, help=argparse.SUPPRESS)
    discover_parser.add_argument("--max-depth", type=int, default=config.max_depth, help=argparse.SUPPRESS)
    discover_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    discover_source_parser = subcommands.add_parser("discover-source", help="Run the source discovery crew")
    discover_source_parser.add_argument("source", help="Local source tree path to discover")
    discover_source_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    plan_parser = subcommands.add_parser("plan-security", help="Create a security test plan from discovery output")
    plan_parser.add_argument("url", help="Target application URL to plan from")
    plan_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    test_parser = subcommands.add_parser("test-security", help="Run security testing preflight from a security plan")
    test_parser.add_argument("url", help="Target application URL to test")
    test_parser.add_argument("--engagement-file", help="Path to the engagement YAML file")
    test_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    report_parser = subcommands.add_parser("report", help="Create the final customer-facing report")
    report_parser.add_argument("url", help="Target application URL to report on")
    report_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    args = parser.parse_args(argv)

    if args.command == "discover":
        return _run_discovery(config, args)
    if args.command == "discover-source":
        return _run_source_discovery(config, args)
    if args.command == "plan-security":
        return _run_security_test_planning(config, args)
    if args.command == "test-security":
        return _run_security_testing(config, args)
    if args.command == "report":
        return _run_final_reporting(config, args)
    parser.error(f"Unsupported command: {args.command}")
    return 2


def _run_discovery(config: AppConfig, args: argparse.Namespace) -> int:
    orchestrator = DiscoveryOrchestrator(
        config,
        output_root=Path(args.output_root),
        event_sink=_print_event,
    )
    try:
        report_dir = orchestrator.run(args.url, max_pages=args.max_pages, max_depth=args.max_depth)
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Report written to {report_dir}")
    return 0


def _run_source_discovery(config: AppConfig, args: argparse.Namespace) -> int:
    orchestrator = SourceDiscoveryOrchestrator(
        config,
        output_root=Path(args.output_root),
        event_sink=_print_event,
    )
    try:
        report_dir = orchestrator.run(args.source)
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Source discovery report written to {report_dir}")
    return 0


def _run_security_test_planning(config: AppConfig, args: argparse.Namespace) -> int:
    orchestrator = SecurityTestPlanningOrchestrator(
        config,
        output_root=Path(args.output_root),
        event_sink=_print_event,
    )
    try:
        report_dir = orchestrator.run(args.url)
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Security test plan written to {report_dir}")
    return 0


def _run_security_testing(config: AppConfig, args: argparse.Namespace) -> int:
    output_root = Path(args.output_root)
    engagement_file = (
        Path(args.engagement_file)
        if args.engagement_file
        else output_root / report_dir_name(args.url) / "security-test-planning" / "engagement_template.yaml"
    )
    orchestrator = SecurityTestingOrchestrator(
        config,
        output_root=output_root,
        event_sink=_print_event,
    )
    try:
        report_dir = orchestrator.run(args.url, engagement_file=engagement_file)
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Security testing preflight written to {report_dir}")
    summary = _security_testing_blocked_summary(report_dir, engagement_file)
    if summary:
        print(summary)
    return 0


def _security_testing_blocked_summary(report_dir: Path, engagement_file: Path) -> str:
    memory_path = report_dir / "memory.json"
    try:
        memory = json.loads(memory_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    if not isinstance(memory, list):
        return ""
    preflight = next(
        (
            item.get("content")
            for item in reversed(memory)
            if isinstance(item, dict) and item.get("kind") == "security_testing_preflight"
        ),
        None,
    )
    if not isinstance(preflight, dict):
        return ""
    return render_blocked_tests_cli_summary(
        result=SecurityTestPreflightResult(
            ready=preflight.get("ready") if isinstance(preflight.get("ready"), list) else [],
            blocked=preflight.get("blocked") if isinstance(preflight.get("blocked"), list) else [],
            targets=preflight.get("targets") if isinstance(preflight.get("targets"), dict) else {},
        ),
        engagement_file=engagement_file,
    )


def _run_final_reporting(config: AppConfig, args: argparse.Namespace) -> int:
    orchestrator = FinalReportingOrchestrator(
        config,
        output_root=Path(args.output_root),
        event_sink=_print_event,
    )
    try:
        report_dir = orchestrator.run(args.url)
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Final report written to {report_dir / 'report.md'}")
    return 0


def _normalize_url_shorthand(argv: list[str] | None) -> list[str]:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return args
    commands = {"discover", "discover-source", "plan-security", "test-security", "report"}
    if args[0] in commands or args[0].startswith("-"):
        return args
    return ["discover", *args]


def _print_event(event: Event) -> None:
    print(f"[{event.timestamp}] {event.agent}: {event.message}")


if __name__ == "__main__":
    raise SystemExit(main())
