from __future__ import annotations

import argparse
import sys
from pathlib import Path

from open_security_harness.config import AppConfig
from open_security_harness.models import Event
from open_security_harness.crews.discovery.crew import DiscoveryOrchestrator
from open_security_harness.scope import report_dir_name
from open_security_harness.crews.security_planning.crew import SecurityTestPlanningOrchestrator
from open_security_harness.crews.security_testing.crew import SecurityTestingOrchestrator


def main(argv: list[str] | None = None) -> int:
    argv = _normalize_url_shorthand(argv)
    config = AppConfig.from_env()
    parser = argparse.ArgumentParser(prog="osh")
    subcommands = parser.add_subparsers(dest="command", required=True)

    discover_parser = subcommands.add_parser("discover", help="Run the discovery crew")
    discover_parser.add_argument("url", help="Target application URL to discover")
    discover_parser.add_argument("--max-pages", type=int, default=200, help=argparse.SUPPRESS)
    discover_parser.add_argument("--max-depth", type=int, default=config.max_depth, help=argparse.SUPPRESS)
    discover_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    plan_parser = subcommands.add_parser("plan-security", help="Create a security test plan from discovery output")
    plan_parser.add_argument("url", help="Target application URL to plan from")
    plan_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    test_parser = subcommands.add_parser("test-security", help="Run security testing preflight from a security plan")
    test_parser.add_argument("url", help="Target application URL to test")
    test_parser.add_argument("--engagement-file", help="Path to the engagement YAML file")
    test_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    args = parser.parse_args(argv)

    if args.command == "discover":
        return _run_discovery(config, args)
    if args.command == "plan-security":
        return _run_security_test_planning(config, args)
    if args.command == "test-security":
        return _run_security_testing(config, args)
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
        print(f"osh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Report written to {report_dir}")
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
        print(f"osh failed: {exc}", file=sys.stderr)
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
        print(f"osh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Security testing preflight written to {report_dir}")
    return 0


def _normalize_url_shorthand(argv: list[str] | None) -> list[str]:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return args
    commands = {"discover", "plan-security", "test-security"}
    if args[0] in commands or args[0].startswith("-"):
        return args
    return ["discover", *args]


def _print_event(event: Event) -> None:
    print(f"[{event.timestamp}] {event.agent}: {event.message}")


if __name__ == "__main__":
    raise SystemExit(main())
