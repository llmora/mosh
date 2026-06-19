from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mosh.config import AppConfig
from mosh.models import Event
from mosh.crews.discovery_live.crew import DiscoveryLiveOrchestrator
from mosh.crews.reporting.crew import FinalReportingOrchestrator
from mosh.crews.discovery_source.crew import DiscoverySourceOrchestrator
from mosh.engagements import (
    Engagement,
    EngagementAsset,
    asset_discovery_dir,
    attach_asset,
    create_engagement,
    engagement_exists,
    engagement_dir,
    load_engagement,
    record_asset_discovery,
)
from mosh.crews.planning.crew import SecurityTestPlanningOrchestrator
from mosh.crews.testing.crew import (
    SecurityTestPreflightResult,
    SecurityTestingOrchestrator,
    render_blocked_tests_cli_summary,
)


def main(argv: list[str] | None = None) -> int:
    try:
        config = AppConfig.from_env()
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(prog="mosh")
    subcommands = parser.add_subparsers(dest="command", required=True)

    engagement_parser = subcommands.add_parser("engagement", help="Manage engagement manifests and attached assets")
    engagement_subcommands = engagement_parser.add_subparsers(dest="engagement_command", required=True)
    engagement_create_parser = engagement_subcommands.add_parser("create", help="Create a new engagement")
    engagement_create_parser.add_argument("--title", help="Human-readable engagement title")
    engagement_create_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)
    engagement_attach_parser = engagement_subcommands.add_parser("attach", help="Attach an asset to an engagement")
    engagement_attach_parser.add_argument("engagement_id", help="Engagement ID")
    engagement_attach_parser.add_argument("locator", help="Asset URL, source path, repository URL, or mobile app URL")
    engagement_attach_parser.add_argument("--type", help="Override inferred asset type")
    engagement_attach_parser.add_argument("--label", help="Human-readable asset label")
    engagement_attach_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    discover_parser = subcommands.add_parser("discover", help="Run the live/source discovery crew")
    discover_parser.add_argument("engagement_id", help="Engagement ID to discover")
    discover_parser.add_argument("--asset", action="append", default=[], help="Only discover the selected asset ID; can be repeated")
    discover_parser.add_argument("--refresh", action="store_true", help="Rerun discovery even when an asset already has discovery output")
    discover_parser.add_argument("--max-pages", type=int, default=200, help=argparse.SUPPRESS)
    discover_parser.add_argument("--max-depth", type=int, default=config.max_depth, help=argparse.SUPPRESS)
    discover_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    plan_parser = subcommands.add_parser("plan", help="Create a security test plan from discovery output")
    plan_parser.add_argument("engagement_id", help="Engagement ID to plan from")
    plan_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    test_parser = subcommands.add_parser("test", help="Run security testing preflight from a security plan")
    test_parser.add_argument("engagement_id", help="Engagement ID to test")
    test_parser.add_argument(
        "--hypothesis",
        "--hypothesis-id",
        dest="hypotheses",
        action="append",
        default=[],
        help="Run only the selected hypothesis ID; can be repeated or comma-separated",
    )
    test_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    report_parser = subcommands.add_parser("report", help="Create the final customer-facing report")
    report_parser.add_argument("engagement_id", help="Engagement ID to report on")
    report_parser.add_argument("--output-root", default="report", help=argparse.SUPPRESS)

    args = parser.parse_args(argv)

    if args.command == "engagement":
        if args.engagement_command == "create":
            return _run_engagement_create(args)
        if args.engagement_command == "attach":
            return _run_engagement_attach(args)
        parser.error(f"Unsupported engagement command: {args.engagement_command}")
    if args.command == "discover":
        return _run_discovery(config, args)
    if args.command == "plan":
        return _run_security_test_planning(config, args)
    if args.command == "test":
        return _run_testing(config, args)
    if args.command == "report":
        return _run_final_reporting(config, args)
    parser.error(f"Unsupported command: {args.command}")
    return 2


def _run_discovery(config: AppConfig, args: argparse.Namespace) -> int:
    output_root = Path(args.output_root)
    if engagement_exists(output_root, args.engagement_id):
        return _run_engagement_discovery(config, args)
    print(f"mosh failed: engagement not found: {args.engagement_id}", file=sys.stderr)
    return 1


def _run_engagement_create(args: argparse.Namespace) -> int:
    try:
        engagement = create_engagement(Path(args.output_root), title=args.title)
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Engagement created: {engagement.id}")
    print(f"Manifest written to {engagement_dir(Path(args.output_root), engagement.id) / 'engagement.json'}")
    return 0


def _run_engagement_attach(args: argparse.Namespace) -> int:
    try:
        result = attach_asset(
            Path(args.output_root),
            args.engagement_id,
            args.locator,
            asset_type=args.type,
            label=args.label,
        )
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    action = "Attached" if result.created else "Asset already attached"
    print(f"{action}: {result.asset.id} ({result.asset.type})")
    print(f"Engagement: {result.engagement.id}")
    return 0


def _run_engagement_discovery(config: AppConfig, args: argparse.Namespace) -> int:
    output_root = Path(args.output_root)
    try:
        engagement = load_engagement(output_root, args.engagement_id)
        selected_assets = _selected_discovery_assets(engagement, args.asset)
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    if not selected_assets:
        print(f"Engagement {engagement.id} has no assets to discover.")
        return 0
    due_assets = [
        asset
        for asset in selected_assets
        if args.refresh or _asset_needs_discovery(output_root, engagement.id, asset.id)
    ]
    if not due_assets:
        print(f"No assets need discovery for {engagement.id}; use --refresh to rerun.")
        return 0

    for asset in due_assets:
        try:
            report_dir = _run_asset_discovery(config, output_root, engagement, asset, args)
            record_asset_discovery(output_root, engagement.id, asset.id, report_dir)
        except Exception as exc:
            print(f"mosh failed: asset {asset.id}: {exc}", file=sys.stderr)
            return 1
        print(f"Discovery report for {asset.id} written to {report_dir}")
    return 0


def _selected_discovery_assets(engagement: Engagement, asset_ids: list[str]) -> list[EngagementAsset]:
    if not asset_ids:
        return engagement.assets
    by_id = {asset.id: asset for asset in engagement.assets}
    selected: list[EngagementAsset] = []
    for asset_id in asset_ids:
        asset = by_id.get(asset_id)
        if asset is None:
            raise ValueError(f"Unknown asset id `{asset_id}` for engagement `{engagement.id}`")
        selected.append(asset)
    return selected


def _asset_needs_discovery(output_root: Path, engagement_id: str, asset_id: str) -> bool:
    return not (asset_discovery_dir(output_root, engagement_id, asset_id) / "report.md").exists()


def _run_asset_discovery(
    config: AppConfig,
    output_root: Path,
    engagement: Engagement,
    asset: EngagementAsset,
    args: argparse.Namespace,
) -> Path:
    report_dir = asset_discovery_dir(output_root, engagement.id, asset.id)
    if asset.type == "live_url":
        return DiscoveryLiveOrchestrator(
            config,
            output_root=output_root,
            event_sink=_print_event,
        ).run(
            asset.locator,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            report_dir=report_dir,
        )
    if asset.type == "source_tree":
        return DiscoverySourceOrchestrator(
            config,
            output_root=output_root,
            event_sink=_print_event,
        ).run(asset.locator, report_dir=report_dir)
    raise ValueError(f"Discovery is not implemented for {asset.type} assets yet.")


def _run_security_test_planning(config: AppConfig, args: argparse.Namespace) -> int:
    orchestrator = SecurityTestPlanningOrchestrator(
        config,
        output_root=Path(args.output_root),
        event_sink=_print_event,
    )
    try:
        report_dir = orchestrator.run(args.engagement_id)
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    if getattr(orchestrator, "last_run_skipped", False):
        print(f"Security test plan is current; no new discovery since previous plan at {report_dir}")
        return 0
    print(f"Security test plan written to {report_dir}")
    return 0


def _run_testing(config: AppConfig, args: argparse.Namespace) -> int:
    output_root = Path(args.output_root)
    engagement_file = engagement_dir(output_root, args.engagement_id) / "engagement_template.yaml"
    orchestrator = SecurityTestingOrchestrator(
        config,
        output_root=output_root,
        event_sink=_print_event,
    )
    try:
        report_dir = orchestrator.run(
            args.engagement_id,
            hypothesis_ids=args.hypotheses,
        )
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Security testing preflight written to {report_dir}")
    skipped_ids = getattr(orchestrator, "_skipped_test_ids", [])
    if skipped_ids:
        print(f"Skipped {len(skipped_ids)} already-executed tests: {', '.join(skipped_ids)}")
    summary = _testing_blocked_summary(report_dir, engagement_file)
    if summary:
        print(summary)
    return 0


def _testing_blocked_summary(report_dir: Path, engagement_file: Path) -> str:
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
            if isinstance(item, dict) and item.get("kind") == "testing_preflight"
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
            source_ready=preflight.get("source_ready") if isinstance(preflight.get("source_ready"), list) else [],
            combined=preflight.get("combined") if isinstance(preflight.get("combined"), list) else [],
            deferred=preflight.get("deferred") if isinstance(preflight.get("deferred"), list) else [],
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
        report_dir = orchestrator.run(args.engagement_id)
    except Exception as exc:
        print(f"mosh failed: {exc}", file=sys.stderr)
        return 1
    print(f"Final report written to {report_dir / 'report.md'}")
    return 0


def _print_event(event: Event) -> None:
    print(f"[{event.timestamp}] {event.agent}: {event.message}")


if __name__ == "__main__":
    raise SystemExit(main())
