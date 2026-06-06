from __future__ import annotations

from pathlib import Path
from typing import Callable

from appsec_harness.agents import discovery_agent_definitions
from appsec_harness.config import AppConfig
from appsec_harness.discovery_crew import DiscoveryCrewRunner, build_discovery_crew_runner
from appsec_harness.memory import FileMemory
from appsec_harness.models import Event
from appsec_harness.scope import report_dir_name


class DiscoveryOrchestrator:
    def __init__(
        self,
        config: AppConfig,
        output_root: Path = Path("report"),
        event_sink: Callable[[Event], None] | None = None,
        crew_runner: DiscoveryCrewRunner | None = None,
    ) -> None:
        self.config = config
        self.output_root = output_root
        self.event_sink = event_sink
        self.crew_runner = crew_runner or build_discovery_crew_runner(config)

    def run(self, url: str, max_pages: int = 200, max_depth: int | None = None) -> Path:
        max_depth = max_depth if max_depth is not None else self.config.max_depth
        agent_definitions = discovery_agent_definitions(self.config)
        report_dir = self.output_root / report_dir_name(url) / "discovery"
        memory = FileMemory(report_dir, event_sink=self.event_sink)
        memory.record_event(
            "orchestrator",
            "start",
            "Starting discovery crew",
            {
                "target": url,
                "agents": [agent.to_dict() for agent in agent_definitions],
            },
        )
        self.crew_runner.run(url, report_dir, memory, max_pages=max_pages, max_depth=max_depth)
        memory.record_event(
            "orchestrator",
            "complete",
            "Discovery crew completed",
            {"report_dir": str(report_dir)},
        )
        return report_dir
