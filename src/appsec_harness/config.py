from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentModelConfig:
    orchestrator: str = "deepseek/deepseek-v4-flash"
    crawler: str = "deepseek/deepseek-v4-flash"
    sbom_compiler: str = "deepseek/deepseek-v4-flash"
    summarizer: str = "deepseek/deepseek-v4-flash"


@dataclass(frozen=True)
class AppConfig:
    openrouter_api_key: str | None = None
    models: AgentModelConfig = field(default_factory=AgentModelConfig)
    tool_image: str = "appsec-harness-discovery-tools:latest"
    katana_crawl_duration: str = "270s"
    katana_docker_timeout: int = 300
    max_depth: int = 3

    @classmethod
    def from_env(cls) -> "AppConfig":
        return cls(
            openrouter_api_key=os.getenv("OPENROUTER_API_KEY"),
            katana_crawl_duration=os.getenv("APPSEC_HARNESS_KATANA_CRAWL_DURATION", "270s"),
            katana_docker_timeout=int(os.getenv("APPSEC_HARNESS_KATANA_DOCKER_TIMEOUT", "300")),
            max_depth=int(os.getenv("APPSEC_HARNESS_MAX_DEPTH", "3")),
        )
