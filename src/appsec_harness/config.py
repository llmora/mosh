from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentModelConfig:
    orchestrator: str = "deepseek/deepseek-v4-flash"
    crawler: str = "deepseek/deepseek-v4-flash"
    sbom_compiler: str = "deepseek/deepseek-v4-flash"
    summarizer: str = "deepseek/deepseek-v4-flash"
    security_test_planner: str = "deepseek/deepseek-v4-flash"
    security_test_critic: str = "openai/gpt-5.2"
    security_test_finalizer: str = "deepseek/deepseek-v4-flash"
    engagement_template_refiner: str = "deepseek/deepseek-v4-flash"
    security_test_executor: str = "deepseek/deepseek-v4-flash"
    security_test_reviewer: str = "deepseek/deepseek-v4-flash"
    security_test_reporter: str = "deepseek/deepseek-v4-flash"


@dataclass(frozen=True)
class AppConfig:
    openrouter_api_key: str | None = None
    models: AgentModelConfig = field(default_factory=AgentModelConfig)
    tool_image: str = "appsec-harness-discovery-tools:latest"
    security_tool_image: str = "appsec-harness-security-tools:latest"
    security_command_timeout: int = 300
    security_execution_max_revisions: int = 2
    katana_crawl_duration: str = "270s"
    katana_docker_timeout: int = 300
    dirb_wordlist: str = "/usr/share/dirb/wordlists/common.txt"
    dirb_docker_timeout: int = 120
    candidate_follow_up_limit: int = 5
    max_depth: int = 5
    planning_max_revisions: int = 1
    refine_engagement_template_with_llm: bool = True

    @classmethod
    def from_env(cls) -> "AppConfig":
        return cls(
            openrouter_api_key=os.getenv("OPENROUTER_API_KEY"),
            security_tool_image=os.getenv("APPSEC_HARNESS_SECURITY_TOOL_IMAGE", "appsec-harness-security-tools:latest"),
            security_command_timeout=int(os.getenv("APPSEC_HARNESS_SECURITY_COMMAND_TIMEOUT", "300")),
            security_execution_max_revisions=int(os.getenv("APPSEC_HARNESS_SECURITY_EXECUTION_MAX_REVISIONS", "2")),
            katana_crawl_duration=os.getenv("APPSEC_HARNESS_KATANA_CRAWL_DURATION", "270s"),
            katana_docker_timeout=int(os.getenv("APPSEC_HARNESS_KATANA_DOCKER_TIMEOUT", "300")),
            dirb_wordlist=os.getenv("APPSEC_HARNESS_DIRB_WORDLIST", "/usr/share/dirb/wordlists/common.txt"),
            dirb_docker_timeout=int(os.getenv("APPSEC_HARNESS_DIRB_DOCKER_TIMEOUT", "120")),
            candidate_follow_up_limit=int(os.getenv("APPSEC_HARNESS_CANDIDATE_FOLLOW_UP_LIMIT", "5")),
            max_depth=int(os.getenv("APPSEC_HARNESS_MAX_DEPTH", "5")),
            planning_max_revisions=int(os.getenv("APPSEC_HARNESS_PLANNING_MAX_REVISIONS", "1")),
            refine_engagement_template_with_llm=_env_bool("APPSEC_HARNESS_REFINE_ENGAGEMENT_TEMPLATE_WITH_LLM", True),
        )


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
