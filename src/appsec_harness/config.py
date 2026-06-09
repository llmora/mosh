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
    security_test_critic: str = "deepseek/deepseek-v4-pro"
    security_test_finalizer: str = "deepseek/deepseek-v4-flash"
    engagement_template_refiner: str = "deepseek/deepseek-v4-flash"
    security_test_executor: str = "deepseek/deepseek-v4-flash"
    security_test_reviewer: str = "deepseek/deepseek-v4-pro"
    security_test_reporter: str = "deepseek/deepseek-v4-flash"


@dataclass(frozen=True)
class AppConfig:
    openrouter_api_key: str | None = None
    deepseek_api_key: str | None = None
    models: AgentModelConfig = field(default_factory=AgentModelConfig)
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
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
            deepseek_api_key=os.getenv("DEEPSEEK_API_KEY"),
            openrouter_base_url=os.getenv("APPSEC_HARNESS_OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
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

    def llm_api_key_for_model(self, model: str) -> str | None:
        if self.uses_direct_deepseek(model):
            return self.deepseek_api_key
        return self.openrouter_api_key

    def llm_api_key_name_for_model(self, model: str) -> str:
        if self.uses_direct_deepseek(model):
            return "DEEPSEEK_API_KEY"
        return "OPENROUTER_API_KEY"

    def llm_provider_for_model(self, model: str) -> str:
        if self.uses_direct_deepseek(model):
            return "deepseek"
        return "openai"

    def llm_model_name(self, model: str) -> str:
        if self.uses_direct_deepseek(model):
            return _direct_deepseek_model(model)
        return _openrouter_model(model)

    def uses_direct_deepseek(self, model: str) -> bool:
        return bool(self.deepseek_api_key and _is_deepseek_model(model))

    def missing_llm_api_keys_for_models(self, models: list[str]) -> list[str]:
        missing = {
            self.llm_api_key_name_for_model(model)
            for model in models
            if not self.llm_api_key_for_model(model)
        }
        return sorted(missing)


def _is_deepseek_model(model: str) -> bool:
    normalized = model.strip().lower()
    return (
        normalized.startswith("deepseek/")
        or normalized.startswith("openrouter/deepseek/")
        or normalized.startswith("deepseek-")
    )


def _direct_deepseek_model(model: str) -> str:
    normalized = model.strip()
    if normalized.startswith("openrouter/deepseek/"):
        return normalized.removeprefix("openrouter/deepseek/")
    if normalized.startswith("deepseek/"):
        return normalized.removeprefix("deepseek/")
    if normalized.startswith("openrouter/"):
        return normalized.removeprefix("openrouter/")
    return normalized


def _openrouter_model(model: str) -> str:
    normalized = model.strip()
    return normalized.removeprefix("openrouter/")


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
