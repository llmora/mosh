from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DiscoveryModelConfig:
    crawler: str = "deepseek/deepseek-v4-flash"
    technology_mapper: str = "deepseek/deepseek-v4-flash"
    reporter: str = "deepseek/deepseek-v4-flash"


@dataclass(frozen=True)
class SecurityPlanningModelConfig:
    planner: str = "deepseek/deepseek-v4-flash"
    reviewer: str = "deepseek/deepseek-v4-pro"
    reporter: str = "deepseek/deepseek-v4-flash"
    engagement_refiner: str = "deepseek/deepseek-v4-flash"


@dataclass(frozen=True)
class SecurityTestingModelConfig:
    executor: str = "deepseek/deepseek-v4-flash"
    reviewer: str = "deepseek/deepseek-v4-pro"
    reporter: str = "deepseek/deepseek-v4-flash"


@dataclass(frozen=True)
class ReportingModelConfig:
    writer: str = "deepseek/deepseek-v4-flash"
    reviewer: str = "deepseek/deepseek-v4-pro"


@dataclass(frozen=True)
class AgentModelConfig:
    discovery: DiscoveryModelConfig = field(default_factory=DiscoveryModelConfig)
    security_planning: SecurityPlanningModelConfig = field(default_factory=SecurityPlanningModelConfig)
    security_testing: SecurityTestingModelConfig = field(default_factory=SecurityTestingModelConfig)
    reporting: ReportingModelConfig = field(default_factory=ReportingModelConfig)


@dataclass(frozen=True)
class AppConfig:
    openrouter_api_key: str | None = None
    deepseek_api_key: str | None = None
    models: AgentModelConfig = field(default_factory=AgentModelConfig)
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    tool_image: str = "osh-discovery-tools:latest"
    security_tool_image: str = "osh-security-tools:latest"
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
    def from_env(cls, config_path: str | Path = "osh.yaml") -> "AppConfig":
        models = _load_agent_model_config(Path(config_path))
        return cls(
            openrouter_api_key=os.getenv("OPENROUTER_API_KEY"),
            deepseek_api_key=os.getenv("DEEPSEEK_API_KEY"),
            models=models,
            openrouter_base_url=os.getenv("OSH_OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            security_tool_image=os.getenv("OSH_SECURITY_TOOL_IMAGE", "osh-security-tools:latest"),
            security_command_timeout=int(os.getenv("OSH_SECURITY_COMMAND_TIMEOUT", "300")),
            security_execution_max_revisions=int(os.getenv("OSH_SECURITY_EXECUTION_MAX_REVISIONS", "2")),
            katana_crawl_duration=os.getenv("OSH_KATANA_CRAWL_DURATION", "270s"),
            katana_docker_timeout=int(os.getenv("OSH_KATANA_DOCKER_TIMEOUT", "300")),
            dirb_wordlist=os.getenv("OSH_DIRB_WORDLIST", "/usr/share/dirb/wordlists/common.txt"),
            dirb_docker_timeout=int(os.getenv("OSH_DIRB_DOCKER_TIMEOUT", "120")),
            candidate_follow_up_limit=int(os.getenv("OSH_CANDIDATE_FOLLOW_UP_LIMIT", "5")),
            max_depth=int(os.getenv("OSH_MAX_DEPTH", "5")),
            planning_max_revisions=int(os.getenv("OSH_PLANNING_MAX_REVISIONS", "1")),
            refine_engagement_template_with_llm=_env_bool("OSH_REFINE_ENGAGEMENT_TEMPLATE_WITH_LLM", True),
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


def _load_agent_model_config(path: Path) -> AgentModelConfig:
    if not path.exists():
        return AgentModelConfig()
    data = _parse_osh_yaml(path.read_text(encoding="utf-8"), path)
    unknown_top_level = sorted(set(data) - {"models"})
    if unknown_top_level:
        raise ValueError(f"Unknown osh.yaml section(s): {', '.join(unknown_top_level)}.")
    raw_models = data.get("models", {})
    if raw_models is None:
        return AgentModelConfig()
    if not isinstance(raw_models, dict):
        raise ValueError("osh.yaml `models` must be grouped by crew.")

    defaults = AgentModelConfig()
    crew_configs = {
        "discovery": defaults.discovery,
        "reporting": defaults.reporting,
        "security_planning": defaults.security_planning,
        "security_testing": defaults.security_testing,
    }
    overrides: dict[str, object] = {}
    for crew_name, crew_values in raw_models.items():
        if crew_name not in crew_configs:
            valid = ", ".join(sorted(crew_configs))
            raise ValueError(f"Unknown model crew `models.{crew_name}` in osh.yaml. Valid crews: {valid}.")
        if not isinstance(crew_values, dict):
            raise ValueError(f"Model crew `models.{crew_name}` must be a mapping of agent names to model IDs.")
        crew_config = crew_configs[crew_name]
        valid_model_keys = {item.name for item in fields(crew_config)}
        crew_overrides: dict[str, str] = {}
        for key, value in crew_values.items():
            if key not in valid_model_keys:
                valid = ", ".join(sorted(valid_model_keys))
                raise ValueError(
                    f"Unknown model key `models.{crew_name}.{key}` in osh.yaml. Valid keys: {valid}."
                )
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Model key `models.{crew_name}.{key}` in osh.yaml must be a non-empty string.")
            crew_overrides[key] = value.strip()
        overrides[crew_name] = replace(crew_config, **crew_overrides)
    return replace(defaults, **overrides)


def _parse_osh_yaml(text: str, path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_section: str | None = None
    current_subsection: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if "\t" in raw_line:
            raise ValueError(f"{path}:{line_number}: tabs are not supported in osh.yaml.")
        indent = len(line) - len(line.lstrip(" "))
        key, value = _split_yaml_key_value(line.strip(), path, line_number)
        if indent == 0:
            if value is None:
                data[key] = {}
                current_section = key
                current_subsection = None
            else:
                data[key] = _parse_yaml_scalar(value)
                current_section = None
                current_subsection = None
            continue
        if indent == 2 and current_section:
            section = data[current_section]
            if not isinstance(section, dict):
                raise ValueError(f"{path}:{line_number}: cannot add nested values under `{current_section}`.")
            if value is None:
                section[key] = {}
                current_subsection = key
            else:
                section[key] = _parse_yaml_scalar(value)
                current_subsection = None
            continue
        if indent == 4 and current_section and current_subsection:
            section = data[current_section]
            if not isinstance(section, dict):
                raise ValueError(f"{path}:{line_number}: cannot add nested values under `{current_section}`.")
            subsection = section[current_subsection]
            if not isinstance(subsection, dict):
                raise ValueError(
                    f"{path}:{line_number}: cannot add nested values under `{current_section}.{current_subsection}`."
                )
            subsection[key] = _parse_yaml_scalar(value or "")
            continue
        raise ValueError(
            f"{path}:{line_number}: only top-level keys and two/four-space nested mappings are supported."
        )
    return data


def _split_yaml_key_value(line: str, path: Path, line_number: int) -> tuple[str, str | None]:
    if ":" not in line:
        raise ValueError(f"{path}:{line_number}: expected `key: value`.")
    key, value = line.split(":", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"{path}:{line_number}: key cannot be empty.")
    value = value.strip()
    return key, value if value else None


def _parse_yaml_scalar(value: str) -> str:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
