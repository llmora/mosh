from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

from appsec_harness.agents import CrawlerAgent, SbomCompilerAgent, SummarizerAgent, build_discovery_agents
from appsec_harness.config import AppConfig
from appsec_harness.memory import FileMemory
from appsec_harness.models import CrawlResult
from appsec_harness.reporting import write_reports


OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
CREW_CONFIG_PACKAGE = "appsec_harness.crew_config"


@dataclass
class DiscoveryCrewState:
    target_url: str
    report_dir: Path
    memory: FileMemory
    max_pages: int
    max_depth: int
    crawl: CrawlResult | None = None
    components: list[dict[str, str]] | None = None
    summary: dict[str, int] | None = None


@dataclass(frozen=True)
class DiscoveryCrewResult:
    crawl: CrawlResult
    components: list[dict[str, str]]
    summary: dict[str, int]


class DiscoveryCrewRunner(Protocol):
    def run(
        self,
        target_url: str,
        report_dir: Path,
        memory: FileMemory,
        max_pages: int,
        max_depth: int,
    ) -> DiscoveryCrewResult:
        pass


class CrewAIUnavailable(RuntimeError):
    pass


class CrewAIDiscoveryCrewRunner:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def run(
        self,
        target_url: str,
        report_dir: Path,
        memory: FileMemory,
        max_pages: int,
        max_depth: int,
    ) -> DiscoveryCrewResult:
        if not self.config.openrouter_api_key:
            raise CrewAIUnavailable("OPENROUTER_API_KEY is not set.")

        crewai = _load_crewai()
        state = DiscoveryCrewState(
            target_url=target_url,
            report_dir=report_dir,
            memory=memory,
            max_pages=max_pages,
            max_depth=max_depth,
        )

        memory.record_event(
            "orchestrator",
            "crew_start",
            "Starting CrewAI discovery crew",
            {"target": target_url},
        )

        discovery_agents = build_discovery_agents(self.config)
        crawler_agent = discovery_agents.crawler
        sbom_agent = discovery_agents.sbom_compiler
        summarizer_agent = discovery_agents.summarizer

        crew = _build_yaml_discovery_crew(
            crewai=crewai,
            config=self.config,
            state=state,
            crawler_agent=crawler_agent,
            sbom_agent=sbom_agent,
            summarizer_agent=summarizer_agent,
        )
        crew.crew().kickoff(
            inputs={
                "target_url": target_url,
                "max_pages": max_pages,
                "max_depth": max_depth,
            }
        )

        if not state.crawl:
            raise RuntimeError("CrewAI crawler agent did not produce crawl findings.")
        if state.components is None:
            raise RuntimeError("CrewAI SBOM/component agent did not produce component findings.")
        if state.summary is None:
            raise RuntimeError("CrewAI summarizer agent did not write the report.")

        memory.record_event(
            "orchestrator",
            "crew_complete",
            "CrewAI discovery crew completed",
            {"target": target_url},
        )
        return DiscoveryCrewResult(crawl=state.crawl, components=state.components, summary=state.summary)


def build_discovery_crew_runner(config: AppConfig) -> DiscoveryCrewRunner:
    return CrewAIDiscoveryCrewRunner(config)


def _load_crewai():
    try:
        from crewai import Agent, Crew, LLM, Process, Task
        from crewai.project import CrewBase, agent, crew, task
        from crewai.tools import BaseTool
        from pydantic import BaseModel, Field
    except ModuleNotFoundError as exc:
        raise CrewAIUnavailable("CrewAI is not installed. Install project dependencies with `pip install -e .`.") from exc

    class CrewAIModule:
        pass

    crewai = CrewAIModule()
    crewai.Agent = Agent
    crewai.Crew = Crew
    crewai.LLM = LLM
    crewai.Process = Process
    crewai.Task = Task
    crewai.CrewBase = CrewBase
    crewai.agent = agent
    crewai.crew = crew
    crewai.task = task
    crewai.BaseTool = BaseTool
    crewai.BaseModel = BaseModel
    crewai.Field = Field
    return crewai


def _llm(crewai: Any, model: str, api_key: str):
    return crewai.LLM(
        model=_openrouter_model(model),
        base_url=OPENROUTER_BASE_URL,
        api_key=api_key,
        temperature=0,
    )


def _build_yaml_discovery_crew(
    crewai: Any,
    config: AppConfig,
    state: DiscoveryCrewState,
    crawler_agent: CrawlerAgent,
    sbom_agent: SbomCompilerAgent,
    summarizer_agent: SummarizerAgent,
):
    crawler_tool = _build_crawler_tool(crewai, state, crawler_agent)
    component_tool = _build_component_tool(crewai, state, sbom_agent)
    report_tool = _build_report_tool(crewai, state, summarizer_agent)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("tasks.yaml"))

    @crewai.CrewBase
    class DiscoveryCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def crawler(self):
            return crewai.Agent(
                config=self.agents_config["crawler"],
                llm=_llm(crewai, config.models.crawler, config.openrouter_api_key),
                tools=[crawler_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def sbom_compiler(self):
            return crewai.Agent(
                config=self.agents_config["sbom_compiler"],
                llm=_llm(crewai, config.models.sbom_compiler, config.openrouter_api_key),
                tools=[component_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def summarizer(self):
            return crewai.Agent(
                config=self.agents_config["summarizer"],
                llm=_llm(crewai, config.models.summarizer, config.openrouter_api_key),
                tools=[report_tool],
                allow_delegation=False,
            )

        @crewai.task
        def crawl_application_task(self):
            return crewai.Task(config=self.tasks_config["crawl_application_task"], agent=self.crawler())

        @crewai.task
        def compile_components_task(self):
            return crewai.Task(config=self.tasks_config["compile_components_task"], agent=self.sbom_compiler())

        @crewai.task
        def write_report_task(self):
            return crewai.Task(config=self.tasks_config["write_report_task"], agent=self.summarizer())

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=self.agents,
                tasks=self.tasks,
                process=crewai.Process.sequential,
                verbose=True,
            )

    return DiscoveryCrew()


def _build_crawler_tool(crewai: Any, state: DiscoveryCrewState, crawler_agent: CrawlerAgent):
    class CrawlInput(crewai.BaseModel):
        target_url: str = crewai.Field(..., description="Target URL to crawl.")

    class DiscoveryCrawlerTool(crewai.BaseTool):
        name: str = "crawl_application_surface"
        description: str = "Discover in-scope application pages, links, references, files, forms, and out-of-scope URLs."
        args_schema: type[crewai.BaseModel] = CrawlInput

        def _run(self, target_url: str) -> str:
            try:
                state.crawl = crawler_agent.discover(
                    target_url,
                    state.memory,
                    max_pages=state.max_pages,
                    max_depth=state.max_depth,
                )
                return json.dumps(state.crawl.to_dict(), sort_keys=True)
            except Exception as exc:
                state.memory.record_event(
                    "crawler",
                    "tool_error",
                    "crawl_application_surface failed",
                    {"error": str(exc), "error_type": type(exc).__name__},
                )
                raise

    return DiscoveryCrawlerTool()


def _build_component_tool(crewai: Any, state: DiscoveryCrewState, sbom_agent: SbomCompilerAgent):
    class ComponentInput(crewai.BaseModel):
        reason: str = crewai.Field(..., description="Why component inventory is being compiled.")

    class ComponentInventoryTool(crewai.BaseTool):
        name: str = "compile_component_inventory"
        description: str = "Compile observable remote component inventory from crawler findings."
        args_schema: type[crewai.BaseModel] = ComponentInput

        def _run(self, reason: str) -> str:
            if not state.crawl:
                raise RuntimeError("Crawler findings are required before component inventory.")
            state.components = sbom_agent.compile_inventory(state.crawl, state.memory)
            return json.dumps({"components": state.components, "reason": reason}, sort_keys=True)

    return ComponentInventoryTool()


def _build_report_tool(crewai: Any, state: DiscoveryCrewState, summarizer_agent: SummarizerAgent):
    class ReportInput(crewai.BaseModel):
        markdown_report: str = crewai.Field(
            ...,
            description="Complete Markdown report authored by the summarizer agent. This exact content is written to report.md.",
        )
        report_json: Any | None = crewai.Field(
            default=None,
            description="Optional structured report content authored by the summarizer agent for report.json.",
        )

    class WriteDiscoveryReportTool(crewai.BaseTool):
        name: str = "write_discovery_report"
        description: str = "Persist the summarizer agent's Markdown report and structured JSON report artifacts."
        args_schema: type[crewai.BaseModel] = ReportInput

        def _run(self, markdown_report: str, report_json: Any | None = None) -> str:
            if not state.crawl:
                raise RuntimeError("Crawler findings are required before writing the report.")
            components = state.components or []
            state.summary = summarizer_agent.summarize(state.crawl, components, state.memory)
            agent_report = _coerce_agent_report(report_json)
            state.memory.add_item(
                "llm_report",
                {
                    "markdown": markdown_report,
                    "structured": agent_report,
                },
                "summarizer",
            )
            state.memory.record_event(
                "summarizer",
                "report_written",
                "Summarizer agent wrote discovery report artifacts",
                {
                    "report_dir": str(state.report_dir),
                    "markdown_bytes": len(markdown_report.encode("utf-8")),
                    "structured_keys": sorted(agent_report.keys()),
                },
            )
            write_reports(
                state.report_dir,
                state.crawl.start_url,
                state.crawl,
                components,
                state.summary,
                markdown_report,
                agent_report=agent_report,
            )
            return json.dumps(
                {
                    "report_dir": str(state.report_dir),
                    "summary": state.summary,
                    "markdown_bytes": len(markdown_report.encode("utf-8")),
                    "structured_keys": sorted(agent_report.keys()),
                },
                sort_keys=True,
            )

    return WriteDiscoveryReportTool()


def _openrouter_model(model: str) -> str:
    return model if model.startswith("openrouter/") else f"openrouter/{model}"


def _coerce_agent_report(report_json: Any | None) -> dict[str, Any]:
    if report_json is None:
        return {}
    if isinstance(report_json, dict):
        return report_json
    if isinstance(report_json, str):
        report_json = report_json.strip()
        if not report_json:
            return {}
        try:
            parsed = json.loads(report_json)
        except json.JSONDecodeError:
            return {"raw": report_json}
        if isinstance(parsed, dict):
            return parsed
        return {"content": parsed}
    return {"content": report_json}
