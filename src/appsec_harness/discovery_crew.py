from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

from appsec_harness.agents import CrawlerAgent, SummarizerAgent, build_discovery_agents
from appsec_harness.config import AppConfig
from appsec_harness.memory import FileMemory
from appsec_harness.models import CrawlResult
from appsec_harness.reporting import write_reports
from appsec_harness.scope import normalize_url


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
    crawl_results: dict[str, CrawlResult] = field(default_factory=dict)
    components: list[dict[str, str]] = field(default_factory=list)
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
        summarizer_agent = discovery_agents.summarizer

        crew = _build_yaml_discovery_crew(
            crewai=crewai,
            config=self.config,
            state=state,
            crawler_agent=crawler_agent,
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
    summarizer_agent: SummarizerAgent,
):
    crawler_tool = _build_crawler_tool(crewai, state, crawler_agent)
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
                tools=[],
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
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["crawl_application_task"],
                agent=self.crawler(),
                agent_name="crawler",
                task_name="crawl_application_task",
            )

        @crewai.task
        def compile_components_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["compile_components_task"],
                agent=self.sbom_compiler(),
                agent_name="sbom_compiler",
                task_name="compile_components_task",
            )

        @crewai.task
        def write_report_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["write_report_task"],
                agent=self.summarizer(),
                agent_name="summarizer",
                task_name="write_report_task",
            )

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
                canonical_url = normalize_url(target_url)
                if canonical_url in state.crawl_results:
                    state.memory.record_event(
                        "crawler",
                        "tool_skip",
                        "Skipping crawl_application_surface because URL was already crawled",
                        {
                            "url": target_url,
                            "canonical_url": canonical_url,
                            "crawled_urls": sorted(state.crawl_results.keys()),
                        },
                    )
                    return json.dumps(
                        {
                            "skipped": True,
                            "reason": "already_crawled",
                            "canonical_url": canonical_url,
                            "crawled_urls": sorted(state.crawl_results.keys()),
                            "crawl": state.crawl.to_dict() if state.crawl else state.crawl_results[canonical_url].to_dict(),
                        },
                        sort_keys=True,
                    )

                crawl = crawler_agent.discover(
                    target_url,
                    state.memory,
                    max_pages=state.max_pages,
                    max_depth=state.max_depth,
                )
                state.crawl_results[canonical_url] = crawl
                state.crawl = _merge_crawl_results(state.crawl, crawl)
                state.memory.add_item(
                    "crawl_registry",
                    {"urls": sorted(state.crawl_results.keys())},
                    "crawler",
                )
                return json.dumps(
                    {
                        "skipped": False,
                        "canonical_url": canonical_url,
                        "crawled_urls": sorted(state.crawl_results.keys()),
                        "crawl": state.crawl.to_dict(),
                    },
                    sort_keys=True,
                )
            except Exception as exc:
                state.memory.record_event(
                    "crawler",
                    "tool_error",
                    "crawl_application_surface failed",
                    {"error": str(exc), "error_type": type(exc).__name__},
                )
                raise

    return DiscoveryCrawlerTool()


def _build_report_tool(crewai: Any, state: DiscoveryCrewState, summarizer_agent: SummarizerAgent):
    class NarrativeItem(crewai.BaseModel):
        title: str = crewai.Field(..., description="Short stable item title.")
        detail: str = crewai.Field(..., description="Concise item detail.")
        confidence: str | None = crewai.Field(default=None, description="confirmed, likely, possible, inferred, or unknown.")
        evidence: list[str] = crewai.Field(default_factory=list, description="Observable evidence or source URLs.")

    class RouteItem(crewai.BaseModel):
        url: str = crewai.Field(..., description="Route or URL.")
        status: str | int | None = crewai.Field(default=None, description="Observed HTTP status when known.")
        content_type: str | None = crewai.Field(default=None, description="Observed content type when known.")
        notes: str | None = crewai.Field(default=None, description="Short route notes.")
        evidence: list[str] = crewai.Field(default_factory=list, description="Evidence or source references.")

    class ApiEndpointItem(crewai.BaseModel):
        endpoint: str = crewai.Field(..., description="Endpoint URL or path.")
        method: str | None = crewai.Field(default=None, description="Observed or inferred HTTP method.")
        status: str | int | None = crewai.Field(default=None, description="Observed status when known.")
        purpose: str | None = crewai.Field(default=None, description="Endpoint purpose.")
        confidence: str | None = crewai.Field(default=None, description="confirmed, likely, possible, inferred, or unknown.")
        evidence: list[str] = crewai.Field(default_factory=list, description="Observable evidence or source URLs.")

    class FormItem(crewai.BaseModel):
        page: str = crewai.Field(..., description="Page URL where the form was observed or inferred.")
        type: str | None = crewai.Field(default=None, description="Form type or purpose.")
        fields: list[str] = crewai.Field(default_factory=list, description="Observed or inferred fields.")
        method: str | None = crewai.Field(default=None, description="Observed or inferred HTTP method.")
        notes: str | None = crewai.Field(default=None, description="Short form notes.")

    class ComponentItem(crewai.BaseModel):
        name: str = crewai.Field(..., description="Component or service name.")
        type: str | None = crewai.Field(default=None, description="Component category.")
        version: str | None = crewai.Field(default=None, description="Version if visible.")
        confidence: str | None = crewai.Field(default=None, description="confirmed, likely, possible, inferred, or unknown.")
        evidence: list[str] = crewai.Field(default_factory=list, description="Observable evidence or source URLs.")

    class NextStepItem(crewai.BaseModel):
        priority: str = crewai.Field(..., description="Priority such as critical, high, medium, low, or informational.")
        action: str = crewai.Field(..., description="Recommended action.")
        rationale: str = crewai.Field(..., description="Reason for the recommendation.")

    class DiscoveryMarkdownReport(crewai.BaseModel):
        title: str = crewai.Field(..., description="Report title.")
        executive_summary: str = crewai.Field(..., description="Short executive summary.")
        application_description: str = crewai.Field(..., description="High-level description of what the application appears to do.")
        target_scope: list[NarrativeItem] = crewai.Field(default_factory=list)
        key_discovered_areas: list[NarrativeItem] = crewai.Field(default_factory=list)
        discovered_routes: list[RouteItem] = crewai.Field(default_factory=list)
        api_endpoints: list[ApiEndpointItem] = crewai.Field(default_factory=list)
        forms: list[FormItem] = crewai.Field(default_factory=list)
        technologies: list[ComponentItem] = crewai.Field(default_factory=list)
        third_party_services: list[ComponentItem] = crewai.Field(default_factory=list)
        authentication_observations: list[NarrativeItem] = crewai.Field(default_factory=list)
        confirmed_findings: list[NarrativeItem] = crewai.Field(default_factory=list)
        inferred_findings: list[NarrativeItem] = crewai.Field(default_factory=list)
        limitations: list[NarrativeItem] = crewai.Field(default_factory=list)
        recommended_next_steps: list[NextStepItem] = crewai.Field(default_factory=list)
        appendix: list[NarrativeItem] = crewai.Field(default_factory=list)

    class ReportInput(crewai.BaseModel):
        report: DiscoveryMarkdownReport = crewai.Field(
            ...,
            description="Structured report content. The tool renders report.md in a fixed layout from this object.",
        )

    class WriteDiscoveryReportTool(crewai.BaseTool):
        name: str = "write_discovery_report"
        description: str = "Persist the summarizer agent's structured discovery content as a stable Markdown report."
        args_schema: type[crewai.BaseModel] = ReportInput

        def _run(self, report: Any) -> str:
            if not state.crawl:
                raise RuntimeError("Crawler findings are required before writing the report.")
            state.summary = summarizer_agent.summarize(state.crawl, state.components, state.memory)
            report_content = _coerce_report_content(report)
            state.memory.add_item(
                "llm_report",
                {
                    "structured": report_content,
                },
                "summarizer",
            )
            markdown_report = write_reports(
                state.report_dir,
                state.crawl.start_url,
                state.crawl,
                state.components,
                state.summary,
                report_content,
            )
            state.memory.record_event(
                "summarizer",
                "report_written",
                "Summarizer agent wrote Markdown discovery report",
                {
                    "report_dir": str(state.report_dir),
                    "markdown_bytes": len(markdown_report.encode("utf-8")),
                    "structured_keys": sorted(report_content.keys()),
                },
            )
            return json.dumps(
                {
                    "report_dir": str(state.report_dir),
                    "summary": state.summary,
                    "markdown_bytes": len(markdown_report.encode("utf-8")),
                    "structured_keys": sorted(report_content.keys()),
                },
                sort_keys=True,
            )

    return WriteDiscoveryReportTool()


def _openrouter_model(model: str) -> str:
    return model if model.startswith("openrouter/") else f"openrouter/{model}"


def _build_task_with_output_event(
    crewai: Any,
    state: DiscoveryCrewState,
    *,
    config: dict[str, Any],
    agent: Any,
    agent_name: str,
    task_name: str,
):
    callback = _agent_output_callback(state, agent_name, task_name)
    try:
        return crewai.Task(config=config, agent=agent, callback=callback)
    except TypeError as exc:
        if "callback" not in str(exc):
            raise
        state.memory.record_event(
            "orchestrator",
            "agent_output_capture_unavailable",
            "CrewAI Task does not accept callback; agent output capture is unavailable",
            {"agent": agent_name, "task": task_name},
        )
        return crewai.Task(config=config, agent=agent)


def _agent_output_callback(state: DiscoveryCrewState, agent_name: str, task_name: str):
    def callback(output: Any) -> None:
        state.memory.record_event(
            agent_name,
            "agent_output",
            f"{agent_name} completed {task_name}",
            {
                "task": task_name,
                "output": _serialize_agent_output(output),
            },
        )

    return callback


def _serialize_agent_output(output: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"text": str(output)}
    for attr in ("raw", "json_dict", "pydantic"):
        if hasattr(output, attr):
            data[attr] = _json_safe(getattr(output, attr))
    return data


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _coerce_report_content(report: Any | None) -> dict[str, Any]:
    if report is None:
        return {}
    if isinstance(report, dict):
        return report
    if hasattr(report, "model_dump"):
        dumped = report.model_dump(mode="json")
        return dumped if isinstance(dumped, dict) else {"content": dumped}
    if hasattr(report, "dict"):
        dumped = report.dict()
        return dumped if isinstance(dumped, dict) else {"content": dumped}
    if isinstance(report, str):
        report = report.strip()
        if not report:
            return {}
        try:
            parsed = json.loads(report)
        except json.JSONDecodeError:
            return {"executive_summary": report}
        if isinstance(parsed, dict):
            return parsed
        return {"content": parsed}
    return {"content": report}


def _merge_crawl_results(existing: CrawlResult | None, new: CrawlResult) -> CrawlResult:
    if existing is None:
        return new

    pages_by_url = {page.url: page for page in existing.pages}
    for page in new.pages:
        current = pages_by_url.get(page.url)
        if current is None or (current.status == 0 and page.status != 0):
            pages_by_url[page.url] = page
    candidates_by_key = {(candidate.url, candidate.source_tool): candidate for candidate in existing.candidates}
    for candidate in new.candidates:
        candidates_by_key.setdefault((candidate.url, candidate.source_tool), candidate)

    return CrawlResult(
        start_url=existing.start_url,
        pages=sorted(pages_by_url.values(), key=lambda page: page.url),
        out_of_scope=sorted({*existing.out_of_scope, *new.out_of_scope}),
        failed=[*existing.failed, *new.failed],
        robots=existing.robots or new.robots,
        candidates=sorted(candidates_by_key.values(), key=lambda candidate: (candidate.url, candidate.source_tool)),
    )
