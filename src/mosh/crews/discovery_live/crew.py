from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Callable, Protocol

from mosh.config import AppConfig
from mosh.crews.harness_improvements import build_harness_improvement_tool
from mosh.crews.discovery_live.agents import (
    CrawlerAgent,
    DiscoveryLiveReporterAgent,
    build_discovery_live_agents,
    discovery_live_agent_definitions,
)
from mosh.crews.events import MoshCrewAIEventListener
from mosh.engagement import engagement_steer_prompt_value
from mosh.memory import FileMemory
from mosh.models import Event
from mosh.models import CrawlResult
from mosh.crews.discovery_live.reporting import write_reports
from mosh.scope import normalize_url


CREW_CONFIG_PACKAGE = "mosh.crews"


@dataclass
class DiscoveryLiveCrewState:
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
class DiscoveryLiveCrewResult:
    crawl: CrawlResult
    components: list[dict[str, str]]
    summary: dict[str, int]


class DiscoveryLiveCrewRunner(Protocol):
    def run(
        self,
        target_url: str,
        report_dir: Path,
        memory: FileMemory,
        max_pages: int,
        max_depth: int,
        engagement_steer: str = "",
    ) -> DiscoveryLiveCrewResult:
        pass


class CrewAIUnavailable(RuntimeError):
    pass


class CrewAIDiscoveryLiveCrewRunner:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def run(
        self,
        target_url: str,
        report_dir: Path,
        memory: FileMemory,
        max_pages: int,
        max_depth: int,
        engagement_steer: str = "",
    ) -> DiscoveryLiveCrewResult:
        missing_settings = self.config.missing_llm_settings_for_models(
            [
                self.config.models.discovery_live.crawler,
                self.config.models.discovery_live.technology_mapper,
                self.config.models.discovery_live.reporter,
            ]
        )
        if missing_settings:
            raise CrewAIUnavailable(f"Missing LLM setting(s): {', '.join(missing_settings)}.")

        crewai = _load_crewai()
        state = DiscoveryLiveCrewState(
            target_url=target_url,
            report_dir=report_dir,
            memory=memory,
            max_pages=max_pages,
            max_depth=max_depth,
        )

        memory.record_event(
            "orchestrator",
            "crew_start",
            "Starting CrewAI live discovery crew",
            {
                "target": target_url,
                "engagement_steer_chars": len(engagement_steer.strip()),
            },
        )

        discovery_agents = build_discovery_live_agents(self.config)
        crawler_agent = discovery_agents.crawler
        reporter_agent = discovery_agents.reporter

        crew = _build_yaml_discovery_crew(
            crewai=crewai,
            config=self.config,
            state=state,
            crawler_agent=crawler_agent,
            reporter_agent=reporter_agent,
        )
        crew.crew().kickoff(
            inputs={
                "target_url": target_url,
                "max_pages": max_pages,
                "max_depth": max_depth,
                "engagement_steer": engagement_steer_prompt_value(engagement_steer),
            }
        )

        if not state.crawl:
            raise RuntimeError("CrewAI crawler agent did not produce crawl findings.")
        if state.summary is None:
            raise RuntimeError("CrewAI reporter agent did not write the report.")

        memory.record_event(
            "orchestrator",
            "crew_complete",
            "CrewAI live discovery crew completed",
            {"target": target_url},
        )
        return DiscoveryLiveCrewResult(crawl=state.crawl, components=state.components, summary=state.summary)


def build_discovery_live_crew_runner(config: AppConfig) -> DiscoveryLiveCrewRunner:
    return CrewAIDiscoveryLiveCrewRunner(config)


class DiscoveryLiveOrchestrator:
    def __init__(
        self,
        config: AppConfig,
        output_root: Path = Path("report"),
        event_sink: Callable[[Event], None] | None = None,
        crew_runner: DiscoveryLiveCrewRunner | None = None,
    ) -> None:
        self.config = config
        self.output_root = output_root
        self.event_sink = event_sink
        self.crew_runner = crew_runner or build_discovery_live_crew_runner(config)

    def run(
        self,
        url: str,
        max_pages: int = 200,
        max_depth: int | None = None,
        *,
        report_dir: Path,
        engagement_steer: str = "",
    ) -> Path:
        max_depth = max_depth if max_depth is not None else self.config.max_depth
        agent_definitions = discovery_live_agent_definitions(self.config)
        memory = FileMemory(report_dir, event_sink=self.event_sink)
        memory.record_event(
            "orchestrator",
            "start",
            "Starting live discovery crew",
            {
                "target": url,
                "agents": [agent.to_dict() for agent in agent_definitions],
            },
        )
        self.crew_runner.run(
            url,
            report_dir,
            memory,
            max_pages=max_pages,
            max_depth=max_depth,
            engagement_steer=engagement_steer,
        )
        memory.record_event(
            "orchestrator",
            "complete",
            "Live discovery crew completed",
            {"report_dir": str(report_dir)},
        )
        return report_dir


def _load_crewai():
    try:
        from crewai import Agent, Crew, LLM, Process, Task
        from crewai.events import BaseEventListener
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
    crewai.BaseEventListener = BaseEventListener
    return crewai


def _llm(crewai: Any, config: AppConfig, model: str, *, max_tokens: int | None = None):
    api_key = config.llm_api_key_for_model(model)
    if not api_key:
        raise CrewAIUnavailable(f"{config.llm_api_key_name_for_model(model)} is not set.")
    base_url = config.llm_base_url_for_model(model)
    if config.uses_custom_llm(model) and not base_url:
        raise CrewAIUnavailable("MOSH_LLM_BASE_URL is not set.")
    kwargs = {
        "model": config.llm_model_name(model),
        "provider": config.llm_provider_for_model(model),
        "api_key": api_key,
        "temperature": 0,
    }
    if base_url:
        kwargs["base_url"] = base_url
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens
    return crewai.LLM(**kwargs)


def _build_yaml_discovery_crew(
    crewai: Any,
    config: AppConfig,
    state: DiscoveryLiveCrewState,
    crawler_agent: CrawlerAgent,
    reporter_agent: DiscoveryLiveReporterAgent,
):
    crawler_tool = _build_crawler_tool(crewai, state, crawler_agent)
    report_tool = _build_report_tool(crewai, state, reporter_agent)
    crawler_improvement_tool = build_harness_improvement_tool(
        crewai,
        state.memory,
        stage="discovery_live",
        agent="crawler",
    )
    technology_improvement_tool = build_harness_improvement_tool(
        crewai,
        state.memory,
        stage="discovery_live",
        agent="technology_mapper",
    )
    reporter_improvement_tool = build_harness_improvement_tool(
        crewai,
        state.memory,
        stage="discovery_live",
        agent="reporter",
    )
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("discovery_live/agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("discovery_live/tasks.yaml"))

    @crewai.CrewBase
    class DiscoveryCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def crawler(self):
            return crewai.Agent(
                config=self.agents_config["crawler"],
                llm=_llm(crewai, config, config.models.discovery_live.crawler),
                tools=[crawler_tool, crawler_improvement_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def technology_mapper(self):
            return crewai.Agent(
                config=self.agents_config["technology_mapper"],
                llm=_llm(crewai, config, config.models.discovery_live.technology_mapper),
                tools=[technology_improvement_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def reporter(self):
            return crewai.Agent(
                config=self.agents_config["reporter"],
                llm=_llm(crewai, config, config.models.discovery_live.reporter),
                tools=[report_tool, reporter_improvement_tool],
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
                agent=self.technology_mapper(),
                agent_name="technology_mapper",
                task_name="compile_components_task",
            )

        @crewai.task
        def write_report_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["write_report_task"],
                agent=self.reporter(),
                agent_name="reporter",
                task_name="write_report_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=self.agents,
                tasks=self.tasks,
                process=crewai.Process.sequential,
                verbose=True,
                event_listeners=[MoshCrewAIEventListener(state.memory)],
            )

    return DiscoveryCrew()


def _build_crawler_tool(crewai: Any, state: DiscoveryLiveCrewState, crawler_agent: CrawlerAgent):
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


def _build_report_tool(crewai: Any, state: DiscoveryLiveCrewState, reporter_agent: DiscoveryLiveReporterAgent):
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
        report: DiscoveryMarkdownReport | dict[str, Any] | str = crewai.Field(
            ...,
            description=(
                "Structured report content. Prefer passing a JSON object. "
                "A JSON string is accepted as a compatibility fallback."
            ),
        )

    class WriteDiscoveryReportTool(crewai.BaseTool):
        name: str = "write_discovery_report"
        description: str = "Persist the reporter agent's structured discovery content as a stable Markdown report."
        args_schema: type[crewai.BaseModel] = ReportInput

        def _run(self, report: Any) -> str:
            if not state.crawl:
                raise RuntimeError("Crawler findings are required before writing the report.")
            state.summary = reporter_agent.summarize(state.crawl, state.components, state.memory)
            report_content = _coerce_report_content(report)
            state.memory.add_item(
                "llm_report",
                {
                    "structured": report_content,
                },
                "reporter",
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
                "reporter",
                "report_written",
                "Discovery reporter wrote Markdown discovery report",
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



def _build_task_with_output_event(
    crewai: Any,
    state: DiscoveryLiveCrewState,
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


def _agent_output_callback(state: DiscoveryLiveCrewState, agent_name: str, task_name: str):
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
