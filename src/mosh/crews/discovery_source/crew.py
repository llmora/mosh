from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Callable, Protocol

from mosh.config import AppConfig
from mosh.crews.discovery_live.crew import (
    CREW_CONFIG_PACKAGE,
    CrewAIUnavailable,
    _build_task_with_output_event,
    _llm,
    _load_crewai,
)
from mosh.crews.events import MoshCrewAIEventListener
from mosh.crews.discovery_source.agents import (
    DependencyConfigAgent,
    DiscoverySourceReporterAgent,
    SourceIntakeAgent,
    SourceMapperAgent,
    build_discovery_source_agents,
    discovery_source_agent_definitions,
)
from mosh.crews.discovery_source.reporting import write_discovery_source_report
from mosh.crews.discovery_source.tools import build_source_index
from mosh.memory import FileMemory
from mosh.models import Event


@dataclass
class DiscoverySourceCrewState:
    source: str
    report_dir: Path
    memory: FileMemory
    source_info: dict[str, Any] | None = None
    inventory: dict[str, Any] | None = None
    routes: dict[str, Any] | None = None
    route_resolution: dict[str, Any] | None = None
    dependencies: dict[str, Any] | None = None
    configuration: dict[str, Any] | None = None
    component_map: dict[str, Any] | None = None
    gap_analysis: dict[str, Any] | None = None
    summary: dict[str, Any] | None = None
    source_index: dict[str, Any] | None = None
    report_written: bool = False


@dataclass(frozen=True)
class DiscoverySourceCrewResult:
    source_index: dict[str, Any]
    summary: dict[str, Any]


class DiscoverySourceCrewRunner(Protocol):
    def run(self, source: str, report_dir: Path, memory: FileMemory) -> DiscoverySourceCrewResult:
        pass


class CrewAIDiscoverySourceCrewRunner:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def run(self, source: str, report_dir: Path, memory: FileMemory) -> DiscoverySourceCrewResult:
        missing_settings = self.config.missing_llm_settings_for_models(
            [
                self.config.models.discovery_source.intake,
                self.config.models.discovery_source.mapper,
                self.config.models.discovery_source.route_resolver,
                self.config.models.discovery_source.dependency_config,
                self.config.models.discovery_source.component_mapper,
                self.config.models.discovery_source.gap_analyst,
                self.config.models.discovery_source.reporter,
            ]
        )
        if missing_settings:
            raise CrewAIUnavailable(f"Missing LLM setting(s): {', '.join(missing_settings)}.")

        crewai = _load_crewai()
        state = DiscoverySourceCrewState(source=source, report_dir=report_dir, memory=memory)
        agents = build_discovery_source_agents(self.config)

        memory.record_event(
            "orchestrator",
            "crew_start",
            "Starting CrewAI source discovery crew",
            {"source": source},
        )
        crew = _build_yaml_discovery_source_crew(
            crewai=crewai,
            config=self.config,
            state=state,
            intake_agent=agents.intake,
            mapper_agent=agents.mapper,
            dependency_config_agent=agents.dependency_config,
            reporter_agent=agents.reporter,
        )
        crew.crew().kickoff(inputs={"source": source})

        if not state.source_index:
            raise RuntimeError("CrewAI source discovery reporter did not write a source index.")
        if not state.report_written:
            raise RuntimeError("CrewAI source discovery reporter did not write the report.")
        memory.record_event(
            "orchestrator",
            "crew_complete",
            "CrewAI source discovery crew completed",
            {"source": source},
        )
        return DiscoverySourceCrewResult(source_index=state.source_index, summary=state.summary or {})


def build_discovery_source_crew_runner(config: AppConfig) -> DiscoverySourceCrewRunner:
    return CrewAIDiscoverySourceCrewRunner(config)


class DiscoverySourceOrchestrator:
    def __init__(
        self,
        config: AppConfig,
        output_root: Path = Path("report"),
        event_sink: Callable[[Event], None] | None = None,
        crew_runner: DiscoverySourceCrewRunner | None = None,
    ) -> None:
        self.config = config
        self.output_root = output_root
        self.event_sink = event_sink
        self.crew_runner = crew_runner or build_discovery_source_crew_runner(config)

    def run(self, source: str, *, report_dir: Path) -> Path:
        memory = FileMemory(report_dir, event_sink=self.event_sink)
        agent_definitions = discovery_source_agent_definitions(self.config)
        memory.record_event(
            "orchestrator",
            "start",
            "Starting source discovery crew",
            {
                "source": source,
                "agents": [agent.to_dict() for agent in agent_definitions],
            },
        )
        self.crew_runner.run(source, report_dir, memory)
        memory.record_event(
            "orchestrator",
            "complete",
            "Source discovery crew completed",
            {"report_dir": str(report_dir)},
        )
        return report_dir


def _build_yaml_discovery_source_crew(
    *,
    crewai: Any,
    config: AppConfig,
    state: DiscoverySourceCrewState,
    intake_agent: SourceIntakeAgent,
    mapper_agent: SourceMapperAgent,
    dependency_config_agent: DependencyConfigAgent,
    reporter_agent: DiscoverySourceReporterAgent,
):
    validate_tool = _build_validate_source_path_tool(crewai, state, intake_agent)
    inventory_tool = _build_source_inventory_tool(crewai, state, mapper_agent)
    route_tool = _build_route_api_extractor_tool(crewai, state, mapper_agent)
    search_tool = _build_source_search_tool(crewai, state, mapper_agent)
    read_slice_tool = _build_read_source_slice_tool(crewai, state, mapper_agent)
    route_search_tool = _build_source_search_tool(crewai, state, mapper_agent, agent_name="source_route_resolver")
    route_read_slice_tool = _build_read_source_slice_tool(
        crewai,
        state,
        mapper_agent,
        agent_name="source_route_resolver",
    )
    route_context_tool = _build_route_resolution_context_tool(crewai, state)
    route_resolution_tool = _build_submit_route_resolution_tool(crewai, state)
    dependency_tool = _build_dependency_inventory_tool(crewai, state, dependency_config_agent)
    config_tool = _build_config_inventory_tool(crewai, state, dependency_config_agent)
    context_tool = _build_discovery_source_context_tool(crewai, state)
    component_map_tool = _build_submit_source_component_map_tool(crewai, state)
    gap_analysis_tool = _build_submit_source_gap_analysis_tool(crewai, state)
    report_tool = _build_write_discovery_source_report_tool(crewai, state, reporter_agent)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("discovery_source/agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("discovery_source/tasks.yaml"))

    @crewai.CrewBase
    class DiscoverySourceCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def source_intake(self):
            return crewai.Agent(
                config=self.agents_config["source_intake"],
                llm=_llm(crewai, config, config.models.discovery_source.intake),
                tools=[validate_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def source_mapper(self):
            return crewai.Agent(
                config=self.agents_config["source_mapper"],
                llm=_llm(crewai, config, config.models.discovery_source.mapper),
                tools=[inventory_tool, route_tool, search_tool, read_slice_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def dependency_config(self):
            return crewai.Agent(
                config=self.agents_config["dependency_config"],
                llm=_llm(crewai, config, config.models.discovery_source.dependency_config),
                tools=[dependency_tool, config_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def source_route_resolver(self):
            return crewai.Agent(
                config=self.agents_config["source_route_resolver"],
                llm=_llm(crewai, config, config.models.discovery_source.route_resolver),
                tools=[route_context_tool, route_search_tool, route_read_slice_tool, route_resolution_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def source_component_mapper(self):
            return crewai.Agent(
                config=self.agents_config["source_component_mapper"],
                llm=_llm(crewai, config, config.models.discovery_source.component_mapper),
                tools=[context_tool, component_map_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def source_gap_analyst(self):
            return crewai.Agent(
                config=self.agents_config["source_gap_analyst"],
                llm=_llm(crewai, config, config.models.discovery_source.gap_analyst),
                tools=[context_tool, gap_analysis_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def reporter(self):
            return crewai.Agent(
                config=self.agents_config["reporter"],
                llm=_llm(crewai, config, config.models.discovery_source.reporter),
                tools=[report_tool],
                allow_delegation=False,
            )

        @crewai.task
        def validate_source_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["validate_source_task"],
                agent=self.source_intake(),
                agent_name="source_intake",
                task_name="validate_source_task",
            )

        @crewai.task
        def map_source_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["map_source_task"],
                agent=self.source_mapper(),
                agent_name="source_mapper",
                task_name="map_source_task",
            )

        @crewai.task
        def inspect_dependency_config_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["inspect_dependency_config_task"],
                agent=self.dependency_config(),
                agent_name="dependency_config",
                task_name="inspect_dependency_config_task",
            )

        @crewai.task
        def resolve_source_routes_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["resolve_source_routes_task"],
                agent=self.source_route_resolver(),
                agent_name="source_route_resolver",
                task_name="resolve_source_routes_task",
            )

        @crewai.task
        def map_source_components_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["map_source_components_task"],
                agent=self.source_component_mapper(),
                agent_name="source_component_mapper",
                task_name="map_source_components_task",
            )

        @crewai.task
        def analyze_discovery_source_gaps_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["analyze_discovery_source_gaps_task"],
                agent=self.source_gap_analyst(),
                agent_name="source_gap_analyst",
                task_name="analyze_discovery_source_gaps_task",
            )

        @crewai.task
        def write_discovery_source_report_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["write_discovery_source_report_task"],
                agent=self.reporter(),
                agent_name="reporter",
                task_name="write_discovery_source_report_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[
                    self.source_intake(),
                    self.source_mapper(),
                    self.source_route_resolver(),
                    self.dependency_config(),
                    self.source_component_mapper(),
                    self.source_gap_analyst(),
                    self.reporter(),
                ],
                tasks=[
                    self.validate_source_task(),
                    self.map_source_task(),
                    self.resolve_source_routes_task(),
                    self.inspect_dependency_config_task(),
                    self.map_source_components_task(),
                    self.analyze_discovery_source_gaps_task(),
                    self.write_discovery_source_report_task(),
                ],
                process=crewai.Process.sequential,
                verbose=True,
                event_listeners=[MoshCrewAIEventListener(state.memory)],
            )

    return DiscoverySourceCrew()


def _build_validate_source_path_tool(crewai: Any, state: DiscoverySourceCrewState, agent: SourceIntakeAgent):
    class ValidateSourcePathInput(crewai.BaseModel):
        source: str = crewai.Field(..., description="Local filesystem path to the source tree.")

    class ValidateSourcePathCrewTool(crewai.BaseTool):
        name: str = "validate_source_path"
        description: str = "Validate a local source tree path and record source identity metadata."
        args_schema: type[crewai.BaseModel] = ValidateSourcePathInput

        def _run(self, source: str) -> str:
            source_info = agent.validate(source, state.memory)
            state.source_info = source_info
            return json.dumps(source_info, sort_keys=True)

    return ValidateSourcePathCrewTool()


def _build_source_inventory_tool(crewai: Any, state: DiscoverySourceCrewState, agent: SourceMapperAgent):
    class SourceInventoryInput(crewai.BaseModel):
        source: str = crewai.Field(..., description="Local filesystem path to inventory.")

    class SourceInventoryCrewTool(crewai.BaseTool):
        name: str = "source_inventory"
        description: str = "Build a compact file, language, manifest, and entrypoint inventory."
        args_schema: type[crewai.BaseModel] = SourceInventoryInput

        def _run(self, source: str) -> str:
            inventory = agent.inventory(_source_arg(state, source), state.memory)
            state.inventory = inventory
            return json.dumps(_tool_result_summary(inventory), sort_keys=True)

    return SourceInventoryCrewTool()


def _build_route_api_extractor_tool(crewai: Any, state: DiscoverySourceCrewState, agent: SourceMapperAgent):
    class RouteApiExtractorInput(crewai.BaseModel):
        source: str = crewai.Field(..., description="Local filesystem path to inspect for route definitions.")

    class RouteApiExtractorCrewTool(crewai.BaseTool):
        name: str = "route_api_extractor"
        description: str = "Extract likely HTTP route and API candidates from common framework patterns."
        args_schema: type[crewai.BaseModel] = RouteApiExtractorInput

        def _run(self, source: str) -> str:
            routes = agent.routes(_source_arg(state, source), state.memory)
            state.routes = routes
            return json.dumps({"routes": len(routes.get("routes") or [])}, sort_keys=True)

    return RouteApiExtractorCrewTool()


def _build_source_search_tool(
    crewai: Any,
    state: DiscoverySourceCrewState,
    agent: SourceMapperAgent,
    agent_name: str = "source_mapper",
):
    class SourceSearchInput(crewai.BaseModel):
        source: str = crewai.Field(..., description="Local filesystem path to search.")
        pattern: str = crewai.Field(..., description="Literal or regex search pattern.")
        regex: bool = crewai.Field(False, description="Whether pattern is a regular expression.")
        limit: int = crewai.Field(50, description="Maximum matches to return.")

    class SourceSearchCrewTool(crewai.BaseTool):
        name: str = "source_search"
        description: str = "Search bounded source files for source discovery follow-up."
        args_schema: type[crewai.BaseModel] = SourceSearchInput

        def _run(self, source: str, pattern: str, regex: bool = False, limit: int = 50) -> str:
            result = agent.search_tool.run(_source_arg(state, source), pattern, regex=regex, limit=limit)
            state.memory.record_event(
                agent_name,
                "tool_result",
                "source_search completed",
                {"pattern": pattern, "matches": len(result.get("matches") or [])},
            )
            return json.dumps(result, sort_keys=True)

    return SourceSearchCrewTool()


def _build_read_source_slice_tool(
    crewai: Any,
    state: DiscoverySourceCrewState,
    agent: SourceMapperAgent,
    agent_name: str = "source_mapper",
):
    class ReadSourceSliceInput(crewai.BaseModel):
        source: str = crewai.Field(..., description="Local filesystem source root.")
        relative_path: str = crewai.Field(..., description="File path relative to the source root.")
        start_line: int = crewai.Field(..., description="First line to read.")
        end_line: int = crewai.Field(..., description="Last line to read.")

    class ReadSourceSliceCrewTool(crewai.BaseTool):
        name: str = "read_source_slice"
        description: str = "Read a bounded source slice by path and line range."
        args_schema: type[crewai.BaseModel] = ReadSourceSliceInput

        def _run(self, source: str, relative_path: str, start_line: int, end_line: int) -> str:
            result = agent.read_slice_tool.run(_source_arg(state, source), relative_path, start_line, end_line)
            state.memory.record_event(
                agent_name,
                "tool_result",
                "read_source_slice completed",
                {"path": relative_path, "start_line": start_line, "end_line": result.get("end_line")},
            )
            return json.dumps(result, sort_keys=True)

    return ReadSourceSliceCrewTool()


def _build_dependency_inventory_tool(crewai: Any, state: DiscoverySourceCrewState, agent: DependencyConfigAgent):
    class DependencyInventoryInput(crewai.BaseModel):
        source: str = crewai.Field(..., description="Local filesystem path to inspect for manifests.")

    class DependencyInventoryCrewTool(crewai.BaseTool):
        name: str = "dependency_inventory"
        description: str = "Extract dependencies from supported source manifests."
        args_schema: type[crewai.BaseModel] = DependencyInventoryInput

        def _run(self, source: str) -> str:
            dependencies = agent.dependencies(_source_arg(state, source), state.memory)
            state.dependencies = dependencies
            return json.dumps(
                {
                    "manifests": len(dependencies.get("manifests") or []),
                    "dependencies": len(dependencies.get("dependencies") or []),
                },
                sort_keys=True,
            )

    return DependencyInventoryCrewTool()


def _build_config_inventory_tool(crewai: Any, state: DiscoverySourceCrewState, agent: DependencyConfigAgent):
    class ConfigInventoryInput(crewai.BaseModel):
        source: str = crewai.Field(..., description="Local filesystem path to inspect for configuration.")

    class ConfigInventoryCrewTool(crewai.BaseTool):
        name: str = "config_inventory"
        description: str = "Identify configuration, deployment, environment, and CI files."
        args_schema: type[crewai.BaseModel] = ConfigInventoryInput

        def _run(self, source: str) -> str:
            configuration = agent.configuration(_source_arg(state, source), state.memory)
            state.configuration = configuration
            return json.dumps({"configuration": len(configuration.get("configuration") or [])}, sort_keys=True)

    return ConfigInventoryCrewTool()


def _build_route_resolution_context_tool(crewai: Any, state: DiscoverySourceCrewState):
    class RouteResolutionContextInput(crewai.BaseModel):
        include_entrypoints: bool = crewai.Field(
            True,
            description="Include app entrypoints and app units as route-mount evidence.",
        )

    class RouteResolutionContextCrewTool(crewai.BaseTool):
        name: str = "get_route_resolution_context"
        description: str = "Return compact route, app, and entrypoint evidence for full path resolution."
        args_schema: type[crewai.BaseModel] = RouteResolutionContextInput

        def _run(self, include_entrypoints: bool = True) -> str:
            if not state.source_info:
                raise RuntimeError("Source info is required before resolving routes.")
            if not state.inventory:
                raise RuntimeError("Source inventory is required before resolving routes.")
            if not state.routes:
                raise RuntimeError("Route/API extraction is required before resolving routes.")
            context = _route_resolution_context(state.inventory, state.routes, include_entrypoints=include_entrypoints)
            state.memory.record_event(
                "source_route_resolver",
                "tool_result",
                "Provided route resolution context",
                {"routes": len(context.get("routes") or []), "apps": len(context.get("apps") or [])},
            )
            return json.dumps(context, sort_keys=True)

    return RouteResolutionContextCrewTool()


def _build_submit_route_resolution_tool(crewai: Any, state: DiscoverySourceCrewState):
    class RouteResolutionInput(crewai.BaseModel):
        route_resolution: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured route resolution output for existing route IDs.",
        )

    class SubmitRouteResolutionCrewTool(crewai.BaseTool):
        name: str = "submit_route_resolution"
        description: str = "Record evidence-backed full route path corrections for existing route records."
        args_schema: type[crewai.BaseModel] = RouteResolutionInput

        def _run(self, route_resolution: Any) -> str:
            if not state.routes:
                raise RuntimeError("Route/API extraction is required before submitting route resolution.")
            normalized = _normalize_route_resolution(_coerce_mapping(route_resolution))
            updated_routes, applied = _apply_route_resolutions(state.routes, normalized)
            state.routes = updated_routes
            normalized["applied_count"] = applied
            state.route_resolution = normalized
            state.memory.add_item("source_route_resolution", normalized, "source_route_resolver")
            state.memory.add_item("source_routes_resolved", updated_routes, "source_route_resolver")
            state.memory.record_event(
                "source_route_resolver",
                "tool_result",
                "Route resolution submitted",
                {
                    "submitted": len(_list(normalized.get("resolved_routes"))),
                    "applied": applied,
                },
            )
            return json.dumps({"route_resolution_recorded": True, "applied": applied}, sort_keys=True)

    return SubmitRouteResolutionCrewTool()


def _build_discovery_source_context_tool(crewai: Any, state: DiscoverySourceCrewState):
    class DiscoverySourceContextInput(crewai.BaseModel):
        include_component_map: bool = crewai.Field(
            True,
            description="Include the submitted component map when one is available.",
        )

    class DiscoverySourceContextCrewTool(crewai.BaseTool):
        name: str = "get_discovery_source_context"
        description: str = "Return compact deterministic source discovery context for model-assisted analysis."
        args_schema: type[crewai.BaseModel] = DiscoverySourceContextInput

        def _run(self, include_component_map: bool = True) -> str:
            source_index = _deterministic_source_index(state)
            context = _compact_discovery_source_context(source_index)
            if include_component_map and state.component_map:
                context["component_map"] = state.component_map
            state.memory.record_event(
                "discovery_source_context",
                "tool_result",
                "Provided compact source discovery context",
                {
                    "apps": len(context.get("apps") or []),
                    "routes": len(context.get("routes") or []),
                    "dependencies": len(context.get("dependencies") or []),
                },
            )
            return json.dumps(context, sort_keys=True)

    return DiscoverySourceContextCrewTool()


def _build_submit_source_component_map_tool(crewai: Any, state: DiscoverySourceCrewState):
    class SourceComponentMapInput(crewai.BaseModel):
        component_map: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured source component map with evidence-backed purpose, components, data, and trust boundaries.",
        )

    class SubmitSourceComponentMapCrewTool(crewai.BaseTool):
        name: str = "submit_source_component_map"
        description: str = "Record model-assisted source purpose and component mapping."
        args_schema: type[crewai.BaseModel] = SourceComponentMapInput

        def _run(self, component_map: Any) -> str:
            _deterministic_source_index(state)
            normalized = _normalize_component_map(_coerce_mapping(component_map))
            state.component_map = normalized
            state.memory.add_item("source_component_map", normalized, "source_component_mapper")
            state.memory.record_event(
                "source_component_mapper",
                "tool_result",
                "Source component map submitted",
                {
                    "components": len(_list(normalized.get("key_components"))),
                    "sensitive_data": len(_list(normalized.get("sensitive_data"))),
                    "trust_boundaries": len(_list(normalized.get("trust_boundaries"))),
                },
            )
            return json.dumps({"component_map_recorded": True}, sort_keys=True)

    return SubmitSourceComponentMapCrewTool()


def _build_submit_source_gap_analysis_tool(crewai: Any, state: DiscoverySourceCrewState):
    class SourceGapAnalysisInput(crewai.BaseModel):
        gap_analysis: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured source discovery gap analysis with evidence-backed follow-up recommendations.",
        )

    class SubmitSourceGapAnalysisCrewTool(crewai.BaseTool):
        name: str = "submit_source_gap_analysis"
        description: str = "Record model-assisted source discovery gap analysis."
        args_schema: type[crewai.BaseModel] = SourceGapAnalysisInput

        def _run(self, gap_analysis: Any) -> str:
            _deterministic_source_index(state)
            normalized = _normalize_gap_analysis(_coerce_mapping(gap_analysis))
            state.gap_analysis = normalized
            state.memory.add_item("source_gap_analysis", normalized, "source_gap_analyst")
            state.memory.record_event(
                "source_gap_analyst",
                "tool_result",
                "Source discovery gap analysis submitted",
                {
                    "gaps": len(_list(normalized.get("gaps"))),
                    "limitations": len(_list(normalized.get("limitations"))),
                    "follow_ups": len(_list(normalized.get("recommended_follow_up"))),
                },
            )
            return json.dumps({"gap_analysis_recorded": True}, sort_keys=True)

    return SubmitSourceGapAnalysisCrewTool()


def _build_write_discovery_source_report_tool(
    crewai: Any,
    state: DiscoverySourceCrewState,
    agent: DiscoverySourceReporterAgent,
):
    class ReportInput(crewai.BaseModel):
        report: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured source discovery report content. Prefer a JSON object.",
        )

    class WriteDiscoverySourceReportCrewTool(crewai.BaseTool):
        name: str = "write_discovery_source_report"
        description: str = "Persist source discovery as a stable Markdown report."
        args_schema: type[crewai.BaseModel] = ReportInput

        def _run(self, report: Any) -> str:
            if not state.source_info:
                raise RuntimeError("Source info is required before writing the report.")
            if not state.inventory:
                raise RuntimeError("Source inventory is required before writing the report.")
            if not state.routes:
                raise RuntimeError("Route/API extraction is required before writing the report.")
            if not state.dependencies:
                raise RuntimeError("Dependency inventory is required before writing the report.")
            if not state.configuration:
                raise RuntimeError("Configuration inventory is required before writing the report.")
            report_content = _coerce_mapping(report)
            state.summary = agent.summarize(
                state.source_info,
                state.inventory,
                state.routes,
                state.dependencies,
                state.configuration,
                state.memory,
            )
            state.source_index = agent.build_source_index(
                state.source_info,
                state.inventory,
                state.routes,
                state.dependencies,
                state.configuration,
                state.memory,
                route_resolution=state.route_resolution,
                component_map=state.component_map,
                gap_analysis=state.gap_analysis,
            )
            state.memory.add_item("llm_report", {"structured": report_content}, "reporter")
            markdown = write_discovery_source_report(state.report_dir, state.source_index, report_content)
            state.report_written = True
            state.memory.record_event(
                "reporter",
                "report_written",
                "Source discovery reporter wrote Markdown source discovery report",
                {
                    "report_dir": str(state.report_dir),
                    "markdown_bytes": len(markdown.encode("utf-8")),
                    "structured_keys": sorted(report_content.keys()),
                },
            )
            return json.dumps({"report_dir": str(state.report_dir), "markdown_bytes": len(markdown.encode("utf-8"))})

    return WriteDiscoverySourceReportCrewTool()


def _source_arg(state: DiscoverySourceCrewState, source: str) -> str:
    if state.source_info and state.source_info.get("path"):
        return str(state.source_info["path"])
    return source


def _tool_result_summary(inventory: dict[str, Any]) -> dict[str, Any]:
    return {
        "files": inventory.get("total_files"),
        "languages": sorted((inventory.get("languages") or {}).keys()),
        "manifests": len(inventory.get("manifests") or []),
        "lockfiles": len(inventory.get("lockfiles") or []),
    }


def _route_resolution_context(
    inventory: dict[str, Any],
    routes: dict[str, Any],
    include_entrypoints: bool = True,
) -> dict[str, Any]:
    route_items = []
    for route in _list(routes.get("routes"))[:200]:
        if not isinstance(route, dict):
            continue
        route_items.append(
            {
                "route_id": _route_id(route),
                "method": route.get("method"),
                "route": route.get("route"),
                "full_route": route.get("full_route") or route.get("route"),
                "mount_prefix": route.get("mount_prefix"),
                "app_id": route.get("app_id"),
                "path": route.get("path"),
                "line": route.get("line"),
                "handler": route.get("handler"),
                "framework": route.get("framework"),
                "snippet_hash": route.get("snippet_hash"),
            }
        )
    context = {
        "schema": "mosh.route-resolution-context.v1",
        "routes": route_items,
        "apps": _limit_items(inventory.get("apps"), 50),
    }
    if include_entrypoints:
        context["entrypoints"] = _limit_items(inventory.get("entrypoints"), 100)
    return context


def _normalize_route_resolution(route_resolution: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(route_resolution)
    normalized.setdefault("schema", "mosh.source-route-resolution.v1")
    normalized["resolved_routes"] = _list(
        normalized.get("resolved_routes")
        or normalized.get("routes")
        or normalized.get("corrections")
    )
    normalized["notes"] = _list(normalized.get("notes"))
    return normalized


def _apply_route_resolutions(
    routes: dict[str, Any],
    route_resolution: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    corrections = {
        _text(item.get("route_id")): item
        for item in _list(route_resolution.get("resolved_routes"))
        if isinstance(item, dict) and _text(item.get("route_id"))
    }
    updated = dict(routes)
    updated_routes = []
    applied = 0
    for route in _list(routes.get("routes")):
        if not isinstance(route, dict):
            updated_routes.append(route)
            continue
        correction = corrections.get(_route_id(route))
        if not correction:
            updated_routes.append(route)
            continue
        full_route = _normalize_route_path(correction.get("full_route") or correction.get("resolved_full_route"))
        route_copy = dict(route)
        if full_route:
            if route_copy.get("full_route") and route_copy.get("full_route") != full_route:
                route_copy["deterministic_full_route"] = route_copy.get("full_route")
            route_copy["full_route"] = full_route
        mount_prefix = _normalize_route_path(correction.get("mount_prefix"))
        if mount_prefix:
            route_copy["mount_prefix"] = mount_prefix
        route_copy["route_resolution_source"] = "model-assisted"
        route_copy["route_resolution_confidence"] = _text(correction.get("confidence")) or "unknown"
        if correction.get("evidence"):
            route_copy["route_resolution_evidence"] = _list(correction.get("evidence"))
        if correction.get("reason"):
            route_copy["route_resolution_reason"] = _text(correction.get("reason"))
        updated_routes.append(route_copy)
        applied += 1
    updated["routes"] = updated_routes
    return updated, applied


def _route_id(route: dict[str, Any]) -> str:
    parts = [
        _text(route.get("method")),
        _text(route.get("path")),
        _text(route.get("line")),
        _text(route.get("route")),
        _text(route.get("handler") or route.get("framework")),
    ]
    return "|".join(parts)


def _normalize_route_path(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    if text == "/":
        return text
    return "/" + text.strip("/")


def _deterministic_source_index(state: DiscoverySourceCrewState) -> dict[str, Any]:
    if not state.source_info:
        raise RuntimeError("Source info is required before reading source discovery context.")
    if not state.inventory:
        raise RuntimeError("Source inventory is required before reading source discovery context.")
    if not state.routes:
        raise RuntimeError("Route/API extraction is required before reading source discovery context.")
    if not state.dependencies:
        raise RuntimeError("Dependency inventory is required before reading source discovery context.")
    if not state.configuration:
        raise RuntimeError("Configuration inventory is required before reading source discovery context.")
    return build_source_index(
        state.source_info,
        state.inventory,
        state.routes,
        state.dependencies,
        state.configuration,
        route_resolution=state.route_resolution,
    )


def _compact_discovery_source_context(source_index: dict[str, Any]) -> dict[str, Any]:
    inventory = source_index.get("inventory") if isinstance(source_index.get("inventory"), dict) else {}
    return {
        "schema": "mosh.discovery-source-context.v1",
        "source": source_index.get("source"),
        "summary": source_index.get("summary"),
        "apps": _limit_items(inventory.get("apps"), 50),
        "languages": inventory.get("languages"),
        "frameworks": _limit_items(inventory.get("frameworks"), 50),
        "entrypoints": _limit_items(inventory.get("entrypoints"), 100),
        "routes": _limit_items(inventory.get("routes"), 150),
        "route_resolution": source_index.get("route_resolution"),
        "auth": _limit_items(inventory.get("auth"), 75),
        "sessions": _limit_items(inventory.get("sessions"), 75),
        "data_stores": _limit_items(inventory.get("data_stores"), 75),
        "dependencies": _limit_items(inventory.get("dependencies"), 150),
        "configuration": _limit_items(inventory.get("configuration"), 100),
        "environment_variables": _limit_items(inventory.get("environment_variables"), 150),
        "compose_topology": _limit_items(inventory.get("compose_topology"), 50),
        "evidence_refs": _limit_items(source_index.get("evidence_refs"), 150),
        "context_limits": {
            "files_omitted": True,
            "max_apps": 50,
            "max_entrypoints": 100,
            "max_routes": 150,
            "max_dependencies": 150,
            "max_configuration": 100,
        },
    }


def _normalize_component_map(component_map: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(component_map)
    normalized.setdefault("schema", "mosh.source-component-map.v1")
    for key in (
        "key_components",
        "sensitive_data",
        "trust_boundaries",
        "external_integrations",
        "open_questions",
    ):
        if key in normalized:
            normalized[key] = _list(normalized.get(key))
    return normalized


def _normalize_gap_analysis(gap_analysis: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(gap_analysis)
    normalized.setdefault("schema", "mosh.source-gap-analysis.v1")
    for key in (
        "gaps",
        "limitations",
        "recommended_follow_up",
        "deterministic_tool_opportunities",
    ):
        if key in normalized:
            normalized[key] = _list(normalized.get(key))
    return normalized


def _limit_items(value: Any, limit: int) -> list[Any]:
    return _list(value)[:limit]


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _coerce_mapping(value: Any | None) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        return dumped if isinstance(dumped, dict) else {"content": dumped}
    if hasattr(value, "dict"):
        dumped = value.dict()
        return dumped if isinstance(dumped, dict) else {"content": dumped}
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"executive_summary": value}
        return parsed if isinstance(parsed, dict) else {"content": parsed}
    return {"content": value}
