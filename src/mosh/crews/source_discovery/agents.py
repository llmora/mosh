from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mosh.config import AppConfig
from mosh.crews.definitions import AgentDefinition
from mosh.crews.source_discovery.tools import (
    ConfigInventoryTool,
    DependencyInventoryTool,
    ReadSourceSliceTool,
    RouteApiExtractorTool,
    SourceInventoryTool,
    SourceSearchTool,
    ToolDefinition,
    ValidateSourcePathTool,
    build_source_index,
    source_summary,
)
from mosh.memory import FileMemory


def source_discovery_agent_definitions(config: AppConfig) -> list[AgentDefinition]:
    source_context_tool = ToolDefinition(
        name="get_source_discovery_context",
        description="Read a compact deterministic source discovery context without full file contents.",
    )
    component_map_tool = ToolDefinition(
        name="submit_source_component_map",
        description="Submit model-assisted application purpose, component, data, and trust-boundary mapping.",
    )
    route_context_tool = ToolDefinition(
        name="get_route_resolution_context",
        description="Read compact route, app, entrypoint, and source evidence for full path resolution.",
    )
    route_resolution_tool = ToolDefinition(
        name="submit_route_resolution",
        description="Submit model-assisted full route path corrections for existing deterministic route records.",
    )
    gap_analysis_tool = ToolDefinition(
        name="submit_source_gap_analysis",
        description="Submit model-assisted source discovery gaps and follow-up recommendations.",
    )
    return [
        AgentDefinition(
            name="orchestrator",
            role="Source discovery coordinator",
            goal="Coordinate source discovery work and route findings between source agents.",
            model=config.models.source_discovery.reporter,
        ),
        AgentDefinition(
            name="source_intake",
            role="Source intake validator",
            goal="Validate the source tree and record source identity metadata.",
            model=config.models.source_discovery.intake,
            tools=[ValidateSourcePathTool.definition],
        ),
        AgentDefinition(
            name="source_mapper",
            role="Source surface mapper",
            goal="Build a compact source inventory, route map, and retrievable source evidence references.",
            model=config.models.source_discovery.mapper,
            tools=[
                SourceInventoryTool.definition,
                RouteApiExtractorTool.definition,
                SourceSearchTool.definition,
                ReadSourceSliceTool.definition,
            ],
        ),
        AgentDefinition(
            name="dependency_config",
            role="Dependency and configuration mapper",
            goal="Identify dependency manifests, lockfiles, configuration, deployment, and CI files.",
            model=config.models.source_discovery.dependency_config,
            tools=[DependencyInventoryTool.definition, ConfigInventoryTool.definition],
        ),
        AgentDefinition(
            name="source_route_resolver",
            role="Source route resolver",
            goal="Resolve API candidates to evidence-backed full paths, especially when router mounts or app prefixes are ambiguous.",
            model=config.models.source_discovery.route_resolver,
            tools=[
                route_context_tool,
                SourceSearchTool.definition,
                ReadSourceSliceTool.definition,
                route_resolution_tool,
            ],
        ),
        AgentDefinition(
            name="source_component_mapper",
            role="Source component mapper",
            goal="Summarize what the source tree appears to do and map key business/security components from deterministic evidence.",
            model=config.models.source_discovery.component_mapper,
            tools=[source_context_tool, component_map_tool],
        ),
        AgentDefinition(
            name="source_gap_analyst",
            role="Source discovery gap analyst",
            goal="Identify discovery blind spots and practical follow-up needed before source-backed security planning.",
            model=config.models.source_discovery.gap_analyst,
            tools=[source_context_tool, gap_analysis_tool],
        ),
        AgentDefinition(
            name="reporter",
            role="Source discovery reporter",
            goal="Persist source discovery findings into a stable Markdown report.",
            model=config.models.source_discovery.reporter,
        ),
    ]


@dataclass(frozen=True)
class SourceDiscoveryAgents:
    intake: "SourceIntakeAgent"
    mapper: "SourceMapperAgent"
    dependency_config: "DependencyConfigAgent"
    reporter: "SourceDiscoveryReporterAgent"


class SourceIntakeAgent:
    name = "source_intake"

    def __init__(self, validate_tool: ValidateSourcePathTool | None = None) -> None:
        self.validate_tool = validate_tool or ValidateSourcePathTool()

    @property
    def available_tool_definitions(self) -> list[ToolDefinition]:
        return [self.validate_tool.definition]

    def validate(self, source: str, memory: FileMemory) -> dict[str, Any]:
        memory.record_event(self.name, "tool_call", "Invoking validate_source_path", {"source": source})
        source_info = self.validate_tool.run(source)
        memory.add_item("source_info", source_info, self.name)
        memory.record_event(
            self.name,
            "tool_result",
            "validate_source_path completed",
            {
                "path": source_info.get("path"),
                "commit_sha": source_info.get("commit_sha"),
                "dirty": source_info.get("dirty"),
            },
        )
        return source_info


class SourceMapperAgent:
    name = "source_mapper"

    def __init__(
        self,
        inventory_tool: SourceInventoryTool | None = None,
        route_tool: RouteApiExtractorTool | None = None,
        search_tool: SourceSearchTool | None = None,
        read_slice_tool: ReadSourceSliceTool | None = None,
    ) -> None:
        self.inventory_tool = inventory_tool or SourceInventoryTool()
        self.route_tool = route_tool or RouteApiExtractorTool()
        self.search_tool = search_tool or SourceSearchTool()
        self.read_slice_tool = read_slice_tool or ReadSourceSliceTool()

    @property
    def available_tool_definitions(self) -> list[ToolDefinition]:
        return [
            self.inventory_tool.definition,
            self.route_tool.definition,
            self.search_tool.definition,
            self.read_slice_tool.definition,
        ]

    def inventory(self, source: str, memory: FileMemory) -> dict[str, Any]:
        memory.record_event(self.name, "tool_call", "Invoking source_inventory", {"source": source})
        inventory = self.inventory_tool.run(source)
        memory.add_item("source_inventory", inventory, self.name)
        memory.record_event(
            self.name,
            "tool_result",
            "source_inventory completed",
            {
                "files": inventory.get("total_files"),
                "languages": sorted((inventory.get("languages") or {}).keys()),
            },
        )
        return inventory

    def routes(self, source: str, memory: FileMemory) -> dict[str, Any]:
        memory.record_event(self.name, "tool_call", "Invoking route_api_extractor", {"source": source})
        routes = self.route_tool.run(source)
        memory.add_item("source_routes", routes, self.name)
        memory.record_event(
            self.name,
            "tool_result",
            "route_api_extractor completed",
            {"routes": len(routes.get("routes") or [])},
        )
        return routes


class DependencyConfigAgent:
    name = "dependency_config"

    def __init__(
        self,
        dependency_tool: DependencyInventoryTool | None = None,
        config_tool: ConfigInventoryTool | None = None,
    ) -> None:
        self.dependency_tool = dependency_tool or DependencyInventoryTool()
        self.config_tool = config_tool or ConfigInventoryTool()

    @property
    def available_tool_definitions(self) -> list[ToolDefinition]:
        return [self.dependency_tool.definition, self.config_tool.definition]

    def dependencies(self, source: str, memory: FileMemory) -> dict[str, Any]:
        memory.record_event(self.name, "tool_call", "Invoking dependency_inventory", {"source": source})
        dependencies = self.dependency_tool.run(source)
        memory.add_item("source_dependencies", dependencies, self.name)
        memory.record_event(
            self.name,
            "tool_result",
            "dependency_inventory completed",
            {
                "manifests": len(dependencies.get("manifests") or []),
                "dependencies": len(dependencies.get("dependencies") or []),
            },
        )
        return dependencies

    def configuration(self, source: str, memory: FileMemory) -> dict[str, Any]:
        memory.record_event(self.name, "tool_call", "Invoking config_inventory", {"source": source})
        configuration = self.config_tool.run(source)
        memory.add_item("source_configuration", configuration, self.name)
        memory.record_event(
            self.name,
            "tool_result",
            "config_inventory completed",
            {"configuration": len(configuration.get("configuration") or [])},
        )
        return configuration


class SourceDiscoveryReporterAgent:
    name = "reporter"

    def summarize(
        self,
        source_info: dict[str, Any],
        inventory: dict[str, Any],
        routes: dict[str, Any],
        dependencies: dict[str, Any],
        configuration: dict[str, Any],
        memory: FileMemory,
    ) -> dict[str, Any]:
        summary = source_summary(inventory, routes, dependencies, configuration)
        memory.add_item("summary", summary, self.name)
        return summary

    def build_source_index(
        self,
        source_info: dict[str, Any],
        inventory: dict[str, Any],
        routes: dict[str, Any],
        dependencies: dict[str, Any],
        configuration: dict[str, Any],
        memory: FileMemory,
        route_resolution: dict[str, Any] | None = None,
        component_map: dict[str, Any] | None = None,
        gap_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        source_index = build_source_index(
            source_info,
            inventory,
            routes,
            dependencies,
            configuration,
            route_resolution=route_resolution,
            component_map=component_map,
            gap_analysis=gap_analysis,
        )
        memory.add_item("source_index", source_index, self.name)
        return source_index


def build_source_discovery_agents(config: AppConfig) -> SourceDiscoveryAgents:
    return SourceDiscoveryAgents(
        intake=SourceIntakeAgent(),
        mapper=SourceMapperAgent(),
        dependency_config=DependencyConfigAgent(),
        reporter=SourceDiscoveryReporterAgent(),
    )
