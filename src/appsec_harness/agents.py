from __future__ import annotations

from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from appsec_harness.config import AppConfig
from appsec_harness.memory import FileMemory
from appsec_harness.models import CrawledPage, CrawlResult
from appsec_harness.tools import (
    CompileComponentInventoryTool,
    CrawlApplicationTool,
    KatanaDockerCrawlerTool,
    ToolDefinition,
)


JS_SURFACE_MARKERS = (
    "/_next/",
    "/static/js/",
    "/assets/",
    "app.",
    "bundle.",
    "chunk.",
    "main.",
    "runtime.",
    "webpack",
    "vite",
    "react",
    "vue",
    "angular",
    "svelte",
    "nuxt",
)


@dataclass(frozen=True)
class AgentDefinition:
    name: str
    role: str
    goal: str
    model: str
    tools: list[ToolDefinition] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def discovery_agent_definitions(config: AppConfig) -> list[AgentDefinition]:
    return [
        AgentDefinition(
            name="orchestrator",
            role="Discovery crew coordinator",
            goal="Coordinate appsec discovery work and route findings between agents.",
            model=config.models.orchestrator,
        ),
        AgentDefinition(
            name="crawler",
            role="Application surface crawler",
            goal="Discover in-scope pages, links, URLs, paths, references, and files.",
            model=config.models.crawler,
            tools=[CrawlApplicationTool.definition, KatanaDockerCrawlerTool.definition],
        ),
        AgentDefinition(
            name="sbom_compiler",
            role="Remote component inventory compiler",
            goal="Identify observable libraries, servers, frameworks, and application components.",
            model=config.models.sbom_compiler,
            tools=[CompileComponentInventoryTool.definition],
        ),
        AgentDefinition(
            name="summarizer",
            role="Discovery report summarizer",
            goal="Summarize discovery findings into Markdown and structured JSON outputs.",
            model=config.models.summarizer,
        ),
    ]


@dataclass(frozen=True)
class DiscoveryAgents:
    crawler: "CrawlerAgent"
    sbom_compiler: "SbomCompilerAgent"
    summarizer: "SummarizerAgent"


class CrawlerAgent:
    name = "crawler"

    def __init__(
        self,
        crawl_tool: CrawlApplicationTool | None = None,
        additional_tools: list[KatanaDockerCrawlerTool] | None = None,
    ) -> None:
        self.crawl_tool = crawl_tool or CrawlApplicationTool()
        self.additional_tools = additional_tools or []

    @property
    def available_tool_definitions(self) -> list[ToolDefinition]:
        return [self.crawl_tool.definition, *[tool.definition for tool in self.additional_tools]]

    def discover(self, url: str, memory: FileMemory, max_pages: int, max_depth: int) -> CrawlResult:
        memory.record_event(self.name, "task_received", "Crawl the target and discover app surface")
        crawl = self._run_crawl_tool(self.crawl_tool, url, memory, max_pages, max_depth)
        decision = self._javascript_crawler_decision(crawl)
        if decision.select_katana:
            memory.record_event(
                self.name,
                "tool_selection",
                "Selecting Katana because the target appears JavaScript-heavy",
                {"evidence": decision.evidence},
            )
            katana_crawl = self._run_optional_tool("katana_docker_crawler", url, memory, max_pages, max_depth)
            if katana_crawl:
                crawl = self._merge_crawls(crawl, katana_crawl)
        else:
            memory.record_event(
                self.name,
                "tool_selection",
                "Keeping app-native crawler results; no strong SPA or JavaScript-heavy signal detected",
                {"evidence": decision.evidence},
            )
        self._store_crawl(memory, crawl)
        return crawl

    def _run_crawl_tool(
        self,
        tool: CrawlApplicationTool | KatanaDockerCrawlerTool,
        url: str,
        memory: FileMemory,
        max_pages: int,
        max_depth: int,
    ) -> CrawlResult:
        memory.record_event(
            self.name,
            "tool_call",
            f"Invoking {tool.definition.name}",
            {"tool": tool.definition.name, "url": url, "max_pages": max_pages, "max_depth": max_depth},
        )
        crawl = tool.run(url, max_pages=max_pages, max_depth=max_depth)
        result_data: dict[str, object] = {
            "pages": len(crawl.pages),
            "out_of_scope": len(crawl.out_of_scope),
            "failed": len(crawl.failed),
        }
        if crawl.failed:
            result_data["failures"] = crawl.failed
        memory.record_event(
            self.name,
            "tool_result",
            f"{tool.definition.name} completed",
            result_data,
        )
        return crawl

    def _run_optional_tool(
        self,
        tool_name: str,
        url: str,
        memory: FileMemory,
        max_pages: int,
        max_depth: int,
    ) -> CrawlResult | None:
        tool = next((candidate for candidate in self.additional_tools if candidate.definition.name == tool_name), None)
        if not tool:
            memory.record_event(
                self.name,
                "tool_unavailable",
                f"{tool_name} is not available to the crawler agent",
                {"tool": tool_name},
            )
            return None
        return self._run_crawl_tool(tool, url, memory, max_pages, max_depth)

    def _store_crawl(self, memory: FileMemory, crawl: CrawlResult) -> None:
        memory.add_item("robots", crawl.robots or {"found": False}, self.name)
        for page in crawl.pages:
            memory.add_item("crawled_page", page.to_dict(), self.name)
        if crawl.out_of_scope:
            memory.add_item("out_of_scope", {"urls": crawl.out_of_scope}, self.name)
        if crawl.failed:
            memory.add_item("failed_requests", {"requests": crawl.failed}, self.name)

    def _javascript_crawler_decision(self, crawl: CrawlResult) -> "JavascriptCrawlerDecision":
        evidence: list[str] = []
        js_references = [
            reference
            for page in crawl.pages
            for reference in page.references
            if _looks_like_javascript_reference(reference)
        ]
        if js_references:
            evidence.append(f"Found {len(js_references)} JavaScript reference(s)")

        marker_hits = sorted(
            {
                reference
                for reference in js_references
                if any(marker in reference.lower() for marker in JS_SURFACE_MARKERS)
            }
        )
        if marker_hits:
            evidence.append(f"JavaScript bundle/framework markers: {', '.join(marker_hits[:3])}")

        sparse_js_pages = [
            page.url
            for page in crawl.pages
            if page.references and not page.links and not page.forms and any(
                _looks_like_javascript_reference(reference) for reference in page.references
            )
        ]
        if sparse_js_pages:
            evidence.append(f"Page relies on JavaScript with little crawlable HTML navigation: {sparse_js_pages[0]}")

        framework_headers = [
            f"{header}: {value}"
            for page in crawl.pages
            for header, value in page.headers.items()
            if header.lower() == "x-powered-by" and any(
                framework in value.lower() for framework in ("next", "nuxt", "react", "vue", "angular")
            )
        ]
        if framework_headers:
            evidence.append(f"Framework header signal: {framework_headers[0]}")

        return JavascriptCrawlerDecision(
            select_katana=bool(marker_hits or sparse_js_pages or framework_headers or len(js_references) >= 3),
            evidence=evidence or ["No JavaScript-heavy indicators found"],
        )

    def _merge_crawls(self, primary: CrawlResult, secondary: CrawlResult) -> CrawlResult:
        pages_by_url: dict[str, CrawledPage] = {page.url: page for page in primary.pages}
        for page in secondary.pages:
            existing = pages_by_url.get(page.url)
            if not existing:
                pages_by_url[page.url] = page
            elif existing.status == 0 and page.status != 0:
                pages_by_url[page.url] = page
        return CrawlResult(
            start_url=primary.start_url,
            pages=sorted(pages_by_url.values(), key=lambda page: page.url),
            out_of_scope=sorted({*primary.out_of_scope, *secondary.out_of_scope}),
            failed=[*primary.failed, *secondary.failed],
            robots=primary.robots or secondary.robots,
        )


@dataclass(frozen=True)
class JavascriptCrawlerDecision:
    select_katana: bool
    evidence: list[str]


def _looks_like_javascript_reference(reference: str) -> bool:
    path = urlparse(reference).path.lower()
    return path.endswith(".js") or path.endswith(".mjs") or path.endswith(".jsx") or ".js?" in reference.lower()


class SbomCompilerAgent:
    name = "sbom_compiler"

    def __init__(self, component_tool: CompileComponentInventoryTool | None = None) -> None:
        self.component_tool = component_tool or CompileComponentInventoryTool()

    def compile_inventory(self, crawl: CrawlResult, memory: FileMemory) -> list[dict[str, str]]:
        memory.record_event(
            self.name,
            "task_received",
            "Compile remote component inventory from crawler findings",
        )
        memory.record_event(
            self.name,
            "tool_call",
            f"Invoking {self.component_tool.definition.name}",
            {"tool": self.component_tool.definition.name, "pages": len(crawl.pages)},
        )
        components = self.component_tool.run(crawl)
        memory.add_item("component_inventory", {"components": components}, self.name)
        memory.record_event(
            self.name,
            "tool_result",
            f"{self.component_tool.definition.name} completed",
            {"components": len(components)},
        )
        return components


class SummarizerAgent:
    name = "summarizer"

    def summarize(
        self,
        crawl: CrawlResult,
        components: list[dict[str, str]],
        memory: FileMemory,
    ) -> dict[str, int]:
        memory.record_event(self.name, "task_received", "Summarize discovery crew findings")
        summary = {
            "pages_crawled": len(crawl.pages),
            "in_scope_references": sum(len(page.links) + len(page.references) + len(page.forms) for page in crawl.pages),
            "out_of_scope_references": len(crawl.out_of_scope),
            "components_identified": len(components),
            "failed_requests": len(crawl.failed),
        }
        memory.add_item("summary", summary, self.name)
        return summary


def build_discovery_agents(config: AppConfig | None = None) -> DiscoveryAgents:
    config = config or AppConfig()
    return DiscoveryAgents(
        crawler=CrawlerAgent(
            additional_tools=[
                KatanaDockerCrawlerTool(
                    config.tool_image,
                    crawl_duration=config.katana_crawl_duration,
                    docker_timeout=config.katana_docker_timeout,
                )
            ]
        ),
        sbom_compiler=SbomCompilerAgent(),
        summarizer=SummarizerAgent(),
    )
