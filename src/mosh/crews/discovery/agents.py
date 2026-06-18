from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from mosh.config import AppConfig
from mosh.crews.definitions import AgentDefinition
from mosh.memory import FileMemory
from mosh.models import CrawledPage, CrawlResult, DiscoveryCandidate
from mosh.scope import ScopePolicy, normalize_url
from mosh.crews.discovery.tools import (
    CrawlApplicationTool,
    DirbDockerDiscoveryTool,
    ExtractifyDockerTool,
    JsStaticEndpointDockerTool,
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

HTTP_METHOD_TITLES = tuple(
    f"{method} " for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
)


def discovery_agent_definitions(config: AppConfig) -> list[AgentDefinition]:
    return [
        AgentDefinition(
            name="orchestrator",
            role="Discovery crew coordinator",
            goal="Coordinate appsec discovery work and route findings between agents.",
            model=config.models.discovery.reporter,
        ),
        AgentDefinition(
            name="crawler",
            role="Application surface crawler",
            goal="Discover in-scope pages, links, URLs, paths, references, and files.",
            model=config.models.discovery.crawler,
            tools=[
                CrawlApplicationTool.definition,
                KatanaDockerCrawlerTool.definition,
                DirbDockerDiscoveryTool.definition,
                ExtractifyDockerTool.definition,
                JsStaticEndpointDockerTool.definition,
            ],
        ),
        AgentDefinition(
            name="technology_mapper",
            role="Remote component inventory compiler",
            goal="Identify observable libraries, servers, frameworks, and application components.",
            model=config.models.discovery.technology_mapper,
        ),
        AgentDefinition(
            name="reporter",
            role="Discovery reporter",
            goal="Summarize discovery findings into a stable Markdown report.",
            model=config.models.discovery.reporter,
        ),
    ]


@dataclass(frozen=True)
class DiscoveryAgents:
    crawler: "CrawlerAgent"
    technology_mapper: "TechnologyMapperAgent"
    reporter: "DiscoveryReporterAgent"


class CrawlerAgent:
    name = "crawler"

    def __init__(
        self,
        crawl_tool: CrawlApplicationTool | None = None,
        additional_tools: list[
            KatanaDockerCrawlerTool | DirbDockerDiscoveryTool | ExtractifyDockerTool | JsStaticEndpointDockerTool
        ]
        | None = None,
        candidate_follow_up_limit: int = 5,
    ) -> None:
        self.crawl_tool = crawl_tool or CrawlApplicationTool()
        self.additional_tools = additional_tools or []
        self.candidate_follow_up_limit = candidate_follow_up_limit

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
        dirb_crawl = self._run_optional_tool("dirb_docker_discovery", url, memory, max_pages, max_depth)
        if dirb_crawl:
            crawl = self._merge_crawls(crawl, dirb_crawl)
            crawl = self._follow_up_discovery_candidates(crawl, memory, max_pages, max_depth)
        extractify_crawl = self._run_extractify_tool(crawl, memory)
        if extractify_crawl:
            crawl = self._merge_crawls(crawl, extractify_crawl)
        js_static_crawl = self._run_js_static_tool(crawl, memory)
        if js_static_crawl:
            crawl = self._merge_crawls(crawl, js_static_crawl)
        openapi_crawl = self._run_openapi_spec_parsing(crawl, memory)
        if openapi_crawl:
            crawl = self._merge_crawls(crawl, openapi_crawl)
        self._store_crawl(memory, crawl)
        return crawl

    def _run_crawl_tool(
        self,
        tool: CrawlApplicationTool | KatanaDockerCrawlerTool | DirbDockerDiscoveryTool,
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
        result_data = _crawl_event_result_data(crawl)
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

    def _run_extractify_tool(self, crawl: CrawlResult, memory: FileMemory) -> CrawlResult | None:
        return self._run_javascript_asset_tool(
            "extractify_js_endpoint_discovery",
            "Invoking extractify_js_endpoint_discovery",
            crawl,
            memory,
        )

    def _run_js_static_tool(self, crawl: CrawlResult, memory: FileMemory) -> CrawlResult | None:
        return self._run_javascript_asset_tool(
            "js_static_endpoint_discovery",
            "Invoking js_static_endpoint_discovery",
            crawl,
            memory,
        )

    def _run_openapi_spec_parsing(self, crawl: CrawlResult, memory: FileMemory) -> CrawlResult | None:
        """Detect and parse OpenAPI/Swagger specs from crawled JSON endpoints."""
        from mosh.crews.discovery.openapi_parser import is_openapi_spec, parse_openapi_spec
        import urllib.request

        json_pages = [
            page for page in crawl.pages
            if page.status == 200 and "json" in page.content_type.lower()
        ]
        if not json_pages:
            return None
        scope = ScopePolicy.from_url(crawl.start_url)
        all_pages: list[CrawledPage] = []
        out_of_scope: set[str] = set()
        for page in json_pages:
            try:
                with urllib.request.urlopen(page.url, timeout=30) as response:
                    body = response.read().decode("utf-8", errors="replace")
            except Exception:
                continue
            if not is_openapi_spec(page.content_type, body):
                continue
            memory.record_event(
                self.name,
                "openapi_spec_found",
                f"Parsing OpenAPI specification from {page.url}",
                {"url": page.url, "size": len(body)},
            )
            pages = parse_openapi_spec(page.url, body)
            in_scope_pages: list[CrawledPage] = []
            for candidate in pages:
                if scope.in_scope(candidate.url):
                    in_scope_pages.append(candidate)
                else:
                    out_of_scope.add(candidate.url)
            all_pages.extend(in_scope_pages)
            memory.record_event(
                self.name,
                "openapi_spec_parsed",
                f"Extracted {len(pages)} API endpoints from OpenAPI spec",
                {
                    "url": page.url,
                    "endpoints": len(pages),
                    "in_scope": len(in_scope_pages),
                    "out_of_scope": len(pages) - len(in_scope_pages),
                },
            )
        if not all_pages and not out_of_scope:
            return None
        from mosh.models import CrawlResult as CR
        return CR(
            start_url=crawl.start_url,
            pages=all_pages,
            out_of_scope=sorted(out_of_scope),
            failed=[],
        )

    def _run_javascript_asset_tool(
        self,
        tool_name: str,
        message: str,
        crawl: CrawlResult,
        memory: FileMemory,
    ) -> CrawlResult | None:
        js_urls = _javascript_urls(crawl)
        if not js_urls:
            return None
        tool = next((candidate for candidate in self.additional_tools if candidate.definition.name == tool_name), None)
        if not tool:
            memory.record_event(
                self.name,
                "tool_unavailable",
                f"{tool_name} is not available to the crawler agent",
                {"tool": tool_name},
            )
            return None
        memory.record_event(
            self.name,
            "tool_call",
            message,
            {
                "tool": tool_name,
                "javascript_urls": len(js_urls),
                "sample": js_urls[:5],
                "javascript_contexts": len(_javascript_contexts(crawl)) if tool_name == "js_static_endpoint_discovery" else 0,
            },
        )
        if tool_name == "js_static_endpoint_discovery":
            javascript_crawl = tool.run(crawl.start_url, js_urls, _javascript_contexts(crawl))
        else:
            javascript_crawl = tool.run(crawl.start_url, js_urls)
        result_data = _crawl_event_result_data(javascript_crawl)
        memory.record_event(
            self.name,
            "tool_result",
            f"{tool_name} completed",
            result_data,
        )
        return javascript_crawl

    def _store_crawl(self, memory: FileMemory, crawl: CrawlResult) -> None:
        memory.add_item("robots", crawl.robots or {"found": False}, self.name)
        for page in crawl.pages:
            memory.add_item("crawled_page", page.to_dict(), self.name)
        for candidate in crawl.candidates:
            memory.add_item("discovery_candidate", candidate.to_dict(), self.name)
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
        pages_by_key: dict[tuple[str, str], CrawledPage] = {_page_merge_key(page): page for page in primary.pages}
        for page in secondary.pages:
            page_key = _page_merge_key(page)
            existing = pages_by_key.get(page_key)
            if not existing:
                pages_by_key[page_key] = page
            elif existing.status == 0 and page.status != 0:
                pages_by_key[page_key] = page
        candidates_by_key: dict[tuple[str, str], DiscoveryCandidate] = {
            (candidate.url, candidate.source_tool): candidate for candidate in primary.candidates
        }
        for candidate in secondary.candidates:
            candidates_by_key.setdefault((candidate.url, candidate.source_tool), candidate)
        return CrawlResult(
            start_url=primary.start_url,
            pages=sorted(pages_by_key.values(), key=lambda page: (page.url, page.title or "")),
            out_of_scope=sorted({*primary.out_of_scope, *secondary.out_of_scope}),
            failed=[*primary.failed, *secondary.failed],
            robots=primary.robots or secondary.robots,
            candidates=sorted(candidates_by_key.values(), key=lambda candidate: (candidate.url, candidate.source_tool)),
        )

    def _follow_up_discovery_candidates(
        self,
        crawl: CrawlResult,
        memory: FileMemory,
        max_pages: int,
        max_depth: int,
    ) -> CrawlResult:
        crawled_urls = {_safe_normalize(crawl.start_url)}
        crawled_urls.update(_safe_normalize(page.url) for page in crawl.pages)
        selected = 0
        aggregate = crawl
        for candidate in crawl.candidates:
            normalized_candidate_url = _safe_normalize(candidate.url)
            skip_reason = _candidate_skip_reason(
                candidate,
                normalized_candidate_url,
                crawled_urls,
                selected,
                self.candidate_follow_up_limit,
            )
            if skip_reason:
                memory.record_event(
                    self.name,
                    "candidate_skipped",
                    "Skipping discovery candidate follow-up crawl",
                    {
                        "url": candidate.url,
                        "kind": candidate.kind,
                        "source_tool": candidate.source_tool,
                        "reason": skip_reason,
                    },
                )
                continue

            selected += 1
            crawled_urls.add(normalized_candidate_url)
            memory.record_event(
                self.name,
                "candidate_selected",
                "Selected discovery candidate for follow-up crawl",
                {
                    "url": candidate.url,
                    "kind": candidate.kind,
                    "source_tool": candidate.source_tool,
                    "status": candidate.status,
                    "reason": candidate.reason,
                },
            )
            follow_up = self._run_crawl_tool(self.crawl_tool, candidate.url, memory, max_pages, max_depth)
            aggregate = self._merge_crawls(aggregate, follow_up)
            crawled_urls.update(_safe_normalize(page.url) for page in follow_up.pages)
        return aggregate


@dataclass(frozen=True)
class JavascriptCrawlerDecision:
    select_katana: bool
    evidence: list[str]


def _looks_like_javascript_reference(reference: str) -> bool:
    path = urlparse(reference).path.lower()
    return path.endswith(".js") or path.endswith(".mjs") or path.endswith(".jsx") or ".js?" in reference.lower()


def _javascript_urls(crawl: CrawlResult) -> list[str]:
    return sorted(
        {
            value
            for page in crawl.pages
            for value in [page.url, *page.references]
            if value.startswith(("http://", "https://")) and _looks_like_javascript_reference(value)
        }
    )


def _javascript_contexts(crawl: CrawlResult) -> list[dict[str, object]]:
    contexts: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for page in crawl.pages:
        page_js_urls = [
            value
            for value in [page.url, *page.references]
            if value.startswith(("http://", "https://")) and _looks_like_javascript_reference(value)
        ]
        for js_url in sorted(set(page_js_urls)):
            key = (page.url, js_url)
            if key in seen:
                continue
            seen.add(key)
            contexts.append(
                {
                    "source": js_url,
                    "page_url": page.url,
                    "inline_scripts": page.inline_scripts,
                }
            )
    return contexts


def _page_merge_key(page: CrawledPage) -> tuple[str, str]:
    if page.status == 0 and page.references and page.title and page.title.startswith(HTTP_METHOD_TITLES):
        return (page.url, page.title)
    return (page.url, "")


def _crawl_event_result_data(crawl: CrawlResult, sample_limit: int = 20) -> dict[str, object]:
    result_data: dict[str, object] = {
        "pages": len(crawl.pages),
        "page_urls": [page.url for page in crawl.pages[:sample_limit]],
        "candidates": len(crawl.candidates),
        "candidate_urls": [candidate.url for candidate in crawl.candidates[:sample_limit]],
        "out_of_scope": len(crawl.out_of_scope),
        "out_of_scope_urls": crawl.out_of_scope[:sample_limit],
        "failed": len(crawl.failed),
    }
    if crawl.failed:
        result_data["failures"] = crawl.failed
    return result_data


def _candidate_skip_reason(
    candidate: DiscoveryCandidate,
    normalized_candidate_url: str,
    crawled_urls: set[str],
    selected_count: int,
    follow_up_limit: int,
) -> str | None:
    if not candidate.should_crawl:
        return "not_crawlable"
    if normalized_candidate_url in crawled_urls:
        return "already_crawled"
    if selected_count >= follow_up_limit:
        return "follow_up_limit_reached"
    return None


def _safe_normalize(url: str) -> str:
    try:
        return normalize_url(url)
    except ValueError:
        return url


class TechnologyMapperAgent:
    name = "technology_mapper"


class DiscoveryReporterAgent:
    name = "reporter"

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
            "discovery_candidates": len(crawl.candidates),
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
                ),
                DirbDockerDiscoveryTool(
                    config.tool_image,
                    wordlist=config.dirb_wordlist,
                    docker_timeout=config.dirb_docker_timeout,
                ),
                ExtractifyDockerTool(config.tool_image),
                JsStaticEndpointDockerTool(config.tool_image),
            ],
            candidate_follow_up_limit=config.candidate_follow_up_limit,
        ),
        technology_mapper=TechnologyMapperAgent(),
        reporter=DiscoveryReporterAgent(),
    )
