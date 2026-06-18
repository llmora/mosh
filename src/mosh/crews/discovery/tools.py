from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

from mosh.crews.discovery.crawler import Crawler
from mosh.docker_tools import DockerToolRunner
from mosh.models import CrawledPage, CrawlResult, DiscoveryCandidate
from mosh.scope import ScopePolicy, normalize_url, strip_fragment


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str


class CrawlApplicationTool:
    definition = ToolDefinition(
        name="crawl_application",
        description="Crawl an in-scope application URL and return discovered pages, references, forms, and out-of-scope URLs.",
    )

    def __init__(self, crawler: Crawler | None = None) -> None:
        self.crawler = crawler or Crawler()

    def run(self, url: str, max_pages: int, max_depth: int) -> CrawlResult:
        return self.crawler.crawl(url, max_pages=max_pages, max_depth=max_depth)


class KatanaDockerCrawlerTool:
    definition = ToolDefinition(
        name="katana_docker_crawler",
        description="Run Katana inside the discovery tools container for JavaScript-aware endpoint discovery.",
    )

    def __init__(
        self,
        image: str,
        runner: DockerToolRunner | None = None,
        crawl_duration: str = "270s",
        docker_timeout: int = 300,
    ) -> None:
        self.runner = runner or DockerToolRunner(image)
        self.crawl_duration = crawl_duration
        self.docker_timeout = docker_timeout

    def run(self, url: str, max_pages: int, max_depth: int) -> CrawlResult:
        start_url = normalize_url(url)
        result = self.runner.run(
            [
                "katana",
                "-u",
                start_url,
                "-d",
                str(max_depth),
                "-mdp",
                str(max_pages),
                "-ct",
                self.crawl_duration,
                "-headless",
                "-system-chrome",
                "-system-chrome-path",
                "/usr/bin/chromium",
                "-no-sandbox",
                "-headless-options",
                "--disable-dev-shm-usage,--disable-gpu",
                "-xhr",
                "-aff",
                "-jc",
                "-jsl",
                "-kf",
                "all",
                "-fx",
                "-do",
                "-j",
                "-or",
                "-ob",
                "-silent",
            ],
            timeout=self.docker_timeout,
            tty=True,
        )
        crawl = parse_katana_output(start_url, result.stdout)
        if result.exit_code != 0:
            return CrawlResult(
                start_url=start_url,
                pages=crawl.pages,
                out_of_scope=crawl.out_of_scope,
                failed=[*crawl.failed, {"url": start_url, "error": _katana_error(result.stderr, result.stdout)}],
                robots=crawl.robots,
            )
        return crawl


class DirbDockerDiscoveryTool:
    definition = ToolDefinition(
        name="dirb_docker_discovery",
        description="Run Dirb inside the discovery tools container to discover additional in-scope paths from a bounded wordlist.",
    )

    def __init__(
        self,
        image: str,
        runner: DockerToolRunner | None = None,
        wordlist: str = "/usr/share/dirb/wordlists/small.txt",
        docker_timeout: int = 300,
    ) -> None:
        self.runner = runner or DockerToolRunner(image)
        self.wordlist = wordlist
        self.docker_timeout = docker_timeout

    def run(self, url: str, max_pages: int, max_depth: int) -> CrawlResult:
        start_url = normalize_url(url)
        result = self.runner.run(
            [
                "dirb",
                start_url,
                self.wordlist,
                "-S",
                "-r",
                "-w",
            ],
            timeout=self.docker_timeout,
        )
        crawl = parse_dirb_output(start_url, result.stdout)
        if result.exit_code != 0:
            return CrawlResult(
                start_url=start_url,
                pages=crawl.pages,
                out_of_scope=crawl.out_of_scope,
                failed=[*crawl.failed, {"url": start_url, "error": _dirb_error(result.stderr, result.stdout)}],
                robots=None,
                candidates=crawl.candidates,
            )
        return crawl


class ExtractifyDockerTool:
    definition = ToolDefinition(
        name="extractify_js_endpoint_discovery",
        description="Run Extractify inside the discovery tools container to extract endpoints and URLs from JavaScript assets.",
    )

    def __init__(
        self,
        image: str,
        runner: DockerToolRunner | None = None,
        docker_timeout: int = 120,
    ) -> None:
        self.runner = runner or DockerToolRunner(image)
        self.docker_timeout = docker_timeout

    def run(self, start_url: str, js_urls: list[str]) -> CrawlResult:
        normalized_start_url = normalize_url(start_url)
        unique_js_urls = sorted({strip_fragment(url) for url in js_urls if url.startswith(("http://", "https://"))})
        if not unique_js_urls:
            return CrawlResult(normalized_start_url, [], [], [], None)

        result = self.runner.run(
            [
                "extractify",
                "-ee",
                "-eu",
                "-json",
                "-dedup",
            ],
            input_text="\n".join(unique_js_urls) + "\n",
            timeout=self.docker_timeout,
        )
        crawl = parse_extractify_output(normalized_start_url, result.stdout)
        if result.exit_code != 0:
            return CrawlResult(
                start_url=normalized_start_url,
                pages=crawl.pages,
                out_of_scope=crawl.out_of_scope,
                failed=[*crawl.failed, {"url": normalized_start_url, "error": _extractify_error(result.stderr, result.stdout)}],
                robots=None,
            )
        return crawl


class JsStaticEndpointDockerTool:
    definition = ToolDefinition(
        name="js_static_endpoint_discovery",
        description="Run static JavaScript AST analysis in the discovery tools container to resolve constructed API endpoints.",
    )

    def __init__(
        self,
        image: str,
        runner: DockerToolRunner | None = None,
        docker_timeout: int = 120,
    ) -> None:
        self.runner = runner or DockerToolRunner(image)
        self.docker_timeout = docker_timeout

    def run(
        self,
        start_url: str,
        js_urls: list[str],
        contexts: list[dict[str, object]] | None = None,
    ) -> CrawlResult:
        normalized_start_url = normalize_url(start_url)
        unique_js_urls = sorted({strip_fragment(url) for url in js_urls if url.startswith(("http://", "https://"))})
        if not unique_js_urls:
            return CrawlResult(normalized_start_url, [], [], [], None)

        input_text = _js_static_input(unique_js_urls, contexts)
        result = self.runner.run(
            [
                "js-endpoint-extractor",
                "--base-url",
                normalized_start_url,
                "--json",
            ],
            input_text=input_text,
            timeout=self.docker_timeout,
        )
        crawl = parse_js_static_output(normalized_start_url, result.stdout)
        if result.exit_code != 0:
            return CrawlResult(
                start_url=normalized_start_url,
                pages=crawl.pages,
                out_of_scope=crawl.out_of_scope,
                failed=[*crawl.failed, {"url": normalized_start_url, "error": _js_static_error(result.stderr, result.stdout)}],
                robots=None,
            )
        return crawl


def _js_static_input(unique_js_urls: list[str], contexts: list[dict[str, object]] | None) -> str:
    if not contexts:
        return "\n".join(unique_js_urls) + "\n"
    known_urls = set(unique_js_urls)
    selected_contexts = [
        context
        for context in contexts
        if isinstance(context.get("source"), str) and strip_fragment(str(context["source"])) in known_urls
    ]
    if not selected_contexts:
        return "\n".join(unique_js_urls) + "\n"
    return json.dumps(selected_contexts) + "\n"


def parse_katana_output(start_url: str, output: str) -> CrawlResult:
    scope = ScopePolicy.from_url(start_url)
    pages_by_url: dict[str, CrawledPage] = {}
    out_of_scope: set[str] = set()
    failed: list[dict[str, str]] = []

    for parsed_line in _parse_katana_stream(output):
        discovered_url = parsed_line.get("url")
        if not discovered_url:
            continue
        discovered_url = strip_fragment(discovered_url)
        if not discovered_url.startswith(("http://", "https://")):
            continue
        if not scope.in_scope(discovered_url):
            out_of_scope.add(discovered_url)
            continue
        status = _int_or_default(parsed_line.get("status"), 0)
        source = parsed_line.get("source")
        page = pages_by_url.get(discovered_url)
        if page:
            continue
        references = [source] if source and source != discovered_url and source.startswith(("http://", "https://")) else []
        pages_by_url[discovered_url] = CrawledPage(
            url=discovered_url,
            status=status,
            content_type=str(parsed_line.get("content_type") or ""),
            title=None,
            headers={},
            links=[],
            references=references,
            forms=[],
        )

    return CrawlResult(
        start_url=normalize_url(start_url),
        pages=sorted(pages_by_url.values(), key=lambda page: page.url),
        out_of_scope=sorted(out_of_scope),
        failed=failed,
        robots=None,
    )


def parse_dirb_output(start_url: str, output: str) -> CrawlResult:
    normalized_start_url = normalize_url(start_url)
    scope = ScopePolicy.from_url(normalized_start_url)
    candidates_by_url: dict[str, DiscoveryCandidate] = {}
    out_of_scope: set[str] = set()

    for parsed_line in _parse_dirb_stream(output):
        discovered_url = parsed_line.get("url")
        if not discovered_url:
            continue
        discovered_url = strip_fragment(discovered_url)
        if not discovered_url.startswith(("http://", "https://")):
            discovered_url = strip_fragment(urljoin(normalized_start_url, discovered_url))
        if not scope.in_scope(discovered_url):
            out_of_scope.add(discovered_url)
            continue
        if discovered_url in candidates_by_url:
            continue
        kind = _classify_candidate(discovered_url, bool(parsed_line.get("directory")))
        should_crawl = _candidate_should_crawl(kind, _int_or_default(parsed_line.get("status"), 0))
        candidates_by_url[discovered_url] = DiscoveryCandidate(
            url=discovered_url,
            source_tool="dirb_docker_discovery",
            status=_int_or_default(parsed_line.get("status"), 0),
            kind=kind,
            confidence="confirmed" if parsed_line.get("status") else "likely",
            reason="Dirb discovered a candidate path from the configured wordlist.",
            evidence=[normalized_start_url],
            should_crawl=should_crawl,
        )

    return CrawlResult(
        start_url=normalized_start_url,
        pages=[],
        out_of_scope=sorted(out_of_scope),
        failed=[],
        robots=None,
        candidates=sorted(candidates_by_url.values(), key=lambda candidate: candidate.url),
    )


def parse_extractify_output(start_url: str, output: str) -> CrawlResult:
    return _parse_endpoint_findings_output(start_url, output, "extractify")


def parse_js_static_output(start_url: str, output: str) -> CrawlResult:
    return _parse_endpoint_findings_output(start_url, output, "js static endpoint extractor")


def _parse_endpoint_findings_output(start_url: str, output: str, tool_name: str) -> CrawlResult:
    normalized_start_url = normalize_url(start_url)
    scope = ScopePolicy.from_url(normalized_start_url)
    pages_by_url: dict[str, CrawledPage] = {}
    out_of_scope: set[str] = set()
    failed: list[dict[str, str]] = []

    try:
        findings = json.loads(output or "[]")
    except json.JSONDecodeError as exc:
        return CrawlResult(
            start_url=normalized_start_url,
            pages=[],
            out_of_scope=[],
            failed=[{"url": normalized_start_url, "error": f"{tool_name} returned invalid JSON: {exc}"}],
            robots=None,
        )
    if not isinstance(findings, list):
        return CrawlResult(
            start_url=normalized_start_url,
            pages=[],
            out_of_scope=[],
            failed=[{"url": normalized_start_url, "error": f"{tool_name} returned non-list JSON"}],
            robots=None,
        )

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        source = finding.get("source") if isinstance(finding.get("source"), str) else normalized_start_url
        candidates = _endpoint_candidates(finding)
        for candidate in candidates:
            discovered_url = _normalize_extracted_url(candidate, source, normalized_start_url)
            if not discovered_url:
                continue
            if not scope.in_scope(discovered_url):
                out_of_scope.add(discovered_url)
                continue
            page = pages_by_url.get(discovered_url)
            if page:
                continue
            references = [source] if source.startswith(("http://", "https://")) and source != discovered_url else []
            pages_by_url[discovered_url] = CrawledPage(
                url=discovered_url,
                status=0,
                content_type="",
                title=None,
                headers={},
                links=[],
                references=references,
                forms=[],
            )

    return CrawlResult(
        start_url=normalized_start_url,
        pages=sorted(pages_by_url.values(), key=lambda page: page.url),
        out_of_scope=sorted(out_of_scope),
        failed=failed,
        robots=None,
    )


def _endpoint_candidates(finding: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in ("urls", "endpoints"):
        values = finding.get(key)
        if isinstance(values, list):
            candidates.extend(value for value in values if isinstance(value, str))
    return candidates


def _normalize_extracted_url(candidate: str, source: str, start_url: str) -> str | None:
    candidate = candidate.strip()
    if not candidate:
        return None
    if candidate.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None
    if candidate.startswith("//"):
        return strip_fragment(f"{urlparse(start_url).scheme}:{candidate}")
    if candidate.startswith(("http://", "https://")):
        return strip_fragment(candidate)
    base = source if source.startswith(("http://", "https://")) else start_url
    return strip_fragment(urljoin(base, candidate))


def _parse_dirb_stream(output: str) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    cleaned = _strip_terminal_sequences(output)
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.search(r"^\+\s+(\S+)\s+\(CODE:(\d+)\|", line)
        if match:
            parsed.append({"url": match.group(1), "status": match.group(2)})
            continue
        directory_match = re.search(r"^==>\s+DIRECTORY:\s+(\S+)", line)
        if directory_match:
            parsed.append({"url": directory_match.group(1), "status": 0, "directory": True})
    return parsed


def _classify_candidate(url: str, is_directory: bool) -> str:
    path = urlparse(url).path.lower()
    if is_directory or path.endswith("/"):
        return "directory"
    if any(marker in path for marker in ("/api", "/graphql", "/rest", "/v1", "/v2", "/v3")):
        return "api"
    if _is_static_asset_path(path):
        return "asset"
    return "path"


def _candidate_should_crawl(kind: str, status: int) -> bool:
    if kind == "asset":
        return False
    return status in {0, 200, 204, 301, 302, 307, 308, 401, 403}


def _is_static_asset_path(path: str) -> bool:
    return path.endswith(
        (
            ".js",
            ".mjs",
            ".css",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".webp",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".map",
            ".pdf",
            ".zip",
            ".gz",
        )
    )


def _parse_katana_stream(output: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    cleaned = _strip_terminal_sequences(output)
    parsed: list[dict[str, Any]] = []
    index = 0
    while index < len(cleaned):
        while index < len(cleaned) and cleaned[index].isspace():
            index += 1
        if index >= len(cleaned):
            break
        if cleaned[index] != "{":
            next_line = cleaned.find("\n", index)
            line = cleaned[index:] if next_line == -1 else cleaned[index:next_line]
            line = line.strip()
            if line:
                parsed.append({"url": line})
            index = len(cleaned) if next_line == -1 else next_line + 1
            continue
        try:
            value, next_index = decoder.raw_decode(cleaned, index)
        except json.JSONDecodeError:
            next_line = cleaned.find("\n", index)
            line = cleaned[index:] if next_line == -1 else cleaned[index:next_line]
            parsed.append(_parse_katana_line(line.strip()))
            index = len(cleaned) if next_line == -1 else next_line + 1
            continue
        if isinstance(value, dict):
            parsed.append(_normalize_katana_object(value))
        index = next_index
    return parsed


def _parse_katana_line(line: str) -> dict[str, Any]:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return {"url": line}
    if not isinstance(data, dict):
        return {}
    return _normalize_katana_object(data)


def _normalize_katana_object(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": _first_string(data, "url", "endpoint", "qurl", "request.endpoint"),
        "source": _first_string(data, "source", "source_url", "request.source"),
        "status": _first_value(data, "status_code", "status", "response.status_code"),
        "content_type": _first_string(data, "content_type", "response.content_type", "response.headers.Content-Type"),
    }


def _first_string(data: dict[str, Any], *keys: str) -> str | None:
    value = _first_value(data, *keys)
    return value if isinstance(value, str) else None


def _first_value(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = _nested_value(data, key)
        if value is not None:
            return value
    return None


def _nested_value(data: dict[str, Any], key: str) -> Any:
    current: Any = data
    for part in key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _int_or_default(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _katana_error(stderr: str, stdout: str) -> str:
    error = stderr.strip() or stdout.strip() or "katana failed"
    return error[:2000]


def _dirb_error(stderr: str, stdout: str) -> str:
    error = stderr.strip() or stdout.strip() or "dirb failed"
    return error[:2000]


def _extractify_error(stderr: str, stdout: str) -> str:
    error = stderr.strip() or stdout.strip() or "extractify failed"
    return error[:2000]


def _js_static_error(stderr: str, stdout: str) -> str:
    error = stderr.strip() or stdout.strip() or "js static endpoint extractor failed"
    return error[:2000]


def _strip_terminal_sequences(output: str) -> str:
    output = output.replace("\r", "\n")
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
