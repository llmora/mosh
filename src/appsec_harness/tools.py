from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from appsec_harness.components import compile_component_inventory
from appsec_harness.crawler import Crawler
from appsec_harness.docker_tools import DockerToolRunner
from appsec_harness.models import CrawledPage, CrawlResult
from appsec_harness.scope import ScopePolicy, normalize_url, strip_fragment


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


def _strip_terminal_sequences(output: str) -> str:
    output = output.replace("\r", "\n")
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)


class CompileComponentInventoryTool:
    definition = ToolDefinition(
        name="compile_component_inventory",
        description="Compile an observable remote component inventory from crawler findings.",
    )

    def run(self, crawl: CrawlResult) -> list[dict[str, str]]:
        return compile_component_inventory(crawl)
