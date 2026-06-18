from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from mosh.config import AppConfig
from mosh.crews.discovery.crew import CREW_CONFIG_PACKAGE, CrewAIUnavailable, _llm, _load_crewai
from mosh.crews.events import MoshCrewAIEventListener
from mosh.evidence_links import EvidenceLinkerToolContext, LiveEndpoint, SourceRoute
from mosh.memory import FileMemory
from mosh.scope import ScopePolicy


@dataclass
class EvidenceLinkerState:
    context: dict[str, Any] = field(default_factory=dict)
    tool_context: EvidenceLinkerToolContext | None = None
    memory: FileMemory | None = None
    candidates: dict[str, Any] | None = None
    observations: list[dict[str, Any]] = field(default_factory=list)


class CrewAIModelAssistedEvidenceLinker:
    def __init__(self, config: AppConfig, memory: FileMemory | None = None) -> None:
        self.config = config
        self.memory = memory
        model = config.models.planning.evidence_linker
        self.model_metadata = {
            "crew": "planning",
            "agent": "evidence_linker",
            "model": config.llm_model_name(model),
            "provider": config.llm_provider_for_model(model),
        }

    def suggest_links(
        self,
        context: dict[str, Any],
        tool_context: EvidenceLinkerToolContext | None = None,
    ) -> dict[str, Any]:
        if not context.get("pairs"):
            return {"links": []}
        model = self.config.models.planning.evidence_linker
        missing_keys = self.config.missing_llm_api_keys_for_models([model])
        if missing_keys:
            raise CrewAIUnavailable(f"Missing LLM API key(s): {', '.join(missing_keys)}.")

        crewai = _load_crewai()
        state = EvidenceLinkerState(context=context, tool_context=tool_context, memory=self.memory)
        crew = _build_planning_evidence_linker_crew(crewai, self.config, state)
        crew.crew().kickoff(inputs={"link_context": json.dumps(context, sort_keys=True)})
        if state.candidates is None:
            raise RuntimeError("Evidence linker did not submit candidate links.")
        return state.candidates


def build_model_assisted_linker(
    config: AppConfig,
    memory: FileMemory | None = None,
) -> CrewAIModelAssistedEvidenceLinker:
    return CrewAIModelAssistedEvidenceLinker(config, memory=memory)


def _build_planning_evidence_linker_crew(crewai: Any, config: AppConfig, state: EvidenceLinkerState):
    submit_tool = _build_submit_evidence_link_candidates_tool(crewai, state)
    load_ref_tool = _build_load_evidence_ref_tool(crewai, state)
    source_search_tool = _build_source_search_tool(crewai, state)
    source_read_slice_tool = _build_source_read_slice_tool(crewai, state)
    live_metadata_tool = _build_live_endpoint_metadata_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/evidence_linker_agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("planning/evidence_linker_tasks.yaml"))

    @crewai.CrewBase
    class EvidenceLinkerCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def evidence_linker(self):
            return crewai.Agent(
                config=self.agents_config["evidence_linker"],
                llm=_llm(crewai, config, config.models.planning.evidence_linker),
                tools=[
                    load_ref_tool,
                    source_search_tool,
                    source_read_slice_tool,
                    live_metadata_tool,
                    submit_tool,
                ],
                allow_delegation=False,
            )

        @crewai.task
        def suggest_evidence_link_candidates_task(self):
            return crewai.Task(
                config=self.tasks_config["suggest_evidence_link_candidates_task"],
                agent=self.evidence_linker(),
            )

        @crewai.crew
        def crew(self):
            kwargs = {
                "agents": [self.evidence_linker()],
                "tasks": [self.suggest_evidence_link_candidates_task()],
                "process": crewai.Process.sequential,
                "verbose": True,
            }
            if state.memory is not None:
                kwargs["event_listeners"] = [MoshCrewAIEventListener(state.memory)]
            return crewai.Crew(**kwargs)

    return EvidenceLinkerCrew()


def _build_load_evidence_ref_tool(crewai: Any, state: EvidenceLinkerState):
    class LoadEvidenceRefInput(crewai.BaseModel):
        ref_id: str = crewai.Field(..., description="Existing source_ref_id or live_ref_id from the link context.")

    class LoadEvidenceRefTool(crewai.BaseTool):
        name: str = "load_evidence_ref"
        description: str = "Fetch full details for an existing source route or live endpoint evidence ref."
        args_schema: type[crewai.BaseModel] = LoadEvidenceRefInput

        def _run(self, ref_id: str) -> str:
            result = _load_ref(state, ref_id)
            _record_observation(state, "load_evidence_ref", result)
            return json.dumps(result, sort_keys=True)

    return LoadEvidenceRefTool()


def _build_source_search_tool(crewai: Any, state: EvidenceLinkerState):
    class SourceSearchInput(crewai.BaseModel):
        source_ref_id: str = crewai.Field(..., description="Existing source_ref_id whose source asset should be searched.")
        pattern: str = crewai.Field(..., description="Literal or regex pattern to search for.")
        regex: bool = crewai.Field(False, description="Treat pattern as a regular expression.")
        limit: int = crewai.Field(20, description="Maximum matches to return, capped by the tool.")
        path_glob: str | None = crewai.Field(None, description="Optional relative-path glob filter.")

    class SourceSearchTool(crewai.BaseTool):
        name: str = "source_search"
        description: str = "Search bounded nonignored text files inside the source asset for an existing source ref."
        args_schema: type[crewai.BaseModel] = SourceSearchInput

        def _run(
            self,
            source_ref_id: str,
            pattern: str,
            regex: bool = False,
            limit: int = 20,
            path_glob: str | None = None,
        ) -> str:
            route = _source_route_for_ref(state, source_ref_id)
            result = _run_source_search(route, pattern, regex=regex, limit=limit, path_glob=path_glob)
            result["source_ref_id"] = source_ref_id
            _record_observation(state, "source_search", result)
            return json.dumps(result, sort_keys=True)

    return SourceSearchTool()


def _build_source_read_slice_tool(crewai: Any, state: EvidenceLinkerState):
    class SourceReadSliceInput(crewai.BaseModel):
        source_ref_id: str = crewai.Field(..., description="Existing source_ref_id whose source asset should be read.")
        relative_path: str | None = crewai.Field(
            None,
            description="Optional file path relative to the source root; defaults to the source ref path.",
        )
        start_line: int | None = crewai.Field(None, description="Optional first line to read.")
        end_line: int | None = crewai.Field(None, description="Optional last line to read.")

    class SourceReadSliceTool(crewai.BaseTool):
        name: str = "source_read_slice"
        description: str = "Read a bounded source file slice for an existing source ref."
        args_schema: type[crewai.BaseModel] = SourceReadSliceInput

        def _run(
            self,
            source_ref_id: str,
            relative_path: str | None = None,
            start_line: int | None = None,
            end_line: int | None = None,
        ) -> str:
            route = _source_route_for_ref(state, source_ref_id)
            result = _run_source_read_slice(route, relative_path=relative_path, start_line=start_line, end_line=end_line)
            result["source_ref_id"] = source_ref_id
            _record_observation(state, "source_read_slice", result)
            return json.dumps(result, sort_keys=True)

    return SourceReadSliceTool()


def _build_live_endpoint_metadata_tool(crewai: Any, state: EvidenceLinkerState):
    class LiveEndpointMetadataInput(crewai.BaseModel):
        live_ref_id: str = crewai.Field(..., description="Existing live_ref_id to inspect.")
        method: str = crewai.Field("HEAD", description="Safe method to use: HEAD, GET, or OPTIONS.")
        timeout: int = crewai.Field(5, description="Request timeout in seconds, capped by the tool.")

    class LiveEndpointMetadataTool(crewai.BaseTool):
        name: str = "live_endpoint_metadata"
        description: str = "Fetch safe response metadata for an already discovered live endpoint ref."
        args_schema: type[crewai.BaseModel] = LiveEndpointMetadataInput

        def _run(self, live_ref_id: str, method: str = "HEAD", timeout: int = 5) -> str:
            endpoint = _live_endpoint_for_ref(state, live_ref_id)
            result = _run_live_endpoint_metadata(endpoint, method=method, timeout=timeout)
            result["live_ref_id"] = live_ref_id
            _record_observation(state, "live_endpoint_metadata", result)
            return json.dumps(result, sort_keys=True)

    return LiveEndpointMetadataTool()


def _build_submit_evidence_link_candidates_tool(crewai: Any, state: EvidenceLinkerState):
    class SubmitEvidenceLinkCandidatesInput(crewai.BaseModel):
        links: list[dict[str, Any]] | str = crewai.Field(
            ...,
            description="Candidate source/live evidence links using only source_ref_id and live_ref_id values from the input.",
        )

    class SubmitEvidenceLinkCandidatesTool(crewai.BaseTool):
        name: str = "submit_evidence_link_candidates"
        description: str = "Submit model-assisted source/live evidence link candidates."
        args_schema: type[crewai.BaseModel] = SubmitEvidenceLinkCandidatesInput

        def _run(self, links: Any) -> str:
            normalized = _normalize_candidate_payload({"links": links})
            state.candidates = normalized
            return json.dumps({"candidate_links": len(normalized.get("links") or [])}, sort_keys=True)

    return SubmitEvidenceLinkCandidatesTool()


def _load_ref(state: EvidenceLinkerState, ref_id: str) -> dict[str, Any]:
    source_route = _source_route_for_ref(state, ref_id)
    if source_route is not None:
        return {"ref_id": ref_id, "kind": "source_route", **_source_route_payload(source_route)}
    live_endpoint = _live_endpoint_for_ref(state, ref_id)
    if live_endpoint is not None:
        return {"ref_id": ref_id, "kind": "live_endpoint", **_live_endpoint_payload(live_endpoint)}
    return {"ref_id": ref_id, "error": "unknown evidence ref"}


def _source_route_for_ref(state: EvidenceLinkerState, ref_id: str) -> SourceRoute | None:
    if state.tool_context is None:
        return None
    return state.tool_context.source_refs.get(_text(ref_id))


def _live_endpoint_for_ref(state: EvidenceLinkerState, ref_id: str) -> LiveEndpoint | None:
    if state.tool_context is None:
        return None
    return state.tool_context.live_refs.get(_text(ref_id))


def _source_route_payload(route: SourceRoute) -> dict[str, Any]:
    return {
        "asset_id": route.asset.id,
        "method": route.method,
        "route": route.route,
        "path": route.source_path,
        "line": route.line,
        "handler": route.handler,
        "framework": route.framework,
        "snippet_hash": route.snippet_hash,
        "route_resolution_confidence": route.route_resolution_confidence,
        "source_root_available": _source_root(route) is not None,
    }


def _live_endpoint_payload(endpoint: LiveEndpoint) -> dict[str, Any]:
    return {
        "asset_id": endpoint.asset.id,
        "method": endpoint.method,
        "url": endpoint.url,
        "path": endpoint.path,
        "status": endpoint.status,
        "source_kind": endpoint.source_kind,
    }


def _run_source_search(
    route: SourceRoute | None,
    pattern: str,
    *,
    regex: bool = False,
    limit: int = 20,
    path_glob: str | None = None,
) -> dict[str, Any]:
    root = _source_root(route)
    if route is None or root is None:
        return {"matches": [], "truncated": False, "error": "source ref has no readable local source root"}
    pattern = _text(pattern)[:240]
    if not pattern:
        return {"matches": [], "truncated": False, "error": "empty search pattern"}
    limit = min(max(_int(limit, 20), 1), 50)
    try:
        compiled = re.compile(pattern) if regex else None
    except re.error as exc:
        return {"matches": [], "truncated": False, "error": f"invalid regex: {exc}"}
    matches: list[dict[str, Any]] = []
    for path in _iter_nonignored_text_files(root):
        relative = _relative_path(root, path)
        if path_glob and not fnmatch.fnmatch(relative, path_glob):
            continue
        text = _read_text_file(path)
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            matched = bool(compiled.search(line)) if compiled else pattern in line
            if not matched:
                continue
            preview = line.strip()[:240]
            matches.append(
                {
                    "path": relative,
                    "line": line_number,
                    "preview": preview,
                    "snippet_hash": _snippet_hash(preview),
                }
            )
            if len(matches) >= limit:
                return {"matches": matches, "truncated": True}
    return {"matches": matches, "truncated": False}


def _run_source_read_slice(
    route: SourceRoute | None,
    *,
    relative_path: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
) -> dict[str, Any]:
    root = _source_root(route)
    if route is None or root is None:
        return {"error": "source ref has no readable local source root"}
    relative = _text(relative_path) or _text(route.source_path)
    if not relative:
        return {"error": "source ref has no source path"}
    if Path(relative).is_absolute():
        return {"error": "source_read_slice requires a relative path"}
    start = _int(start_line, max(1, (route.line or 1) - 20))
    end = _int(end_line, start + 80)
    if start < 1 or end < start:
        return {"error": "invalid source slice line range"}
    end = min(end, start + 160)
    path = (root / relative).resolve()
    if root not in path.parents and path != root:
        return {"error": "source slice path escapes source root"}
    text = _read_text_file(path)
    if text is None:
        return {"error": f"source slice is not readable text: {relative}"}
    lines = text.splitlines()
    selected = lines[start - 1 : end]
    body = "\n".join(selected)
    return {
        "path": _relative_path(root, path),
        "start_line": start,
        "end_line": start + len(selected) - 1,
        "content": body[:12000],
        "snippet_hash": _snippet_hash(body),
    }


def _run_live_endpoint_metadata(endpoint: LiveEndpoint | None, *, method: str = "HEAD", timeout: int = 5) -> dict[str, Any]:
    if endpoint is None:
        return {"error": "unknown live endpoint ref"}
    method = _text(method).upper() or "HEAD"
    if method not in {"HEAD", "GET", "OPTIONS"}:
        return {"error": "live_endpoint_metadata only allows HEAD, GET, or OPTIONS"}
    if not _endpoint_is_in_asset_scope(endpoint):
        return {"url": endpoint.url, "method": method, "blocked": True, "error": "endpoint URL is outside asset scope"}
    request_timeout = min(max(_int(timeout, 5), 1), 10)
    request = Request(
        endpoint.url,
        method=method,
        headers={"User-Agent": "mosh-evidence-linker/0.1", "Accept": "*/*"},
    )
    try:
        with urlopen(request, timeout=request_timeout) as response:
            body = ""
            if method == "GET":
                body = response.read(2048).decode("utf-8", errors="replace")
            return {
                "url": endpoint.url,
                "method": method,
                "status": response.status,
                "final_url": response.geturl(),
                "headers": _safe_headers(dict(response.headers.items())),
                "body_preview": body[:1000],
            }
    except HTTPError as exc:
        return {
            "url": endpoint.url,
            "method": method,
            "status": exc.code,
            "final_url": exc.geturl(),
            "headers": _safe_headers(dict(exc.headers.items())),
            "body_preview": "",
        }
    except URLError as exc:
        return {"url": endpoint.url, "method": method, "error": str(exc.reason)[:240]}
    except TimeoutError:
        return {"url": endpoint.url, "method": method, "error": f"request timed out after {request_timeout}s"}


def _endpoint_is_in_asset_scope(endpoint: LiveEndpoint) -> bool:
    try:
        return ScopePolicy.from_url(endpoint.asset.locator).in_scope(endpoint.url)
    except ValueError:
        return False


def _safe_headers(headers: dict[str, Any]) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in sorted(headers.items()):
        normalized = str(key).lower()
        if normalized in {"authorization", "cookie", "set-cookie", "proxy-authorization"}:
            safe[str(key)] = "[redacted]"
            continue
        safe[str(key)] = str(value)[:300]
        if len(safe) >= 20:
            break
    return safe


def _source_root(route: SourceRoute | None) -> Path | None:
    if route is None:
        return None
    path = Path(route.asset.locator).expanduser()
    if not path.exists() or not path.is_dir():
        return None
    return path.resolve()


IGNORED_SOURCE_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
}


def _iter_nonignored_text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_SOURCE_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
        except OSError:
            continue
        yield path


def _read_text_file(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError:
            return None


def _relative_path(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _snippet_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _record_observation(state: EvidenceLinkerState, tool: str, result: dict[str, Any]) -> None:
    state.observations.append({"tool": tool, "result": result})


def _normalize_candidate_payload(value: dict[str, Any]) -> dict[str, Any]:
    links = _candidate_link_items(value.get("links"))
    normalized_links = []
    for item in links:
        if not isinstance(item, dict):
            continue
        source_ref_id = _text(item.get("source_ref_id"))
        live_ref_id = _text(item.get("live_ref_id"))
        if not source_ref_id or not live_ref_id:
            continue
        normalized_links.append(
            {
                "source_ref_id": source_ref_id,
                "live_ref_id": live_ref_id,
                "confidence": _normalize_confidence(item.get("confidence")),
                "reason": _text(item.get("reason"))[:600],
            }
        )
    return {"links": normalized_links[:100]}


def _candidate_link_items(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return _candidate_link_items(parsed.get("links"))
    return []


def _normalize_confidence(value: Any) -> str:
    confidence = _text(value).lower()
    if confidence in {"low", "medium", "high"}:
        return confidence
    return "low"


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
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {"content": text}
        return parsed if isinstance(parsed, dict) else {"content": parsed}
    return {"content": value}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default
