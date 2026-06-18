from __future__ import annotations

import fnmatch
import json
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mosh.config import AppConfig
from mosh.crews.source_discovery.tools import (
    ReadSourceSliceTool,
    _iter_nonignored_files,
    _read_text_file,
    _relative_path,
    _snippet_hash,
)
from mosh.crews.testing.crew import (
    _append_command_log,
    _hypothesis_id,
    _redact_result,
    _redact_text,
    _text,
    _truncate,
)
from mosh.docker_tools import DockerToolResult, DockerToolRunner


LOCAL_RUNTIME_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"}
MAX_WORKSPACE_FILE_BYTES = 200_000


def _build_read_source_slice_tool(crewai: Any, state: Any):
    class ReadSourceSliceInput(crewai.BaseModel):
        relative_path: str = crewai.Field(..., description="Path relative to the assessed source root.")
        start_line: int = crewai.Field(..., description="First line to read, 1-indexed.")
        end_line: int = crewai.Field(..., description="Last line to read. The tool caps large slices.")
        purpose: str = crewai.Field(..., description="Why this source slice is needed for the current hypothesis.")

    class ReadBoundedSourceSliceTool(crewai.BaseTool):
        name: str = "read_source_slice"
        description: str = "Read a bounded line slice from a file under the source root."
        args_schema: type[crewai.BaseModel] = ReadSourceSliceInput

        def _run(self, relative_path: str, start_line: int, end_line: int, purpose: str) -> str:
            result = ReadSourceSliceTool().run(str(state.source_root), relative_path, start_line, end_line)
            record = {
                "purpose": purpose,
                "path": result.get("path"),
                "start_line": result.get("start_line"),
                "end_line": result.get("end_line"),
                "snippet_hash": result.get("snippet_hash"),
                "content": _truncate(_text(result.get("content"))),
            }
            state.source_reads.append(record)
            state.memory.record_event(
                "source_executor",
                "tool_result",
                "read_source_slice completed",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "path": result.get("path"),
                    "start_line": result.get("start_line"),
                    "end_line": result.get("end_line"),
                    "purpose": purpose,
                },
            )
            return json.dumps(record, sort_keys=True)

    return ReadBoundedSourceSliceTool()


def _build_source_search_tool(crewai: Any, state: Any):
    class SourceSearchInput(crewai.BaseModel):
        pattern: str = crewai.Field(..., description="Literal or regular expression pattern to search for.")
        purpose: str = crewai.Field(..., description="Why this search is needed for the current hypothesis.")
        regex: bool = crewai.Field(False, description="Treat pattern as a regular expression.")
        limit: int = crewai.Field(50, description="Maximum number of matches to return.")
        path_glob: str | None = crewai.Field(None, description="Optional relative-path glob filter.")

    class BoundedSourceSearchTool(crewai.BaseTool):
        name: str = "source_search"
        description: str = "Search nonignored text files under the source root with bounded results."
        args_schema: type[crewai.BaseModel] = SourceSearchInput

        def _run(
            self,
            pattern: str,
            purpose: str,
            regex: bool = False,
            limit: int = 50,
            path_glob: str | None = None,
        ) -> str:
            result = _run_bounded_source_search(state.source_root, pattern, regex=regex, limit=limit, path_glob=path_glob)
            record = {
                "purpose": purpose,
                "pattern": pattern,
                "regex": regex,
                "limit": min(max(int(limit or 50), 1), 200),
                "path_glob": path_glob,
                **result,
            }
            state.source_searches.append(record)
            state.memory.record_event(
                "source_executor",
                "tool_result",
                "source_search completed",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "pattern": pattern,
                    "matches": len(result.get("matches") or []),
                    "truncated": result.get("truncated"),
                    "purpose": purpose,
                },
            )
            return json.dumps(record, sort_keys=True)

    return BoundedSourceSearchTool()


def _build_write_workspace_file_tool(crewai: Any, state: Any):
    class WorkspaceFileInput(crewai.BaseModel):
        relative_path: str = crewai.Field(..., description="Path under /work for the generated harness or test file.")
        content: str = crewai.Field(..., description="File content to write.")
        purpose: str = crewai.Field(..., description="Why this workspace file is needed for the current hypothesis.")
        executable: bool = crewai.Field(False, description="Whether to mark the file executable.")

    class WriteWorkspaceFileTool(crewai.BaseTool):
        name: str = "write_workspace_file"
        description: str = "Write a bounded generated harness/test file under the writable /work directory."
        args_schema: type[crewai.BaseModel] = WorkspaceFileInput

        def _run(self, relative_path: str, content: str, purpose: str, executable: bool = False) -> str:
            path = _workspace_path(state.workspace_dir, relative_path)
            encoded = content.encode("utf-8")
            if len(encoded) > MAX_WORKSPACE_FILE_BYTES:
                raise ValueError(f"Workspace file exceeds {MAX_WORKSPACE_FILE_BYTES} bytes.")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            if executable:
                path.chmod(path.stat().st_mode | 0o111)
            record = {
                "path": path.relative_to(state.workspace_dir.resolve()).as_posix(),
                "purpose": purpose,
                "bytes": len(encoded),
                "snippet_hash": _snippet_hash(content),
                "executable": bool(executable),
            }
            state.workspace_files.append(record)
            state.memory.record_event(
                "source_executor",
                "tool_result",
                "write_workspace_file completed",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "path": record["path"],
                    "bytes": record["bytes"],
                    "purpose": purpose,
                },
            )
            return json.dumps(record, sort_keys=True)

    return WriteWorkspaceFileTool()


def _build_run_source_command_tool(crewai: Any, config: AppConfig, state: Any):
    class SourceCommandInput(crewai.BaseModel):
        command: str = crewai.Field(..., description="Shell command to run in the security container.")
        purpose: str = crewai.Field(..., description="Why this command is needed for the current source hypothesis.")
        env: dict[str, Any] | str | None = crewai.Field(None, description="Explicit environment overrides for this command.")
        timeout: int | None = crewai.Field(None, description="Optional command timeout in seconds.")

    class RunSourceCommandTool(crewai.BaseTool):
        name: str = "run_source_command"
        description: str = "Run a local command with /source mounted read-only and /work writable."
        args_schema: type[crewai.BaseModel] = SourceCommandInput

        def _run(self, command: str, purpose: str, env: Any = None, timeout: int | None = None) -> str:
            blocked_hosts = _source_command_disallowed_hosts(command, state.targets)
            if blocked_hosts:
                state.memory.record_event(
                    "source_executor",
                    "tool_blocked",
                    "Blocked source command because it referenced non-local hosts",
                    {
                        "test_id": _hypothesis_id(state.hypothesis),
                        "blocked_hosts": blocked_hosts,
                        "purpose": purpose,
                    },
                )
                return json.dumps(
                    {
                        "exit_code": 126,
                        "blocked": True,
                        "blocked_hosts": blocked_hosts,
                        "stdout": "",
                        "stderr": "Source commands may use /source, /work, localhost, and explicit engagement targets only.",
                    },
                    sort_keys=True,
                )
            env_map = _validated_env(env)
            runner = DockerToolRunner(config.security_tool_image)
            result = runner.run(
                ["bash", "-lc", command],
                timeout=_command_timeout(config, timeout),
                volumes=[
                    (str(state.source_root.resolve()), "/source", "ro"),
                    (str(state.workspace_dir.resolve()), "/work"),
                ],
                workdir="/work",
                env=env_map,
            )
            redacted = _redact_result(result, state.engagement)
            command_record = {
                "command": _redact_text(command, state.engagement),
                "purpose": purpose,
                "env": _redacted_env(env_map, state.engagement),
                "exit_code": redacted.exit_code,
                "stdout": _truncate(redacted.stdout),
                "stderr": _truncate(redacted.stderr),
                "source_mount": "/source:ro",
                "workspace": "/work",
            }
            state.commands.append(command_record)
            _append_command_log(state.workspace_dir, command_record)
            state.memory.record_event(
                "source_executor",
                "tool_result",
                "run_source_command completed",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "purpose": purpose,
                    "exit_code": redacted.exit_code,
                },
            )
            return json.dumps(command_record, sort_keys=True)

    return RunSourceCommandTool()


def _build_start_source_process_tool(crewai: Any, config: AppConfig, state: Any):
    class StartSourceProcessInput(crewai.BaseModel):
        command: str = crewai.Field(..., description="Command to run as a detached local source process.")
        purpose: str = crewai.Field(..., description="Why this process is needed for the current hypothesis.")
        container_port: int = crewai.Field(..., description="Port the process listens on inside the container.")
        host_port: int | None = crewai.Field(None, description="Optional host port. Defaults to container_port.")
        env: dict[str, Any] | str | None = crewai.Field(None, description="Explicit environment overrides for the process.")

    class StartSourceProcessTool(crewai.BaseTool):
        name: str = "start_source_process"
        description: str = "Start a detached source-local process with /source read-only and /work writable."
        args_schema: type[crewai.BaseModel] = StartSourceProcessInput

        def _run(
            self,
            command: str,
            purpose: str,
            container_port: int,
            host_port: int | None = None,
            env: Any = None,
        ) -> str:
            blocked_hosts = _source_command_disallowed_hosts(command, state.targets)
            if blocked_hosts:
                return json.dumps(
                    {
                        "blocked": True,
                        "blocked_hosts": blocked_hosts,
                        "stderr": "Source process command references non-local hosts.",
                    },
                    sort_keys=True,
                )
            container_port = _validated_port(container_port, "container_port")
            host_port = _validated_port(host_port or container_port, "host_port")
            env_map = _validated_env(env)
            docker_command = [
                "docker",
                "run",
                "-d",
                "--rm",
                "-p",
                f"127.0.0.1:{host_port}:{container_port}",
                "-v",
                f"{state.source_root.resolve()}:/source:ro",
                "-v",
                f"{state.workspace_dir.resolve()}:/work",
                "-w",
                "/work",
            ]
            for key, value in sorted(env_map.items()):
                docker_command.extend(["-e", f"{key}={value}"])
            docker_command.extend([config.security_tool_image, "bash", "-lc", command])
            result = _run_docker_cli(docker_command, timeout=30)
            container_id = result.stdout.strip().splitlines()[-1] if result.exit_code == 0 and result.stdout.strip() else ""
            record = {
                "purpose": purpose,
                "command": _redact_text(command, state.engagement),
                "env": _redacted_env(env_map, state.engagement),
                "container_id": container_id,
                "container_port": container_port,
                "host_port": host_port,
                "local_url": f"http://host.docker.internal:{host_port}",
                "host_url": f"http://127.0.0.1:{host_port}",
                "exit_code": result.exit_code,
                "stdout": _truncate(_redact_text(result.stdout, state.engagement)),
                "stderr": _truncate(_redact_text(result.stderr, state.engagement)),
                "status": "started" if container_id else "failed",
            }
            state.local_processes.append(record)
            state.memory.record_event(
                "source_executor",
                "tool_result",
                "start_source_process completed",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "container_id": container_id,
                    "container_port": container_port,
                    "host_port": host_port,
                    "status": record["status"],
                    "purpose": purpose,
                },
            )
            return json.dumps(record, sort_keys=True)

    return StartSourceProcessTool()


def _build_request_local_http_tool(crewai: Any, config: AppConfig, state: Any):
    class LocalHttpInput(crewai.BaseModel):
        url: str = crewai.Field(..., description="Local URL to request, such as http://host.docker.internal:8000/path.")
        purpose: str = crewai.Field(..., description="Why this request is needed for the current hypothesis.")
        method: str = crewai.Field("GET", description="HTTP method.")
        headers: dict[str, Any] | str | None = crewai.Field(None, description="Optional headers.")
        body: str | None = crewai.Field(None, description="Optional request body.")
        timeout: int | None = crewai.Field(None, description="Optional request timeout in seconds.")

    class RequestLocalHttpTool(crewai.BaseTool):
        name: str = "request_local_http"
        description: str = "Send an HTTP request to a local source runtime and capture response evidence."
        args_schema: type[crewai.BaseModel] = LocalHttpInput

        def _run(
            self,
            url: str,
            purpose: str,
            method: str = "GET",
            headers: Any = None,
            body: str | None = None,
            timeout: int | None = None,
        ) -> str:
            blocked_hosts = _source_command_disallowed_hosts(url, state.targets)
            if blocked_hosts:
                record = {
                    "blocked": True,
                    "blocked_hosts": blocked_hosts,
                    "url": _redact_text(url, state.engagement),
                    "purpose": purpose,
                    "exit_code": 126,
                    "stdout": "",
                    "stderr": "Local HTTP requests may target localhost, host.docker.internal, or explicit engagement targets only.",
                }
                state.local_requests.append(record)
                return json.dumps(record, sort_keys=True)
            header_map = _validated_headers(headers)
            method = _validated_method(method)
            request_timeout = min(max(int(timeout or 15), 1), 120)
            command_parts = ["curl", "-i", "-sS", "--max-time", str(request_timeout), "-X", method]
            for key, value in sorted(header_map.items()):
                command_parts.extend(["-H", f"{key}: {value}"])
            if body is not None:
                command_parts.extend(["--data-binary", body])
            command_parts.append(url)
            shell_command = " ".join(shlex.quote(part) for part in command_parts)
            runner = DockerToolRunner(config.security_tool_image)
            result = runner.run(
                ["bash", "-lc", shell_command],
                timeout=request_timeout + 5,
                volumes=[(str(state.workspace_dir.resolve()), "/work")],
                workdir="/work",
            )
            redacted = _redact_result(result, state.engagement)
            record = {
                "purpose": purpose,
                "method": method,
                "url": _redact_text(url, state.engagement),
                "headers": _redacted_env(header_map, state.engagement),
                "body_present": body is not None,
                "exit_code": redacted.exit_code,
                "stdout": _truncate(redacted.stdout),
                "stderr": _truncate(redacted.stderr),
            }
            state.local_requests.append(record)
            state.memory.record_event(
                "source_executor",
                "tool_result",
                "request_local_http completed",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "method": method,
                    "url": record["url"],
                    "exit_code": redacted.exit_code,
                    "purpose": purpose,
                },
            )
            return json.dumps(record, sort_keys=True)

    return RequestLocalHttpTool()


def _build_stop_source_process_tool(crewai: Any, state: Any):
    class StopSourceProcessInput(crewai.BaseModel):
        container_id: str = crewai.Field(..., description="Container ID returned by start_source_process.")
        purpose: str = crewai.Field(..., description="Why this process is being stopped.")

    class StopSourceProcessTool(crewai.BaseTool):
        name: str = "stop_source_process"
        description: str = "Stop a detached source process and capture its final logs."
        args_schema: type[crewai.BaseModel] = StopSourceProcessInput

        def _run(self, container_id: str, purpose: str) -> str:
            known_ids = {_text(process.get("container_id")) for process in state.local_processes}
            if container_id not in known_ids:
                return json.dumps(
                    {
                        "blocked": True,
                        "container_id": container_id,
                        "stderr": "Can only stop containers started by this security test.",
                    },
                    sort_keys=True,
                )
            logs = _run_docker_cli(["docker", "logs", "--tail", "120", container_id], timeout=15)
            stopped = _run_docker_cli(["docker", "rm", "-f", container_id], timeout=15)
            record = {
                "purpose": purpose,
                "container_id": container_id,
                "logs_stdout": _truncate(_redact_text(logs.stdout, state.engagement)),
                "logs_stderr": _truncate(_redact_text(logs.stderr, state.engagement)),
                "stop_exit_code": stopped.exit_code,
                "stop_stdout": _truncate(_redact_text(stopped.stdout, state.engagement)),
                "stop_stderr": _truncate(_redact_text(stopped.stderr, state.engagement)),
                "status": "stopped" if stopped.exit_code == 0 else "stop-failed",
            }
            state.local_processes.append(record)
            state.memory.record_event(
                "source_executor",
                "tool_result",
                "stop_source_process completed",
                {
                    "test_id": _hypothesis_id(state.hypothesis),
                    "container_id": container_id,
                    "status": record["status"],
                    "purpose": purpose,
                },
            )
            return json.dumps(record, sort_keys=True)

    return StopSourceProcessTool()


def _cleanup_source_processes(state: Any) -> None:
    stopped_ids = {
        _text(process.get("container_id"))
        for process in state.local_processes
        if _text(process.get("status")) == "stopped"
    }
    for process in list(state.local_processes):
        container_id = _text(process.get("container_id"))
        if not container_id or _text(process.get("status")) != "started" or container_id in stopped_ids:
            continue
        logs = _run_docker_cli(["docker", "logs", "--tail", "120", container_id], timeout=15)
        stopped = _run_docker_cli(["docker", "rm", "-f", container_id], timeout=15)
        record = {
            "purpose": "Automatic cleanup for source process left running after execution.",
            "container_id": container_id,
            "logs_stdout": _truncate(_redact_text(logs.stdout, state.engagement)),
            "logs_stderr": _truncate(_redact_text(logs.stderr, state.engagement)),
            "stop_exit_code": stopped.exit_code,
            "stop_stdout": _truncate(_redact_text(stopped.stdout, state.engagement)),
            "stop_stderr": _truncate(_redact_text(stopped.stderr, state.engagement)),
            "status": "stopped" if stopped.exit_code == 0 else "stop-failed",
            "automatic_cleanup": True,
        }
        state.local_processes.append(record)
        if record["status"] == "stopped":
            stopped_ids.add(container_id)
        state.memory.record_event(
            "source_executor",
            "tool_result",
            "source process cleanup completed",
            {
                "test_id": _hypothesis_id(state.hypothesis),
                "container_id": container_id,
                "status": record["status"],
            },
        )


def _compact_source_context(source_context: dict[str, Any]) -> dict[str, Any]:
    inventory = source_context.get("inventory") if isinstance(source_context.get("inventory"), dict) else {}
    return {
        "summary": source_context.get("summary") if isinstance(source_context.get("summary"), dict) else {},
        "apps": _limit_list(inventory.get("apps"), 25),
        "routes": _limit_list(inventory.get("routes") or inventory.get("apis"), 100),
        "auth": _limit_list(inventory.get("auth") or inventory.get("sessions"), 50),
        "data_stores": _limit_list(inventory.get("data_stores"), 50),
        "configuration": _limit_list(inventory.get("configuration"), 50),
        "environment_variables": _limit_list(inventory.get("environment_variables"), 75),
        "component_map": source_context.get("component_map") if isinstance(source_context.get("component_map"), dict) else {},
        "gap_analysis": source_context.get("gap_analysis") if isinstance(source_context.get("gap_analysis"), dict) else {},
    }


def _load_source_context(source_discovery_dir: Path | None) -> dict[str, Any]:
    if not source_discovery_dir:
        return {}
    memory_path = source_discovery_dir / "memory.json"
    if not memory_path.exists():
        return {}
    try:
        items = json.loads(memory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(items, list):
        return {}
    source_index: dict[str, Any] = {}
    for item in items:
        if not isinstance(item, dict) or item.get("kind") != "source_index":
            continue
        content = item.get("content")
        if isinstance(content, dict):
            source_index = content
    return source_index


def _run_bounded_source_search(
    source_root: Path,
    pattern: str,
    *,
    regex: bool = False,
    limit: int = 50,
    path_glob: str | None = None,
) -> dict[str, Any]:
    source_root = source_root.resolve()
    limit = min(max(int(limit or 50), 1), 200)
    try:
        compiled = re.compile(pattern) if regex else None
    except re.error as exc:
        return {"matches": [], "truncated": False, "error": f"invalid regex: {exc}"}
    matches: list[dict[str, Any]] = []
    for path in _iter_nonignored_files(source_root):
        relative = _relative_path(source_root, path)
        if path_glob and not fnmatch.fnmatch(relative, path_glob):
            continue
        text = _read_text_file(path)
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            matched = bool(compiled.search(line)) if compiled else pattern in line
            if not matched:
                continue
            matches.append(
                {
                    "path": relative,
                    "line": line_number,
                    "preview": line.strip()[:240],
                    "snippet_hash": _snippet_hash(line.strip()),
                }
            )
            if len(matches) >= limit:
                return {"matches": matches, "truncated": True}
    return {"matches": matches, "truncated": False}


def _source_command_disallowed_hosts(command: str, targets: dict[str, str]) -> list[str]:
    allowed_hosts = set(LOCAL_RUNTIME_HOSTS)
    allowed_hosts.update(_target_hosts(targets))
    found_hosts = []
    for raw_url in re.findall(r"https?://[^\s\"'<>),]+", command):
        try:
            host = (urlparse(raw_url).hostname or "").lower()
        except ValueError:
            host = ""
        if host and host not in allowed_hosts:
            found_hosts.append(host)
    return sorted(set(found_hosts))


def _target_hosts(targets: dict[str, str]) -> set[str]:
    hosts: set[str] = set()
    for url in targets.values():
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            host = ""
        if host:
            hosts.add(host)
    return hosts


def _limit_list(value: Any, limit: int) -> list[Any]:
    if isinstance(value, list):
        return value[:limit]
    return []


def _workspace_path(workspace_dir: Path, relative_path: str) -> Path:
    clean = _text(relative_path).lstrip("/")
    if not clean:
        raise ValueError("Workspace file path is required.")
    path = (workspace_dir / clean).resolve()
    workspace_root = workspace_dir.resolve()
    if path != workspace_root and workspace_root not in path.parents:
        raise ValueError("Workspace file path escapes the writable workspace.")
    return path


def _validated_env(value: Any) -> dict[str, str]:
    if value in (None, "", {}, []):
        return {}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("Environment overrides must be a mapping or JSON object string.") from exc
        value = parsed
    if not isinstance(value, dict):
        raise ValueError("Environment overrides must be a mapping.")
    env: dict[str, str] = {}
    for key, item in value.items():
        name = _text(key)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"Invalid environment variable name: {name}")
        text = _text(item)
        if len(text) > 4000:
            raise ValueError(f"Environment variable value is too large: {name}")
        env[name] = text
    if len(env) > 50:
        raise ValueError("Too many environment variables for one source command.")
    return env


def _validated_headers(value: Any) -> dict[str, str]:
    if value in (None, "", {}, []):
        return {}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("Headers must be a mapping or JSON object string.") from exc
        value = parsed
    if not isinstance(value, dict):
        raise ValueError("Headers must be a mapping.")
    headers: dict[str, str] = {}
    for key, item in value.items():
        name = _text(key)
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
            raise ValueError(f"Invalid HTTP header name: {name}")
        headers[name] = _text(item)
    if len(headers) > 50:
        raise ValueError("Too many headers for one local request.")
    return headers


def _redacted_env(value: dict[str, str], engagement: dict[str, Any]) -> dict[str, str]:
    return {key: _redact_text(item, engagement) for key, item in sorted(value.items())}


def _validated_method(method: str) -> str:
    normalized = _text(method).upper() or "GET"
    if not re.fullmatch(r"[A-Z]{1,12}", normalized):
        raise ValueError(f"Invalid HTTP method: {method}")
    return normalized


def _validated_port(value: int, name: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer port.") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"{name} must be between 1 and 65535.")
    return port


def _command_timeout(config: AppConfig, value: int | None) -> int:
    if value is None:
        return config.security_command_timeout
    return min(max(int(value), 1), config.security_command_timeout)


def _run_docker_cli(command: list[str], timeout: int) -> DockerToolResult:
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
        return DockerToolResult(
            exit_code=124,
            stdout=stdout,
            stderr=f"Docker command timed out after {timeout} seconds",
        )
    return DockerToolResult(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
