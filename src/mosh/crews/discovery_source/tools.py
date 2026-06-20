from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SOURCE_INDEX_SCHEMA = "mosh.source-index.v1"

IGNORED_DIRS = {
    ".deriveddata",
    ".git",
    ".gradle",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "build-maestro",
    "build-share-flow",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}

IGNORED_FILE_NAMES = {
    ".ds_store",
    "desktop.ini",
    "thumbs.db",
}

SOURCE_SUFFIX_LANGUAGES = {
    ".go": "go",
    ".gradle": "gradle",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".mjs": "javascript",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".swift": "swift",
    ".ts": "typescript",
    ".tsx": "typescript",
}

MANIFEST_NAMES = {
    "cargo.toml",
    "composer.json",
    "go.mod",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "settings.gradle",
    "settings.gradle.kts",
    "package.swift",
    "podfile",
}

LOCKFILE_NAMES = {
    "cargo.lock",
    "composer.lock",
    "go.sum",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}

CONFIG_NAME_PATTERNS = (
    ".env.example",
    ".env.sample",
    "docker-compose.yml",
    "docker-compose.yaml",
    "dockerfile",
    "nginx.conf",
    "androidmanifest.xml",
    "info.plist",
    "podfile",
)

TEXT_SUFFIXES = {
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".md",
    ".plist",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    *SOURCE_SUFFIX_LANGUAGES,
}

MAX_TEXT_FILE_BYTES = 1_000_000
MAX_INDEXED_FILES = 10000
MAX_ROUTES = 500


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str


class ValidateSourcePathTool:
    definition = ToolDefinition(
        name="validate_source_path",
        description="Validate a local source tree path and return source identity metadata.",
    )

    def run(self, source: str) -> dict[str, Any]:
        path = Path(source).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Source path not found: {source}")
        if not path.is_dir():
            raise NotADirectoryError(f"Source path is not a directory: {source}")
        root = path.resolve()
        git_info = _git_info(root)
        return {
            "schema": "mosh.source-info.v1",
            "kind": "local-path",
            "path": str(root),
            "display_name": root.name or "source",
            "repo_url": git_info.get("repo_url"),
            "commit_sha": git_info.get("commit_sha") or "unknown",
            "dirty": git_info.get("dirty"),
            "git_root": git_info.get("git_root"),
        }


class SourceInventoryTool:
    definition = ToolDefinition(
        name="source_inventory",
        description="Build a compact file, language, manifest, and entrypoint inventory for a source tree.",
    )

    def run(self, source: str) -> dict[str, Any]:
        root = _validated_root(source)
        files: list[dict[str, Any]] = []
        languages: dict[str, int] = {}
        ignored_dirs: dict[str, int] = {}
        total_bytes = 0

        for current_root, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(
                dirname
                for dirname in dirnames
                if not _ignore_dir(dirname, ignored_dirs)
            )
            for filename in sorted(filenames):
                path = Path(current_root) / filename
                relative_path = _relative_path(root, path)
                role = _file_role(path)
                if role == "binary":
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                total_bytes += size
                language = _language_for_path(path)
                if language:
                    languages[language] = languages.get(language, 0) + 1
                files.append(
                    {
                        "path": relative_path,
                        "size": size,
                        "language": language,
                        "role": role,
                    }
                )
                if len(files) >= MAX_INDEXED_FILES:
                    break
            if len(files) >= MAX_INDEXED_FILES:
                break

        manifests = [file for file in files if file["role"] == "manifest"]
        lockfiles = [file for file in files if file["role"] == "lockfile"]
        apps = _app_inventory(root, files)
        entrypoints = _entrypoints_from_apps(apps)
        return {
            "schema": "mosh.source-inventory.v1",
            "root": str(root),
            "total_files": len(files),
            "total_bytes": total_bytes,
            "truncated": len(files) >= MAX_INDEXED_FILES,
            "languages": dict(sorted(languages.items())),
            "files": files,
            "manifests": manifests,
            "lockfiles": lockfiles,
            "apps": apps,
            "entrypoints": entrypoints,
            "ignored_dirs": dict(sorted(ignored_dirs.items())),
        }


class RouteApiExtractorTool:
    definition = ToolDefinition(
        name="route_api_extractor",
        description="Extract likely HTTP routes and API endpoints from common Python, JavaScript, and Rails patterns.",
    )

    def run(self, source: str) -> dict[str, Any]:
        root = _validated_root(source)
        routes: list[dict[str, Any]] = []
        for path in _iter_source_files(root):
            routes.extend(_extract_routes_from_file(root, path))
            if len(routes) >= MAX_ROUTES:
                routes = routes[:MAX_ROUTES]
                break
        return {
            "schema": "mosh.source-routes.v1",
            "routes": routes,
            "truncated": len(routes) >= MAX_ROUTES,
        }


class DependencyInventoryTool:
    definition = ToolDefinition(
        name="dependency_inventory",
        description="Extract dependency names and version constraints from common manifests.",
    )

    def run(self, source: str) -> dict[str, Any]:
        root = _validated_root(source)
        dependencies: list[dict[str, Any]] = []
        manifests: list[dict[str, Any]] = []
        for path in _iter_manifest_files(root):
            relative_path = _relative_path(root, path)
            manifests.append({"path": relative_path, "kind": Path(path).name.lower()})
            dependencies.extend(_dependencies_from_manifest(root, path))
        return {
            "schema": "mosh.source-dependencies.v1",
            "manifests": manifests,
            "dependencies": dependencies,
        }


class ConfigInventoryTool:
    definition = ToolDefinition(
        name="config_inventory",
        description="Identify configuration, deployment, environment, and CI files that may affect security posture.",
    )

    def run(self, source: str) -> dict[str, Any]:
        root = _validated_root(source)
        configuration: list[dict[str, Any]] = []
        for path in _iter_nonignored_files(root):
            if not _looks_like_config(path):
                continue
            configuration.append(
                {
                    "path": _relative_path(root, path),
                    "kind": _config_kind(path),
                    "size": path.stat().st_size,
                }
            )
        return {
            "schema": "mosh.source-config.v1",
            "configuration": configuration,
            "environment_variables": _environment_variable_inventory(root),
            "compose_topology": _compose_topology_inventory(root),
        }


class SourceSearchTool:
    definition = ToolDefinition(
        name="source_search",
        description="Search bounded source files for a literal or regular expression pattern.",
    )

    def run(self, source: str, pattern: str, regex: bool = False, limit: int = 50) -> dict[str, Any]:
        root = _validated_root(source)
        matches: list[dict[str, Any]] = []
        compiled = re.compile(pattern) if regex else None
        for path in _iter_source_files(root):
            text = _read_text_file(path)
            if text is None:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if compiled.search(line) if compiled else pattern in line:
                    matches.append(
                        {
                            "path": _relative_path(root, path),
                            "line": line_number,
                            "preview": line.strip()[:240],
                        }
                    )
                    if len(matches) >= limit:
                        return {"matches": matches, "truncated": True}
        return {"matches": matches, "truncated": False}


class ReadSourceSliceTool:
    definition = ToolDefinition(
        name="read_source_slice",
        description="Read a bounded source file slice by path and line range.",
    )

    def run(self, source: str, relative_path: str, start_line: int, end_line: int) -> dict[str, Any]:
        root = _validated_root(source)
        if start_line < 1 or end_line < start_line:
            raise ValueError("Invalid source slice line range.")
        end_line = min(end_line, start_line + 200)
        path = (root / relative_path).resolve()
        if root not in path.parents and path != root:
            raise ValueError("Source slice path escapes source root.")
        text = _read_text_file(path)
        if text is None:
            raise ValueError(f"Source slice is not readable text: {relative_path}")
        lines = text.splitlines()
        selected = lines[start_line - 1 : end_line]
        body = "\n".join(selected)
        return {
            "path": relative_path,
            "start_line": start_line,
            "end_line": start_line + len(selected) - 1,
            "content": body,
            "snippet_hash": _snippet_hash(body),
        }


def build_source_index(
    source_info: dict[str, Any],
    inventory: dict[str, Any],
    routes: dict[str, Any],
    dependencies: dict[str, Any],
    configuration: dict[str, Any],
    route_resolution: dict[str, Any] | None = None,
    component_map: dict[str, Any] | None = None,
    gap_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence_refs = []
    for route in routes.get("routes", []):
        if isinstance(route, dict):
            evidence_refs.append(
                {
                    "path": route.get("path"),
                    "start_line": route.get("line"),
                    "end_line": route.get("line"),
                    "symbol": route.get("handler") or route.get("framework"),
                    "snippet_hash": route.get("snippet_hash"),
                    "reason": "route definition",
                }
            )
    source_index = {
        "schema": SOURCE_INDEX_SCHEMA,
        "source": source_info,
        "inventory": {
            "files": inventory.get("files", []),
            "apps": inventory.get("apps", []),
            "languages": inventory.get("languages", {}),
            "frameworks": _infer_frameworks(inventory, dependencies),
            "entrypoints": inventory.get("entrypoints", []),
            "routes": routes.get("routes", []),
            "apis": routes.get("routes", []),
            "auth": _auth_candidates(inventory, routes),
            "sessions": _session_candidates(inventory),
            "data_stores": _data_store_candidates(dependencies, configuration),
            "dependencies": dependencies.get("dependencies", []),
            "configuration": configuration.get("configuration", []),
            "environment_variables": configuration.get("environment_variables", []),
            "compose_topology": configuration.get("compose_topology", []),
        },
        "evidence_refs": evidence_refs,
        "summary": source_summary(inventory, routes, dependencies, configuration),
    }
    if route_resolution:
        source_index["route_resolution"] = route_resolution
    if component_map:
        source_index["component_map"] = component_map
    if gap_analysis:
        source_index["gap_analysis"] = gap_analysis
    return source_index


def source_summary(
    inventory: dict[str, Any],
    routes: dict[str, Any],
    dependencies: dict[str, Any],
    configuration: dict[str, Any],
) -> dict[str, Any]:
    return {
        "files_indexed": int(inventory.get("total_files") or 0),
        "languages_identified": len(inventory.get("languages") or {}),
        "routes_identified": len(routes.get("routes") or []),
        "apps_identified": len(inventory.get("apps") or []),
        "mobile_apps_identified": len(
            [
                app
                for app in _list(inventory.get("apps"))
                if isinstance(app, dict) and _text(app.get("type")) in {"android-app", "ios-app"}
            ]
        ),
        "dependencies_identified": len(dependencies.get("dependencies") or []),
        "configuration_files_identified": len(configuration.get("configuration") or []),
        "environment_variables_identified": len(configuration.get("environment_variables") or []),
        "compose_services_identified": sum(
            len(item.get("services") or [])
            for item in _list(configuration.get("compose_topology"))
            if isinstance(item, dict)
        ),
        "manifests_identified": len(inventory.get("manifests") or []),
        "lockfiles_identified": len(inventory.get("lockfiles") or []),
    }


def _validated_root(source: str) -> Path:
    path = Path(source).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Source path not found: {source}")
    if not path.is_dir():
        raise NotADirectoryError(f"Source path is not a directory: {source}")
    return path.resolve()


def _git_info(root: Path) -> dict[str, Any]:
    git_root = _run_git(root, "rev-parse", "--show-toplevel")
    commit = _run_git(root, "rev-parse", "HEAD") if git_root else ""
    remote = _run_git(root, "config", "--get", "remote.origin.url") if git_root else ""
    dirty = None
    if git_root:
        status = _run_git(root, "status", "--porcelain")
        dirty = bool(status.strip())
    return {
        "git_root": git_root or None,
        "commit_sha": commit or None,
        "repo_url": remote or None,
        "dirty": dirty,
    }


def _run_git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _ignore_dir(dirname: str, ignored_dirs: dict[str, int]) -> bool:
    normalized = dirname.lower()
    if normalized not in IGNORED_DIRS:
        return False
    ignored_dirs[dirname] = ignored_dirs.get(dirname, 0) + 1
    return True


def _iter_nonignored_files(root: Path):
    for current_root, dirnames, filenames in os.walk(root):
        ignored: dict[str, int] = {}
        dirnames[:] = sorted(dirname for dirname in dirnames if not _ignore_dir(dirname, ignored))
        for filename in sorted(filenames):
            if filename.lower() in IGNORED_FILE_NAMES:
                continue
            path = Path(current_root) / filename
            if _file_role(path) == "binary":
                continue
            yield path


def _iter_source_files(root: Path):
    for path in _iter_nonignored_files(root):
        if path.suffix.lower() in SOURCE_SUFFIX_LANGUAGES:
            yield path


def _iter_manifest_files(root: Path):
    for path in _iter_nonignored_files(root):
        name = path.name.lower()
        if name in MANIFEST_NAMES or name in LOCKFILE_NAMES or name in {"build.gradle", "build.gradle.kts", "androidmanifest.xml", "info.plist", "podfile", "package.swift"}:
            yield path


def _app_inventory(root: Path, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    file_by_path = {str(file.get("path")): file for file in files}
    app_roots: dict[str, dict[str, Any]] = {}
    for file in files:
        relative_path = str(file.get("path") or "")
        name = Path(relative_path).name.lower()
        if name == "package.json":
            _merge_app(app_roots, _javascript_app(root, relative_path, file_by_path))
        elif name in {"pyproject.toml", "requirements.txt"}:
            _merge_app(app_roots, _python_app(root, relative_path, file_by_path))
        elif name in {"build.gradle", "build.gradle.kts", "androidmanifest.xml"}:
            _merge_app(app_roots, _android_app(root, relative_path, file_by_path))
        elif name in {"info.plist", "podfile", "package.swift"} or relative_path.endswith(".xcodeproj/project.pbxproj"):
            _merge_app(app_roots, _ios_app(root, relative_path, file_by_path))

    for file in files:
        relative_path = str(file.get("path") or "")
        entrypoint = _mobile_source_entrypoint(relative_path, file_by_path)
        if not entrypoint:
            continue
        app_root = _nearest_known_app_root(relative_path, app_roots) or _top_level_root(relative_path)
        app_id = _app_id(app_root)
        _merge_app(
            app_roots,
            {
                "app_id": app_id,
                "root": app_root,
                "type": "mobile-app" if _is_mobile_entrypoint(relative_path) else "application",
                "languages": [_text(file.get("language"))],
                "frameworks": [],
                "entrypoints": [entrypoint],
                "manifests": [],
                "confidence": "medium",
                "evidence": [relative_path],
            },
        )
    return sorted(app_roots.values(), key=lambda app: str(app.get("root") or ""))


def _javascript_app(root: Path, relative_path: str, file_by_path: dict[str, dict[str, Any]]) -> dict[str, Any]:
    app_root = str(Path(relative_path).parent)
    if app_root == ".":
        app_root = ""
    package = _read_json_file(root / relative_path)
    dependencies = {}
    scripts = {}
    main = ""
    if isinstance(package, dict):
        scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
        main = _text(package.get("main"))
        for section in ("dependencies", "devDependencies"):
            values = package.get(section)
            if isinstance(values, dict):
                dependencies.update({str(key).lower(): value for key, value in values.items()})
    frameworks = [name for name in ("express", "next", "react", "vue", "angular", "svelte") if name in dependencies]
    entrypoints = []
    for entrypoint_path, reason in _package_entrypoint_candidates(app_root, main, scripts):
        if entrypoint_path in file_by_path:
            entrypoints.append(_entrypoint(entrypoint_path, "application", reason, "high", file_by_path[entrypoint_path]))
    if not entrypoints:
        entrypoints = _fallback_entrypoints(app_root, file_by_path, {"server.js", "server.ts", "index.js", "index.ts", "app.js", "app.ts"})
    return {
        "app_id": _app_id(app_root or "root"),
        "root": app_root or ".",
        "type": "web-app" if frameworks else "javascript-app",
        "languages": _languages_under_root(app_root, file_by_path),
        "frameworks": frameworks,
        "entrypoints": entrypoints,
        "manifests": [relative_path],
        "confidence": "high",
        "evidence": [relative_path],
    }


def _python_app(root: Path, relative_path: str, file_by_path: dict[str, dict[str, Any]]) -> dict[str, Any]:
    app_root = str(Path(relative_path).parent)
    if app_root == ".":
        app_root = ""
    pyproject = _read_toml_file(root / relative_path)
    entrypoints = []
    if isinstance(pyproject, dict):
        project = pyproject.get("project") if isinstance(pyproject.get("project"), dict) else {}
        scripts = project.get("scripts") if isinstance(project.get("scripts"), dict) else {}
        for name, target in sorted(scripts.items()):
            candidate = _python_module_to_path(app_root, _text(target).split(":", 1)[0])
            if candidate in file_by_path:
                entrypoints.append(_entrypoint(candidate, "application", f"pyproject script {name}", "high", file_by_path[candidate]))
    frameworks = _python_frameworks(root, app_root, relative_path, file_by_path)
    if not entrypoints:
        entrypoints = _python_entrypoints(root, app_root, file_by_path)
    return {
        "app_id": _app_id(app_root or "root"),
        "root": app_root or ".",
        "type": "web-api" if frameworks else "python-app",
        "languages": _languages_under_root(app_root, file_by_path),
        "frameworks": frameworks,
        "entrypoints": entrypoints,
        "manifests": [relative_path],
        "confidence": "high",
        "evidence": [relative_path],
    }


def _android_app(root: Path, relative_path: str, file_by_path: dict[str, dict[str, Any]]) -> dict[str, Any]:
    app_root = _android_root(relative_path)
    manifests = [path for path in file_by_path if _under_app_root(path, app_root) and Path(path).name.lower() in {"build.gradle", "build.gradle.kts", "androidmanifest.xml"}]
    entrypoints = []
    manifest_path = next((path for path in manifests if Path(path).name.lower() == "androidmanifest.xml"), "")
    launcher = _android_launcher_activity(root / manifest_path) if manifest_path else ""
    if launcher:
        candidate = _android_activity_to_path(app_root, launcher, file_by_path)
        if candidate:
            entrypoints.append(_entrypoint(candidate, "android-activity", "AndroidManifest launcher activity", "high", file_by_path[candidate]))
    if not entrypoints:
        entrypoints = _fallback_entrypoints(app_root, file_by_path, {"MainActivity.kt", "MainActivity.java"})
    return {
        "app_id": _app_id(app_root or "android"),
        "root": app_root or ".",
        "type": "android-app",
        "languages": _languages_under_root(app_root, file_by_path),
        "frameworks": ["android"],
        "entrypoints": entrypoints,
        "manifests": manifests or [relative_path],
        "confidence": "high",
        "evidence": manifests or [relative_path],
    }


def _ios_app(root: Path, relative_path: str, file_by_path: dict[str, dict[str, Any]]) -> dict[str, Any]:
    app_root = _ios_root(relative_path)
    manifests = [
        path
        for path in file_by_path
        if _under_app_root(path, app_root)
        and (Path(path).name.lower() in {"info.plist", "podfile", "package.swift"} or path.endswith(".xcodeproj/project.pbxproj"))
    ]
    entrypoints = _ios_entrypoints(app_root, file_by_path)
    return {
        "app_id": _app_id(app_root or "ios"),
        "root": app_root or ".",
        "type": "ios-app",
        "languages": _languages_under_root(app_root, file_by_path),
        "frameworks": ["ios"],
        "entrypoints": entrypoints,
        "manifests": manifests or [relative_path],
        "confidence": "high",
        "evidence": manifests or [relative_path],
    }


def _merge_app(apps: dict[str, dict[str, Any]], candidate: dict[str, Any] | None) -> None:
    if not candidate:
        return
    app_id = _text(candidate.get("app_id"))
    if not app_id:
        return
    existing = apps.get(app_id)
    if not existing:
        apps[app_id] = candidate
        return
    for key in ("languages", "frameworks", "entrypoints", "manifests", "evidence"):
        existing[key] = _dedupe_list([*existing.get(key, []), *candidate.get(key, [])])
    if existing.get("type") in {"application", "javascript-app"} and candidate.get("type"):
        existing["type"] = candidate["type"]
    if candidate.get("confidence") == "high":
        existing["confidence"] = "high"


def _entrypoints_from_apps(apps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entrypoints: list[dict[str, Any]] = []
    seen = set()
    for app in apps:
        for entrypoint in app.get("entrypoints", []):
            if not isinstance(entrypoint, dict):
                continue
            path = _text(entrypoint.get("path"))
            marker = (app.get("app_id"), path, entrypoint.get("reason"))
            if marker in seen:
                continue
            seen.add(marker)
            entrypoints.append({**entrypoint, "app_id": app.get("app_id"), "app_root": app.get("root")})
    return entrypoints


def _package_entrypoint_candidates(app_root: str, main: str, scripts: dict[str, Any]) -> list[tuple[str, str]]:
    candidates = []
    if main:
        candidates.append((_join_relative(app_root, main), "package.json main"))
    for script_name in ("start", "dev", "serve"):
        command = _text(scripts.get(script_name))
        for path in re.findall(r"([A-Za-z0-9_./-]+\.(?:js|mjs|ts|tsx))", command):
            if "node_modules" not in path:
                candidates.append((_join_relative(app_root, path), f"package.json scripts.{script_name}"))
    return candidates


def _fallback_entrypoints(app_root: str, file_by_path: dict[str, dict[str, Any]], names: set[str]) -> list[dict[str, Any]]:
    entrypoints = []
    for path, file in sorted(file_by_path.items()):
        if not _under_app_root(path, app_root):
            continue
        if Path(path).name in names:
            entrypoints.append(_entrypoint(path, "application", "conventional entrypoint filename", "medium", file))
    return entrypoints


def _mobile_source_entrypoint(relative_path: str, file_by_path: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    name = Path(relative_path).name
    if name in {"MainActivity.kt", "MainActivity.java"}:
        return _entrypoint(relative_path, "android-activity", "conventional Android activity filename", "medium", file_by_path[relative_path])
    if name in {"AppDelegate.swift", "SceneDelegate.swift"}:
        return _entrypoint(relative_path, "ios-app-entrypoint", "conventional iOS delegate filename", "medium", file_by_path[relative_path])
    if relative_path.endswith("App.swift"):
        return _entrypoint(relative_path, "ios-swiftui-app", "SwiftUI app filename", "medium", file_by_path[relative_path])
    return None


def _is_mobile_entrypoint(relative_path: str) -> bool:
    name = Path(relative_path).name
    return name in {"MainActivity.kt", "MainActivity.java", "AppDelegate.swift", "SceneDelegate.swift"} or relative_path.endswith("App.swift")


def _ios_entrypoints(app_root: str, file_by_path: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    entrypoints = []
    for path, file in sorted(file_by_path.items()):
        if not _under_app_root(path, app_root):
            continue
        name = Path(path).name
        if (
            name in {"AppDelegate.swift", "SceneDelegate.swift"}
            or path.endswith("App.swift")
            or name.endswith("ViewController.swift")
            or name.endswith("Extension.swift")
        ):
            entrypoints.append(_entrypoint(path, "ios-app-entrypoint", "iOS application entrypoint", "high", file))
    return entrypoints


def _entrypoint(path: str, kind: str, reason: str, confidence: str, file: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": path,
        "kind": kind,
        "role": "entrypoint",
        "reason": reason,
        "confidence": confidence,
        "language": file.get("language"),
        "size": file.get("size"),
    }


def _languages_under_root(app_root: str, file_by_path: dict[str, dict[str, Any]]) -> list[str]:
    languages = {
        _text(file.get("language"))
        for path, file in file_by_path.items()
        if _under_app_root(path, app_root) and _text(file.get("language"))
    }
    return sorted(languages)


def _nearest_known_app_root(relative_path: str, apps: dict[str, dict[str, Any]]) -> str | None:
    roots = sorted((_text(app.get("root")).strip(".") for app in apps.values()), key=len, reverse=True)
    for root in roots:
        if root and _under_app_root(relative_path, root):
            return root
    return None


def _android_root(relative_path: str) -> str:
    parts = Path(relative_path).parts
    if "src" in parts:
        index = parts.index("src")
        return "/".join(parts[:index]) or "."
    if Path(relative_path).name.lower() in {"build.gradle", "build.gradle.kts"}:
        parent = str(Path(relative_path).parent)
        return "" if parent == "." else parent
    return _top_level_root(relative_path)


def _ios_root(relative_path: str) -> str:
    parts = Path(relative_path).parts
    for index, part in enumerate(parts):
        if part.endswith((".xcodeproj", ".xcworkspace")):
            return "/".join(parts[:index]) or "."
    name = Path(relative_path).name.lower()
    if name in {"info.plist", "podfile", "package.swift"}:
        parent = str(Path(relative_path).parent)
        return "" if parent == "." else parent
    return _top_level_root(relative_path)


def _top_level_root(relative_path: str) -> str:
    parts = Path(relative_path).parts
    if len(parts) <= 1:
        return "."
    if parts[0] in {"apps", "packages", "services"} and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _under_app_root(path: str, app_root: str) -> bool:
    normalized_root = app_root.strip("./")
    if not normalized_root:
        return True
    return path == normalized_root or path.startswith(f"{normalized_root}/")


def _join_relative(app_root: str, value: str) -> str:
    clean = value.strip().removeprefix("./")
    root = app_root.strip("./")
    return f"{root}/{clean}" if root else clean


def _python_module_to_path(app_root: str, module: str) -> str:
    path = module.replace(".", "/") + ".py"
    return _join_relative(app_root, path)


def _python_frameworks(
    root: Path,
    app_root: str,
    manifest_path: str,
    file_by_path: dict[str, dict[str, Any]],
) -> list[str]:
    framework_markers = {
        "fastapi": "fastapi",
        "flask": "flask",
        "django": "django",
        "starlette": "starlette",
    }
    frameworks: set[str] = set()
    manifest_text = _read_text_file(root / manifest_path) or ""
    lowered_manifest = manifest_text.lower()
    for marker, framework in framework_markers.items():
        if re.search(rf"\b{re.escape(marker)}\b", lowered_manifest):
            frameworks.add(framework)
    for relative_path in sorted(file_by_path):
        if not _under_app_root(relative_path, app_root) or not relative_path.endswith(".py"):
            continue
        text = _read_text_file(root / relative_path) or ""
        if re.search(r"\bFastAPI\(", text):
            frameworks.add("fastapi")
        if re.search(r"\bFlask\(", text):
            frameworks.add("flask")
        if "django" in text:
            frameworks.add("django")
    return sorted(frameworks)


def _python_entrypoints(root: Path, app_root: str, file_by_path: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    entrypoints = []
    for relative_path, file in sorted(file_by_path.items()):
        if not _under_app_root(relative_path, app_root) or not relative_path.endswith(".py"):
            continue
        text = _read_text_file(root / relative_path) or ""
        if re.search(r"\b(FastAPI|Flask)\(", text) or "uvicorn.run" in text:
            entrypoints.append(_entrypoint(relative_path, "web-application", "Python web application instance", "high", file))
    if entrypoints:
        return entrypoints
    return _fallback_entrypoints(app_root, file_by_path, {"app.py", "main.py", "manage.py", "asgi.py", "wsgi.py"})


def _android_launcher_activity(manifest_path: Path) -> str:
    text = _read_text_file(manifest_path)
    if not text:
        return ""
    activities = re.findall(r"<activity[^>]+android:name=[\"']([^\"']+)[\"'][\s\S]*?</activity>", text)
    for activity in activities:
        activity_block = next((block for block in re.findall(r"<activity[\s\S]*?</activity>", text) if activity in block), "")
        if "android.intent.action.MAIN" in activity_block and "android.intent.category.LAUNCHER" in activity_block:
            return activity
    return activities[0] if activities else ""


def _android_activity_to_path(app_root: str, activity: str, file_by_path: dict[str, dict[str, Any]]) -> str:
    activity_name = activity.split(".")[-1]
    for suffix in (".kt", ".java"):
        for path in file_by_path:
            if _under_app_root(path, app_root) and Path(path).name == f"{activity_name}{suffix}":
                return path
    return ""


def _read_json_file(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _read_toml_file(path: Path) -> dict[str, Any]:
    try:
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _app_id(app_root: str) -> str:
    root = app_root.strip("./") or "root"
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", root).strip("-") or "root"


def _file_role(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in IGNORED_FILE_NAMES:
        return "binary"
    if name in MANIFEST_NAMES or name in {"build.gradle", "build.gradle.kts", "androidmanifest.xml", "info.plist", "podfile", "package.swift"}:
        return "manifest"
    if name in LOCKFILE_NAMES:
        return "lockfile"
    if _looks_like_config(path):
        return "config"
    if suffix in SOURCE_SUFFIX_LANGUAGES:
        return "source"
    if suffix in TEXT_SUFFIXES:
        return "text"
    return "binary"


def _language_for_path(path: Path) -> str | None:
    return SOURCE_SUFFIX_LANGUAGES.get(path.suffix.lower())


def _looks_like_config(path: Path) -> bool:
    name = path.name.lower()
    if name in CONFIG_NAME_PATTERNS:
        return True
    if name.startswith(".github") or ".github" in path.parts:
        return True
    if name.endswith((".config.js", ".config.ts", ".conf", ".ini")):
        return True
    if path.suffix.lower() in {".yaml", ".yml"} and any(
        marker in name for marker in ("deploy", "service", "config", "compose", "workflow")
    ):
        return True
    return False


def _config_kind(path: Path) -> str:
    name = path.name.lower()
    if name == "androidmanifest.xml":
        return "android-manifest"
    if name == "info.plist":
        return "ios-info-plist"
    if name == "podfile":
        return "ios-dependencies"
    if name.startswith(".env"):
        return "environment-template"
    if name == "dockerfile" or name.startswith("dockerfile"):
        return "container-build"
    if "compose" in name:
        return "container-compose"
    if ".github" in path.parts:
        return "ci-workflow"
    return "configuration"


def _environment_variable_inventory(root: Path) -> list[dict[str, Any]]:
    variables: dict[tuple[str, str], dict[str, Any]] = {}
    for path in _iter_nonignored_files(root):
        if path.suffix.lower() not in TEXT_SUFFIXES and not _looks_like_config(path):
            continue
        text = _read_text_file(path)
        if text is None:
            continue
        relative_path = _relative_path(root, path)
        for line_number, line in enumerate(text.splitlines(), start=1):
            names = _environment_names_from_line(line)
            if path.name.lower().startswith(".env") or "compose" in path.name.lower():
                names.extend(_environment_assignment_names_from_line(line))
            for name in sorted(set(names)):
                key = (relative_path, name)
                variables[key] = {
                    "name": name,
                    "path": relative_path,
                    "line": line_number,
                    "source": _environment_source(path, line),
                }
    return sorted(variables.values(), key=lambda item: (str(item["name"]), str(item["path"])))[:500]


def _environment_names_from_line(line: str) -> list[str]:
    names = []
    patterns = [
        r"\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)",
        r"\bprocess\.env\[['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\]",
        r"\bos\.getenv\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
        r"\bgetenv\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
    ]
    for pattern in patterns:
        names.extend(re.findall(pattern, line))
    return sorted(set(names))


def _environment_assignment_names_from_line(line: str) -> list[str]:
    return re.findall(r"^\s*(?:-\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*[:=]", line)


def _environment_source(path: Path, line: str) -> str:
    name = path.name.lower()
    if name.startswith(".env"):
        return "environment-template"
    if "compose" in name:
        return "compose"
    if "process.env" in line or "getenv" in line:
        return "source-reference"
    return "configuration"


def _compose_topology_inventory(root: Path) -> list[dict[str, Any]]:
    topology = []
    for path in _iter_nonignored_files(root):
        name = path.name.lower()
        if name not in {"docker-compose.yml", "docker-compose.yaml"} and "compose" not in name:
            continue
        text = _read_text_file(path)
        if not text:
            continue
        topology.append(
            {
                "path": _relative_path(root, path),
                "services": _compose_services(text),
            }
        )
    return topology


def _compose_services(text: str) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    in_services = False
    current: dict[str, Any] | None = None
    current_key = ""
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if indent == 0:
            in_services = line == "services:"
            current = None
            current_key = ""
            continue
        if not in_services:
            continue
        if indent == 2 and line.endswith(":"):
            if current:
                services.append(current)
            current = {"name": line[:-1], "ports": [], "environment": [], "depends_on": [], "networks": []}
            current_key = ""
            continue
        if current is None:
            continue
        if indent == 4 and ":" in line:
            key, value = line.split(":", 1)
            current_key = key.strip()
            value = value.strip().strip("'\"")
            if current_key in {"image", "build", "container_name"} and value:
                current[current_key] = value
            continue
        if indent >= 6 and line.startswith("- "):
            value = line[2:].strip().strip("'\"")
            if current_key in {"ports", "environment", "depends_on", "networks"}:
                current.setdefault(current_key, []).append(value)
    if current:
        services.append(current)
    return services


def _dependencies_from_manifest(root: Path, path: Path) -> list[dict[str, Any]]:
    name = path.name.lower()
    if name == "package.json":
        return _package_json_dependencies(root, path)
    if name == "pyproject.toml":
        return _pyproject_dependencies(root, path)
    if name.startswith("requirements") and name.endswith(".txt"):
        return _requirements_dependencies(root, path)
    if name in {"build.gradle", "build.gradle.kts"}:
        return _gradle_dependencies(root, path)
    if name == "podfile":
        return _podfile_dependencies(root, path)
    if name == "package.swift":
        return _swift_package_dependencies(root, path)
    return []


def _package_json_dependencies(root: Path, path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    dependencies: list[dict[str, Any]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for package, version in sorted(values.items()):
            dependencies.append(
                {
                    "ecosystem": "npm",
                    "name": package,
                    "version": str(version),
                    "scope": section,
                    "manifest": _relative_path(root, path),
                }
            )
    return dependencies


def _pyproject_dependencies(root: Path, path: Path) -> list[dict[str, Any]]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []
    dependencies = []
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    for item in _list(project.get("dependencies")):
        parsed = _python_dependency(str(item))
        if parsed:
            dependencies.append({**parsed, "scope": "dependencies", "manifest": _relative_path(root, path)})
    optional = project.get("optional-dependencies") if isinstance(project.get("optional-dependencies"), dict) else {}
    for group, values in optional.items():
        for item in _list(values):
            parsed = _python_dependency(str(item))
            if parsed:
                dependencies.append({**parsed, "scope": f"optional:{group}", "manifest": _relative_path(root, path)})
    return dependencies


def _requirements_dependencies(root: Path, path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    dependencies = []
    for line in lines:
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith(("-", "git+", "http://", "https://")):
            continue
        parsed = _python_dependency(stripped)
        if parsed:
            dependencies.append({**parsed, "scope": "requirements", "manifest": _relative_path(root, path)})
    return dependencies


def _python_dependency(value: str) -> dict[str, str] | None:
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*(.*)$", value)
    if not match:
        return None
    name = match.group(1)
    version = match.group(2).strip() or "unspecified"
    return {"ecosystem": "python", "name": name, "version": version}


def _gradle_dependencies(root: Path, path: Path) -> list[dict[str, Any]]:
    text = _read_text_file(path) or ""
    dependencies: list[dict[str, Any]] = []
    for match in re.finditer(
        r"\b(\w+(?:Implementation|Api|CompileOnly|RuntimeOnly|TestImplementation|implementation|api|compileOnly|runtimeOnly|testImplementation)?)\s*\(\s*['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]",
        text,
    ):
        dependencies.append(
            {
                "ecosystem": "gradle",
                "name": f"{match.group(2)}:{match.group(3)}",
                "version": match.group(4),
                "scope": match.group(1),
                "manifest": _relative_path(root, path),
            }
        )
    for match in re.finditer(r"\b(?:alias|implementation|api|testImplementation)\s*\(\s*libs\.([A-Za-z0-9_.-]+)", text):
        dependencies.append(
            {
                "ecosystem": "gradle",
                "name": f"libs.{match.group(1)}",
                "version": "version-catalog",
                "scope": "version-catalog",
                "manifest": _relative_path(root, path),
            }
        )
    return dependencies


def _podfile_dependencies(root: Path, path: Path) -> list[dict[str, Any]]:
    text = _read_text_file(path) or ""
    dependencies: list[dict[str, Any]] = []
    for match in re.finditer(r"^\s*pod\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", text, re.MULTILINE):
        dependencies.append(
            {
                "ecosystem": "cocoapods",
                "name": match.group(1),
                "version": match.group(2) or "unspecified",
                "scope": "pod",
                "manifest": _relative_path(root, path),
            }
        )
    return dependencies


def _swift_package_dependencies(root: Path, path: Path) -> list[dict[str, Any]]:
    text = _read_text_file(path) or ""
    dependencies: list[dict[str, Any]] = []
    for match in re.finditer(r"\.package\(\s*url:\s*['\"]([^'\"]+)['\"]\s*,\s*([^)]*)\)", text):
        dependencies.append(
            {
                "ecosystem": "swift-package",
                "name": match.group(1).rstrip("/").split("/")[-1].removesuffix(".git"),
                "version": re.sub(r"\s+", " ", match.group(2)).strip() or "unspecified",
                "scope": "package",
                "manifest": _relative_path(root, path),
            }
        )
    return dependencies


def _extract_routes_from_file(root: Path, path: Path) -> list[dict[str, Any]]:
    text = _read_text_file(path)
    if text is None:
        return []
    suffix = path.suffix.lower()
    if suffix == ".py":
        return _extract_python_routes(root, path, text)
    if suffix in {".js", ".jsx", ".mjs", ".ts", ".tsx"}:
        return _extract_javascript_routes(root, path, text)
    if suffix == ".rb" and _looks_like_rails_routes_file(path, text):
        return _extract_rails_routes(root, path, text)
    return []


@dataclass(frozen=True)
class _RailsRouteContext:
    path_prefix: str = ""
    handler_prefix: str = ""
    conditional: bool = False


def _extract_python_routes(root: Path, path: Path, text: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    lines = text.splitlines()
    router_prefixes = _python_router_prefixes(text)
    include_prefixes = _python_include_router_prefixes(text)
    blueprint_prefixes = _python_blueprint_prefixes(text)
    registered_blueprint_prefixes = _python_registered_blueprint_prefixes(text)
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        match = re.match(
            r"@(?:(\w+)\.)?(route|get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"](.*)\)",
            stripped,
        )
        if not match:
            continue
        receiver = match.group(1) or "app"
        method = _python_route_method(stripped, match.group(2), match.group(4))
        handler = _next_python_function(lines, index)
        mount_prefix = _join_route_paths(
            include_prefixes.get(receiver) or registered_blueprint_prefixes.get(receiver) or "",
            router_prefixes.get(receiver) or blueprint_prefixes.get(receiver) or "",
        )
        routes.append(
            _route(
                root,
                path,
                index,
                method,
                match.group(3),
                "python",
                handler,
                stripped,
                mount_prefix=mount_prefix,
            )
        )
    return routes


def _python_route_method(decorator: str, decorator_name: str, remainder: str) -> str:
    if decorator_name.lower() in {"get", "post", "put", "patch", "delete"}:
        return decorator_name.upper()
    methods_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", remainder)
    if not methods_match:
        return "ANY"
    methods = re.findall(r"['\"]([A-Za-z]+)['\"]", methods_match.group(1))
    return ",".join(method.upper() for method in methods) if methods else "ANY"


def _next_python_function(lines: list[str], route_line_number: int) -> str | None:
    for line in lines[route_line_number : route_line_number + 5]:
        match = re.match(r"\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\(", line)
        if match:
            return match.group(1)
    return None


def _python_router_prefixes(text: str) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    for match in re.finditer(r"(\w+)\s*=\s*APIRouter\(([^)]*)\)", text):
        prefix = _keyword_string_value(match.group(2), "prefix")
        if prefix:
            prefixes[match.group(1)] = prefix
    return prefixes


def _python_include_router_prefixes(text: str) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    for match in re.finditer(r"\binclude_router\(\s*(\w+)\s*(?:,([^)]*))?\)", text):
        prefix = _keyword_string_value(match.group(2) or "", "prefix")
        if prefix:
            prefixes[match.group(1)] = prefix
    return prefixes


def _python_blueprint_prefixes(text: str) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    for match in re.finditer(r"(\w+)\s*=\s*Blueprint\(([^)]*)\)", text):
        prefix = _keyword_string_value(match.group(2), "url_prefix")
        if prefix:
            prefixes[match.group(1)] = prefix
    return prefixes


def _python_registered_blueprint_prefixes(text: str) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    for match in re.finditer(r"\bregister_blueprint\(\s*(\w+)\s*(?:,([^)]*))?\)", text):
        prefix = _keyword_string_value(match.group(2) or "", "url_prefix")
        if prefix:
            prefixes[match.group(1)] = prefix
    return prefixes


def _keyword_string_value(text: str, key: str) -> str:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*['\"]([^'\"]+)['\"]", text)
    return match.group(1) if match else ""


def _looks_like_rails_routes_file(path: Path, text: str) -> bool:
    return path.name == "routes.rb" and "Rails.application.routes.draw" in text


def _extract_rails_routes(root: Path, path: Path, text: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    context_stack: list[_RailsRouteContext] = []
    for index, raw_line in enumerate(text.splitlines(), start=1):
        stripped = _strip_ruby_comment(raw_line).strip()
        if not stripped:
            continue
        if re.fullmatch(r"end\b.*", stripped):
            if context_stack:
                context_stack.pop()
            continue
        context = _rails_context_from_line(stripped)
        if context:
            context_stack.append(context)
            continue
        route_data = _rails_route_from_line(stripped)
        if not route_data:
            continue
        method, route_path, handler = route_data
        mount_prefix = _join_route_paths(*(context.path_prefix for context in context_stack))
        resolved_handler = _rails_handler_with_namespace(handler or _rails_implicit_handler(route_path), context_stack)
        route = _route(
            root,
            path,
            index,
            method,
            route_path,
            "rails",
            resolved_handler,
            stripped,
            mount_prefix=mount_prefix,
        )
        if any(context.conditional for context in context_stack):
            route["conditional"] = True
        routes.append(route)
    return routes


def _strip_ruby_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#":
            return line[:index]
    return line


def _rails_context_from_line(line: str) -> _RailsRouteContext | None:
    scope_match = re.match(r"scope\b(.*)\bdo\b", line)
    if scope_match:
        return _RailsRouteContext(path_prefix=_rails_scope_path(scope_match.group(1)))
    namespace_match = re.match(r"namespace\s+(?::([A-Za-z_][\w]*)|['\"]([^'\"]+)['\"])(?:\s*,.*)?\s+do\b", line)
    if namespace_match:
        namespace = namespace_match.group(1) or namespace_match.group(2) or ""
        return _RailsRouteContext(path_prefix=f"/{namespace}", handler_prefix=namespace)
    if re.match(r"constraints\b.*\bdo\b", line):
        return _RailsRouteContext(conditional=True)
    return None


def _rails_scope_path(scope_args: str) -> str:
    positional = _first_string_literal(scope_args)
    if positional:
        return positional
    keyword = re.search(r"\bpath:\s*['\"]([^'\"]+)['\"]", scope_args)
    return keyword.group(1) if keyword else ""


def _rails_route_from_line(line: str) -> tuple[str, str, str | None] | None:
    match = re.match(r"\b(get|post|put|patch|delete)\s+(.+)$", line)
    if not match:
        return None
    route_path = _first_string_literal(match.group(2))
    if not route_path:
        return None
    handler = _rails_explicit_handler(match.group(2), route_path)
    return match.group(1).upper(), route_path, handler


def _first_string_literal(text: str) -> str:
    match = re.search(r"['\"]([^'\"]+)['\"]", text)
    return match.group(1) if match else ""


def _rails_explicit_handler(route_tail: str, route_path: str) -> str | None:
    tail = route_tail
    first_literal = re.escape(route_path)
    tail = re.sub(rf"^\s*['\"]{first_literal}['\"]\s*,?", "", tail, count=1)
    handler_match = re.search(r"(?:=>|to:)\s*['\"]([^'\"]+#\w+)['\"]", tail)
    if handler_match:
        return handler_match.group(1)
    controller_match = re.search(r"\bcontroller:\s*['\"]([^'\"]+)['\"]", tail)
    action_match = re.search(r"\baction:\s*['\"]([^'\"]+)['\"]", tail)
    if controller_match and action_match:
        return f"{controller_match.group(1)}#{action_match.group(1)}"
    return None


def _rails_implicit_handler(route_path: str) -> str | None:
    parts = [part for part in _normalize_route_path(route_path).strip("/").split("/") if part and not part.startswith(":")]
    if len(parts) < 2:
        return None
    return f"{'/'.join(parts[:-1])}#{parts[-1]}"


def _rails_handler_with_namespace(handler: str | None, context_stack: list[_RailsRouteContext]) -> str | None:
    if not handler:
        return None
    namespace = "/".join(context.handler_prefix for context in context_stack if context.handler_prefix)
    if not namespace:
        return handler
    controller, separator, action = handler.partition("#")
    if "/" in controller:
        return handler
    return f"{namespace}/{controller}{separator}{action}"


def _extract_javascript_routes(root: Path, path: Path, text: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    router_vars = set(re.findall(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:express\.)?Router\(\s*\)", text))
    mount_prefixes = _javascript_router_mount_prefixes(text)
    pattern = re.compile(
        r"\b(\w+)\.(get|post|put|patch|delete|all)\(\s*['\"]([^'\"]+)['\"]([^)]*)",
        re.IGNORECASE,
    )
    for index, line in enumerate(text.splitlines(), start=1):
        for match in pattern.finditer(line):
            receiver = match.group(1)
            if receiver not in {"app", "server", "router"} and receiver not in router_vars:
                continue
            routes.append(
                _route(
                    root,
                    path,
                    index,
                    match.group(2).upper(),
                    match.group(3),
                    "javascript",
                    None,
                    line.strip(),
                    mount_prefix=mount_prefixes.get(receiver, ""),
                    middleware=_javascript_middlewares_from_tail(match.group(4)),
                )
            )
    routes.extend(_extract_javascript_wrapper_routes(root, path, text))
    return routes


def _javascript_router_mount_prefixes(text: str) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    for match in re.finditer(r"\b(?:app|server)\.use\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\w+)", text):
        prefixes[match.group(2)] = match.group(1)
    return prefixes


def _extract_javascript_wrapper_routes(root: Path, path: Path, text: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    route_wrapper_names = set(
        re.findall(
            r"\b(?:function|const|let|var)\s+([A-Za-z_$][\w$]*(?:Route|Endpoint)[\w$]*)\b",
            text,
        )
    )
    if not route_wrapper_names:
        return routes
    prefix_arrays = _javascript_string_arrays(text)
    default_prefixes = next((values for name, values in prefix_arrays.items() if "prefix" in name.lower()), [""])
    call_pattern = re.compile(
        r"\b([A-Za-z_$][\w$]*)\(\s*(?:(?:app|router|server)\s*,\s*)?['\"]([A-Za-z]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]([^)]*)",
        re.IGNORECASE,
    )
    for index, line in enumerate(text.splitlines(), start=1):
        for match in call_pattern.finditer(line):
            function_name = match.group(1)
            if function_name not in route_wrapper_names:
                continue
            for prefix in default_prefixes:
                routes.append(
                    _route(
                        root,
                        path,
                        index,
                        match.group(2).upper(),
                        match.group(3),
                        "javascript",
                        function_name,
                        line.strip(),
                        mount_prefix=prefix,
                        middleware=_javascript_middlewares_from_tail(match.group(4)),
                        registration="custom-wrapper",
                    )
                )
    return routes


def _javascript_string_arrays(text: str) -> dict[str, list[str]]:
    arrays: dict[str, list[str]] = {}
    for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[([^\]]*)\]", text):
        values = re.findall(r"['\"]([^'\"]*)['\"]", match.group(2))
        if values:
            arrays[match.group(1)] = values
    return arrays


def _javascript_middlewares_from_tail(tail: str) -> list[str]:
    middlewares = []
    for match in re.finditer(r",\s*([A-Za-z_$][\w$]*)\s*(?=,|\))", tail):
        name = match.group(1)
        if name not in {"req", "res", "next", "request", "response"}:
            middlewares.append(name)
    return middlewares[:20]


def _route(
    root: Path,
    path: Path,
    line: int,
    method: str,
    route_path: str,
    framework: str,
    handler: str | None,
    evidence_line: str,
    mount_prefix: str = "",
    middleware: list[str] | None = None,
    registration: str = "direct",
) -> dict[str, Any]:
    local_route = _normalize_route_path(route_path)
    normalized_mount = _normalize_route_path(mount_prefix) if mount_prefix else ""
    full_route = _join_route_paths(normalized_mount, local_route)
    relative_path = _relative_path(root, path)
    return {
        "method": method,
        "route": local_route,
        "mount_prefix": normalized_mount,
        "full_route": full_route,
        "path": relative_path,
        "line": line,
        "framework": framework,
        "handler": handler,
        "app_id": _app_id(_top_level_root(relative_path)),
        "scope": _route_scope(relative_path),
        "middleware": middleware or [],
        "registration": registration,
        "snippet_hash": _snippet_hash(evidence_line),
    }


def _route_scope(relative_path: str) -> str:
    path = relative_path.lower()
    name = Path(path).name
    if (
        ".test." in name
        or ".spec." in name
        or "/test/" in path
        or "/tests/" in path
        or "/__tests__/" in path
        or name.startswith("test_")
        or name.endswith("_test.py")
    ):
        return "test"
    if "/example" in path or "/sample" in path or "/demo" in path:
        return "example"
    return "production"


def _normalize_route_path(path: str) -> str:
    text = _text(path)
    if not text:
        return ""
    return text if text.startswith("/") else f"/{text}"


def _join_route_paths(*parts: str) -> str:
    clean = [_normalize_route_path(part).strip("/") for part in parts if _text(part) and _text(part) != "/"]
    if not clean:
        return "/"
    return "/" + "/".join(part for part in clean if part)


def _infer_frameworks(inventory: dict[str, Any], dependencies: dict[str, Any]) -> list[dict[str, str]]:
    frameworks: list[dict[str, str]] = []
    framework_names = {"django", "fastapi", "flask", "express", "next", "next.js", "rails"}
    for dependency in dependencies.get("dependencies", []):
        name = str(dependency.get("name") or "").lower()
        if name in framework_names:
            frameworks.append(
                {
                    "name": str(dependency.get("name")),
                    "version": str(dependency.get("version") or "unspecified"),
                    "evidence": str(dependency.get("manifest") or ""),
                }
            )
    if inventory.get("languages"):
        for language in inventory["languages"]:
            if language in {"python", "javascript", "typescript"}:
                frameworks.append({"name": f"{language} application", "version": "unknown", "evidence": "file inventory"})
    return _dedupe_dicts(frameworks, "name")


def _auth_candidates(inventory: dict[str, Any], routes: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for file in inventory.get("files", []):
        path = str(file.get("path") or "")
        if re.search(r"(auth|login|session|jwt|permission|policy)", path, re.IGNORECASE):
            candidates.append({"path": path, "reason": "auth-related filename"})
    for route in routes.get("routes", []):
        route_path = str(route.get("route") or "")
        if re.search(r"(auth|login|logout|session|token)", route_path, re.IGNORECASE):
            candidates.append({"path": route.get("path"), "route": route_path, "reason": "auth-related route"})
    return candidates[:100]


def _session_candidates(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for file in inventory.get("files", []):
        path = str(file.get("path") or "")
        if re.search(r"(session|cookie|csrf|jwt|token)", path, re.IGNORECASE):
            candidates.append({"path": path, "reason": "session-related filename"})
    return candidates[:100]


def _data_store_candidates(dependencies: dict[str, Any], configuration: dict[str, Any]) -> list[dict[str, Any]]:
    markers = {"postgres", "psycopg", "mysql", "sqlite", "redis", "mongoose", "mongodb", "sqlalchemy"}
    candidates = []
    for dependency in dependencies.get("dependencies", []):
        name = str(dependency.get("name") or "").lower()
        if any(marker in name for marker in markers):
            candidates.append({"name": dependency.get("name"), "evidence": dependency.get("manifest")})
    for item in configuration.get("configuration", []):
        path = str(item.get("path") or "").lower()
        if any(marker in path for marker in markers):
            candidates.append({"path": item.get("path"), "reason": "configuration filename"})
    return candidates[:100]


def _read_text_file(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _relative_path(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _snippet_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _dedupe_dicts(values: list[dict[str, str]], key: str) -> list[dict[str, str]]:
    seen = set()
    deduped = []
    for value in values:
        marker = value.get(key)
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(value)
    return deduped


def _dedupe_list(values: list[Any]) -> list[Any]:
    seen = set()
    deduped = []
    for value in values:
        marker = json.dumps(value, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(value)
    return deduped


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
