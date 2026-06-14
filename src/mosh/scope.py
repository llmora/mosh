from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import ParseResult, urldefrag, urlparse, urlunparse


COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac",
    "co",
    "com",
    "edu",
    "gov",
    "net",
    "org",
}


def normalize_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("URL must include a host")
    path = parsed.path or "/"
    normalized = ParseResult(
        scheme=parsed.scheme.lower(),
        netloc=_normalized_netloc(parsed),
        path=path,
        params="",
        query=parsed.query,
        fragment="",
    )
    return urlunparse(normalized)


def strip_fragment(url: str) -> str:
    return urldefrag(url)[0]


def report_dir_name(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    host = parsed.hostname or "unknown"
    name = host.lower()
    if parsed.port:
        name = f"{name}_{parsed.port}"
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", name)


def source_report_dir_name(source: str | Path) -> str:
    source_text = str(source).strip()
    if not source_text:
        source_text = "source"
    parsed = urlparse(source_text)
    if parsed.scheme in {"http", "https", "ssh", "git"} and parsed.netloc:
        repo_name = Path(parsed.path.rstrip("/")).name.removesuffix(".git") or parsed.netloc
        readable = f"source-{parsed.netloc}-{repo_name}"
        identity = source_text
    else:
        source_path = Path(source_text).expanduser()
        readable = f"source-{source_path.name or 'source'}"
        identity = str(source_path.resolve(strict=False))
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:8]
    return f"{_safe_dir_name(readable)}-{digest}"


@dataclass(frozen=True)
class ScopePolicy:
    start_url: str
    root: str

    @classmethod
    def from_url(cls, url: str) -> "ScopePolicy":
        normalized = normalize_url(url)
        parsed = urlparse(normalized)
        host = parsed.hostname or ""
        return cls(start_url=normalized, root=_scope_root(host))

    def in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            return False
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return False
        if _is_ip_or_local(self.root):
            return host == self.root
        return host == self.root or host.endswith(f".{self.root}")


def _normalized_netloc(parsed: ParseResult) -> str:
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.port:
        return f"{host}:{parsed.port}"
    return host


def _safe_dir_name(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value.strip().lower()).strip("._-")
    return safe or "source"


def _scope_root(host: str) -> str:
    host = host.lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if _is_ip_or_local(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels) >= 3 and labels[-2] in COMMON_SECOND_LEVEL_SUFFIXES and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip_or_local(host: str) -> bool:
    if host in {"localhost"}:
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
