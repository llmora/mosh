from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Event:
    agent: str
    action: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MemoryItem:
    kind: str
    content: dict[str, Any]
    source: str
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CrawledPage:
    url: str
    status: int
    content_type: str
    title: str | None
    headers: dict[str, str]
    links: list[str]
    references: list[str]
    forms: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DiscoveryCandidate:
    url: str
    source_tool: str
    status: int
    kind: str
    confidence: str
    reason: str
    evidence: list[str]
    should_crawl: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CrawlResult:
    start_url: str
    pages: list[CrawledPage]
    out_of_scope: list[str]
    failed: list[dict[str, Any]]
    robots: dict[str, Any] | None = None
    candidates: list[DiscoveryCandidate] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_url": self.start_url,
            "pages": [page.to_dict() for page in self.pages],
            "out_of_scope": self.out_of_scope,
            "failed": self.failed,
            "robots": self.robots,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }
