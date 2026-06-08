from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AgentDefinition:
    name: str
    role: str
    goal: str
    model: str
    tools: list[Any] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
