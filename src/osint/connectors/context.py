from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from osint.orchestrator.authorization import Authorization


class HttpClient(Protocol):
    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        ...

    async def get(self, url: str, **kwargs: Any) -> Any:
        ...


@dataclass(slots=True)
class CollectionContext:
    http: HttpClient
    cache: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    logger: Any = None
    authorization: Authorization | None = None
