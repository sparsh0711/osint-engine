from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from osint.orchestrator.authorization import Authorization
from osint.util.http import RateLimitedAsyncClient


@dataclass(slots=True)
class CollectionContext:
    http: RateLimitedAsyncClient
    cache: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    logger: Any = None
    authorization: Authorization | None = None
