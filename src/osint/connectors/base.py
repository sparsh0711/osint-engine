from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import TYPE_CHECKING, AsyncIterator, TypeVar

from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding

if TYPE_CHECKING:
    from osint.connectors.context import CollectionContext


class CollectionMode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"


class EnrichmentClass(StrEnum):
    IDENTIFICATION = "identification"
    EXPOSURE = "exposure"


class Connector(ABC):
    name: str
    source: str
    description: str
    mode: CollectionMode
    accepts: set[EntityType]
    produces: set[EntityType]
    requires_api_key: bool = False
    base_confidence: float = 0.6
    enrichment_class: EnrichmentClass = EnrichmentClass.EXPOSURE

    @abstractmethod
    async def collect(
        self, seed: Entity, ctx: "CollectionContext"
    ) -> AsyncIterator[Finding]:
        """Yield Findings derived from seed without mutating it."""
        raise NotImplementedError


ConnectorT = TypeVar("ConnectorT", bound=type[Connector])
REGISTRY: dict[str, Connector] = {}


def register(connector_cls: ConnectorT) -> ConnectorT:
    connector = connector_cls()
    REGISTRY[connector.name] = connector
    return connector_cls
