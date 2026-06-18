from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from osint.core.entities import Entity
from osint.core.relationships import Relationship


class EntityStore(ABC):
    @abstractmethod
    def upsert_entity(self, entity: Entity) -> Entity:
        raise NotImplementedError

    @abstractmethod
    def upsert_relationship(self, relationship: Relationship) -> Relationship:
        raise NotImplementedError

    @abstractmethod
    def get(self, id_: str) -> Entity | Relationship | None:
        raise NotImplementedError

    @abstractmethod
    def all_entities(self) -> list[Entity]:
        raise NotImplementedError

    @abstractmethod
    def all_relationships(self) -> list[Relationship]:
        raise NotImplementedError

    @abstractmethod
    def snapshot(self, path: str | Path) -> None:
        raise NotImplementedError
