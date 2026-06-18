from __future__ import annotations

import json
from pathlib import Path

from osint.core.entities import Entity
from osint.core.relationships import Relationship
from osint.store.base import EntityStore
from osint.store.merge import (
    merge_attributes,
    merge_source_confidences,
    merge_sources,
    noisy_or,
    source_confidences,
)


class MemoryEntityStore(EntityStore):
    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._relationships: dict[str, Relationship] = {}
        self._entity_confidences: dict[str, dict[str, float]] = {}
        self._relationship_confidences: dict[str, dict[str, float]] = {}

    def upsert_entity(self, entity: Entity) -> Entity:
        if entity.id not in self._entities:
            stored = entity.model_copy(deep=True)
            self._entities[stored.id] = stored
            self._entity_confidences[stored.id] = source_confidences(stored.sources, stored.confidence)
            return stored

        existing = self._entities[entity.id]
        existing.sources = merge_sources(existing.sources, entity.sources)
        existing.tags = existing.tags | entity.tags
        existing.first_seen = min(existing.first_seen, entity.first_seen)
        existing.last_seen = max(existing.last_seen, entity.last_seen)
        existing.attributes = merge_attributes(existing.attributes, entity.attributes)

        self._entity_confidences[entity.id] = merge_source_confidences(
            self._entity_confidences[entity.id],
            source_confidences(entity.sources, entity.confidence),
        )
        existing.confidence = noisy_or(self._entity_confidences[entity.id])
        return existing

    def upsert_relationship(self, relationship: Relationship) -> Relationship:
        if relationship.id not in self._relationships:
            stored = relationship.model_copy(deep=True)
            self._relationships[stored.id] = stored
            self._relationship_confidences[stored.id] = source_confidences(
                stored.sources, stored.confidence
            )
            return stored

        existing = self._relationships[relationship.id]
        existing.sources = merge_sources(existing.sources, relationship.sources)
        existing.first_seen = min(existing.first_seen, relationship.first_seen)
        existing.last_seen = max(existing.last_seen, relationship.last_seen)
        self._relationship_confidences[relationship.id] = merge_source_confidences(
            self._relationship_confidences[relationship.id],
            source_confidences(relationship.sources, relationship.confidence),
        )
        existing.confidence = noisy_or(self._relationship_confidences[relationship.id])
        return existing

    def get(self, id_: str) -> Entity | Relationship | None:
        return self._entities.get(id_) or self._relationships.get(id_)

    def all_entities(self) -> list[Entity]:
        return [self._entities[id_] for id_ in sorted(self._entities)]

    def all_relationships(self) -> list[Relationship]:
        return [self._relationships[id_] for id_ in sorted(self._relationships)]

    def snapshot(self, path: str | Path) -> None:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "entities": [entity.model_dump(mode="json") for entity in self.all_entities()],
            "relationships": [
                relationship.model_dump(mode="json")
                for relationship in self.all_relationships()
            ],
        }
        output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
