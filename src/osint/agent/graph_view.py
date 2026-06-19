from __future__ import annotations

from collections import Counter, defaultdict
from enum import Enum
from typing import Literal

from osint.core.entities import Entity, EntityType
from osint.core.relationships import RelationType, Relationship
from osint.store.base import EntityStore

Direction = Literal["out", "in", "both"]


class GraphView:
    def __init__(self, store: EntityStore) -> None:
        self.entities = {entity.id: entity for entity in store.all_entities()}
        self.relationships = {
            relationship.id: relationship for relationship in store.all_relationships()
        }
        self._entities_by_type: dict[EntityType, list[Entity]] = defaultdict(list)
        self._entities_by_tag: dict[str, list[Entity]] = defaultdict(list)
        self._out_edges: dict[str, list[Relationship]] = defaultdict(list)
        self._in_edges: dict[str, list[Relationship]] = defaultdict(list)

        for entity in self.entities.values():
            self._entities_by_type[entity.type].append(entity)
            for tag in entity.tags:
                self._entities_by_tag[tag].append(entity)
        for relationship in self.relationships.values():
            self._out_edges[relationship.src_id].append(relationship)
            self._in_edges[relationship.dst_id].append(relationship)

    def get(self, id_: str) -> Entity | Relationship | None:
        return self.entities.get(id_) or self.relationships.get(id_)

    def by_type(self, type_: EntityType | str) -> list[Entity]:
        entity_type = _entity_type(type_)
        return sorted(self._entities_by_type.get(entity_type, []), key=_entity_sort_key)

    def by_tag(self, tag: str) -> list[Entity]:
        return sorted(self._entities_by_tag.get(tag, []), key=_entity_sort_key)

    def neighbors(
        self,
        id_: str,
        rel_type: RelationType | str | None = None,
        direction: Direction = "both",
    ) -> list[dict[str, Entity | Relationship]]:
        relation_type = _relation_type(rel_type) if rel_type is not None else None
        items: list[dict[str, Entity | Relationship]] = []

        if direction in {"out", "both"}:
            for relationship in self._out_edges.get(id_, []):
                if relation_type is None or relationship.type == relation_type:
                    entity = self.entities.get(relationship.dst_id)
                    if entity is not None:
                        items.append({"relationship": relationship, "entity": entity})

        if direction in {"in", "both"}:
            for relationship in self._in_edges.get(id_, []):
                if relation_type is None or relationship.type == relation_type:
                    entity = self.entities.get(relationship.src_id)
                    if entity is not None:
                        items.append({"relationship": relationship, "entity": entity})

        return sorted(
            items,
            key=lambda item: (
                item["relationship"].id or "",
                item["entity"].id or "",
            ),
        )

    def unenriched_ips(self) -> list[Entity]:
        enriched_ids = {
            relationship.src_id
            for relationship in self.relationships.values()
            if relationship.type == RelationType.HOSTS
        }
        return [
            entity
            for entity in self.by_type(EntityType.IPAddress)
            if entity.id not in enriched_ids
        ]

    def high_confidence(self, threshold: float) -> list[Entity]:
        return sorted(
            [entity for entity in self.entities.values() if entity.confidence >= threshold],
            key=lambda item: (-item.confidence, item.type.value, item.value),
        )

    def co_san_domains(self) -> list[Entity]:
        return [
            entity
            for entity in self.by_type(EntityType.Domain)
            if "co-san" in entity.tags or entity.attributes.get("under_seed") is False
        ]

    def summary(self) -> dict[str, object]:
        counts = Counter(entity.type.value for entity in self.entities.values())
        confidence = {"high": 0, "medium": 0, "low": 0}
        for entity in self.entities.values():
            if entity.confidence >= 0.8:
                confidence["high"] += 1
            elif entity.confidence >= 0.5:
                confidence["medium"] += 1
            else:
                confidence["low"] += 1
        return {
            "entity_counts": dict(sorted(counts.items())),
            "relationship_count": len(self.relationships),
            "confidence_distribution": confidence,
        }


def _entity_type(type_: EntityType | str) -> EntityType:
    if isinstance(type_, EntityType):
        return type_
    return EntityType(type_)


def _entity_sort_key(entity: Entity) -> tuple[str, str, str]:
    return (entity.type.value, entity.value, entity.id or "")


def _relation_type(type_: RelationType | str) -> RelationType:
    if isinstance(type_, RelationType):
        return type_
    return RelationType(type_)
