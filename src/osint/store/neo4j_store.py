from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase

from osint.core.entities import Entity, EntityType
from osint.core.relationships import RelationType, Relationship
from osint.store.base import EntityStore
from osint.store.merge import (
    merge_attributes,
    merge_source_confidences,
    merge_sources,
    noisy_or,
    source_confidences,
)
from osint.store.serialize import (
    entity_from_props,
    entity_to_props,
    relationship_from_props,
    relationship_to_props,
)

_PROMOTED_ENTITY_PROPERTIES: dict[EntityType, dict[str, type]] = {
    EntityType.Vulnerability: {
        "cvss": float,
        "epss": float,
        "kev": bool,
        "severity": str,
    }
}


class Neo4jEntityStore(EntityStore):
    def __init__(self, uri: str, user: str, password: str) -> None:
        self.driver = GraphDatabase.driver(
            uri,
            auth=(user, password),
            connection_timeout=2.0,
        )
        self._ensure_schema()

    def upsert_entity(self, entity: Entity) -> Entity:
        with self.driver.session() as session:
            return session.execute_write(self._upsert_entity_tx, entity)

    def upsert_relationship(self, relationship: Relationship) -> Relationship:
        relationship_type = _relationship_type(relationship.type)
        with self.driver.session() as session:
            return session.execute_write(
                self._upsert_relationship_tx, relationship, relationship_type
            )

    def get(self, id_: str) -> Entity | Relationship | None:
        with self.driver.session() as session:
            node_record = session.run(
                "MATCH (n:Entity {id: $id}) RETURN properties(n) AS props",
                id=id_,
            ).single()
            if node_record:
                return entity_from_props(node_record["props"])[0]

            rel_record = session.run(
                """
                MATCH (a:Entity)-[r {id: $id}]->(b:Entity)
                RETURN properties(r) AS props, type(r) AS type,
                       a.id AS src_id, b.id AS dst_id
                """,
                id=id_,
            ).single()
            if rel_record:
                return relationship_from_props(_relationship_record_props(rel_record))[0]
        return None

    def all_entities(self) -> list[Entity]:
        with self.driver.session() as session:
            records = session.run(
                "MATCH (n:Entity) RETURN properties(n) AS props ORDER BY n.id"
            )
            return [entity_from_props(record["props"])[0] for record in records]

    def all_relationships(self) -> list[Relationship]:
        with self.driver.session() as session:
            records = session.run(
                """
                MATCH (a:Entity)-[r]->(b:Entity)
                WHERE r.id IS NOT NULL
                RETURN properties(r) AS props, type(r) AS type,
                       a.id AS src_id, b.id AS dst_id
                ORDER BY r.id
                """
            )
            return [
                relationship_from_props(_relationship_record_props(record))[0]
                for record in records
            ]

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

    def close(self) -> None:
        self.driver.close()

    def __enter__(self) -> "Neo4jEntityStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def clear(self) -> None:
        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run("MATCH (n) DETACH DELETE n").consume())

    def _ensure_schema(self) -> None:
        with self.driver.session() as session:
            session.run(
                """
                CREATE CONSTRAINT entity_id_unique IF NOT EXISTS
                FOR (n:Entity) REQUIRE n.id IS UNIQUE
                """
            ).consume()

    @staticmethod
    def _upsert_entity_tx(tx: Any, entity: Entity) -> Entity:
        existing_record = tx.run(
            "MATCH (n:Entity {id: $id}) RETURN properties(n) AS props",
            id=entity.id,
        ).single()

        if existing_record:
            existing, existing_map = entity_from_props(existing_record["props"])
            existing.sources = merge_sources(existing.sources, entity.sources)
            existing.tags = existing.tags | entity.tags
            existing.first_seen = min(existing.first_seen, entity.first_seen)
            existing.last_seen = max(existing.last_seen, entity.last_seen)
            existing.attributes = merge_attributes(existing.attributes, entity.attributes)
            merged_map = merge_source_confidences(
                existing_map,
                source_confidences(entity.sources, entity.confidence),
            )
            existing.confidence = noisy_or(merged_map)
            stored = existing
            source_map = merged_map
        else:
            stored = entity.model_copy(deep=True)
            source_map = source_confidences(stored.sources, stored.confidence)

        props = _entity_props_for_store(stored, source_map)
        label = _entity_label(stored.type.value)
        tx.run(
            f"MERGE (n:Entity {{id: $id}}) SET n += $props SET n:{label}",
            id=stored.id,
            props=props,
        ).consume()
        return stored

    @staticmethod
    def _upsert_relationship_tx(
        tx: Any, relationship: Relationship, relationship_type: str
    ) -> Relationship:
        existing_record = tx.run(
            """
            MATCH (a:Entity)-[r {id: $id}]->(b:Entity)
            RETURN properties(r) AS props, type(r) AS type,
                   a.id AS src_id, b.id AS dst_id
            """,
            id=relationship.id,
        ).single()

        if existing_record:
            existing, existing_map = relationship_from_props(
                _relationship_record_props(existing_record)
            )
            existing.sources = merge_sources(existing.sources, relationship.sources)
            existing.first_seen = min(existing.first_seen, relationship.first_seen)
            existing.last_seen = max(existing.last_seen, relationship.last_seen)
            merged_map = merge_source_confidences(
                existing_map,
                source_confidences(relationship.sources, relationship.confidence),
            )
            existing.confidence = noisy_or(merged_map)
            stored = existing
            source_map = merged_map
        else:
            stored = relationship.model_copy(deep=True)
            source_map = source_confidences(stored.sources, stored.confidence)

        props = relationship_to_props(stored, source_map)
        props_to_store = {
            key: value for key, value in props.items() if key not in {"src_id", "dst_id"}
        }
        tx.run(
            f"""
            MATCH (a:Entity {{id: $src_id}})
            MATCH (b:Entity {{id: $dst_id}})
            MERGE (a)-[r:{relationship_type} {{id: $id}}]->(b)
            SET r += $props
            """,
            src_id=stored.src_id,
            dst_id=stored.dst_id,
            id=stored.id,
            props=props_to_store,
        ).consume()
        return stored


def _entity_label(label: str) -> str:
    allowed = {entity_type.value for entity_type in EntityType}
    if label not in allowed:
        raise ValueError(f"Invalid entity label: {label}")
    return label


def _relationship_type(relation_type: RelationType) -> str:
    allowed = {item.value for item in RelationType}
    value = relation_type.value
    if value not in allowed:
        raise ValueError(f"Unsupported relationship type: {value}")
    return value


def _relationship_record_props(record: Any) -> dict[str, Any]:
    props = dict(record["props"])
    props["type"] = record["type"]
    props["src_id"] = record["src_id"]
    props["dst_id"] = record["dst_id"]
    return props


def _entity_props_for_store(
    entity: Entity, source_confidences_map: dict[str, float]
) -> dict[str, Any]:
    props = entity_to_props(entity, source_confidences_map)
    promoted_fields = _PROMOTED_ENTITY_PROPERTIES.get(entity.type, {})
    for name, property_type in promoted_fields.items():
        props[name] = _promoted_property_value(entity.attributes.get(name), property_type)
    return props


def _promoted_property_value(value: Any, property_type: type) -> Any:
    if value is None:
        return None
    if property_type is bool:
        if isinstance(value, bool):
            return value
        return None
    if property_type is float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    if property_type is str:
        return str(value)
    return value
