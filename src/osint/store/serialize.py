from __future__ import annotations

import json
from typing import Any

from osint.core.entities import Entity, EntityType
from osint.core.relationships import RelationType, Relationship


def entity_to_props(
    entity: Entity, source_confidences_map: dict[str, float]
) -> dict[str, Any]:
    return {
        "id": entity.id,
        "type": entity.type.value,
        "value": entity.value,
        "confidence": entity.confidence,
        "first_seen": entity.first_seen.isoformat(),
        "last_seen": entity.last_seen.isoformat(),
        "tags": sorted(entity.tags),
        "attributes_json": _dump_json(entity.attributes),
        "sources_json": _dump_json(
            [source.model_dump(mode="json") for source in entity.sources]
        ),
        "source_confidences_json": _dump_json(source_confidences_map),
    }


def entity_from_props(record: Any) -> tuple[Entity, dict[str, float]]:
    props = _as_props(record)
    source_confidences = _loads_map(props.get("source_confidences_json"))
    entity = Entity.model_validate(
        {
            "id": props["id"],
            "type": EntityType(props["type"]),
            "value": props["value"],
            "attributes": json.loads(props["attributes_json"]),
            "sources": json.loads(props["sources_json"]),
            "confidence": props["confidence"],
            "first_seen": props["first_seen"],
            "last_seen": props["last_seen"],
            "tags": props.get("tags", []),
        }
    )
    return entity, source_confidences


def relationship_to_props(
    relationship: Relationship, source_confidences_map: dict[str, float]
) -> dict[str, Any]:
    return {
        "id": relationship.id,
        "type": relationship.type.value,
        "src_id": relationship.src_id,
        "dst_id": relationship.dst_id,
        "confidence": relationship.confidence,
        "first_seen": relationship.first_seen.isoformat(),
        "last_seen": relationship.last_seen.isoformat(),
        "sources_json": _dump_json(
            [source.model_dump(mode="json") for source in relationship.sources]
        ),
        "source_confidences_json": _dump_json(source_confidences_map),
    }


def relationship_from_props(record: Any) -> tuple[Relationship, dict[str, float]]:
    props = _as_props(record)
    source_confidences = _loads_map(props.get("source_confidences_json"))
    relationship = Relationship.model_validate(
        {
            "id": props["id"],
            "type": RelationType(props["type"]),
            "src_id": props["src_id"],
            "dst_id": props["dst_id"],
            "sources": json.loads(props["sources_json"]),
            "confidence": props["confidence"],
            "first_seen": props["first_seen"],
            "last_seen": props["last_seen"],
        }
    )
    return relationship, source_confidences


def _dump_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _loads_map(value: str | None) -> dict[str, float]:
    if not value:
        return {}
    return {str(key): float(confidence) for key, confidence in json.loads(value).items()}


def _as_props(record: Any) -> dict[str, Any]:
    if isinstance(record, dict):
        return dict(record)
    if hasattr(record, "items"):
        return dict(record.items())
    return dict(record)
