from __future__ import annotations

from datetime import datetime, timezone

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType, Relationship
from osint.store.serialize import (
    entity_from_props,
    entity_to_props,
    relationship_from_props,
    relationship_to_props,
)


def test_entity_props_round_trip_is_lossless() -> None:
    entity = Entity(
        type=EntityType.Domain,
        value="Example.COM",
        attributes={
            "registered_domain": "example.com",
            "nested": {"a": 1},
            "_conflicts": {"nested.a": [{"existing": 1, "incoming": 2}]},
        },
        sources=[_source("crtsh", "crt.sh")],
        confidence=0.88,
        tags={"wildcard", "co-san"},
    )
    source_map = {"crt.sh": 0.7, "web.archive.org": 0.6}

    restored, restored_map = entity_from_props(entity_to_props(entity, source_map))

    assert restored == entity
    assert restored_map == source_map


def test_relationship_props_round_trip_is_lossless() -> None:
    relationship = Relationship(
        type=RelationType.HAS_SUBDOMAIN,
        src_id="root",
        dst_id="child",
        sources=[_source("wayback", "web.archive.org")],
        confidence=0.6,
    )
    source_map = {"web.archive.org": 0.6}

    restored, restored_map = relationship_from_props(
        relationship_to_props(relationship, source_map)
    )

    assert restored == relationship
    assert restored_map == source_map


def _source(connector: str, source: str) -> Provenance:
    return Provenance(
        connector=connector,
        source=source,
        query="q",
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw_ref={"id": connector},
    )
