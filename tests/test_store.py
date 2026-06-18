from __future__ import annotations

from datetime import datetime, timezone

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.store.memory import MemoryEntityStore


def test_store_merges_sources_tags_confidence_and_conflicts() -> None:
    store = MemoryEntityStore()
    first = _domain("Example.COM", "source-a", 0.7, {"owner": "old"}, {"seed"})
    second = _domain("example.com.", "source-b", 0.6, {"owner": "new"}, {"wildcard"})

    store.upsert_entity(first)
    merged = store.upsert_entity(second)

    assert len(store.all_entities()) == 1
    assert {source.source for source in merged.sources} == {"source-a", "source-b"}
    assert merged.tags == {"seed", "wildcard"}
    assert round(merged.confidence, 2) == 0.88
    assert merged.attributes["owner"] == "old"
    assert merged.attributes["_conflicts"]["owner"] == [
        {"existing": "old", "incoming": "new"}
    ]


def test_same_source_does_not_raise_confidence() -> None:
    store = MemoryEntityStore()
    store.upsert_entity(_domain("example.com", "crt.sh", 0.7, {}, set()))
    merged = store.upsert_entity(_domain("example.com", "crt.sh", 0.7, {}, set()))

    assert merged.confidence == 0.7


def _domain(
    value: str,
    source: str,
    confidence: float,
    attributes: dict[str, str],
    tags: set[str],
) -> Entity:
    return Entity(
        type=EntityType.Domain,
        value=value,
        attributes=attributes,
        sources=[
            Provenance(
                connector=source,
                source=source,
                query=value,
                collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                raw_ref={"id": source},
            )
        ],
        confidence=confidence,
        tags=tags,
    )
