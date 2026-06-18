from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType, Relationship
from osint.store.neo4j_store import Neo4jEntityStore


@pytest.fixture()
def neo4j_store(request):
    uri = request.config.getoption("--neo4j-uri") or os.environ.get(
        "NEO4J_URI", "bolt://localhost:7687"
    )
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "change-me")
    try:
        store = Neo4jEntityStore(uri, user, password)
        store.driver.verify_connectivity()
    except Exception as exc:
        pytest.skip(f"Neo4j not available: {exc}")
    store.clear()
    yield store
    store.clear()
    store.close()


def test_neo4j_upsert_deduplicates_nodes_and_round_trips(neo4j_store) -> None:
    first = _domain("example.com", "crt.sh", 0.7)
    second = _domain("example.com", "web.archive.org", 0.6)

    neo4j_store.upsert_entity(first)
    merged = neo4j_store.upsert_entity(second)

    assert len(neo4j_store.all_entities()) == 1
    assert neo4j_store.get(first.id) == merged
    assert {source.source for source in merged.sources} == {
        "crt.sh",
        "web.archive.org",
    }
    assert merged.confidence == pytest.approx(0.88)


def test_neo4j_relationship_round_trip(neo4j_store) -> None:
    root = _domain("example.com", "crt.sh", 0.7)
    child = _domain("api.example.com", "crt.sh", 0.7)
    neo4j_store.upsert_entity(root)
    neo4j_store.upsert_entity(child)
    relationship = Relationship(
        type=RelationType.HAS_SUBDOMAIN,
        src_id=root.id,
        dst_id=child.id,
        sources=[_source("crtsh", "crt.sh")],
        confidence=0.7,
    )

    stored = neo4j_store.upsert_relationship(relationship)

    assert neo4j_store.get(relationship.id) == stored
    assert neo4j_store.all_relationships() == [stored]


def _domain(value: str, source_name: str, confidence: float) -> Entity:
    return Entity(
        type=EntityType.Domain,
        value=value,
        attributes={"registered_domain": "example.com"},
        sources=[_source(source_name.replace(".", ""), source_name)],
        confidence=confidence,
    )


def _source(connector: str, source: str) -> Provenance:
    return Provenance(
        connector=connector,
        source=source,
        query="q",
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw_ref={"id": connector},
    )
