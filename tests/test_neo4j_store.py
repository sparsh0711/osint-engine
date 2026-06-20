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


def test_neo4j_promotes_vulnerability_scalars_for_queries(neo4j_store) -> None:
    vulnerability = _vulnerability("CVE-2026-12345")

    neo4j_store.upsert_entity(vulnerability)

    with neo4j_store.driver.session() as session:
        record = session.run(
            """
            MATCH (v:Vulnerability)
            WHERE v.kev = true
            RETURN v.cvss AS cvss, v.epss AS epss, v.kev AS kev, v.severity AS severity
            ORDER BY v.cvss DESC
            """
        ).single()
    assert record is not None
    assert record["cvss"] == pytest.approx(9.8)
    assert record["epss"] == pytest.approx(0.42)
    assert record["kev"] is True
    assert record["severity"] == "critical"
    assert neo4j_store.get(vulnerability.id) == vulnerability


def test_neo4j_vulnerability_attributes_json_remains_source_of_truth(
    neo4j_store,
) -> None:
    vulnerability = _vulnerability("CVE-2026-12345")
    neo4j_store.upsert_entity(vulnerability)

    with neo4j_store.driver.session() as session:
        session.run(
            """
            MATCH (v:Vulnerability {id: $id})
            SET v.cvss = 1.0, v.epss = 0.0, v.kev = false, v.severity = 'low'
            """,
            id=vulnerability.id,
        ).consume()

    restored = neo4j_store.get(vulnerability.id)
    assert restored == vulnerability
    assert restored.attributes["references"] == ["https://example.test/cve"]


def test_neo4j_promoted_properties_do_not_affect_other_entity_types(
    neo4j_store,
) -> None:
    domain = Entity(
        type=EntityType.Domain,
        value="example.com",
        attributes={"cvss": 9.8, "epss": 0.42, "kev": True, "severity": "critical"},
        sources=[_source("test", "test")],
        confidence=1.0,
    )

    neo4j_store.upsert_entity(domain)

    with neo4j_store.driver.session() as session:
        record = session.run(
            """
            MATCH (d:Domain {id: $id})
            RETURN d.cvss AS cvss, d.epss AS epss, d.kev AS kev, d.severity AS severity
            """,
            id=domain.id,
        ).single()
    assert record is not None
    assert record["cvss"] is None
    assert record["epss"] is None
    assert record["kev"] is None
    assert record["severity"] is None
    assert neo4j_store.get(domain.id) == domain


def _domain(value: str, source_name: str, confidence: float) -> Entity:
    return Entity(
        type=EntityType.Domain,
        value=value,
        attributes={"registered_domain": "example.com"},
        sources=[_source(source_name.replace(".", ""), source_name)],
        confidence=confidence,
    )


def _vulnerability(value: str) -> Entity:
    return Entity(
        type=EntityType.Vulnerability,
        value=value,
        attributes={
            "cve_id": value,
            "cvss": 9.8,
            "epss": 0.42,
            "kev": True,
            "severity": "critical",
            "summary": "Test vulnerability",
            "references": ["https://example.test/cve"],
        },
        sources=[_source("cvedb", "shodan-cvedb")],
        confidence=0.9,
    )


def _source(connector: str, source: str) -> Provenance:
    return Provenance(
        connector=connector,
        source=source,
        query="q",
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw_ref={"id": connector},
    )
