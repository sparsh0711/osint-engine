from __future__ import annotations

import json
import os
import re

import pytest

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine
from osint.store.neo4j_store import Neo4jEntityStore


CRTSH_URL = "https://crt.sh/?q=%25.example.com&output=json"
WAYBACK_URL = (
    "https://web.archive.org/cdx/search/cdx"
    "?url=example.com&matchType=domain&output=json&fl=original"
    "&collapse=urlkey&limit=10000"
)
CERTSPOTTER_PATTERN = re.compile(r"https://api\.certspotter\.com/v1/issuances.*")


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


async def test_memory_and_neo4j_store_parity(respx_mock, neo4j_store) -> None:
    _mock_sources(respx_mock)
    memory_store, _ = await Engine().run(_seed("example.com"), Authorization())

    _mock_sources(respx_mock)
    await Engine().run(_seed("example.com"), Authorization(), store=neo4j_store)

    assert _entity_view(memory_store.all_entities()) == _entity_view(
        neo4j_store.all_entities()
    )
    assert _relationship_view(memory_store.all_relationships()) == _relationship_view(
        neo4j_store.all_relationships()
    )

    entities = {entity.value: entity for entity in neo4j_store.all_entities()}
    assert entities["shared.example.com"].confidence == pytest.approx(0.88)
    assert entities["only-crt.example.com"].confidence == pytest.approx(0.70)
    assert entities["only-wb.example.com"].confidence == pytest.approx(0.60)


def _mock_sources(respx_mock) -> None:
    respx_mock.get(CRTSH_URL).mock(
        return_value=__import__("httpx").Response(
            200,
            json=[
                {
                    "id": 1,
                    "serial_number": "abc",
                    "issuer_name": "Test CA",
                    "common_name": "shared.example.com",
                    "not_before": "2026-01-01T00:00:00",
                    "not_after": "2026-04-01T00:00:00",
                    "name_value": "shared.example.com\nonly-crt.example.com",
                }
            ],
        )
    )
    respx_mock.get(WAYBACK_URL).mock(
        return_value=__import__("httpx").Response(
            200,
            json=[
                ["original"],
                ["https://shared.example.com/"],
                ["https://only-wb.example.com/path"],
            ],
        )
    )
    respx_mock.get(CERTSPOTTER_PATTERN).mock(
        return_value=__import__("httpx").Response(200, json=[])
    )


def _entity_view(entities):
    return {
        entity.id: {
            "type": entity.type.value,
            "value": entity.value,
            "confidence": round(entity.confidence, 6),
            "attributes": entity.attributes,
            "tags": sorted(entity.tags),
            "sources": _sources_view(entity.sources),
        }
        for entity in entities
    }


def _relationship_view(relationships):
    return {
        relationship.id: {
            "type": relationship.type.value,
            "src_id": relationship.src_id,
            "dst_id": relationship.dst_id,
            "confidence": round(relationship.confidence, 6),
            "sources": _sources_view(relationship.sources),
        }
        for relationship in relationships
        if relationship.type == RelationType.HAS_SUBDOMAIN
    }


def _sources_view(sources):
    return sorted(
        [
            {
                "connector": source.connector,
                "source": source.source,
                "query": source.query,
                "raw_ref": source.raw_ref,
            }
            for source in sources
        ],
        key=lambda item: json.dumps(item, sort_keys=True),
    )


def _seed(domain: str) -> Entity:
    return Entity(
        type=EntityType.Domain,
        value=domain,
        attributes={},
        sources=[
            Provenance(
                connector="test",
                source="test",
                query=domain,
                raw_ref={"seed": domain},
            )
        ],
        confidence=1.0,
    )
