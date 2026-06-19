from __future__ import annotations

import os
import re

import pytest

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
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


async def test_neo4j_full_runs_are_deterministic(respx_mock, neo4j_store) -> None:
    _mock_sources(respx_mock)
    await Engine().run(_seed("example.com"), Authorization(), store=neo4j_store)
    first_entity_ids = {entity.id for entity in neo4j_store.all_entities()}
    first_relationship_ids = {
        relationship.id for relationship in neo4j_store.all_relationships()
    }

    neo4j_store.clear()
    _mock_sources(respx_mock)
    await Engine().run(_seed("example.com"), Authorization(), store=neo4j_store)
    second_entity_ids = {entity.id for entity in neo4j_store.all_entities()}
    second_relationship_ids = {
        relationship.id for relationship in neo4j_store.all_relationships()
    }

    assert second_entity_ids == first_entity_ids
    assert second_relationship_ids == first_relationship_ids
    assert len(neo4j_store.all_entities()) == len(first_entity_ids)
    assert len(neo4j_store.all_relationships()) == len(first_relationship_ids)


def _mock_sources(respx_mock) -> None:
    import httpx

    respx_mock.get(CRTSH_URL).mock(
        return_value=httpx.Response(
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
        return_value=httpx.Response(
            200,
            json=[
                ["original"],
                ["https://shared.example.com/"],
                ["https://only-wb.example.com/path"],
            ],
        )
    )
    respx_mock.get(CERTSPOTTER_PATTERN).mock(return_value=httpx.Response(200, json=[]))


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
