from __future__ import annotations

import pytest

from osint.connectors.base import REGISTRY
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine


CRTSH_URL = "https://crt.sh/?q=%25.example.com&output=json"
WAYBACK_URL = (
    "https://web.archive.org/cdx/search/cdx"
    "?url=example.com&matchType=domain&output=json&fl=original"
    "&collapse=urlkey&limit=10000"
)
CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances"
    "?domain=example.com&include_subdomains=true&expand=dns_names"
)


def test_builtin_connectors_load() -> None:
    import osint.connectors  # noqa: F401

    assert {
        "asn",
        "certspotter",
        "crtsh",
        "wayback",
        "dns",
        "internetdb",
        "usernames",
    } <= set(REGISTRY)


async def test_certspotter_prevents_subdomain_starvation_when_crtsh_empty(
    respx_mock,
) -> None:
    respx_mock.get(CRTSH_URL).respond(404)
    respx_mock.get(WAYBACK_URL).respond(200, json=[["original"]])
    respx_mock.get(CERTSPOTTER_URL).respond(
        200,
        json=[{"id": "1", "dns_names": ["api.example.com"]}],
    )
    respx_mock.get(f"{CERTSPOTTER_URL}&after=1").respond(200, json=[])

    store, _audit_log = await Engine().run(_seed("example.com"), Authorization())

    entities = {entity.value: entity for entity in store.all_entities()}
    relationships = store.all_relationships()
    assert "api.example.com" in entities
    assert any(
        relationship.type == RelationType.HAS_SUBDOMAIN
        and relationship.dst_id == entities["api.example.com"].id
        for relationship in relationships
    )
    assert {source.source for source in entities["api.example.com"].sources} == {
        "certspotter"
    }


async def test_overlapping_crtsh_and_certspotter_subdomain_corroborates(
    respx_mock,
) -> None:
    respx_mock.get(CRTSH_URL).respond(
        200,
        json=[
            {
                "id": 1,
                "serial_number": "abc",
                "issuer_name": "Test CA",
                "common_name": "shared.example.com",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
                "name_value": "shared.example.com",
            }
        ],
    )
    respx_mock.get(WAYBACK_URL).respond(200, json=[["original"]])
    respx_mock.get(CERTSPOTTER_URL).respond(
        200,
        json=[{"id": "1", "dns_names": ["shared.example.com"]}],
    )
    respx_mock.get(f"{CERTSPOTTER_URL}&after=1").respond(200, json=[])

    store, _audit_log = await Engine().run(_seed("example.com"), Authorization())

    entities = {entity.value: entity for entity in store.all_entities()}
    shared = entities["shared.example.com"]
    assert {source.source for source in shared.sources} == {"crt.sh", "certspotter"}
    assert shared.confidence > 0.7
    assert shared.confidence == pytest.approx(0.91)

    shared_edge = next(
        relationship
        for relationship in store.all_relationships()
        if relationship.type == RelationType.HAS_SUBDOMAIN
        and relationship.dst_id == shared.id
    )
    assert {source.source for source in shared_edge.sources} == {
        "crt.sh",
        "certspotter",
    }
    assert shared_edge.confidence == pytest.approx(0.91)


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
