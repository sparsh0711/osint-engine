from __future__ import annotations

from osint.connectors.context import CollectionContext
from osint.connectors.crtsh import CrtShConnector
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.util.http import create_http_client
from osint.util.logging import get_logger
from osint.util.ratelimit import AsyncTokenBucketLimiter


async def test_crtsh_yields_certificate_domains_edges_and_provenance(respx_mock) -> None:
    respx_mock.get("https://crt.sh/?q=%25.example.com&output=json").respond(
        200,
        json=[
            {
                "id": 123,
                "serial_number": "abc",
                "issuer_name": "Test CA",
                "common_name": "www.example.com",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
                "name_value": "*.dev.example.com\nwww.example.com\nexample.com",
            }
        ],
    )
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding
        async for finding in CrtShConnector().collect(_seed("example.com"), ctx)
    ]
    await http.aclose()

    entities = {entity.value: entity for finding in findings for entity in finding.entities}
    relationships = [
        relationship for finding in findings for relationship in finding.relationships
    ]

    assert any(entity.type == EntityType.Certificate for entity in entities.values())
    assert "dev.example.com" in entities
    assert "www.example.com" in entities
    assert "wildcard" in entities["dev.example.com"].tags
    assert entities["dev.example.com"].sources
    assert all(entity.sources for entity in entities.values())
    assert all(relationship.sources for relationship in relationships)
    assert {relationship.type for relationship in relationships} >= {
        RelationType.SECURES,
        RelationType.HAS_SUBDOMAIN,
    }


async def test_crtsh_failure_yields_nothing_and_does_not_raise(respx_mock) -> None:
    respx_mock.get("https://crt.sh/?q=%25.example.com&output=json").respond(500)
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding
        async for finding in CrtShConnector().collect(_seed("example.com"), ctx)
    ]
    await http.aclose()

    assert findings == []


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
