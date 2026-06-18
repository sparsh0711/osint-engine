from __future__ import annotations

from osint.connectors.context import CollectionContext
from osint.connectors.wayback import WaybackConnector
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.util.http import create_http_client
from osint.util.logging import get_logger
from osint.util.ratelimit import AsyncTokenBucketLimiter


WAYBACK_URL = (
    "https://web.archive.org/cdx/search/cdx"
    "?url=example.com&matchType=domain&output=json&fl=original"
    "&collapse=urlkey&limit=10000"
)


async def test_wayback_yields_domains_edges_and_drops_out_of_scope(respx_mock) -> None:
    respx_mock.get(WAYBACK_URL).respond(
        200,
        json=[
            ["original"],
            ["https://example.com/"],
            ["https://api.example.com:8443/path"],
            ["http://outside.example.org/"],
            ["garbage"],
        ],
    )
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding
        async for finding in WaybackConnector().collect(_seed("example.com"), ctx)
    ]
    await http.aclose()

    entities = {entity.value: entity for finding in findings for entity in finding.entities}
    relationships = [
        relationship for finding in findings for relationship in finding.relationships
    ]

    assert set(entities) == {"example.com", "api.example.com"}
    assert entities["api.example.com"].confidence == 0.6
    assert entities["api.example.com"].sources[0].source == "web.archive.org"
    assert "outside.example.org" not in entities
    assert any(
        relationship.type == RelationType.HAS_SUBDOMAIN
        and relationship.dst_id == entities["api.example.com"].id
        for relationship in relationships
    )
    assert all(entity.sources for entity in entities.values())
    assert all(relationship.sources for relationship in relationships)


async def test_wayback_failure_yields_nothing_and_does_not_raise(respx_mock) -> None:
    respx_mock.get(WAYBACK_URL).respond(500)
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding
        async for finding in WaybackConnector().collect(_seed("example.com"), ctx)
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
