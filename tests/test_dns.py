from __future__ import annotations

from osint.connectors.context import CollectionContext
from osint.connectors.dns import DnsConnector
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.util.http import create_http_client
from osint.util.logging import get_logger
from osint.util.ratelimit import AsyncTokenBucketLimiter


async def test_dns_yields_ip_entities_and_resolves_to_edges(monkeypatch) -> None:
    monkeypatch.setattr(
        "osint.connectors.dns.resolve_host",
        lambda name: ["93.184.216.34", "2001:db8::1"],
    )
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [finding async for finding in DnsConnector().collect(_seed(), ctx)]
    await http.aclose()

    entities = {entity.value: entity for finding in findings for entity in finding.entities}
    relationships = [
        relationship for finding in findings for relationship in finding.relationships
    ]

    assert entities["93.184.216.34"].type == EntityType.IPAddress
    assert entities["93.184.216.34"].attributes == {"version": 4, "is_private": False}
    assert entities["2001:db8::1"].attributes == {"version": 6, "is_private": True}
    assert all(entity.confidence == 0.9 for entity in entities.values())
    assert all(entity.sources and entity.sources[0].source == "dns" for entity in entities.values())
    assert {
        relationship.type for relationship in relationships
    } == {RelationType.RESOLVES_TO}
    assert all(relationship.sources for relationship in relationships)


async def test_dns_failure_or_empty_yields_nothing(monkeypatch) -> None:
    def raises(_name: str) -> list[str]:
        raise TimeoutError("dns timeout")

    monkeypatch.setattr("osint.connectors.dns.resolve_host", raises)
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [finding async for finding in DnsConnector().collect(_seed(), ctx)]
    await http.aclose()

    assert findings == []


def _seed() -> Entity:
    return Entity(
        type=EntityType.Domain,
        value="example.com",
        attributes={"under_seed": True},
        sources=[
            Provenance(
                connector="test",
                source="test",
                query="example.com",
                raw_ref={"seed": "example.com"},
            )
        ],
        confidence=1.0,
    )
