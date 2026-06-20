from __future__ import annotations

import dns.resolver
import pytest

from osint.connectors.asn import AsnConnector
from osint.connectors.context import CollectionContext
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType


async def test_asn_yields_asn_netblock_and_relationships(monkeypatch) -> None:
    queries: list[str] = []

    def fake_resolve(name: str) -> list[str]:
        queries.append(name)
        return {
            "31.108.90.216.origin.asn.cymru.com": [
                "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
            ],
            "AS23028.asn.cymru.com": [
                "23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru Inc., US"
            ],
        }[name]

    monkeypatch.setattr("osint.connectors.asn.resolve_txt", fake_resolve)

    findings = [
        finding
        async for finding in AsnConnector().collect(_seed("216.90.108.31"), _ctx())
    ]

    entities = {entity.value: entity for finding in findings for entity in finding.entities}
    relationships = [
        relationship for finding in findings for relationship in finding.relationships
    ]

    assert queries == [
        "31.108.90.216.origin.asn.cymru.com",
        "AS23028.asn.cymru.com",
    ]
    assert entities["AS23028"].type == EntityType.ASN
    assert entities["AS23028"].attributes == {
        "number": 23028,
        "name": "TEAM-CYMRU - Team Cymru Inc., US",
        "org": "TEAM-CYMRU - Team Cymru Inc., US",
        "country": "US",
        "registry": "arin",
    }
    assert entities["216.90.108.0/24"].type == EntityType.Netblock
    assert entities["216.90.108.0/24"].attributes == {
        "cidr": "216.90.108.0/24",
        "asn": "AS23028",
        "country": "US",
        "registry": "arin",
    }
    assert all(entity.confidence == pytest.approx(0.85) for entity in entities.values())
    assert all(entity.sources for entity in entities.values())
    assert {
        relationship.type for relationship in relationships
    } == {RelationType.CONTAINS, RelationType.ANNOUNCES}
    assert all(
        relationship.confidence == pytest.approx(0.85) for relationship in relationships
    )
    assert all(relationship.sources for relationship in relationships)


async def test_asn_ipv6_uses_origin6(monkeypatch) -> None:
    seen_queries: list[str] = []

    def fake_resolve(name: str) -> list[str]:
        seen_queries.append(name)
        if name.endswith(".origin6.asn.cymru.com"):
            return ["64496 | 2001:db8::/32 | ZZ | test | 2026-01-01"]
        return ["64496 | ZZ | test | 2026-01-01 | Example IPv6 ASN"]

    monkeypatch.setattr("osint.connectors.asn.resolve_txt", fake_resolve)

    findings = [
        finding
        async for finding in AsnConnector().collect(_seed("2001:db8::1"), _ctx())
    ]
    entities = {entity.value: entity for finding in findings for entity in finding.entities}

    assert seen_queries[0].endswith(".origin6.asn.cymru.com")
    assert seen_queries[0].startswith("1.0.0.0.0.0.0.0")
    assert entities["AS64496"].attributes["name"] == "Example IPv6 ASN"
    assert entities["2001:db8::/32"].attributes["cidr"] == "2001:db8::/32"


async def test_asn_nxdomain_yields_nothing(monkeypatch) -> None:
    def fake_resolve(_name: str) -> list[str]:
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr("osint.connectors.asn.resolve_txt", fake_resolve)

    findings = [
        finding
        async for finding in AsnConnector().collect(_seed("203.0.113.10"), _ctx())
    ]

    assert findings == []


async def test_asn_multihomed_ip_yields_each_origin(monkeypatch) -> None:
    def fake_resolve(name: str) -> list[str]:
        return {
            "10.113.0.203.origin.asn.cymru.com": [
                "64500 | 203.0.113.0/24 | US | arin | 2026-01-01",
                "64501 | 203.0.113.0/24 | US | arin | 2026-01-01",
            ],
            "AS64500.asn.cymru.com": ["64500 | US | arin | 2026-01-01 | Example A"],
            "AS64501.asn.cymru.com": ["64501 | US | arin | 2026-01-01 | Example B"],
        }[name]

    monkeypatch.setattr("osint.connectors.asn.resolve_txt", fake_resolve)

    findings = [
        finding
        async for finding in AsnConnector().collect(_seed("203.0.113.10"), _ctx())
    ]
    entities = {entity.value: entity for finding in findings for entity in finding.entities}
    relationships = [
        relationship for finding in findings for relationship in finding.relationships
    ]

    assert {"AS64500", "AS64501", "203.0.113.0/24"} <= set(entities)
    assert len([rel for rel in relationships if rel.type == RelationType.ANNOUNCES]) == 2


class DummyHttp:
    async def request(self, method: str, url: str, **kwargs):
        raise AssertionError("ASN connector must not use HTTP")

    async def get(self, url: str, **kwargs):
        raise AssertionError("ASN connector must not use HTTP")


def _ctx() -> CollectionContext:
    return CollectionContext(http=DummyHttp(), logger=RecordingLogger())


def _seed(value: str) -> Entity:
    return Entity(
        type=EntityType.IPAddress,
        value=value,
        attributes={},
        sources=[
            Provenance(
                connector="test",
                source="test",
                query=value,
                raw_ref={"seed": value},
            )
        ],
        confidence=1.0,
    )


class RecordingLogger:
    def __init__(self) -> None:
        self.events = []

    def info(self, event: str, **kwargs) -> None:
        self.events.append(("info", event, kwargs))

    def warning(self, event: str, **kwargs) -> None:
        self.events.append(("warning", event, kwargs))
