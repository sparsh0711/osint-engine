from __future__ import annotations

from osint.connectors.asn import AsnConnector
from osint.core.entities import EntityType
from osint.core.relationships import RelationType
from osint.store.memory import MemoryEntityStore

from tests.test_asn import _ctx, _seed


async def test_same_prefix_shares_netblock_and_distinct_orgs_stay_separate(
    monkeypatch,
) -> None:
    def fake_resolve(name: str) -> list[str]:
        return {
            "10.2.0.192.origin.asn.cymru.com": [
                "64500 | 192.0.2.0/24 | US | arin | 2026-01-01"
            ],
            "11.2.0.192.origin.asn.cymru.com": [
                "64500 | 192.0.2.0/24 | US | arin | 2026-01-01"
            ],
            "20.100.51.198.origin.asn.cymru.com": [
                "64501 | 198.51.100.0/24 | GB | ripe | 2026-01-01"
            ],
            "AS64500.asn.cymru.com": [
                "64500 | US | arin | 2026-01-01 | Example Owned Network"
            ],
            "AS64501.asn.cymru.com": [
                "64501 | GB | ripe | 2026-01-01 | Example Shared CDN"
            ],
        }[name]

    monkeypatch.setattr("osint.connectors.asn.resolve_txt", fake_resolve)
    store = MemoryEntityStore()

    for ip in ("192.0.2.10", "192.0.2.11", "198.51.100.20"):
        async for finding in AsnConnector().collect(_seed(ip), _ctx()):
            for entity in finding.entities:
                store.upsert_entity(entity)
            for relationship in finding.relationships:
                store.upsert_relationship(relationship)

    asns = {
        entity.value: entity
        for entity in store.all_entities()
        if entity.type == EntityType.ASN
    }
    netblocks = {
        entity.value: entity
        for entity in store.all_entities()
        if entity.type == EntityType.Netblock
    }

    assert set(asns) == {"AS64500", "AS64501"}
    assert asns["AS64500"].attributes["org"] == "Example Owned Network"
    assert asns["AS64501"].attributes["org"] == "Example Shared CDN"
    assert set(netblocks) == {"192.0.2.0/24", "198.51.100.0/24"}

    contains_edges = [
        relationship
        for relationship in store.all_relationships()
        if relationship.type == RelationType.CONTAINS
    ]
    assert len(contains_edges) == 3
    assert (
        len(
            [
                relationship
                for relationship in contains_edges
                if relationship.src_id == netblocks["192.0.2.0/24"].id
            ]
        )
        == 2
    )
