from __future__ import annotations

from osint.connectors.asn import AsnConnector
from osint.connectors.base import CollectionMode, Connector
from osint.connectors.context import CollectionContext
from osint.connectors.internetdb import InternetDbConnector
from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine


async def test_unauthorized_ip_runs_identification_but_not_exposure(
    respx_mock,
    monkeypatch,
) -> None:
    internetdb_route = respx_mock.get("https://internetdb.shodan.io/203.0.113.10").respond(
        200,
        json={"ip": "203.0.113.10", "ports": [443]},
    )
    monkeypatch.setattr("osint.connectors.asn.resolve_txt", _team_cymru_resolver)

    store, audit_log = await Engine(
        connectors=[
            DomainToIpConnector(["203.0.113.10"]),
            AsnConnector(),
            InternetDbConnector(),
        ],
    ).run(_domain_seed(), Authorization(), max_depth=2)

    entities = {entity.value: entity for entity in store.all_entities()}
    relationships = store.all_relationships()

    assert "203.0.113.10" in entities
    assert "AS64500" in entities
    assert "203.0.113.0/24" in entities
    assert "203.0.113.10:443" not in entities
    assert any(relationship.type == RelationType.ANNOUNCES for relationship in relationships)
    assert any(relationship.type == RelationType.CONTAINS for relationship in relationships)
    assert not any(relationship.type == RelationType.HOSTS for relationship in relationships)
    assert internetdb_route.call_count == 0
    assert any(
        item.get("event") == "exposure_connector_refused"
        and item.get("connector") == "internetdb"
        for item in audit_log
    )


async def test_authorized_ip_runs_identification_and_exposure(
    respx_mock,
    monkeypatch,
) -> None:
    internetdb_route = respx_mock.get("https://internetdb.shodan.io/203.0.113.10").respond(
        200,
        json={"ip": "203.0.113.10", "ports": [443]},
    )
    monkeypatch.setattr("osint.connectors.asn.resolve_txt", _team_cymru_resolver)

    store, _audit_log = await Engine(
        connectors=[
            DomainToIpConnector(["203.0.113.10"]),
            AsnConnector(),
            InternetDbConnector(),
        ],
    ).run(
        _domain_seed(),
        Authorization(in_scope_targets=["203.0.113.10"]),
        max_depth=2,
    )

    entities = {entity.value: entity for entity in store.all_entities()}
    relationships = store.all_relationships()

    assert "AS64500" in entities
    assert "203.0.113.0/24" in entities
    assert "203.0.113.10:443" in entities
    assert any(relationship.type == RelationType.ANNOUNCES for relationship in relationships)
    assert any(relationship.type == RelationType.CONTAINS for relationship in relationships)
    assert any(relationship.type == RelationType.HOSTS for relationship in relationships)
    assert internetdb_route.call_count == 1


async def test_ip_connector_without_class_defaults_to_exposure_gated(
    monkeypatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr("osint.connectors.asn.resolve_txt", _team_cymru_resolver)

    store, audit_log = await Engine(
        connectors=[
            DomainToIpConnector(["203.0.113.10"]),
            AsnConnector(),
            DefaultIpConnector(calls),
        ],
    ).run(_domain_seed(), Authorization(), max_depth=2)

    entities = {entity.value: entity for entity in store.all_entities()}
    assert "AS64500" in entities
    assert calls == []
    assert any(
        item.get("event") == "exposure_connector_refused"
        and item.get("connector") == "default-ip"
        for item in audit_log
    )


async def test_identification_enrichment_still_respects_call_budget(
    monkeypatch,
) -> None:
    monkeypatch.setattr("osint.connectors.asn.resolve_txt", _team_cymru_resolver)

    store, audit_log = await Engine(
        connectors=[
            DomainToIpConnector(
                [
                    "203.0.113.10",
                    "203.0.113.11",
                    "203.0.113.12",
                    "203.0.113.13",
                ]
            ),
            AsnConnector(),
        ],
    ).run(_domain_seed(), Authorization(), max_depth=2, max_calls=3)

    asns = [entity for entity in store.all_entities() if entity.type == EntityType.ASN]
    assert len(asns) <= 2
    assert any(item.get("event") == "budget_stop" for item in audit_log)


class DomainToIpConnector(Connector):
    name = "domain-to-ip"
    source = "test"
    description = "Test domain-to-IP connector"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.Domain}
    produces = {EntityType.IPAddress}
    requires_api_key = False
    base_confidence = 0.9

    def __init__(self, addresses: list[str]) -> None:
        self.addresses = addresses

    async def collect(self, seed: Entity, ctx: CollectionContext):
        provenance = Provenance(
            connector=self.name,
            source=self.source,
            query=seed.value,
            raw_ref={"addresses": self.addresses},
        )
        yield Finding(
            entities=[
                Entity(
                    type=EntityType.IPAddress,
                    value=address,
                    attributes={"version": 4, "is_private": False},
                    sources=[provenance],
                    confidence=self.base_confidence,
                )
                for address in self.addresses
            ],
            relationships=[],
        )


class DefaultIpConnector(Connector):
    name = "default-ip"
    source = "test"
    description = "IP connector relying on default enrichment class"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.IPAddress}
    produces = {EntityType.Service}
    requires_api_key = False
    base_confidence = 0.6

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    async def collect(self, seed: Entity, ctx: CollectionContext):
        self.calls.append(seed.value)
        if False:
            yield


def _team_cymru_resolver(name: str) -> list[str]:
    if name.endswith(".origin.asn.cymru.com"):
        return ["64500 | 203.0.113.0/24 | US | arin | 2026-01-01"]
    if name == "AS64500.asn.cymru.com":
        return ["64500 | US | arin | 2026-01-01 | Example Owned Network"]
    return []


def _domain_seed() -> Entity:
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
