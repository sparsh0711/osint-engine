from __future__ import annotations

from osint.connectors.base import CollectionMode, Connector
from osint.connectors.context import CollectionContext
from osint.connectors.cvedb import CveDbConnector
from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding
from osint.core.provenance import Provenance
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine


URL = "https://cvedb.shodan.io/cve/CVE-2021-44228"


async def test_cvedb_identification_runs_for_discovered_vulnerability_without_authorization(
    respx_mock,
) -> None:
    calls: list[str] = []
    route = respx_mock.get(URL).respond(
        200,
        json={
            "cve_id": "CVE-2021-44228",
            "summary": "Apache Log4j remote code execution.",
            "cvss": 10.0,
            "kev": True,
            "epss": 0.975,
            "references": [],
        },
    )

    store, audit_log = await Engine(
        connectors=[
            DomainToVulnerabilityConnector(),
            CveDbConnector(),
            DefaultVulnerabilityConnector(calls),
        ],
    ).run(_domain_seed(), Authorization(), max_depth=1)

    vulnerability = {
        entity.value: entity
        for entity in store.all_entities()
        if entity.type == EntityType.Vulnerability
    }["CVE-2021-44228"]

    assert route.call_count == 1
    assert vulnerability.attributes["cvss"] == 10.0
    assert vulnerability.attributes["kev"] is True
    assert {source.source for source in vulnerability.sources} == {
        "test",
        "shodan-cvedb",
    }
    assert calls == []
    assert any(
        item.get("event") == "exposure_connector_refused"
        and item.get("connector") == "default-vulnerability"
        for item in audit_log
    )


class DomainToVulnerabilityConnector(Connector):
    name = "domain-to-vulnerability"
    source = "test"
    description = "Test discovery of a CVE from a domain"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.Domain}
    produces = {EntityType.Vulnerability}
    requires_api_key = False
    base_confidence = 0.6

    async def collect(self, seed: Entity, ctx: CollectionContext):
        provenance = Provenance(
            connector=self.name,
            source=self.source,
            query=seed.value,
            raw_ref={"cve_id": "CVE-2021-44228"},
        )
        yield Finding(
            entities=[
                Entity(
                    type=EntityType.Vulnerability,
                    value="CVE-2021-44228",
                    attributes={"cve_id": "CVE-2021-44228"},
                    sources=[provenance],
                    confidence=self.base_confidence,
                )
            ],
            relationships=[],
        )


class DefaultVulnerabilityConnector(Connector):
    name = "default-vulnerability"
    source = "test"
    description = "Vulnerability connector relying on default exposure class"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.Vulnerability}
    produces = {EntityType.Vulnerability}
    requires_api_key = False
    base_confidence = 0.6

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    async def collect(self, seed: Entity, ctx: CollectionContext):
        self.calls.append(seed.value)
        if False:
            yield


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
