from __future__ import annotations

import re

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
CERTSPOTTER_PATTERN = re.compile(r"https://api\.certspotter\.com/v1/issuances.*")
AUTHORIZED_URL = "https://internetdb.shodan.io/8.8.8.8"
UNAUTHORIZED_URL = "https://internetdb.shodan.io/1.1.1.1"


async def test_internetdb_enriches_authorized_ip_only(
    respx_mock, monkeypatch
) -> None:
    _mock_domain_sources(respx_mock)
    authorized_route = respx_mock.get(AUTHORIZED_URL).respond(
        200,
        json={
            "ip": "8.8.8.8",
            "ports": [53, 443],
            "cpes": [],
            "hostnames": ["dns.google"],
            "tags": [],
            "vulns": [],
        },
    )
    unauthorized_route = respx_mock.get(UNAUTHORIZED_URL).respond(
        200,
        json={"ip": "1.1.1.1", "ports": [443]},
    )

    monkeypatch.setattr(
        "osint.connectors.dns.resolve_host",
        lambda name: ["8.8.8.8", "1.1.1.1"] if name == "example.com" else [],
    )

    store, audit_log = await Engine().run(
        _seed("example.com"),
        Authorization(in_scope_targets=["8.8.8.8"]),
        max_depth=2,
    )

    entities = {entity.value: entity for entity in store.all_entities()}
    relationships = store.all_relationships()

    assert "8.8.8.8" in entities
    assert "1.1.1.1" in entities
    assert "8.8.8.8:53" in entities
    assert "8.8.8.8:443" in entities
    assert "1.1.1.1:443" not in entities
    assert any(
        relationship.type == RelationType.HOSTS
        and relationship.src_id == entities["8.8.8.8"].id
        for relationship in relationships
    )
    assert not any(
        relationship.type == RelationType.HOSTS
        and relationship.src_id == entities["1.1.1.1"].id
        for relationship in relationships
    )
    assert authorized_route.call_count == 1
    assert unauthorized_route.call_count == 0
    assert any(
        item.get("connector") == "internetdb" and "8.8.8.8" in item.get("query", "")
        for item in audit_log
    )
    assert not any(
        item.get("connector") == "internetdb" and "1.1.1.1" in item.get("query", "")
        for item in audit_log
    )


async def test_ip_corroboration_from_dns_and_internetdb(
    respx_mock, monkeypatch
) -> None:
    _mock_domain_sources(respx_mock)
    respx_mock.get(AUTHORIZED_URL).respond(
        200,
        json={
            "ip": "8.8.8.8",
            "ports": [53],
            "cpes": ["cpe:/a:google:dns"],
            "hostnames": ["dns.google"],
            "tags": [],
            "vulns": [],
        },
    )
    monkeypatch.setattr(
        "osint.connectors.dns.resolve_host",
        lambda name: ["8.8.8.8"] if name == "example.com" else [],
    )

    store, _ = await Engine().run(
        _seed("example.com"),
        Authorization(in_scope_targets=["8.8.8.8"]),
        max_depth=2,
    )

    ip = {entity.value: entity for entity in store.all_entities()}["8.8.8.8"]
    sources = {source.source for source in ip.sources}
    assert sources == {"dns", "shodan-internetdb"}
    assert ip.confidence == 0.98
    assert ip.attributes["cpes"] == ["cpe:/a:google:dns"]


def _mock_domain_sources(respx_mock) -> None:
    respx_mock.get(CRTSH_URL).respond(200, json=[])
    respx_mock.get(WAYBACK_URL).respond(200, json=[["original"]])
    respx_mock.get(CERTSPOTTER_PATTERN).respond(200, json=[])


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
