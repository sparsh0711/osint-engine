from __future__ import annotations

import httpx

from osint.connectors.context import CollectionContext
from osint.connectors.internetdb import InternetDbConnector
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.util.http import create_http_client
from osint.util.logging import get_logger
from osint.util.ratelimit import AsyncTokenBucketLimiter


URL = "https://internetdb.shodan.io/8.8.8.8"


async def test_internetdb_yields_services_hosts_edges_and_ip_enrichment(respx_mock) -> None:
    respx_mock.get(URL).respond(
        200,
        json={
            "ip": "8.8.8.8",
            "ports": [443, 53],
            "cpes": ["cpe:/a:google:dns"],
            "hostnames": ["dns.google"],
            "tags": ["resolver"],
            "vulns": ["CVE-2017-15906"],
        },
    )
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding async for finding in InternetDbConnector().collect(_ip_seed("8.8.8.8"), ctx)
    ]
    await http.aclose()

    assert len(findings) == 1
    finding = findings[0]
    entities = {entity.value: entity for entity in finding.entities}
    relationships = finding.relationships

    ip_entity = entities["8.8.8.8"]
    assert ip_entity.type == EntityType.IPAddress
    assert ip_entity.attributes == {
        "version": 4,
        "is_private": False,
        "cpes": ["cpe:/a:google:dns"],
        "vulns": ["CVE-2017-15906"],
        "hostnames": ["dns.google"],
    }
    assert ip_entity.tags == {"resolver"}
    assert ip_entity.confidence == 0.8

    assert set(entities) == {
        "8.8.8.8",
        "8.8.8.8:53",
        "8.8.8.8:443",
        "CVE-2017-15906",
    }
    for value, port in {"8.8.8.8:53": 53, "8.8.8.8:443": 443}.items():
        service = entities[value]
        assert service.type == EntityType.Service
        assert service.attributes == {
            "ip": "8.8.8.8",
            "port": port,
            "protocol": None,
            "product": None,
            "banner": None,
        }
        assert service.sources[0].source == "shodan-internetdb"

    vulnerability = entities["CVE-2017-15906"]
    assert vulnerability.type == EntityType.Vulnerability
    assert vulnerability.attributes == {"cve_id": "CVE-2017-15906"}
    assert vulnerability.confidence == 0.8
    assert vulnerability.sources[0].source == "shodan-internetdb"

    assert {relationship.type for relationship in relationships} == {
        RelationType.HOSTS,
        RelationType.HAS_VULNERABILITY,
    }
    hosts = [relationship for relationship in relationships if relationship.type == RelationType.HOSTS]
    vuln_edges = [
        relationship
        for relationship in relationships
        if relationship.type == RelationType.HAS_VULNERABILITY
    ]
    assert {relationship.src_id for relationship in hosts} == {ip_entity.id}
    assert {relationship.dst_id for relationship in hosts} == {
        entities["8.8.8.8:53"].id,
        entities["8.8.8.8:443"].id,
    }
    assert len(vuln_edges) == 1
    assert vuln_edges[0].src_id == ip_entity.id
    assert vuln_edges[0].dst_id == vulnerability.id
    assert all(relationship.sources for relationship in relationships)
    assert all(entity.sources for entity in finding.entities)


async def test_internetdb_ipv6_yields_nothing() -> None:
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding async for finding in InternetDbConnector().collect(_ip_seed("2001:4860:4860::8888"), ctx)
    ]
    await http.aclose()

    assert findings == []


async def test_internetdb_404_yields_nothing(respx_mock) -> None:
    respx_mock.get(URL).respond(404)
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding async for finding in InternetDbConnector().collect(_ip_seed("8.8.8.8"), ctx)
    ]
    await http.aclose()

    assert findings == []


async def test_internetdb_network_error_yields_nothing(respx_mock) -> None:
    respx_mock.get(URL).mock(side_effect=httpx.ConnectError("network down"))
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding async for finding in InternetDbConnector().collect(_ip_seed("8.8.8.8"), ctx)
    ]
    await http.aclose()

    assert findings == []


def _ip_seed(ip: str) -> Entity:
    return Entity(
        type=EntityType.IPAddress,
        value=ip,
        attributes={},
        sources=[
            Provenance(
                connector="test",
                source="test",
                query=ip,
                raw_ref={"seed": ip},
            )
        ],
        confidence=1.0,
    )
