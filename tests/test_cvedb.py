from __future__ import annotations

import pytest

from osint.connectors.context import CollectionContext
from osint.connectors.cvedb import CveDbConnector
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.store.memory import MemoryEntityStore
from osint.util.http import create_http_client
from osint.util.logging import get_logger
from osint.util.ratelimit import AsyncTokenBucketLimiter


URL = "https://cvedb.shodan.io/cve/CVE-2021-44228"


async def test_cvedb_enriches_vulnerability_with_cvss_kev_epss(respx_mock) -> None:
    respx_mock.get(URL).respond(200, json=_payload())
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding
        async for finding in CveDbConnector().collect(_vulnerability_seed("CVE-2021-44228"), ctx)
    ]
    await http.aclose()

    assert len(findings) == 1
    vulnerability = findings[0].entities[0]
    assert vulnerability.type == EntityType.Vulnerability
    assert vulnerability.value == "CVE-2021-44228"
    assert vulnerability.confidence == pytest.approx(0.9)
    assert vulnerability.sources[0].source == "shodan-cvedb"
    assert vulnerability.attributes == {
        "cve_id": "CVE-2021-44228",
        "summary": "Apache Log4j remote code execution.",
        "cvss": 10.0,
        "cvss_version": "3.1",
        "cvss_v2": 9.3,
        "cvss_v3": 10.0,
        "severity": "critical",
        "kev": True,
        "epss": 0.975,
        "ranking_epss": 0.999,
        "references": ["https://example.test/a", "https://example.test/b"],
        "published_time": "2021-12-10T00:00:00",
    }
    assert findings[0].relationships == []


async def test_cvedb_404_yields_nothing(respx_mock) -> None:
    respx_mock.get(URL).respond(404)
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))

    findings = [
        finding
        async for finding in CveDbConnector().collect(_vulnerability_seed("CVE-2021-44228"), ctx)
    ]
    await http.aclose()

    assert findings == []


async def test_cvedb_merges_with_bare_internetdb_vulnerability(respx_mock) -> None:
    respx_mock.get(URL).respond(200, json=_payload())
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=get_logger("test"))
    store = MemoryEntityStore()
    store.upsert_entity(_vulnerability_seed("cve-2021-44228"))

    async for finding in CveDbConnector().collect(_vulnerability_seed("CVE-2021-44228"), ctx):
        for entity in finding.entities:
            store.upsert_entity(entity)
    await http.aclose()

    vulnerabilities = [
        entity for entity in store.all_entities() if entity.type == EntityType.Vulnerability
    ]
    assert len(vulnerabilities) == 1
    merged = vulnerabilities[0]
    assert merged.value == "CVE-2021-44228"
    assert {source.source for source in merged.sources} == {"shodan-internetdb", "shodan-cvedb"}
    assert merged.confidence == pytest.approx(0.98)
    assert merged.attributes["cvss"] == 10.0
    assert merged.attributes["kev"] is True


def _payload() -> dict:
    return {
        "cve_id": "CVE-2021-44228",
        "summary": "Apache Log4j remote code execution.",
        "cvss": 10.0,
        "cvss_version": "3.1",
        "cvss_v2": 9.3,
        "cvss_v3": 10.0,
        "epss": 0.975,
        "ranking_epss": 0.999,
        "kev": True,
        "references": ["https://example.test/b", "https://example.test/a"],
        "published_time": "2021-12-10T00:00:00",
    }


def _vulnerability_seed(value: str) -> Entity:
    cve_id = value.upper()
    return Entity(
        type=EntityType.Vulnerability,
        value=value,
        attributes={"cve_id": cve_id},
        sources=[
            Provenance(
                connector="internetdb",
                source="shodan-internetdb",
                query=value,
                raw_ref={"cve_id": cve_id},
            )
        ],
        confidence=0.8,
    )
