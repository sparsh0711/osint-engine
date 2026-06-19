from __future__ import annotations

from osint.connectors.certspotter import CertSpotterConnector
from osint.connectors.context import CollectionContext
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.util.http import create_http_client
from osint.util.ratelimit import AsyncTokenBucketLimiter


BASE_URL = (
    "https://api.certspotter.com/v1/issuances"
    "?domain=example.com&include_subdomains=true&expand=dns_names"
)


async def test_certspotter_yields_domains_edges_wildcards_and_provenance(
    respx_mock,
) -> None:
    respx_mock.get(BASE_URL).respond(
        200,
        json=[
            {
                "id": "issuance-1",
                "dns_names": [
                    "example.com",
                    "*.dev.example.com",
                    "api.example.com",
                    "vendor.net",
                ],
            }
        ],
    )
    respx_mock.get(f"{BASE_URL}&after=issuance-1").respond(200, json=[])
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=RecordingLogger())

    findings = [
        finding
        async for finding in CertSpotterConnector().collect(_seed("example.com"), ctx)
    ]
    await http.aclose()

    entities = {entity.value: entity for finding in findings for entity in finding.entities}
    relationships = [
        relationship for finding in findings for relationship in finding.relationships
    ]

    assert set(entities) >= {
        "example.com",
        "dev.example.com",
        "api.example.com",
        "vendor.net",
    }
    assert entities["dev.example.com"].confidence == 0.7
    assert "wildcard" in entities["dev.example.com"].tags
    assert "co-san" in entities["vendor.net"].tags
    assert all(entity.sources for entity in entities.values())
    assert all(relationship.sources for relationship in relationships)
    assert any(
        relationship.type == RelationType.HAS_SUBDOMAIN
        and relationship.dst_id == entities["api.example.com"].id
        for relationship in relationships
    )
    assert not any(
        relationship.type == RelationType.HAS_SUBDOMAIN
        and relationship.dst_id == entities["vendor.net"].id
        for relationship in relationships
    )


async def test_certspotter_follows_pagination_until_empty(respx_mock) -> None:
    first = respx_mock.get(BASE_URL).respond(
        200,
        json=[{"id": "1", "dns_names": ["one.example.com"]}],
    )
    second = respx_mock.get(f"{BASE_URL}&after=1").respond(
        200,
        json=[{"id": "2", "dns_names": ["two.example.com"]}],
    )
    empty = respx_mock.get(f"{BASE_URL}&after=2").respond(200, json=[])
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=RecordingLogger())

    findings = [
        finding
        async for finding in CertSpotterConnector().collect(_seed("example.com"), ctx)
    ]
    await http.aclose()

    values = {entity.value for finding in findings for entity in finding.entities}
    assert {"one.example.com", "two.example.com"} <= values
    assert first.call_count == 1
    assert second.call_count == 1
    assert empty.call_count == 1


async def test_certspotter_page_cap_is_enforced(respx_mock) -> None:
    route = respx_mock.get(BASE_URL).respond(
        200,
        json=[{"id": "1", "dns_names": ["one.example.com"]}],
    )
    logger = RecordingLogger()
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=logger)

    findings = [
        finding
        async for finding in CertSpotterConnector(max_pages=1).collect(
            _seed("example.com"),
            ctx,
        )
    ]
    await http.aclose()

    assert findings
    assert route.call_count == 1
    assert ("info", "certspotter_page_cap_reached", {"domain": "example.com", "max_pages": 1}) in logger.events


async def test_certspotter_404_is_no_data_and_not_retried(respx_mock) -> None:
    route = respx_mock.get(BASE_URL).respond(404)
    logger = RecordingLogger()
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=logger)

    findings = [
        finding
        async for finding in CertSpotterConnector().collect(_seed("example.com"), ctx)
    ]
    await http.aclose()

    assert findings == []
    assert route.call_count == 1
    assert ("info", "certspotter_no_results", {"domain": "example.com"}) in logger.events
    assert not any(
        event == "certspotter_collection_failed" for _level, event, _kw in logger.events
    )


async def test_certspotter_empty_first_page_is_no_data(respx_mock) -> None:
    respx_mock.get(BASE_URL).respond(200, json=[])
    logger = RecordingLogger()
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    ctx = CollectionContext(http=http, logger=logger)

    findings = [
        finding
        async for finding in CertSpotterConnector().collect(_seed("example.com"), ctx)
    ]
    await http.aclose()

    assert findings == []
    assert ("info", "certspotter_no_results", {"domain": "example.com"}) in logger.events


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


class RecordingLogger:
    def __init__(self) -> None:
        self.events = []

    def info(self, event: str, **kwargs) -> None:
        self.events.append(("info", event, kwargs))

    def warning(self, event: str, **kwargs) -> None:
        self.events.append(("warning", event, kwargs))
