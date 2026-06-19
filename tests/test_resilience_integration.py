from __future__ import annotations

import re

import httpx

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine
from osint.util.http import create_http_client
from osint.util.ratelimit import AsyncTokenBucketLimiter


CRTSH_PATTERN = re.compile(r"https://crt\.sh/.*")
WAYBACK_PATTERN = re.compile(r"https://web\.archive\.org/cdx/search/cdx.*")
CERTSPOTTER_PATTERN = re.compile(r"https://api\.certspotter\.com/v1/issuances.*")


async def test_multihop_run_bounds_flaky_source_with_circuit_breaker(
    respx_mock, monkeypatch
) -> None:
    events: list[dict[str, object]] = []
    crtsh_route = respx_mock.get(CRTSH_PATTERN).respond(502)
    wayback_route = respx_mock.get(WAYBACK_PATTERN).mock(side_effect=_wayback_response)
    respx_mock.get(CERTSPOTTER_PATTERN).respond(200, json=[])
    resolved_names: list[str] = []

    def fake_resolve(name: str) -> list[str]:
        resolved_names.append(name)
        if name == "api.example.com":
            return ["10.0.0.10"]
        return []

    monkeypatch.setattr("osint.connectors.dns.resolve_host", fake_resolve)
    http_client = create_http_client(
        AsyncTokenBucketLimiter(default_rate=100, capacity=100),
        max_retries=1,
        cache_enabled=False,
        circuit_failure_threshold=2,
        on_circuit_event=events.append,
    )

    try:
        store, _ = await Engine(http_client=http_client).run(
            _seed("example.com"),
            Authorization(),
            max_depth=1,
            max_seeds=10,
            max_calls=30,
        )
    finally:
        await http_client.aclose()

    values = {entity.value for entity in store.all_entities()}
    assert "api.example.com" in values
    assert "10.0.0.10" in values
    assert "api.example.com" in resolved_names
    assert any(event["event"] == "circuit_opened" for event in events)
    assert crtsh_route.call_count <= 2
    assert wayback_route.call_count >= 2


def _wayback_response(request: httpx.Request) -> httpx.Response:
    domain = request.url.params.get("url")
    if domain == "example.com":
        return httpx.Response(
            200,
            json=[
                ["original"],
                ["https://api.example.com/"],
                ["https://www.example.com/"],
                ["https://mail.example.com/"],
            ],
        )
    return httpx.Response(200, json=[["original"]])


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
