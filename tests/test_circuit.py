from __future__ import annotations

import httpx
import pytest

from osint.util.circuit import CircuitOpenError
from osint.util.http import create_http_client
from osint.util.ratelimit import AsyncTokenBucketLimiter


URL = "https://breaker.example.test/data"


async def test_repeated_502_opens_breaker_and_fails_fast(respx_mock) -> None:
    events: list[dict[str, object]] = []
    route = respx_mock.get(URL).respond(502)
    client = _client(events=events)

    try:
        assert (await client.get(URL)).status_code == 502
        assert (await client.get(URL)).status_code == 502
        with pytest.raises(CircuitOpenError):
            await client.get(URL)
    finally:
        await client.aclose()

    assert route.call_count == 2
    assert any(event["event"] == "circuit_opened" for event in events)


async def test_half_open_success_closes_breaker(respx_mock) -> None:
    now = [0.0]
    events: list[dict[str, object]] = []
    route = respx_mock.get(URL).mock(
        side_effect=[
            httpx.Response(502),
            httpx.Response(502),
            httpx.Response(200, text="ok"),
        ]
    )
    client = _client(events=events, clock=lambda: now[0])

    try:
        assert (await client.get(URL)).status_code == 502
        assert (await client.get(URL)).status_code == 502
        now[0] = 61.0
        assert (await client.get(URL)).status_code == 200
    finally:
        await client.aclose()

    assert route.call_count == 3
    assert [event["event"] for event in events] == [
        "circuit_opened",
        "circuit_closed",
    ]


def _client(events, clock=None):
    return create_http_client(
        AsyncTokenBucketLimiter(default_rate=100, capacity=100),
        max_retries=1,
        cache_enabled=False,
        circuit_failure_threshold=2,
        circuit_cooldown_seconds=60,
        clock=clock,
        on_circuit_event=events.append,
    )
