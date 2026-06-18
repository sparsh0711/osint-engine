from __future__ import annotations

import httpx

from osint.util.http import create_http_client
from osint.util.ratelimit import AsyncTokenBucketLimiter


URL = "https://retry.example.test/data"


async def test_retry_502_twice_then_200(respx_mock) -> None:
    sleeps: list[float] = []
    route = respx_mock.get(URL).mock(
        side_effect=[
            httpx.Response(502),
            httpx.Response(502),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    client = create_http_client(
        AsyncTokenBucketLimiter(default_rate=100, capacity=100),
        max_retries=3,
        cache_enabled=False,
        circuit_failure_threshold=0,
        sleep=_record_sleep(sleeps),
        rng=lambda: 0.0,
    )

    try:
        response = await client.get(URL)
    finally:
        await client.aclose()

    assert response.status_code == 200
    assert route.call_count == 3
    assert len(sleeps) == 2


async def test_404_is_not_retried(respx_mock) -> None:
    route = respx_mock.get(URL).respond(404)
    client = create_http_client(
        AsyncTokenBucketLimiter(default_rate=100, capacity=100),
        max_retries=3,
        cache_enabled=False,
        circuit_failure_threshold=0,
        sleep=_record_sleep([]),
    )

    try:
        response = await client.get(URL)
    finally:
        await client.aclose()

    assert response.status_code == 404
    assert route.call_count == 1


async def test_timeout_then_success_is_retried(respx_mock) -> None:
    route = respx_mock.get(URL).mock(
        side_effect=[
            httpx.ReadTimeout("timeout"),
            httpx.Response(200, text="ok"),
        ]
    )
    client = create_http_client(
        AsyncTokenBucketLimiter(default_rate=100, capacity=100),
        max_retries=2,
        cache_enabled=False,
        circuit_failure_threshold=0,
        sleep=_record_sleep([]),
        rng=lambda: 0.0,
    )

    try:
        response = await client.get(URL)
    finally:
        await client.aclose()

    assert response.status_code == 200
    assert route.call_count == 2


def _record_sleep(delays: list[float]):
    async def sleep(delay: float) -> None:
        delays.append(delay)

    return sleep
