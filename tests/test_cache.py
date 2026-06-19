from __future__ import annotations

import gzip
import hashlib
import json

import httpx

from osint.util.http import create_http_client
from osint.util.ratelimit import AsyncTokenBucketLimiter


URL = "https://cache.example.test/data"


async def test_identical_get_serves_second_response_from_cache(respx_mock, tmp_path) -> None:
    route = respx_mock.get(URL).respond(200, json={"value": 1})
    client = _client(tmp_path)

    try:
        first = await client.get(URL)
        second = await client.get(URL)
    finally:
        await client.aclose()

    assert first.json() == {"value": 1}
    assert second.json() == {"value": 1}
    assert route.call_count == 1


async def test_5xx_is_not_cached(respx_mock, tmp_path) -> None:
    route = respx_mock.get(URL).mock(
        side_effect=[
            httpx.Response(500),
            httpx.Response(200, text="fresh"),
        ]
    )
    client = _client(tmp_path)

    try:
        first = await client.get(URL)
        second = await client.get(URL)
    finally:
        await client.aclose()

    assert first.status_code == 500
    assert second.text == "fresh"
    assert route.call_count == 2


async def test_ttl_expiry_refetches(respx_mock, tmp_path) -> None:
    now = [1000.0]
    route = respx_mock.get(URL).mock(
        side_effect=[
            httpx.Response(200, text="old"),
            httpx.Response(200, text="new"),
        ]
    )
    client = _client(tmp_path, ttl=10, clock=lambda: now[0])

    try:
        first = await client.get(URL)
        now[0] += 11
        second = await client.get(URL)
    finally:
        await client.aclose()

    assert first.text == "old"
    assert second.text == "new"
    assert route.call_count == 2


async def test_404_is_cached(respx_mock, tmp_path) -> None:
    route = respx_mock.get(URL).respond(404)
    client = _client(tmp_path)

    try:
        first = await client.get(URL)
        second = await client.get(URL)
    finally:
        await client.aclose()

    assert first.status_code == 404
    assert second.status_code == 404
    assert route.call_count == 1


async def test_gzip_response_round_trips_from_cache(respx_mock, tmp_path) -> None:
    compressed = gzip.compress(b'{"value": 1}')
    route = respx_mock.get(URL).respond(
        200,
        headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
        content=compressed,
    )
    client = _client(tmp_path)

    try:
        first = await client.get(URL)
        second = await client.get(URL)
    finally:
        await client.aclose()

    assert first.json() == {"value": 1}
    assert second.json() == {"value": 1}
    assert route.call_count == 1


async def test_corrupt_cache_entry_is_treated_as_miss(respx_mock, tmp_path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_path = cache_dir / f"{hashlib.sha256(URL.encode('utf-8')).hexdigest()}.json"
    cache_path.write_text(
        json.dumps(
            {
                "url": URL,
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "not-valid-base64!",
                "fetched_at": 1000.0,
            }
        ),
        encoding="utf-8",
    )
    route = respx_mock.get(URL).respond(200, json={"fresh": True})
    client = _client(tmp_path, clock=lambda: 1001.0)

    try:
        response = await client.get(URL)
    finally:
        await client.aclose()

    assert response.json() == {"fresh": True}
    assert route.call_count == 1


def _client(tmp_path, ttl: float = 3600, clock=None):
    return create_http_client(
        AsyncTokenBucketLimiter(default_rate=100, capacity=100),
        max_retries=1,
        cache_enabled=True,
        cache_dir=tmp_path / "cache",
        cache_ttl_seconds=ttl,
        circuit_failure_threshold=0,
        clock=clock,
    )
