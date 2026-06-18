from __future__ import annotations

import asyncio
from typing import Any

import httpx

from osint.util.ratelimit import AsyncTokenBucketLimiter


class RateLimitedAsyncClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        limiter: AsyncTokenBucketLimiter,
        retries: int = 2,
        backoff: float = 0.05,
    ) -> None:
        self._client = client
        self._limiter = limiter
        self._retries = retries
        self._backoff = backoff

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        source_key = _source_key(url)
        response: httpx.Response | None = None
        for attempt in range(self._retries + 1):
            await self._limiter.acquire(source_key)
            try:
                response = await self._client.request(method, url, **kwargs)
            except (httpx.TimeoutException, httpx.TransportError):
                if attempt == self._retries:
                    raise
            else:
                if response.status_code not in {429} and response.status_code < 500:
                    return response
                if attempt == self._retries:
                    return response
            await asyncio.sleep(self._backoff * (2**attempt))

        if response is None:
            raise RuntimeError("HTTP request failed without a response")
        return response

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "RateLimitedAsyncClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()


def create_http_client(
    limiter: AsyncTokenBucketLimiter | None = None,
    timeout: float = 10.0,
    user_agent: str = "osint-engine/0.1 (+https://example.invalid/osint-engine)",
) -> RateLimitedAsyncClient:
    limiter = limiter or AsyncTokenBucketLimiter(default_rate=1.0, capacity=1)
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": user_agent},
        follow_redirects=True,
    )
    return RateLimitedAsyncClient(client, limiter)


def _source_key(url: str) -> str:
    return httpx.URL(url).host or url
