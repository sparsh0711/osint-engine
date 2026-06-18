from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from osint.util.cache import DiskHttpCache
from osint.util.circuit import HostCircuitBreaker
from osint.util.ratelimit import AsyncTokenBucketLimiter
from osint.util.retry import RetryPolicy, is_retryable_status


@dataclass(slots=True)
class HostHttpConfig:
    timeout: float | None = None
    max_retries: int | None = None


DEFAULT_HOST_CONFIG: dict[str, HostHttpConfig] = {
    "web.archive.org": HostHttpConfig(timeout=20.0, max_retries=3),
}


class RateLimitedAsyncClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        limiter: AsyncTokenBucketLimiter,
        retry_policy: RetryPolicy | None = None,
        cache: DiskHttpCache | None = None,
        circuit_breaker: HostCircuitBreaker | None = None,
        host_config: dict[str, HostHttpConfig] | None = None,
    ) -> None:
        self._client = client
        self._limiter = limiter
        self._retry_policy = retry_policy or RetryPolicy()
        self._cache = cache
        self._circuit_breaker = circuit_breaker or HostCircuitBreaker()
        self._host_config = host_config or DEFAULT_HOST_CONFIG

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        method = method.upper()
        request_url = str(url)
        if method == "GET" and self._cache is not None:
            cached = self._cache.get(request_url)
            if cached is not None:
                return cached

        host = _source_key(request_url)
        config = self._host_config.get(host)
        self._circuit_breaker.before_request(host)

        request_kwargs = dict(kwargs)
        if config is not None and config.timeout is not None and "timeout" not in request_kwargs:
            request_kwargs["timeout"] = config.timeout

        policy = self._policy_for(config)
        try:
            response = await policy.run(
                lambda: self._send(method, request_url, host, **request_kwargs)
            )
        except httpx.HTTPError:
            self._circuit_breaker.record_failure(host)
            raise

        if is_retryable_status(response.status_code):
            self._circuit_breaker.record_failure(host)
        else:
            self._circuit_breaker.record_success(host)

        if method == "GET" and self._cache is not None:
            self._cache.set(request_url, response)
        return response

    async def _send(
        self,
        method: str,
        url: str,
        host: str,
        **kwargs: Any,
    ) -> httpx.Response:
        await self._limiter.acquire(host)
        return await self._client.request(method, url, **kwargs)

    def _policy_for(self, config: HostHttpConfig | None) -> RetryPolicy:
        if config is None or config.max_retries is None:
            return self._retry_policy
        return self._retry_policy.with_max_attempts(max(1, config.max_retries))

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
    retries: int | None = None,
    backoff: float = 0.25,
    *,
    max_retries: int | None = None,
    cache_enabled: bool | None = None,
    cache_dir: str | Path | None = None,
    cache_ttl_seconds: float = 24 * 60 * 60,
    circuit_failure_threshold: int | None = None,
    circuit_cooldown_seconds: float = 60.0,
    host_config: dict[str, HostHttpConfig] | None = None,
    sleep: Callable[[float], Any] | None = None,
    rng: Callable[[], float] | None = None,
    clock: Callable[[], float] | None = None,
    on_circuit_event: Callable[[dict[str, Any]], None] | None = None,
) -> RateLimitedAsyncClient:
    limiter = limiter or AsyncTokenBucketLimiter(default_rate=1.0, capacity=1)
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": user_agent},
        follow_redirects=True,
    )

    attempts = _configured_attempts(max_retries, retries)
    retry_policy = RetryPolicy(
        max_attempts=attempts,
        base_delay=backoff,
        sleep=sleep,  # type: ignore[arg-type]
        rng=rng,
    )
    cache = _build_cache(cache_enabled, cache_dir, cache_ttl_seconds, clock)
    breaker = HostCircuitBreaker(
        failure_threshold=_configured_threshold(circuit_failure_threshold),
        cooldown_seconds=circuit_cooldown_seconds,
        clock=clock,
        on_event=on_circuit_event,
    )
    return RateLimitedAsyncClient(
        client,
        limiter,
        retry_policy=retry_policy,
        cache=cache,
        circuit_breaker=breaker,
        host_config=host_config,
    )


def _source_key(url: str) -> str:
    return httpx.URL(url).host or url


def _configured_attempts(max_retries: int | None, retries: int | None) -> int:
    if max_retries is not None:
        return max(1, max_retries)
    if retries is not None:
        return max(1, retries + 1)
    value = os.environ.get("OSINT_HTTP_MAX_ATTEMPTS")
    if value:
        return max(1, int(value))
    return 3


def _configured_threshold(circuit_failure_threshold: int | None) -> int:
    if circuit_failure_threshold is not None:
        return circuit_failure_threshold
    value = os.environ.get("OSINT_CIRCUIT_FAILURE_THRESHOLD")
    if value:
        return int(value)
    return 3


def _build_cache(
    cache_enabled: bool | None,
    cache_dir: str | Path | None,
    cache_ttl_seconds: float,
    clock: Callable[[], float] | None,
) -> DiskHttpCache | None:
    if cache_enabled is None:
        cache_enabled = os.environ.get("OSINT_NO_CACHE") not in {"1", "true", "TRUE"}
    if not cache_enabled:
        return None

    configured_dir = cache_dir or os.environ.get("OSINT_CACHE_DIR") or ".cache/osint"
    return DiskHttpCache(configured_dir, ttl_seconds=cache_ttl_seconds, clock=clock)
