from __future__ import annotations

import asyncio
import email.utils
import random
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

import httpx

RETRYABLE_STATUSES = {429, 500, 502, 503, 504}

AsyncSleep = Callable[[float], Awaitable[None]]
RandomFloat = Callable[[], float]


class RetryPolicy:
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 0.25,
        max_delay: float = 5.0,
        jitter: float = 0.2,
        sleep: AsyncSleep | None = None,
        rng: RandomFloat | None = None,
    ) -> None:
        self.max_attempts = max(1, max_attempts)
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.sleep = sleep or asyncio.sleep
        self.rng = rng or random.random

    def with_max_attempts(self, max_attempts: int) -> "RetryPolicy":
        return RetryPolicy(
            max_attempts=max_attempts,
            base_delay=self.base_delay,
            max_delay=self.max_delay,
            jitter=self.jitter,
            sleep=self.sleep,
            rng=self.rng,
        )

    async def run(
        self,
        send: Callable[[], Awaitable[httpx.Response]],
    ) -> httpx.Response:
        last_exc: httpx.HTTPError | None = None
        response: httpx.Response | None = None

        for attempt_index in range(self.max_attempts):
            try:
                response = await send()
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt_index == self.max_attempts - 1:
                    raise
                await self.sleep(self._delay(attempt_index))
                continue

            if not is_retryable_status(response.status_code):
                return response
            if attempt_index == self.max_attempts - 1:
                return response

            await self.sleep(self._delay(attempt_index, response))

        if last_exc is not None:
            raise last_exc
        if response is None:
            raise RuntimeError("HTTP request failed without a response")
        return response

    def _delay(self, attempt_index: int, response: httpx.Response | None = None) -> float:
        retry_after = _retry_after_delay(response)
        if retry_after is not None:
            return min(retry_after, self.max_delay)

        delay = min(self.base_delay * (2**attempt_index), self.max_delay)
        if self.jitter <= 0:
            return delay
        return min(delay + (self.rng() * self.jitter * delay), self.max_delay)


def is_retryable_status(status_code: int) -> bool:
    return status_code in RETRYABLE_STATUSES


def is_retryable_exception(exc: Exception) -> bool:
    return isinstance(exc, (httpx.TimeoutException, httpx.TransportError))


def _retry_after_delay(response: httpx.Response | None) -> float | None:
    if response is None or response.status_code not in {429, 503}:
        return None

    value = response.headers.get("Retry-After")
    if value is None:
        return None

    try:
        return max(0.0, float(value))
    except ValueError:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
