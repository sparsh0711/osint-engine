from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class AsyncTokenBucketLimiter:
    def __init__(self, default_rate: float = 1.0, capacity: int = 1) -> None:
        self.default_rate = default_rate
        self.capacity = capacity
        self._rates: dict[str, float] = {}
        self._tokens: dict[str, float] = defaultdict(lambda: float(capacity))
        self._updated_at: dict[str, float] = defaultdict(time.monotonic)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def set_rate(self, source_key: str, rate: float) -> None:
        self._rates[source_key] = rate

    async def acquire(self, source_key: str) -> None:
        async with self._locks[source_key]:
            while True:
                self._refill(source_key)
                if self._tokens[source_key] >= 1.0:
                    self._tokens[source_key] -= 1.0
                    return

                rate = self._rates.get(source_key, self.default_rate)
                wait_for = (1.0 - self._tokens[source_key]) / rate
                await asyncio.sleep(wait_for)

    def _refill(self, source_key: str) -> None:
        now = time.monotonic()
        elapsed = now - self._updated_at[source_key]
        rate = self._rates.get(source_key, self.default_rate)
        self._tokens[source_key] = min(
            float(self.capacity),
            self._tokens[source_key] + elapsed * rate,
        )
        self._updated_at[source_key] = now
