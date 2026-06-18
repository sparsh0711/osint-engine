from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx


class CircuitOpenError(httpx.HTTPError):
    pass


@dataclass(slots=True)
class _HostState:
    failures: int = 0
    opened_at: float | None = None
    half_open: bool = False


class HostCircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
        clock: Callable[[], float] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._clock = clock or time.monotonic
        self._on_event = on_event
        self._states: dict[str, _HostState] = {}

    def before_request(self, host: str) -> None:
        if self.failure_threshold <= 0:
            return

        state = self._states.get(host)
        if state is None or state.opened_at is None:
            return

        if self._clock() - state.opened_at >= self.cooldown_seconds:
            state.half_open = True
            return

        raise CircuitOpenError(f"circuit open for {host}")

    def record_success(self, host: str) -> None:
        if self.failure_threshold <= 0:
            return

        state = self._states.get(host)
        if state is None:
            return

        was_open = state.opened_at is not None or state.failures > 0
        self._states[host] = _HostState()
        if was_open:
            self._emit(
                {
                    "event": "circuit_closed",
                    "host": host,
                    "failure_count": 0,
                }
            )

    def record_failure(self, host: str) -> None:
        if self.failure_threshold <= 0:
            return

        state = self._states.setdefault(host, _HostState())
        state.failures += 1
        state.half_open = False
        if state.failures >= self.failure_threshold:
            state.opened_at = self._clock()
            self._emit(
                {
                    "event": "circuit_opened",
                    "host": host,
                    "failure_count": state.failures,
                }
            )

    def _emit(self, event: dict[str, Any]) -> None:
        if self._on_event is not None:
            self._on_event(event)
