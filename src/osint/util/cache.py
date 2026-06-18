from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx


class DiskHttpCache:
    def __init__(
        self,
        cache_dir: str | Path,
        ttl_seconds: float = 24 * 60 * 60,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.ttl_seconds = ttl_seconds
        self._clock = clock or time.time

    def get(self, url: str) -> httpx.Response | None:
        path = self._path_for(url)
        if not path.exists():
            return None

        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            fetched_at = float(entry["fetched_at"])
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

        if self._clock() - fetched_at > self.ttl_seconds:
            return None
        if entry.get("url") != url:
            return None

        try:
            body = base64.b64decode(entry["body"])
            status_code = int(entry["status_code"])
            headers = dict(entry.get("headers", {}))
        except (ValueError, KeyError, TypeError):
            return None

        return httpx.Response(
            status_code=status_code,
            headers=headers,
            content=body,
            request=httpx.Request("GET", url),
        )

    def set(self, url: str, response: httpx.Response) -> None:
        if not is_cacheable_status(response.status_code):
            return

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        entry: dict[str, Any] = {
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": base64.b64encode(response.content).decode("ascii"),
            "fetched_at": self._clock(),
        }
        self._path_for(url).write_text(
            json.dumps(entry, sort_keys=True),
            encoding="utf-8",
        )

    def _path_for(self, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"


def is_cacheable_status(status_code: int) -> bool:
    return 200 <= status_code < 300 or status_code == 404
