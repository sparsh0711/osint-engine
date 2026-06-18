from __future__ import annotations

from urllib.parse import urlsplit


def host_from_url(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None

    if not parsed.scheme or not parsed.netloc:
        return None
    return parsed.hostname.lower() if parsed.hostname else None
