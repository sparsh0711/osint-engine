from __future__ import annotations

from osint.util.urls import host_from_url


def test_host_from_url_handles_http_https_ports_and_paths() -> None:
    assert host_from_url("http://Example.COM/path?q=1") == "example.com"
    assert host_from_url("https://user:pass@Sub.Example.COM:8443/a/b") == (
        "sub.example.com"
    )


def test_host_from_url_returns_none_for_garbage() -> None:
    assert host_from_url("not a url") is None
    assert host_from_url("http://[broken") is None
