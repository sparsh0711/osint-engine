from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))


def pytest_addoption(parser):
    parser.addoption(
        "--neo4j-uri",
        default=None,
        help="Neo4j Bolt URI for gated store tests.",
    )


@pytest.fixture(autouse=True)
def isolated_http_resilience(monkeypatch, tmp_path):
    monkeypatch.setenv("OSINT_HTTP_MAX_ATTEMPTS", "1")
    monkeypatch.setenv("OSINT_CIRCUIT_FAILURE_THRESHOLD", "0")
    monkeypatch.setenv("OSINT_CACHE_DIR", str(tmp_path / "cache"))
