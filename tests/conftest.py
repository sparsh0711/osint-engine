from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))


def pytest_addoption(parser):
    parser.addoption(
        "--neo4j-uri",
        default=None,
        help="Neo4j Bolt URI for gated store tests.",
    )
