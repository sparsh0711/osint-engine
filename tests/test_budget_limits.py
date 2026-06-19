from __future__ import annotations

import inspect
import re

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine


CRTSH_ROOT = "https://crt.sh/?q=%25.example.com&output=json"
WAYBACK_ROOT = (
    "https://web.archive.org/cdx/search/cdx"
    "?url=example.com&matchType=domain&output=json&fl=original"
    "&collapse=urlkey&limit=10000"
)
CERTSPOTTER_PATTERN = re.compile(r"https://api\.certspotter\.com/v1/issuances.*")


def test_default_budget_caps_match_live_sane_defaults() -> None:
    signature = inspect.signature(Engine.run)

    assert signature.parameters["max_seeds"].default == 10
    assert signature.parameters["max_calls"].default == 30


async def test_max_calls_budget_stops_before_exceeding_cap(respx_mock, monkeypatch) -> None:
    monkeypatch.setattr("osint.connectors.dns.resolve_host", lambda _name: [])
    respx_mock.get(CRTSH_ROOT).respond(200, json=[])
    respx_mock.get(WAYBACK_ROOT).respond(200, json=[["original"]])
    respx_mock.get(CERTSPOTTER_PATTERN).respond(200, json=[])

    _store, audit_log = await Engine().run(
        _seed(),
        Authorization(),
        max_depth=1,
        max_calls=2,
    )

    assert any(
        item.get("event") == "budget_stop" and item.get("reason") == "max_calls"
        for item in audit_log
    )
    assert not any(item.get("connector") for item in audit_log)


async def test_max_seeds_budget_logs_stop(respx_mock, monkeypatch) -> None:
    monkeypatch.setattr("osint.connectors.dns.resolve_host", lambda _name: [])
    respx_mock.get(CRTSH_ROOT).respond(
        200,
        json=[
            {
                "id": 1,
                "serial_number": "abc",
                "issuer_name": "Test CA",
                "common_name": "api.example.com",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
                "name_value": "api.example.com",
            }
        ],
    )
    respx_mock.get(WAYBACK_ROOT).respond(200, json=[["original"]])
    respx_mock.get(CERTSPOTTER_PATTERN).respond(200, json=[])

    _store, audit_log = await Engine().run(
        _seed(),
        Authorization(),
        max_depth=1,
        max_seeds=1,
    )

    assert any(
        item.get("event") == "budget_stop" and item.get("reason") == "max_seeds"
        for item in audit_log
    )


def _seed() -> Entity:
    return Entity(
        type=EntityType.Domain,
        value="example.com",
        attributes={},
        sources=[
            Provenance(
                connector="test",
                source="test",
                query="example.com",
                raw_ref={"seed": "example.com"},
            )
        ],
        confidence=1.0,
    )
