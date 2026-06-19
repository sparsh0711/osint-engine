from __future__ import annotations

import re

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine


CRTSH_URL = "https://crt.sh/?q=%25.example.com&output=json"
WAYBACK_URL = (
    "https://web.archive.org/cdx/search/cdx"
    "?url=example.com&matchType=domain&output=json&fl=original"
    "&collapse=urlkey&limit=10000"
)
CERTSPOTTER_PATTERN = re.compile(r"https://api\.certspotter\.com/v1/issuances.*")


async def test_default_max_depth_zero_does_not_pivot_or_resolve_dns(
    respx_mock, monkeypatch
) -> None:
    dns_calls: list[str] = []
    monkeypatch.setattr(
        "osint.connectors.dns.resolve_host",
        lambda name: dns_calls.append(name) or ["10.0.0.10"],
    )
    respx_mock.get(CRTSH_URL).respond(
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
    respx_mock.get(WAYBACK_URL).respond(200, json=[["original"]])
    respx_mock.get(CERTSPOTTER_PATTERN).respond(200, json=[])

    store, _audit = await Engine().run(_seed(), Authorization())

    assert dns_calls == []
    assert not any(
        relationship.type == RelationType.RESOLVES_TO
        for relationship in store.all_relationships()
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
