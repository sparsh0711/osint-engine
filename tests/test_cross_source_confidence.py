from __future__ import annotations

import re

import pytest

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


async def test_cross_source_confidence_tiers(respx_mock) -> None:
    respx_mock.get(CRTSH_URL).respond(
        200,
        json=[
            {
                "id": 1,
                "serial_number": "abc",
                "issuer_name": "Test CA",
                "common_name": "shared.example.com",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
                "name_value": "shared.example.com\nonly-crt.example.com",
            }
        ],
    )
    respx_mock.get(WAYBACK_URL).respond(
        200,
        json=[
            ["original"],
            ["https://shared.example.com/"],
            ["https://only-wb.example.com/path"],
        ],
    )
    respx_mock.get(CERTSPOTTER_PATTERN).respond(200, json=[])

    store, _audit_log = await Engine().run(_seed("example.com"), Authorization())
    entities = {entity.value: entity for entity in store.all_entities()}

    shared = entities["shared.example.com"]
    only_crt = entities["only-crt.example.com"]
    only_wb = entities["only-wb.example.com"]

    assert {source.source for source in shared.sources} == {
        "crt.sh",
        "web.archive.org",
    }
    assert shared.confidence == pytest.approx(0.88)
    assert only_crt.confidence == pytest.approx(0.70)
    assert only_wb.confidence == pytest.approx(0.60)

    shared_edge = next(
        relationship
        for relationship in store.all_relationships()
        if relationship.type == RelationType.HAS_SUBDOMAIN
        and relationship.dst_id == shared.id
    )
    assert {source.source for source in shared_edge.sources} == {
        "crt.sh",
        "web.archive.org",
    }
    assert shared_edge.confidence > 0.7
    assert shared_edge.confidence == pytest.approx(0.88)


def _seed(domain: str) -> Entity:
    return Entity(
        type=EntityType.Domain,
        value=domain,
        attributes={},
        sources=[
            Provenance(
                connector="test",
                source="test",
                query=domain,
                raw_ref={"seed": domain},
            )
        ],
        confidence=1.0,
    )
