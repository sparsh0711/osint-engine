from __future__ import annotations

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine


CRTSH_ROOT = "https://crt.sh/?q=%25.example.com&output=json"
WAYBACK_ROOT = (
    "https://web.archive.org/cdx/search/cdx"
    "?url=example.com&matchType=domain&output=json&fl=original"
    "&collapse=urlkey&limit=10000"
)
CRTSH_API = "https://crt.sh/?q=%25.api.example.com&output=json"
WAYBACK_API = (
    "https://web.archive.org/cdx/search/cdx"
    "?url=api.example.com&matchType=domain&output=json&fl=original"
    "&collapse=urlkey&limit=10000"
)


async def test_multihop_resolves_in_scope_subdomain_not_co_san(
    respx_mock, monkeypatch
) -> None:
    _mock_root_sources(respx_mock)
    respx_mock.get(CRTSH_API).respond(200, json=[])
    respx_mock.get(WAYBACK_API).respond(200, json=[["original"]])

    resolved_names: list[str] = []

    def fake_resolve(name: str) -> list[str]:
        resolved_names.append(name)
        return {
            "example.com": [],
            "api.example.com": ["10.0.0.10"],
            "vendor.net": ["203.0.113.10"],
        }.get(name, [])

    monkeypatch.setattr("osint.connectors.dns.resolve_host", fake_resolve)

    store, audit_log = await Engine().run(
        _seed("example.com"),
        Authorization(),
        max_depth=1,
    )
    entities = {entity.value: entity for entity in store.all_entities()}
    relationships = store.all_relationships()

    assert "vendor.net" in entities
    assert "10.0.0.10" in entities
    assert "203.0.113.10" not in entities
    assert "api.example.com" in resolved_names
    assert "vendor.net" not in resolved_names
    assert any(
        relationship.type == RelationType.RESOLVES_TO
        and relationship.src_id == entities["api.example.com"].id
        and relationship.dst_id == entities["10.0.0.10"].id
        for relationship in relationships
    )
    assert any("api.example.com" in item.get("query", "") for item in audit_log)


def _mock_root_sources(respx_mock) -> None:
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
                "name_value": "api.example.com\nvendor.net",
            }
        ],
    )
    respx_mock.get(WAYBACK_ROOT).respond(
        200,
        json=[
            ["original"],
            ["https://api.example.com/"],
        ],
    )


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
