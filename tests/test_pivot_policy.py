from __future__ import annotations

from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.pivot import is_pivot_eligible


def test_in_scope_domain_is_pivot_eligible() -> None:
    entity = _entity(EntityType.Domain, "api.example.com", {"under_seed": True})

    assert is_pivot_eligible(entity, Authorization()) is True


def test_co_san_domain_is_not_pivot_eligible() -> None:
    entity = _entity(EntityType.Domain, "vendor.net", {"under_seed": False})

    assert is_pivot_eligible(entity, Authorization()) is False


def test_ip_is_pivot_eligible_only_when_authorized() -> None:
    entity = _entity(EntityType.IPAddress, "10.0.0.5", {})

    assert is_pivot_eligible(entity, Authorization()) is False
    assert (
        is_pivot_eligible(entity, Authorization(in_scope_targets=["10.0.0.0/24"]))
        is True
    )


def test_other_entity_types_are_not_pivot_eligible() -> None:
    entity = _entity(EntityType.Certificate, "abc123", {"sha256": None})

    assert is_pivot_eligible(entity, Authorization()) is False


def _entity(type_: EntityType, value: str, attributes: dict) -> Entity:
    return Entity(
        type=type_,
        value=value,
        attributes=attributes,
        sources=[
            Provenance(
                connector="test",
                source="test",
                query=value,
                raw_ref={"id": value},
            )
        ],
        confidence=1.0,
    )
