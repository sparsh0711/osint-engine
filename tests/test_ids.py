from __future__ import annotations

from osint.core.entities import EntityType
from osint.core.ids import canonical_domain, canonical_ip, entity_id, relationship_id
from osint.core.relationships import RelationType


def test_entity_ids_are_deterministic_for_canonical_domains() -> None:
    assert entity_id(EntityType.Domain, "Example.COM.") == entity_id(
        EntityType.Domain, "example.com"
    )
    assert canonical_domain("Example.COM.") == "example.com"


def test_ip_canonicalization_normalizes_ipv6() -> None:
    assert canonical_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def test_relationship_ids_are_deterministic() -> None:
    left = relationship_id(RelationType.SECURES, "cert-a", "domain-b")
    right = relationship_id(RelationType.SECURES, "cert-a", "domain-b")
    assert left == right
