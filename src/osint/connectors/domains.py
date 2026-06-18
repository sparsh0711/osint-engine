from __future__ import annotations

from osint.core.entities import Entity, EntityType
from osint.core.ids import canonical_domain
from osint.core.provenance import Provenance


def build_domain_entity(
    value: str,
    seed_domain: str,
    provenance: Provenance,
    base_confidence: float,
    *,
    is_wildcard: bool = False,
    extra_tags: set[str] | None = None,
) -> Entity:
    value = canonical_domain(value)
    seed_domain = canonical_domain(seed_domain)

    # A name is "under the seed" only if it IS the seed or a dotted child of it.
    # Anything else is a co-SAN domain on a different registrable domain: we keep
    # the entity but must NOT stamp the seed's apex/tld onto it.
    under_seed = value == seed_domain or value.endswith(f".{seed_domain}")
    tags = set(extra_tags or set())
    if not under_seed:
        tags.add("co-san")
    if is_wildcard:
        tags.add("wildcard")

    registered_domain = seed_domain if under_seed else None
    # NOTE (known limitation, deferred to a later phase / tldextract): this is
    # the name's last label, not a true public-suffix-aware TLD. It is wrong for
    # multi-label suffixes like ".co.uk".
    tld = value.rsplit(".", 1)[-1] if "." in value else None

    return Entity(
        type=EntityType.Domain,
        value=value,
        attributes={
            "registered_domain": registered_domain,
            "tld": tld,
            "is_wildcard": is_wildcard,
            "under_seed": under_seed,
        },
        sources=[provenance],
        confidence=base_confidence,
        tags=tags,
    )
