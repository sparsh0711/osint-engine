from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import httpx

from osint.connectors.base import CollectionMode, Connector, register
from osint.connectors.context import CollectionContext
from osint.connectors.domains import build_domain_entity
from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding
from osint.core.ids import canonical_domain
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType, Relationship


@register
class CrtShConnector(Connector):
    name = "crtsh"
    source = "crt.sh"
    description = "Certificate Transparency lookup via crt.sh JSON output"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.Domain}
    produces = {EntityType.Domain, EntityType.Certificate}
    requires_api_key = False
    base_confidence = 0.7

    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        domain = canonical_domain(seed.value)
        query = f"https://crt.sh/?q=%25.{domain}&output=json"

        try:
            response = await ctx.http.get(query)
            response.raise_for_status()
            records = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            if ctx.logger:
                ctx.logger.warning(
                    "crtsh_collection_failed",
                    domain=domain,
                    error=str(exc),
                )
            return

        if not isinstance(records, list):
            if ctx.logger:
                ctx.logger.warning("crtsh_unexpected_payload", domain=domain)
            return

        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            finding = self._record_to_finding(record, domain, query, index)
            if finding.entities:
                yield finding

    def _record_to_finding(
        self, record: dict[str, Any], seed_domain: str, query: str, index: int
    ) -> Finding:
        collected_at = datetime.now(timezone.utc)
        raw_ref = {"crtsh_id": record.get("id"), "index": index}
        provenance = Provenance(
            connector=self.name,
            source=self.source,
            query=query,
            collected_at=collected_at,
            raw_ref=raw_ref,
        )

        # The seed apex itself is always the graph root for this finding.
        domain_entities = [
            build_domain_entity(
                seed_domain,
                seed_domain,
                provenance,
                self.base_confidence,
            )
        ]
        names = _extract_names(record.get("name_value"))
        for name, is_wildcard in names:
            if name == seed_domain:
                # Already added as the root; don't duplicate (dedup by id would
                # also handle it, but skipping keeps the entity list clean).
                continue
            domain_entities.append(
                build_domain_entity(
                    name,
                    seed_domain,
                    provenance,
                    self.base_confidence,
                    is_wildcard=is_wildcard,
                )
            )

        cert_entity = self._certificate_entity(record, names, provenance)
        relationships: list[Relationship] = []
        seen_relationships: set[str] = set()
        root = domain_entities[0]

        for domain_entity in domain_entities:
            # The certificate secures EVERY name it lists, including unrelated
            # co-SAN domains. That linkage is a real, useful pivot signal.
            secures = Relationship(
                type=RelationType.SECURES,
                src_id=cert_entity.id,
                dst_id=domain_entity.id,
                sources=[provenance],
                confidence=self.base_confidence,
            )
            if secures.id not in seen_relationships:
                relationships.append(secures)
                seen_relationships.add(secures.id)

            # HAS_SUBDOMAIN is only asserted for names genuinely *under* the seed.
            # Co-SAN domains on other registrable domains are deliberately excluded.
            if (
                domain_entity.value != seed_domain
                and domain_entity.value.endswith(f".{seed_domain}")
            ):
                has_subdomain = Relationship(
                    type=RelationType.HAS_SUBDOMAIN,
                    src_id=root.id,
                    dst_id=domain_entity.id,
                    sources=[provenance],
                    confidence=self.base_confidence,
                )
                if has_subdomain.id not in seen_relationships:
                    relationships.append(has_subdomain)
                    seen_relationships.add(has_subdomain.id)

        unique_entities = {entity.id: entity for entity in [cert_entity, *domain_entities]}
        return Finding(
            entities=list(unique_entities.values()),
            relationships=relationships,
        )

    def _certificate_entity(
        self,
        record: dict[str, Any],
        names: list[tuple[str, bool]],
        provenance: Provenance,
    ) -> Entity:
        sans = sorted({name for name, _ in names})
        synthetic_id = _synthetic_certificate_id(record, sans)
        return Entity(
            type=EntityType.Certificate,
            value=synthetic_id,
            attributes={
                # crt.sh's default JSON does NOT expose the leaf certificate's real
                # SHA-256 fingerprint, so we do not claim one. Left null until a
                # connector that fetches the leaf (Phase 3) can populate it. This is
                # the canonical cross-source pivot key, so it must stay honest.
                "sha256": None,
                # Local, deterministic dedup key for this connector. NOT a real cert
                # hash and not portable to other tools — named to say so.
                "synthetic_id": synthetic_id,
                # crt.sh's own record id, preserved for traceability back to source.
                "crtsh_id": record.get("id"),
                "serial": record.get("serial_number"),
                "issuer": record.get("issuer_name"),
                "subject": record.get("common_name"),
                "not_before": record.get("not_before"),
                "not_after": record.get("not_after"),
                "sans": sans,
            },
            sources=[provenance],
            confidence=self.base_confidence,
        )


def _extract_names(name_value: Any) -> list[tuple[str, bool]]:
    if not isinstance(name_value, str):
        return []

    names: list[tuple[str, bool]] = []
    seen: set[tuple[str, bool]] = set()
    for raw_name in name_value.splitlines():
        name = canonical_domain(raw_name)
        if not name:
            continue
        is_wildcard = name.startswith("*.")
        if is_wildcard:
            name = name[2:]
        item = (name, is_wildcard)
        if item not in seen:
            names.append(item)
            seen.add(item)
    return names


def _synthetic_certificate_id(record: dict[str, Any], sans: list[str]) -> str:
    """Deterministic local identity for a crt.sh record.

    This is NOT the certificate's real SHA-256 fingerprint (crt.sh's default JSON
    does not return one). It exists only so the same crt.sh record dedups to the
    same Certificate entity across runs. Do not treat it as portable to other
    certificate data sources.
    """
    material = {
        "serial": record.get("serial_number") or record.get("id"),
        "issuer": record.get("issuer_name"),
        "subject": record.get("common_name"),
        "not_before": record.get("not_before"),
        "not_after": record.get("not_after"),
        "sans": sans,
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
