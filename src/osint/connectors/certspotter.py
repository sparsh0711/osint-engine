from __future__ import annotations

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
class CertSpotterConnector(Connector):
    name = "certspotter"
    source = "certspotter"
    description = "Certificate Transparency subdomains via SSLMate Cert Spotter"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.Domain}
    produces = {EntityType.Domain}
    requires_api_key = False
    base_confidence = 0.7

    def __init__(self, max_pages: int = 10) -> None:
        self.max_pages = max(1, max_pages)

    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        domain = canonical_domain(seed.value)
        after: str | None = None
        saw_issuance = False

        for page_index in range(self.max_pages):
            query = _query_url(domain, after)
            try:
                response = await ctx.http.get(query)
                if response.status_code == 404:
                    if ctx.logger:
                        ctx.logger.info("certspotter_no_results", domain=domain)
                    return
                response.raise_for_status()
                issuances = response.json()
            except (httpx.HTTPError, ValueError, TypeError) as exc:
                if ctx.logger:
                    ctx.logger.info(
                        "certspotter_collection_incomplete",
                        domain=domain,
                        error=str(exc),
                    )
                return

            if not isinstance(issuances, list):
                if ctx.logger:
                    ctx.logger.info("certspotter_unexpected_payload", domain=domain)
                return

            if not issuances:
                if ctx.logger and not saw_issuance:
                    ctx.logger.info("certspotter_no_results", domain=domain)
                return

            saw_issuance = True
            for issuance_index, issuance in enumerate(issuances):
                if not isinstance(issuance, dict):
                    continue
                finding = self._issuance_to_finding(
                    issuance,
                    domain,
                    query,
                    page_index,
                    issuance_index,
                )
                if finding.entities:
                    yield finding

            after = _last_issuance_id(issuances)
            if after is None:
                return

        if ctx.logger:
            ctx.logger.info(
                "certspotter_page_cap_reached",
                domain=domain,
                max_pages=self.max_pages,
            )

    def _issuance_to_finding(
        self,
        issuance: dict[str, Any],
        seed_domain: str,
        query: str,
        page_index: int,
        issuance_index: int,
    ) -> Finding:
        collected_at = datetime.now(timezone.utc)
        raw_ref = {
            "id": issuance.get("id"),
            "page": page_index,
            "index": issuance_index,
        }
        root_provenance = Provenance(
            connector=self.name,
            source=self.source,
            query=query,
            collected_at=collected_at,
            raw_ref={**raw_ref, "seed": seed_domain},
        )
        root = build_domain_entity(
            seed_domain,
            seed_domain,
            root_provenance,
            self.base_confidence,
        )

        entities: dict[str, Entity] = {root.id: root}
        relationships: dict[str, Relationship] = {}
        for raw_name in _dns_names(issuance.get("dns_names")):
            name, is_wildcard = _normalize_name(raw_name)
            if not name:
                continue
            provenance = Provenance(
                connector=self.name,
                source=self.source,
                query=query,
                collected_at=collected_at,
                raw_ref={**raw_ref, "dns_name": raw_name},
            )
            entity = build_domain_entity(
                name,
                seed_domain,
                provenance,
                self.base_confidence,
                is_wildcard=is_wildcard,
            )
            entities[entity.id] = entity

            if name != seed_domain and name.endswith(f".{seed_domain}"):
                relationship = Relationship(
                    type=RelationType.HAS_SUBDOMAIN,
                    src_id=root.id,
                    dst_id=entity.id,
                    sources=[provenance],
                    confidence=self.base_confidence,
                )
                relationships[relationship.id] = relationship

        return Finding(
            entities=list(entities.values()),
            relationships=list(relationships.values()),
        )


def _query_url(domain: str, after: str | None = None) -> str:
    query = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    if after is not None:
        query += f"&after={after}"
    return query


def _dns_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _normalize_name(value: str) -> tuple[str, bool]:
    name = canonical_domain(value)
    is_wildcard = name.startswith("*.")
    if is_wildcard:
        name = name[2:]
    return name, is_wildcard


def _last_issuance_id(issuances: list[Any]) -> str | None:
    for item in reversed(issuances):
        if not isinstance(item, dict):
            continue
        id_ = item.get("id")
        if id_ is not None:
            return str(id_)
    return None
