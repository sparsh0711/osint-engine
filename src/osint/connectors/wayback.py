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
from osint.util.urls import host_from_url


@register
class WaybackConnector(Connector):
    name = "wayback"
    source = "web.archive.org"
    description = "Historical hostnames via the Wayback Machine CDX API"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.Domain}
    produces = {EntityType.Domain}
    requires_api_key = False
    base_confidence = 0.6

    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        domain = canonical_domain(seed.value)
        query = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={domain}&matchType=domain&output=json&fl=original"
            "&collapse=urlkey&limit=10000"
        )

        try:
            response = await ctx.http.get(query)
            response.raise_for_status()
            rows = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            if ctx.logger:
                ctx.logger.warning(
                    "wayback_collection_failed",
                    domain=domain,
                    error=str(exc),
                )
            return

        if not isinstance(rows, list):
            if ctx.logger:
                ctx.logger.warning("wayback_unexpected_payload", domain=domain)
            return

        finding = self._rows_to_finding(rows, domain, query)
        if finding.entities:
            yield finding

    def _rows_to_finding(
        self, rows: list[Any], seed_domain: str, query: str
    ) -> Finding:
        collected_at = datetime.now(timezone.utc)
        root_provenance = Provenance(
            connector=self.name,
            source=self.source,
            query=query,
            collected_at=collected_at,
            raw_ref={"seed": seed_domain},
        )
        root = build_domain_entity(
            seed_domain,
            seed_domain,
            root_provenance,
            self.base_confidence,
        )

        entities: dict[str, Entity] = {root.id: root}
        relationships: dict[str, Relationship] = {}
        seen_hosts = {seed_domain}

        for index, row in enumerate(rows[1:], start=1):
            original = _original_from_row(row)
            if original is None:
                continue
            host = host_from_url(original)
            if host is None:
                continue
            host = canonical_domain(host)
            if host != seed_domain and not host.endswith(f".{seed_domain}"):
                continue
            if host in seen_hosts:
                continue
            seen_hosts.add(host)

            provenance = Provenance(
                connector=self.name,
                source=self.source,
                query=query,
                collected_at=collected_at,
                raw_ref={"index": index, "original": original},
            )
            entity = build_domain_entity(
                host,
                seed_domain,
                provenance,
                self.base_confidence,
            )
            entities[entity.id] = entity

            if host != seed_domain:
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


def _original_from_row(row: Any) -> str | None:
    if not isinstance(row, list) or not row:
        return None
    original = row[0]
    return original if isinstance(original, str) else None
