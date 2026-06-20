from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import httpx

from osint.connectors.base import CollectionMode, Connector, EnrichmentClass, register
from osint.connectors.context import CollectionContext
from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding
from osint.core.provenance import Provenance


@register
class CveDbConnector(Connector):
    name = "cvedb"
    source = "shodan-cvedb"
    description = "CVE detail (CVSS/KEV/EPSS) via Shodan CVEDB"
    mode = CollectionMode.PASSIVE
    enrichment_class = EnrichmentClass.IDENTIFICATION
    accepts = {EntityType.Vulnerability}
    produces = {EntityType.Vulnerability}
    requires_api_key = False
    base_confidence = 0.9

    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        cve_id = str(seed.value).strip().upper()
        if not cve_id.startswith("CVE-"):
            if ctx.logger:
                ctx.logger.info("cvedb_invalid_cve", value=seed.value)
            return

        query = f"https://cvedb.shodan.io/cve/{cve_id}"
        try:
            response = await ctx.http.get(query)
            if response.status_code == 404:
                if ctx.logger:
                    ctx.logger.info("cvedb_no_data", cve_id=cve_id)
                return
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            if ctx.logger:
                ctx.logger.warning(
                    "cvedb_collection_failed",
                    cve_id=cve_id,
                    error=str(exc),
                )
            return

        if not isinstance(payload, dict):
            if ctx.logger:
                ctx.logger.warning("cvedb_unexpected_payload", cve_id=cve_id)
            return

        yield self._payload_to_finding(cve_id, payload, query)

    def _payload_to_finding(
        self,
        cve_id: str,
        payload: dict[str, Any],
        query: str,
    ) -> Finding:
        enriched_cve_id = _string(payload.get("cve_id")) or cve_id
        enriched_cve_id = enriched_cve_id.upper()
        cvss = _float(payload.get("cvss"))
        provenance = Provenance(
            connector=self.name,
            source=self.source,
            query=query,
            collected_at=datetime.now(timezone.utc),
            raw_ref={"cve_id": enriched_cve_id},
        )
        vulnerability = Entity(
            type=EntityType.Vulnerability,
            value=enriched_cve_id,
            attributes={
                "cve_id": enriched_cve_id,
                "summary": _string(payload.get("summary")),
                "cvss": cvss,
                "cvss_version": _string(payload.get("cvss_version")),
                "cvss_v2": _float(payload.get("cvss_v2")),
                "cvss_v3": _float(payload.get("cvss_v3")),
                "severity": _severity(cvss),
                "kev": _bool(payload.get("kev")),
                "epss": _float(payload.get("epss")),
                "ranking_epss": _float(payload.get("ranking_epss")),
                "references": _string_list(payload.get("references")),
                "published_time": _string(payload.get("published_time")),
            },
            sources=[provenance],
            confidence=self.base_confidence,
        )
        return Finding(entities=[vulnerability], relationships=[])


def _string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str)})


def _severity(cvss: float | None) -> str | None:
    if cvss is None:
        return None
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"
