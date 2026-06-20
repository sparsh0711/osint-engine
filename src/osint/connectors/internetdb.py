from __future__ import annotations

"""Shodan InternetDB connector.

InternetDB is key-free and requires no account. It is free for non-commercial
use; commercial use needs a Shodan enterprise license, and Shodan attribution
is required.
"""

import ipaddress
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import httpx

from osint.connectors.base import CollectionMode, Connector, EnrichmentClass, register
from osint.connectors.context import CollectionContext
from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding
from osint.core.ids import canonical_ip
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType, Relationship


@register
class InternetDbConnector(Connector):
    name = "internetdb"
    source = "shodan-internetdb"
    description = "Key-free IP enrichment via Shodan InternetDB"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.IPAddress}
    produces = {EntityType.Service, EntityType.IPAddress, EntityType.Vulnerability}
    requires_api_key = False
    base_confidence = 0.8
    enrichment_class = EnrichmentClass.EXPOSURE

    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        try:
            ip = ipaddress.ip_address(seed.value)
        except ValueError:
            if ctx.logger:
                ctx.logger.warning("internetdb_invalid_ip", value=seed.value)
            return

        if ip.version != 4:
            if ctx.logger:
                ctx.logger.debug("internetdb_ipv6_skipped", ip=str(ip))
            return

        query = f"https://internetdb.shodan.io/{canonical_ip(str(ip))}"
        try:
            response = await ctx.http.get(query)
            if response.status_code == 404:
                if ctx.logger:
                    ctx.logger.info("internetdb_ip_not_found", ip=str(ip))
                return
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            if ctx.logger:
                ctx.logger.warning(
                    "internetdb_collection_failed",
                    ip=str(ip),
                    error=str(exc),
                )
            return

        if not isinstance(payload, dict):
            if ctx.logger:
                ctx.logger.warning("internetdb_unexpected_payload", ip=str(ip))
            return

        yield self._payload_to_finding(seed, ip, payload, query)

    def _payload_to_finding(
        self,
        seed: Entity,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        payload: dict[str, Any],
        query: str,
    ) -> Finding:
        collected_at = datetime.now(timezone.utc)
        provenance = Provenance(
            connector=self.name,
            source=self.source,
            query=query,
            collected_at=collected_at,
            raw_ref={"ip": str(ip)},
        )
        ip_entity = Entity(
            type=EntityType.IPAddress,
            value=str(ip),
            attributes={
                "version": ip.version,
                "is_private": ip.is_private,
                "cpes": _string_list(payload.get("cpes")),
                "vulns": _string_list(payload.get("vulns")),
                "hostnames": _string_list(payload.get("hostnames")),
            },
            sources=[provenance],
            confidence=self.base_confidence,
            tags=set(_string_list(payload.get("tags"))),
        )

        entities: list[Entity] = [ip_entity]
        relationships: list[Relationship] = []
        for port in _ports(payload.get("ports")):
            service = Entity(
                type=EntityType.Service,
                value=f"{canonical_ip(str(ip))}:{port}",
                attributes={
                    "ip": canonical_ip(str(ip)),
                    "port": port,
                    "protocol": None,
                    "product": None,
                    "banner": None,
                },
                sources=[provenance],
                confidence=self.base_confidence,
            )
            entities.append(service)
            relationships.append(
                Relationship(
                    type=RelationType.HOSTS,
                    src_id=seed.id or ip_entity.id,
                    dst_id=service.id,
                    sources=[provenance],
                    confidence=self.base_confidence,
                )
            )

        for cve_id in _cve_ids(payload.get("vulns")):
            vulnerability = Entity(
                type=EntityType.Vulnerability,
                value=cve_id,
                attributes={"cve_id": cve_id},
                sources=[provenance],
                confidence=self.base_confidence,
            )
            entities.append(vulnerability)
            relationships.append(
                Relationship(
                    type=RelationType.HAS_VULNERABILITY,
                    src_id=seed.id or ip_entity.id,
                    dst_id=vulnerability.id,
                    sources=[provenance],
                    confidence=self.base_confidence,
                )
            )

        return Finding(entities=entities, relationships=relationships)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str)})


def _ports(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    ports: set[int] = set()
    for item in value:
        if not isinstance(item, int):
            continue
        if 0 < item <= 65535:
            ports.add(item)
    return sorted(ports)


def _cve_ids(value: Any) -> list[str]:
    return sorted(
        {
            item.strip().upper()
            for item in _string_list(value)
            if item.strip().upper().startswith("CVE-")
        }
    )
