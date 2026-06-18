from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator
from datetime import datetime, timezone

import dns.exception
import dns.resolver

from osint.connectors.base import CollectionMode, Connector, register
from osint.connectors.context import CollectionContext
from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding
from osint.core.ids import canonical_domain
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType, Relationship

_DNS_SEMAPHORES: dict[asyncio.AbstractEventLoop, asyncio.Semaphore] = {}


@register
class DnsConnector(Connector):
    name = "dns"
    source = "dns"
    description = "A/AAAA resolution via the system resolver"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.Domain}
    produces = {EntityType.IPAddress}
    requires_api_key = False
    base_confidence = 0.9

    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        domain = canonical_domain(seed.value)
        try:
            async with _dns_semaphore():
                addresses = await asyncio.to_thread(resolve_host, domain)
        except Exception as exc:
            if ctx.logger:
                ctx.logger.warning(
                    "dns_collection_failed",
                    domain=domain,
                    error=str(exc),
                )
            return

        unique_addresses = sorted({address for address in addresses if address})
        if not unique_addresses:
            if ctx.logger:
                ctx.logger.warning("dns_no_records", domain=domain)
            return

        collected_at = datetime.now(timezone.utc)
        entities: list[Entity] = []
        relationships: list[Relationship] = []
        for address in unique_addresses:
            try:
                ip_address = ipaddress.ip_address(address)
            except ValueError:
                continue

            provenance = Provenance(
                connector=self.name,
                source=self.source,
                query=domain,
                collected_at=collected_at,
                raw_ref={"address": str(ip_address)},
            )
            entity = Entity(
                type=EntityType.IPAddress,
                value=str(ip_address),
                attributes={
                    "version": ip_address.version,
                    "is_private": ip_address.is_private,
                },
                sources=[provenance],
                confidence=self.base_confidence,
            )
            relationship = Relationship(
                type=RelationType.RESOLVES_TO,
                src_id=seed.id,
                dst_id=entity.id,
                sources=[provenance],
                confidence=self.base_confidence,
            )
            entities.append(entity)
            relationships.append(relationship)

        if entities:
            yield Finding(entities=entities, relationships=relationships)


def resolve_host(name: str) -> list[str]:
    addresses: list[str] = []
    resolver = dns.resolver.Resolver()
    for rdtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(name, rdtype, lifetime=5.0)
        except dns.exception.DNSException:
            continue
        addresses.extend(answer.to_text() for answer in answers)
    return addresses


def _dns_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    if loop not in _DNS_SEMAPHORES:
        _DNS_SEMAPHORES[loop] = asyncio.Semaphore(20)
    return _DNS_SEMAPHORES[loop]
