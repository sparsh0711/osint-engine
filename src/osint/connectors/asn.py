from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone

import dns.exception
import dns.resolver

from osint.connectors.base import CollectionMode, Connector, register
from osint.connectors.context import CollectionContext
from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding
from osint.core.ids import canonical_ip
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType, Relationship

_DNS_SEMAPHORES: dict[asyncio.AbstractEventLoop, asyncio.Semaphore] = {}


@dataclass(frozen=True)
class OriginRecord:
    asn: str
    prefix: str
    country: str | None
    registry: str | None
    raw: str


@dataclass(frozen=True)
class AsnDescription:
    name: str | None
    country: str | None
    registry: str | None
    raw: str | None


@register
class AsnConnector(Connector):
    name = "asn"
    source = "team-cymru"
    description = "IP-to-ASN/netblock mapping via Team Cymru (DNS interface)"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.IPAddress}
    produces = {EntityType.ASN, EntityType.Netblock}
    requires_api_key = False
    base_confidence = 0.85

    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        try:
            ip = ipaddress.ip_address(seed.value)
        except ValueError:
            if ctx.logger:
                ctx.logger.info("asn_invalid_ip", value=seed.value)
            return

        query = _origin_query(ip)
        try:
            async with _dns_semaphore():
                origin_txt = await asyncio.to_thread(resolve_txt, query)
        except dns.exception.DNSException:
            if ctx.logger:
                ctx.logger.info("asn_no_data", ip=str(ip), query=query)
            return
        except Exception as exc:
            if ctx.logger:
                ctx.logger.info("asn_lookup_incomplete", ip=str(ip), query=query, error=str(exc))
            return

        records = [_parse_origin_record(text) for text in origin_txt]
        records = [record for record in records if record is not None]
        if not records:
            if ctx.logger:
                ctx.logger.info("asn_no_data", ip=str(ip), query=query)
            return

        entities: list[Entity] = []
        relationships: list[Relationship] = []
        for record in records:
            description = await self._asn_description(record.asn, ctx)
            finding_entities, finding_relationships = self._record_to_graph(
                seed,
                ip,
                record,
                description,
                query,
            )
            entities.extend(finding_entities)
            relationships.extend(finding_relationships)

        yield Finding(entities=entities, relationships=relationships)

    async def _asn_description(
        self,
        asn: str,
        ctx: CollectionContext,
    ) -> AsnDescription:
        query = f"AS{asn}.asn.cymru.com"
        try:
            async with _dns_semaphore():
                answer = await asyncio.to_thread(resolve_txt, query)
        except Exception:
            return AsnDescription(name=None, country=None, registry=None, raw=None)
        for text in answer:
            description = _parse_asn_description(text)
            if description is not None:
                return description
        return AsnDescription(name=None, country=None, registry=None, raw=None)

    def _record_to_graph(
        self,
        seed: Entity,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        record: OriginRecord,
        description: AsnDescription,
        query: str,
    ) -> tuple[list[Entity], list[Relationship]]:
        collected_at = datetime.now(timezone.utc)
        asn_value = f"AS{record.asn}"
        country = description.country or record.country
        registry = description.registry or record.registry
        provenance = Provenance(
            connector=self.name,
            source=self.source,
            query=query,
            collected_at=collected_at,
            raw_ref={
                "ip": str(ip),
                "origin": record.raw,
                "asn_description": description.raw,
            },
        )
        asn = Entity(
            type=EntityType.ASN,
            value=asn_value,
            attributes={
                "number": int(record.asn),
                "name": description.name,
                "org": description.name,
                "country": country,
                "registry": registry,
            },
            sources=[provenance],
            confidence=self.base_confidence,
        )
        netblock = Entity(
            type=EntityType.Netblock,
            value=str(ipaddress.ip_network(record.prefix, strict=False)),
            attributes={
                "cidr": str(ipaddress.ip_network(record.prefix, strict=False)),
                "asn": asn_value,
                "country": country,
                "registry": registry,
            },
            sources=[provenance],
            confidence=self.base_confidence,
        )
        return (
            [asn, netblock],
            [
                Relationship(
                    type=RelationType.CONTAINS,
                    src_id=netblock.id,
                    dst_id=seed.id,
                    sources=[provenance],
                    confidence=self.base_confidence,
                ),
                Relationship(
                    type=RelationType.ANNOUNCES,
                    src_id=asn.id,
                    dst_id=netblock.id,
                    sources=[provenance],
                    confidence=self.base_confidence,
                ),
            ],
        )


def resolve_txt(name: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    answers = resolver.resolve(name, "TXT", lifetime=5.0)
    records: list[str] = []
    for answer in answers:
        strings = getattr(answer, "strings", None)
        if strings is not None:
            records.append("".join(part.decode("utf-8") for part in strings))
        else:
            records.append(answer.to_text().strip('"'))
    return records


def _origin_query(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.version == 4:
        reversed_octets = ".".join(reversed(str(ip).split(".")))
        return f"{reversed_octets}.origin.asn.cymru.com"
    nibbles = ip.exploded.replace(":", "")
    return f"{'.'.join(reversed(nibbles))}.origin6.asn.cymru.com"


def _parse_origin_record(text: str) -> OriginRecord | None:
    parts = [part.strip() for part in _clean_txt(text).split("|")]
    if len(parts) < 2:
        return None
    asn = parts[0]
    prefix = parts[1]
    if not asn.isdigit():
        return None
    try:
        ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None
    return OriginRecord(
        asn=asn,
        prefix=prefix,
        country=_optional_part(parts, 2),
        registry=_optional_part(parts, 3),
        raw=text,
    )


def _parse_asn_description(text: str) -> AsnDescription | None:
    parts = [part.strip() for part in _clean_txt(text).split("|")]
    if len(parts) < 5 or not parts[0].isdigit():
        return None
    return AsnDescription(
        name=_optional_part(parts, 4),
        country=_optional_part(parts, 1),
        registry=_optional_part(parts, 2),
        raw=text,
    )


def _optional_part(parts: list[str], index: int) -> str | None:
    if index >= len(parts):
        return None
    value = parts[index].strip()
    return value or None


def _clean_txt(text: str) -> str:
    return text.strip().strip('"')


def _dns_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    if loop not in _DNS_SEMAPHORES:
        _DNS_SEMAPHORES[loop] = asyncio.Semaphore(20)
    return _DNS_SEMAPHORES[loop]
