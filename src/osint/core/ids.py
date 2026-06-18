from __future__ import annotations

import hashlib
import ipaddress
from enum import Enum


def _type_value(type_: str | Enum) -> str:
    return type_.value if isinstance(type_, Enum) else str(type_)


def canonical_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def canonical_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def canonical_certificate(value: str) -> str:
    return value.strip().lower()


def canonical_value(type_: str | Enum, value: str) -> str:
    type_value = _type_value(type_)
    if type_value == "Domain":
        return canonical_domain(value)
    if type_value == "IPAddress":
        return canonical_ip(value)
    if type_value == "Certificate":
        return canonical_certificate(value)
    return value.strip()


def entity_id(type_: str | Enum, value: str) -> str:
    canonical = canonical_value(type_, value)
    return hashlib.sha1(f"{_type_value(type_)}:{canonical}".encode("utf-8")).hexdigest()[:16]


def relationship_id(type_: str | Enum, src_id: str, dst_id: str) -> str:
    return hashlib.sha1(
        f"{_type_value(type_)}:{src_id}:{dst_id}".encode("utf-8")
    ).hexdigest()[:16]
