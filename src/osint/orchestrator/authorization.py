from __future__ import annotations

import ipaddress

from pydantic import BaseModel, Field

from osint.core.entities import Entity, EntityType
from osint.core.ids import canonical_domain


class Authorization(BaseModel):
    in_scope_targets: list[str] = Field(default_factory=list)

    def covers(self, seed: Entity) -> bool:
        for target in self.in_scope_targets:
            if _target_covers_seed(target, seed):
                return True
        return False


def _target_covers_seed(target: str, seed: Entity) -> bool:
    if seed.type == EntityType.Domain:
        seed_domain = canonical_domain(seed.value)
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            target_domain = canonical_domain(target)
            return seed_domain == target_domain or seed_domain.endswith(f".{target_domain}")
        return False

    if seed.type == EntityType.IPAddress:
        try:
            seed_ip = ipaddress.ip_address(seed.value)
        except ValueError:
            return False

        try:
            return seed_ip in ipaddress.ip_network(target, strict=False)
        except ValueError:
            try:
                return seed_ip == ipaddress.ip_address(target)
            except ValueError:
                return False

    return False
