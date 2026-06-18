from __future__ import annotations

from osint.core.entities import Entity, EntityType
from osint.orchestrator.authorization import Authorization


def is_pivot_eligible(entity: Entity, authorization: Authorization) -> bool:
    if entity.type == EntityType.Domain:
        return entity.attributes.get("under_seed") is True
    if entity.type == EntityType.IPAddress:
        return authorization.covers(entity)
    return False
