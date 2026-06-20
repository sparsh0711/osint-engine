from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Any

from osint.connectors.base import Connector, CollectionMode, EnrichmentClass, REGISTRY
from osint.connectors.context import CollectionContext
from osint.core.entities import Entity, EntityType
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.pivot import is_pivot_eligible
from osint.store.base import EntityStore
from osint.store.memory import MemoryEntityStore
from osint.util.http import RateLimitedAsyncClient, create_http_client
from osint.util.logging import get_logger


class AuditedHttpClient:
    def __init__(
        self,
        client: RateLimitedAsyncClient,
        connector: str,
        audit_log: list[dict[str, Any]],
    ) -> None:
        self._client = client
        self._connector = connector
        self._audit_log = audit_log

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self._audit_log.append(
            {
                "connector": self._connector,
                "query": str(url),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        return await self._client.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> Any:
        return await self.request("GET", url, **kwargs)


class Engine:
    def __init__(
        self,
        connectors: list[Connector] | None = None,
        http_client: RateLimitedAsyncClient | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        if connectors is None:
            import osint.connectors  # noqa: F401

            connectors = list(REGISTRY.values())
        self.connectors = connectors
        self.http_client = http_client
        self.config = config or {}
        self.logger = get_logger("osint.engine")

    async def run(
        self,
        seed: Entity,
        authorization: Authorization | None = None,
        store: EntityStore | None = None,
        max_depth: int = 0,
        max_seeds: int = 10,
        max_calls: int = 30,
    ) -> tuple[EntityStore, list[dict[str, Any]]]:
        store = store or MemoryEntityStore()
        audit_log: list[dict[str, Any]] = []
        shared_http = self.http_client or create_http_client()
        should_close_http = self.http_client is None
        authorization = authorization or Authorization()

        visited: set[str] = set()
        frontier: deque[tuple[Entity, int]] = deque([(seed, 0)])
        seeds_processed = 0
        connector_calls = 0

        try:
            while frontier and seeds_processed < max_seeds:
                current_seed, depth = frontier.popleft()
                if current_seed.id in visited:
                    continue

                visited.add(current_seed.id)
                seeds_processed += 1

                permitted = self._permitted_connectors(
                    current_seed,
                    authorization,
                    shared_http,
                    audit_log,
                    max_depth=max_depth,
                )
                if connector_calls + len(permitted) > max_calls:
                    audit_log.append(
                        {
                            "event": "budget_stop",
                            "reason": "max_calls",
                            "seed_id": current_seed.id,
                            "seed_value": current_seed.value,
                            "attempted_calls": connector_calls + len(permitted),
                            "max_calls": max_calls,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                    break

                results = await asyncio.gather(
                    *[
                        self._collect_into_store(connector, current_seed, ctx, store)
                        for connector, ctx in permitted
                    ]
                )
                connector_calls += len(permitted)

                if depth < max_depth:
                    discovered = [
                        entity for connector_entities in results for entity in connector_entities
                    ]
                    for entity in sorted(discovered, key=lambda item: item.id):
                        if (
                            entity.id not in visited
                            and self._can_enqueue_entity(entity, authorization)
                        ):
                            if entity.type == EntityType.IPAddress:
                                frontier.appendleft((entity, depth + 1))
                            else:
                                frontier.append((entity, depth + 1))
            if frontier and seeds_processed >= max_seeds:
                audit_log.append(
                    {
                        "event": "budget_stop",
                        "reason": "max_seeds",
                        "seeds_processed": seeds_processed,
                        "max_seeds": max_seeds,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
        finally:
            if should_close_http:
                await shared_http.aclose()

        return store, audit_log

    def _permitted_connectors(
        self,
        seed: Entity,
        authorization: Authorization,
        shared_http: RateLimitedAsyncClient,
        audit_log: list[dict[str, Any]],
        *,
        max_depth: int,
    ) -> list[tuple[Connector, CollectionContext]]:
        eligible = [connector for connector in self.connectors if seed.type in connector.accepts]
        permitted: list[tuple[Connector, CollectionContext]] = []
        for connector in eligible:
            if max_depth == 0 and connector.name == "dns":
                continue
            if (
                seed.type in {EntityType.IPAddress, EntityType.Vulnerability}
                and connector.enrichment_class != EnrichmentClass.IDENTIFICATION
                and not authorization.covers(seed)
            ):
                audit_log.append(
                    {
                        "event": "exposure_connector_refused",
                        "connector": connector.name,
                        "seed_id": seed.id,
                        "seed_value": seed.value,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
                continue
            if connector.mode == CollectionMode.ACTIVE and not authorization.covers(seed):
                refusal = {
                    "event": "active_connector_refused",
                    "connector": connector.name,
                    "seed_id": seed.id,
                    "seed_value": seed.value,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                audit_log.append(refusal)
                self.logger.warning(
                    "active_connector_refused",
                    connector=connector.name,
                    seed_id=seed.id,
                    seed_value=seed.value,
                )
                continue
            permitted.append(
                (
                    connector,
                    CollectionContext(
                        http=AuditedHttpClient(shared_http, connector.name, audit_log),
                        cache={},
                        config=self.config,
                        logger=get_logger(f"osint.connector.{connector.name}"),
                        authorization=authorization,
                    ),
                )
            )
        return permitted

    def _can_enqueue_entity(self, entity: Entity, authorization: Authorization) -> bool:
        if entity.type in {EntityType.IPAddress, EntityType.Vulnerability}:
            return is_pivot_eligible(
                entity,
                authorization,
                has_identification_enrichment=self._has_identification_enrichment(entity),
            )
        return (
            entity.type in {entity_type for connector in self.connectors for entity_type in connector.accepts}
            and is_pivot_eligible(entity, authorization)
        )

    def _has_identification_enrichment(self, entity: Entity) -> bool:
        return any(
            entity.type in connector.accepts
            and connector.enrichment_class == EnrichmentClass.IDENTIFICATION
            for connector in self.connectors
        )

    async def _collect_into_store(
        self,
        connector: Connector,
        seed: Entity,
        ctx: CollectionContext,
        store: EntityStore,
    ) -> list[Entity]:
        discovered: list[Entity] = []
        async for finding in connector.collect(seed, ctx):
            for entity in finding.entities:
                store.upsert_entity(entity)
                discovered.append(entity)
            for relationship in finding.relationships:
                store.upsert_relationship(relationship)
        return discovered
