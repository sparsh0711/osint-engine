from __future__ import annotations

from osint.agent.graph_view import GraphView
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType, Relationship
from osint.store.memory import MemoryEntityStore


def test_graph_view_neighbors_filters_unenriched_ips_and_co_sans() -> None:
    store = _store()
    root = _entity(EntityType.Domain, "example.com", {"under_seed": True}, 0.9)
    co_san = _entity(
        EntityType.Domain,
        "vendor.net",
        {"under_seed": False},
        0.7,
        tags={"co-san"},
    )
    ip_with_service = _entity(EntityType.IPAddress, "8.8.8.8", {"version": 4}, 0.98)
    ip_without_service = _entity(EntityType.IPAddress, "1.1.1.1", {"version": 4}, 0.9)
    service = _entity(
        EntityType.Service,
        "8.8.8.8:443",
        {"ip": "8.8.8.8", "port": 443},
        0.8,
    )
    for entity in [root, co_san, ip_with_service, ip_without_service, service]:
        store.upsert_entity(entity)
    hosts = Relationship(
        type=RelationType.HOSTS,
        src_id=ip_with_service.id,
        dst_id=service.id,
        sources=[_provenance("internetdb")],
        confidence=0.8,
    )
    store.upsert_relationship(hosts)

    graph = GraphView(store)

    assert graph.get(root.id) == root
    assert [entity.value for entity in graph.by_type(EntityType.IPAddress)] == [
        "1.1.1.1",
        "8.8.8.8",
    ]
    assert [entity.value for entity in graph.by_tag("co-san")] == ["vendor.net"]
    assert graph.neighbors(ip_with_service.id, RelationType.HOSTS, "out")[0]["entity"] == service
    assert [entity.value for entity in graph.unenriched_ips()] == ["1.1.1.1"]
    assert [entity.value for entity in graph.co_san_domains()] == ["vendor.net"]
    assert [entity.value for entity in graph.high_confidence(0.95)] == ["8.8.8.8"]


def _store() -> MemoryEntityStore:
    return MemoryEntityStore()


def _entity(
    type_: EntityType,
    value: str,
    attributes: dict,
    confidence: float,
    tags: set[str] | None = None,
) -> Entity:
    return Entity(
        type=type_,
        value=value,
        attributes=attributes,
        sources=[_provenance("test")],
        confidence=confidence,
        tags=tags or set(),
    )


def _provenance(source: str) -> Provenance:
    return Provenance(
        connector=source,
        source=source,
        query=source,
        raw_ref={"test": source},
    )
