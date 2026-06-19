from __future__ import annotations

from osint.agent.graph_view import GraphView
from osint.agent.tools import execute_tool
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.store.memory import MemoryEntityStore


def test_get_neighbors_invalid_rel_type_returns_error_result() -> None:
    graph, entity = _graph()

    result = execute_tool(
        graph,
        "get_neighbors",
        {"entity_id": entity.id, "rel_type": "__LINK__"},
    )

    assert result["error"].startswith("invalid rel_type '__LINK__'")
    assert "HAS_SUBDOMAIN" in result["error"]


def test_get_neighbors_unknown_entity_returns_error_result() -> None:
    graph, _entity = _graph()

    result = execute_tool(graph, "get_neighbors", {"entity_id": "missing"})

    assert result == {"error": "unknown entity_id 'missing'"}


def _graph() -> tuple[GraphView, Entity]:
    store = MemoryEntityStore()
    entity = Entity(
        type=EntityType.Domain,
        value="example.com",
        attributes={"under_seed": True},
        sources=[
            Provenance(
                connector="test",
                source="test",
                query="example.com",
                raw_ref={"test": True},
            )
        ],
        confidence=1.0,
    )
    store.upsert_entity(entity)
    return GraphView(store), entity
