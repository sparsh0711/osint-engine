from __future__ import annotations

from typing import Any

from osint.agent.graph_view import GraphView
from osint.core.entities import Entity, EntityType
from osint.core.relationships import RelationType, Relationship


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "search_entities",
        "description": "Search graph entities by optional type and substring.",
        "input_schema": {
            "type": "object",
            "properties": {
                "entity_type": {"type": "string"},
                "query": {"type": "string"},
            },
        },
    },
    {
        "name": "get_entity",
        "description": "Return one entity by ID.",
        "input_schema": {
            "type": "object",
            "properties": {"entity_id": {"type": "string"}},
            "required": ["entity_id"],
        },
    },
    {
        "name": "get_neighbors",
        "description": "Return neighboring entities and relationships.",
        "input_schema": {
            "type": "object",
            "properties": {
                "entity_id": {"type": "string"},
                "rel_type": {"type": "string"},
                "direction": {"type": "string"},
            },
            "required": ["entity_id"],
        },
    },
    {
        "name": "list_unenriched_ips",
        "description": "List IPAddress entities without HOSTS relationships.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "graph_summary",
        "description": "Return graph counts and confidence distribution.",
        "input_schema": {"type": "object", "properties": {}},
    },
]


def execute_tool(graph: GraphView, name: str, arguments: dict[str, Any]) -> Any:
    if name == "search_entities":
        return _search_entities(
            graph,
            arguments.get("entity_type"),
            arguments.get("query"),
        )
    if name == "get_entity":
        item = graph.get(str(arguments["entity_id"]))
        return _serialize_item(item)
    if name == "get_neighbors":
        rel_type = arguments.get("rel_type")
        direction = arguments.get("direction", "both")
        return [
            {
                "relationship": _serialize_relationship(item["relationship"]),
                "entity": _serialize_entity(item["entity"]),
            }
            for item in graph.neighbors(
                str(arguments["entity_id"]),
                rel_type=rel_type,
                direction=direction,
            )
        ]
    if name == "list_unenriched_ips":
        return [_serialize_entity(entity) for entity in graph.unenriched_ips()]
    if name == "graph_summary":
        return graph.summary()
    raise ValueError(f"unknown agent tool: {name}")


def _search_entities(
    graph: GraphView,
    entity_type: str | None,
    query: str | None,
) -> list[dict[str, Any]]:
    if entity_type:
        try:
            entities = graph.by_type(EntityType(entity_type))
        except ValueError:
            return []
    else:
        entities = list(graph.entities.values())

    if query:
        query_lower = query.lower()
        entities = [
            entity
            for entity in entities
            if query_lower in entity.value.lower() or query_lower in (entity.id or "")
        ]
    return [_serialize_entity(entity) for entity in sorted(entities, key=lambda item: item.id or "")]


def _serialize_item(item: Entity | Relationship | None) -> dict[str, Any] | None:
    if isinstance(item, Entity):
        return _serialize_entity(item)
    if isinstance(item, Relationship):
        return _serialize_relationship(item)
    return None


def _serialize_entity(entity: Entity) -> dict[str, Any]:
    return entity.model_dump(mode="json")


def _serialize_relationship(relationship: Relationship) -> dict[str, Any]:
    return relationship.model_dump(mode="json")
