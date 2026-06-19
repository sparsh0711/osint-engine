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
    try:
        if not isinstance(arguments, dict):
            return _tool_error("tool arguments must be an object")
        if name == "search_entities":
            return _search_entities(
                graph,
                arguments.get("entity_type"),
                arguments.get("query"),
            )
        if name == "get_entity":
            entity_id = _required_string(arguments, "entity_id")
            item = graph.get(entity_id)
            if item is None:
                return _tool_error(f"unknown entity_id '{entity_id}'")
            return _serialize_item(item)
        if name == "get_neighbors":
            entity_id = _required_string(arguments, "entity_id")
            if graph.get(entity_id) is None:
                return _tool_error(f"unknown entity_id '{entity_id}'")
            rel_type = arguments.get("rel_type")
            direction = arguments.get("direction", "both")
            if rel_type is not None:
                rel_type = _validated_relation_type(rel_type)
            direction = _validated_direction(direction)
            return [
                {
                    "relationship": _serialize_relationship(item["relationship"]),
                    "entity": _serialize_entity(item["entity"]),
                }
                for item in graph.neighbors(
                    entity_id,
                    rel_type=rel_type,
                    direction=direction,
                )
            ]
        if name == "list_unenriched_ips":
            return [_serialize_entity(entity) for entity in graph.unenriched_ips()]
        if name == "graph_summary":
            return graph.summary()
    except ValueError as exc:
        return _tool_error(str(exc))
    raise ValueError(f"unknown agent tool: {name}")


def _search_entities(
    graph: GraphView,
    entity_type: Any,
    query: Any,
) -> list[dict[str, Any]] | dict[str, str]:
    if entity_type:
        try:
            entities = graph.by_type(_validated_entity_type(entity_type))
        except ValueError as exc:
            return _tool_error(str(exc))
    else:
        entities = list(graph.entities.values())

    if query is not None and not isinstance(query, str):
        return _tool_error("query must be a string")
    if query:
        query_lower = query.lower()
        entities = [
            entity
            for entity in entities
            if query_lower in entity.value.lower() or query_lower in (entity.id or "")
        ]
    return [_serialize_entity(entity) for entity in sorted(entities, key=lambda item: item.id or "")]


def _required_string(arguments: dict[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing or invalid required argument '{name}'")
    return value


def _validated_entity_type(value: Any) -> EntityType:
    if not isinstance(value, str):
        raise ValueError("entity_type must be a string")
    try:
        return EntityType(value)
    except ValueError:
        valid = ", ".join(item.value for item in EntityType)
        raise ValueError(f"invalid entity_type '{value}'; valid values are: {valid}") from None


def _validated_relation_type(value: Any) -> RelationType:
    if not isinstance(value, str):
        raise ValueError("rel_type must be a string")
    try:
        return RelationType(value)
    except ValueError:
        valid = ", ".join(item.value for item in RelationType)
        raise ValueError(f"invalid rel_type '{value}'; valid values are: {valid}") from None


def _validated_direction(value: Any) -> str:
    if value not in {"out", "in", "both"}:
        raise ValueError("direction must be one of: out, in, both")
    return value


def _tool_error(message: str) -> dict[str, str]:
    return {"error": message}


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
