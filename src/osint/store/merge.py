from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from osint.core.provenance import Provenance


def source_confidences(sources: list[Provenance], confidence: float) -> dict[str, float]:
    confidences: dict[str, float] = {}
    for source in sources:
        confidences[source.source] = max(confidences.get(source.source, 0.0), confidence)
    return confidences


def merge_source_confidences(
    existing_map: dict[str, float], incoming_map: dict[str, float]
) -> dict[str, float]:
    merged = dict(existing_map)
    for source, confidence in incoming_map.items():
        merged[source] = max(merged.get(source, 0.0), confidence)
    return merged


def noisy_or(source_confidences: dict[str, float]) -> float:
    product = 1.0
    for confidence in source_confidences.values():
        product *= 1.0 - confidence
    return min(0.99, 1.0 - product)


def merge_sources(
    existing: list[Provenance], incoming: list[Provenance]
) -> list[Provenance]:
    by_key: dict[str, Provenance] = {}
    for source in [*existing, *incoming]:
        key = json.dumps(source.model_dump(mode="json"), sort_keys=True, default=str)
        by_key[key] = source
    return [by_key[key] for key in sorted(by_key)]


def merge_attributes(
    existing: dict[str, Any], incoming: dict[str, Any], prefix: str = ""
) -> dict[str, Any]:
    merged = deepcopy(existing)
    conflicts = deepcopy(merged.pop("_conflicts", {}))
    incoming_without_conflicts = {
        key: value for key, value in incoming.items() if key != "_conflicts"
    }

    for key, incoming_value in incoming_without_conflicts.items():
        path = f"{prefix}.{key}" if prefix else key
        if incoming_value is None:
            continue
        if key not in merged or merged[key] is None:
            merged[key] = deepcopy(incoming_value)
            continue

        existing_value = merged[key]
        if isinstance(existing_value, dict) and isinstance(incoming_value, dict):
            nested = merge_attributes(existing_value, incoming_value, path)
            nested_conflicts = nested.pop("_conflicts", {})
            merged[key] = nested
            conflicts.update(nested_conflicts)
            continue

        if existing_value != incoming_value:
            conflicts.setdefault(path, [])
            conflict = {"existing": existing_value, "incoming": incoming_value}
            if conflict not in conflicts[path]:
                conflicts[path].append(conflict)

    if conflicts:
        merged["_conflicts"] = conflicts
    return merged
