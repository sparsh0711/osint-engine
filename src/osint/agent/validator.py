from __future__ import annotations

from typing import Any

from osint.agent.graph_view import GraphView
from osint.agent.schema import (
    AgentOutput,
    Finding,
    RecommendedAction,
    RejectedFinding,
    ValidatedAction,
    ValidationResult,
)
from osint.core.entities import Entity

AUTHORIZATION_KEYWORDS = {
    "active",
    "collect",
    "enrich",
    "probe",
    "scan",
    "screenshot",
    "validate",
    "lookup",
}


def validate_agent_output(output: AgentOutput, graph: GraphView) -> ValidationResult:
    valid_findings: list[Finding] = []
    rejected: list[RejectedFinding] = []

    for finding in output.findings:
        reasons = _finding_rejection_reasons(finding, graph)
        if reasons:
            rejected.append(RejectedFinding(finding=finding, reasons=reasons))
        else:
            valid_findings.append(finding)

    actions = [
        ValidatedAction(action=action, warnings=_action_warnings(action, graph))
        for action in output.recommended_actions
    ]
    return ValidationResult(
        findings=valid_findings,
        rejected_findings=rejected,
        recommended_actions=actions,
    )


def _finding_rejection_reasons(finding: Finding, graph: GraphView) -> list[str]:
    reasons: list[str] = []
    if not finding.supporting_entity_ids and not finding.supporting_relationship_ids:
        reasons.append("finding has no supporting graph IDs")

    for entity_id in finding.supporting_entity_ids:
        item = graph.get(entity_id)
        if not isinstance(item, Entity):
            reasons.append(f"missing supporting entity: {entity_id}")

    for relationship_id in finding.supporting_relationship_ids:
        if relationship_id not in graph.relationships:
            reasons.append(f"missing supporting relationship: {relationship_id}")

    for check in finding.checks:
        item = graph.get(check.entity_id)
        if not isinstance(item, Entity):
            reasons.append(f"check references missing entity: {check.entity_id}")
            continue
        if check.entity_id not in finding.supporting_entity_ids:
            reasons.append(f"check entity is not cited by finding: {check.entity_id}")
            continue

        actual = _entity_attribute(item, check.attribute)
        if actual != check.expected:
            reasons.append(
                f"check mismatch for {check.entity_id}.{check.attribute}: "
                f"expected {check.expected!r}, got {actual!r}"
            )
    return reasons


def _entity_attribute(entity: Entity, attribute: str) -> Any:
    if attribute in entity.attributes:
        return entity.attributes[attribute]
    return getattr(entity, attribute, None)


def _action_warnings(action: RecommendedAction, graph: GraphView) -> list[str]:
    warnings: list[str] = []
    missing_targets = _missing_target_entity_ids(action, graph)
    if missing_targets:
        warnings.append(
            "recommended action target does not reference a real entity: "
            + ", ".join(missing_targets)
        )
    elif not action.target_entity_ids and _target_entity(action.target, graph) is None:
        warnings.append(f"recommended action target does not reference a real entity: {action.target}")

    text = f"{action.action} {action.rationale}".lower()
    if _authorization_missing(action.authorization_required) and _needs_authorization(text):
        action.authorization_required = _inferred_authorization(action)
    return warnings


def _missing_target_entity_ids(action: RecommendedAction, graph: GraphView) -> list[str]:
    missing: list[str] = []
    for entity_id in action.target_entity_ids:
        if not isinstance(graph.get(entity_id), Entity):
            missing.append(entity_id)
    return missing


def _authorization_missing(value: str | None) -> bool:
    if value is None:
        return True
    return value.strip().lower() in {"", "none", "null", "n/a", "not required"}


def _needs_authorization(text: str) -> bool:
    return any(keyword in text for keyword in AUTHORIZATION_KEYWORDS) or any(
        phrase in text
        for phrase in (
            "port scan",
            "reverse dns",
            "dns lookup",
            "active probing",
        )
    )


def _inferred_authorization(action: RecommendedAction) -> str:
    if action.target:
        return f"Authorization required before active work against {action.target}"
    return "Authorization required before active or scope-expanding work"


def _target_entity(target: str, graph: GraphView) -> Entity | None:
    item = graph.get(target)
    if isinstance(item, Entity):
        return item
    for entity in graph.entities.values():
        if entity.value == target:
            return entity
    return None
