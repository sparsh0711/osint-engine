from __future__ import annotations

from collections import defaultdict

from osint.agent.graph_view import GraphView
from osint.agent.schema import Priority, ValidationResult
from osint.core.entities import Entity


def render_report(result: ValidationResult, graph: GraphView) -> str:
    lines: list[str] = [
        "# OSINT Investigation Report",
        "",
        "## Findings",
        "",
    ]

    by_priority = defaultdict(list)
    for finding in result.findings:
        by_priority[finding.priority].append(finding)

    for priority in (Priority.HIGH, Priority.MEDIUM, Priority.LOW):
        lines.append(f"### {priority.value.title()} Priority")
        lines.append("")
        findings = sorted(by_priority.get(priority, []), key=lambda item: item.id)
        if not findings:
            lines.append("No validated findings.")
            lines.append("")
            continue

        for finding in findings:
            lines.append(f"- **{finding.claim}**")
            lines.append(f"  Rationale: {finding.rationale}")
            lines.append(f"  Cites: {', '.join(_citation_labels(finding.supporting_entity_ids, graph))}")
            relationship_ids = ", ".join(finding.supporting_relationship_ids) or "none"
            lines.append(f"  Relationships: {relationship_ids}")
            lines.append(f"  Sources: {', '.join(_source_labels(finding.supporting_entity_ids, graph))}")
            lines.append("")

    lines.extend(["## Recommended Next Steps", ""])
    if not result.recommended_actions:
        lines.extend(["No recommendations.", ""])
    for item in result.recommended_actions:
        action = item.action
        lines.append(f"- **{action.action}**: {action.target}")
        lines.append(f"  Rationale: {action.rationale}")
        auth = action.authorization_required or "none stated"
        lines.append(f"  Authorization required: {auth}")
        if item.warnings:
            lines.append(f"  Warnings: {'; '.join(item.warnings)}")
        lines.append("")

    lines.extend(["## Rejected/unverifiable claims", ""])
    if not result.rejected_findings:
        lines.extend(["None.", ""])
    for rejected in result.rejected_findings:
        lines.append(f"- **{rejected.finding.claim}**")
        lines.append(f"  Reasons: {'; '.join(rejected.reasons)}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _citation_labels(entity_ids: list[str], graph: GraphView) -> list[str]:
    labels: list[str] = []
    for entity_id in entity_ids:
        item = graph.get(entity_id)
        if isinstance(item, Entity):
            labels.append(f"{item.type.value} {item.value} ({entity_id})")
    return labels or ["none"]


def _source_labels(entity_ids: list[str], graph: GraphView) -> list[str]:
    labels: set[str] = set()
    for entity_id in entity_ids:
        item = graph.get(entity_id)
        if not isinstance(item, Entity):
            continue
        for source in item.sources:
            labels.add(f"{source.connector}/{source.source} confidence={item.confidence:.2f}")
    return sorted(labels) or ["none"]
