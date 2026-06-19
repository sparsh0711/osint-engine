from __future__ import annotations

from osint.agent.graph_view import GraphView
from osint.agent.report import render_report
from osint.agent.schema import (
    Finding,
    Priority,
    RejectedFinding,
    ValidatedAction,
    ValidationResult,
)
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.store.memory import MemoryEntityStore


def test_report_renders_validated_findings_sources_and_rejection_appendix() -> None:
    store = MemoryEntityStore()
    service = Entity(
        type=EntityType.Service,
        value="8.8.8.8:443",
        attributes={"port": 443},
        sources=[
            Provenance(
                connector="internetdb",
                source="shodan-internetdb",
                query="query",
                raw_ref={"test": True},
            )
        ],
        confidence=0.8,
    )
    store.upsert_entity(service)
    graph = GraphView(store)
    valid = Finding(
        id="valid",
        claim="Validated service exposure.",
        rationale="Cited service exists.",
        priority=Priority.HIGH,
        supporting_entity_ids=[service.id],
    )
    rejected = Finding(
        id="bad",
        claim="Fabricated exposure.",
        rationale="No support.",
        priority=Priority.HIGH,
    )

    report = render_report(
        ValidationResult(
            findings=[valid],
            rejected_findings=[
                RejectedFinding(finding=rejected, reasons=["missing supporting entity"])
            ],
            recommended_actions=[
                ValidatedAction(
                    action={
                        "action": "enrich IP",
                        "target": service.id,
                        "rationale": "Follow up.",
                        "authorization_required": "Authorize 8.8.8.0/24",
                    }
                )
            ],
        ),
        graph,
    )

    body, appendix = report.split("## Rejected/unverifiable claims")
    assert "Validated service exposure." in body
    assert "internetdb/shodan-internetdb confidence=0.80" in body
    assert "Fabricated exposure." not in body
    assert "Fabricated exposure." in appendix
    assert "Authorize 8.8.8.0/24" in report
