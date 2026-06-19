from __future__ import annotations

from osint.agent.graph_view import GraphView
from osint.agent.schema import AgentOutput, Check, Finding, Priority, RecommendedAction
from osint.agent.validator import validate_agent_output
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.store.memory import MemoryEntityStore


def test_validator_accepts_grounded_finding_with_matching_check() -> None:
    graph, service = _graph()
    output = AgentOutput(
        findings=[
            Finding(
                id="f1",
                claim="Service is exposed on port 80.",
                rationale="The cited service has port 80.",
                priority=Priority.HIGH,
                supporting_entity_ids=[service.id],
                checks=[Check(entity_id=service.id, attribute="port", expected=80)],
            )
        ]
    )

    result = validate_agent_output(output, graph)

    assert [finding.id for finding in result.findings] == ["f1"]
    assert result.rejected_findings == []


def test_validator_rejects_missing_entity_id() -> None:
    graph, _service = _graph()
    output = AgentOutput(
        findings=[
            Finding(
                id="f1",
                claim="Missing entity claim.",
                rationale="No graph support.",
                priority=Priority.MEDIUM,
                supporting_entity_ids=["missing"],
            )
        ]
    )

    result = validate_agent_output(output, graph)

    assert result.findings == []
    assert "missing supporting entity" in result.rejected_findings[0].reasons[0]


def test_validator_rejects_mismatched_check() -> None:
    graph, service = _graph()
    output = AgentOutput(
        findings=[
            Finding(
                id="f1",
                claim="Service is exposed on port 22.",
                rationale="Contradicts the graph.",
                priority=Priority.HIGH,
                supporting_entity_ids=[service.id],
                checks=[Check(entity_id=service.id, attribute="port", expected=22)],
            )
        ]
    )

    result = validate_agent_output(output, graph)

    assert result.findings == []
    assert "check mismatch" in result.rejected_findings[0].reasons[0]


def test_validator_rejects_uncited_finding() -> None:
    graph, _service = _graph()
    output = AgentOutput(
        findings=[
            Finding(
                id="f1",
                claim="Ungrounded claim.",
                rationale="No citations.",
                priority=Priority.LOW,
            )
        ]
    )

    result = validate_agent_output(output, graph)

    assert result.findings == []
    assert result.rejected_findings[0].reasons == ["finding has no supporting graph IDs"]


def test_validator_flags_scope_expanding_action_without_authorization() -> None:
    graph, service = _graph()
    output = AgentOutput(
        recommended_actions=[
            RecommendedAction(
                action="scan service",
                target=service.id,
                rationale="Validate exposure.",
            )
        ]
    )

    result = validate_agent_output(output, graph)

    assert result.recommended_actions[0].warnings == [
        "authorization_required is missing for scope-expanding or active work"
    ]


def _graph() -> tuple[GraphView, Entity]:
    store = MemoryEntityStore()
    service = Entity(
        type=EntityType.Service,
        value="8.8.8.8:80",
        attributes={"ip": "8.8.8.8", "port": 80},
        sources=[_provenance()],
        confidence=0.8,
    )
    store.upsert_entity(service)
    return GraphView(store), service


def _provenance() -> Provenance:
    return Provenance(
        connector="internetdb",
        source="shodan-internetdb",
        query="https://internetdb.shodan.io/8.8.8.8",
        raw_ref={"test": True},
    )
