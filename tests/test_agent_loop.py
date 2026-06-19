from __future__ import annotations

from osint.agent.graph_view import GraphView
from osint.agent.llm import AgentRunner, LLMResponse, ToolCall
from osint.agent.report import render_report
from osint.agent.schema import AgentOutput, Check, Finding, Priority
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.store.memory import MemoryEntityStore


async def test_agent_loop_executes_tools_and_drops_fabricated_finding() -> None:
    graph, service = _graph()
    valid = Finding(
        id="valid",
        claim="Port 443 is exposed.",
        rationale="The service entity has port 443.",
        priority=Priority.HIGH,
        supporting_entity_ids=[service.id],
        checks=[Check(entity_id=service.id, attribute="port", expected=443)],
    )
    fabricated = Finding(
        id="fabricated",
        claim="Port 22 is exposed.",
        rationale="The check contradicts the graph.",
        priority=Priority.HIGH,
        supporting_entity_ids=[service.id],
        checks=[Check(entity_id=service.id, attribute="port", expected=22)],
    )
    fake = FakeLLM(
        [
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="tool-1",
                        name="get_entity",
                        arguments={"entity_id": service.id},
                    )
                ]
            ),
            LLMResponse(final_output=AgentOutput(findings=[valid, fabricated])),
        ]
    )

    result = await AgentRunner(fake, max_tool_iterations=3).run(graph)

    assert fake.calls == 2
    assert fake.saw_tool_result is True
    assert [finding.id for finding in result.findings] == ["valid"]
    assert [item.finding.id for item in result.rejected_findings] == ["fabricated"]
    report = render_report(result, graph)
    body, appendix = report.split("## Rejected/unverifiable claims")
    assert "Port 22 is exposed." not in body
    assert "Port 22 is exposed." in appendix


async def test_agent_loop_respects_iteration_cap() -> None:
    graph, service = _graph()
    fake = FakeLLM(
        [
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id=f"tool-{index}",
                        name="get_entity",
                        arguments={"entity_id": service.id},
                    )
                ]
            )
            for index in range(5)
        ]
    )

    result = await AgentRunner(fake, max_tool_iterations=1).run(graph)

    assert fake.calls == 2
    assert result.findings == []


class FakeLLM:
    def __init__(self, responses: list[LLMResponse]) -> None:
        self.responses = responses
        self.calls = 0
        self.saw_tool_result = False

    async def complete(self, messages, tools):
        self.calls += 1
        self.saw_tool_result = self.saw_tool_result or any(
            message.get("role") == "tool" for message in messages
        )
        return self.responses.pop(0)


def _graph() -> tuple[GraphView, Entity]:
    store = MemoryEntityStore()
    service = Entity(
        type=EntityType.Service,
        value="8.8.8.8:443",
        attributes={"ip": "8.8.8.8", "port": 443},
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
    return GraphView(store), service
