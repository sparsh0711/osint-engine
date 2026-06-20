from __future__ import annotations

from osint.agent.graph_view import GraphView
from osint.agent.llm import (
    SYSTEM_PROMPT,
    AgentRunner,
    LLMResponse,
    ToolCall,
    _agent_output_response,
)
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


async def test_agent_loop_returns_tool_error_and_still_renders_report() -> None:
    graph, service = _graph()
    valid = Finding(
        id="valid",
        claim="Port 443 is exposed.",
        rationale="The service entity has port 443.",
        priority=Priority.HIGH,
        supporting_entity_ids=[service.id],
        checks=[Check(entity_id=service.id, attribute="port", expected=443)],
    )
    fake = FakeLLM(
        [
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="bad-tool",
                        name="get_neighbors",
                        arguments={"entity_id": service.id, "rel_type": "__LINK__"},
                    )
                ]
            ),
            LLMResponse(final_output=AgentOutput(findings=[valid])),
        ]
    )

    result = await AgentRunner(fake, max_tool_iterations=3).run(graph)
    report = render_report(result, graph)

    assert [finding.id for finding in result.findings] == ["valid"]
    assert "Port 443 is exposed." in report
    assert any(
        message.get("role") == "tool"
        and message["content"][0]["result"]["error"].startswith("invalid rel_type")
        for message in fake.messages_seen
    )


async def test_agent_loop_parses_variant_final_output_fields() -> None:
    graph, service = _graph()
    fake = RawFinalLLM(
        {
            "findings": [
                {
                    "description": "Service is exposed.",
                    "explanation": "The cited service has port 443.",
                    "severity": "high",
                    "supporting_entity_ids": [service.id],
                    "checks": [
                        {
                            "entity_id": service.id,
                            "attribute": "port",
                            "expected": 443,
                        }
                    ],
                }
            ]
        }
    )

    result = await AgentRunner(fake).run(graph)

    assert len(result.findings) == 1
    assert result.findings[0].id == "f1"
    assert result.findings[0].claim == "Service is exposed."
    assert result.findings[0].rationale == "The cited service has port 443."
    assert result.findings[0].priority.value == "high"


async def test_agent_loop_skips_one_malformed_finding_and_keeps_valid_one() -> None:
    graph, service = _graph()
    fake = RawFinalLLM(
        {
            "findings": [
                {"not_a_claim": "cannot be coerced"},
                {
                    "id": "valid",
                    "claim": "Port 443 is exposed.",
                    "rationale": "The cited service has port 443.",
                    "priority": "high",
                    "supporting_entity_ids": [service.id],
                    "checks": [
                        {
                            "entity_id": service.id,
                            "attribute": "port",
                            "expected": 443,
                        }
                    ],
                },
            ]
        }
    )

    result = await AgentRunner(fake).run(graph)

    assert [finding.id for finding in result.findings] == ["valid"]


async def test_agent_loop_strict_final_output_still_parses() -> None:
    graph, service = _graph()
    fake = RawFinalLLM(
        {
            "findings": [
                {
                    "id": "strict",
                    "claim": "Port 443 is exposed.",
                    "rationale": "The cited service has port 443.",
                    "priority": "high",
                    "supporting_entity_ids": [service.id],
                    "supporting_relationship_ids": [],
                    "checks": [],
                }
            ],
            "recommended_actions": [],
        }
    )

    result = await AgentRunner(fake).run(graph)

    assert [finding.id for finding in result.findings] == ["strict"]


async def test_agent_loop_coerces_observed_gemini_shape_to_valid_finding() -> None:
    graph, service = _graph()
    fake = RawFinalLLM(
        {
            "findings": [
                {
                    "entity_id": service.id,
                    "finding": "Found service exposure on port 443.",
                    "explanation": "The cited service is present in the graph.",
                    "severity": "medium",
                }
            ],
            "next_steps": [
                {
                    "step": f"Review service entity {service.id} for authorization requirements."
                }
            ],
        }
    )

    result = await AgentRunner(fake).run(graph)

    assert [finding.id for finding in result.findings] == ["f1"]
    assert result.findings[0].claim == "Found service exposure on port 443."
    assert result.findings[0].supporting_entity_ids == [service.id]
    assert result.recommended_actions[0].action.target == service.id
    assert result.recommended_actions[0].warnings == []


async def test_agent_loop_coerces_next_steps_entity_targets_and_active_authorization() -> None:
    graph, service = _graph()
    fake = RawFinalLLM(
        {
            "findings": [
                {
                    "id": "f1",
                    "claim": "Service is present.",
                    "rationale": "The cited service is in the graph.",
                    "priority": "medium",
                    "supporting_entity_ids": [service.id],
                    "supporting_relationship_ids": [],
                    "checks": [],
                }
            ],
            "next_steps": [
                {
                    "step": f"Perform a port scan on the identified entity {service.id}."
                }
            ],
        }
    )

    result = await AgentRunner(fake).run(graph)

    action = result.recommended_actions[0]
    assert action.action.target == service.id
    assert action.action.target_entity_ids == [service.id]
    assert action.action.authorization_required is not None
    assert action.warnings == []


async def test_agent_loop_drops_username_profile_content_identity_recommendation() -> None:
    graph, username = _username_graph()
    fake = RawFinalLLM(
        {
            "findings": [
                {
                    "id": "f1",
                    "claim": (
                        "The handle alice appears to exist on ExampleSite; handle "
                        "collision means it may belong to a different person."
                    ),
                    "rationale": "The cited Username entity has account_status exists.",
                    "priority": "medium",
                    "supporting_entity_ids": [username.id],
                    "supporting_relationship_ids": [],
                    "checks": [
                        {
                            "entity_id": username.id,
                            "attribute": "account_status",
                            "expected": "exists",
                        }
                    ],
                }
            ],
            "recommended_actions": [
                {
                    "action": (
                        "Review profile content to verify whether same-handle "
                        "accounts belong to the same individual."
                    ),
                    "target": username.id,
                    "target_entity_ids": [username.id],
                    "rationale": "Look for identifying information across profiles.",
                    "authorization_required": None,
                }
            ],
        }
    )

    result = await AgentRunner(fake).run(graph)

    assert [finding.id for finding in result.findings] == ["f1"]
    assert result.recommended_actions == []


def test_system_prompt_frames_username_hits_as_unverified_same_handle_leads() -> None:
    prompt = SYSTEM_PROMPT.lower()

    assert "username/account-existence results are independent, unverified leads" in prompt
    assert "never claim that accounts sharing a username belong to the same person" in prompt
    assert "handle collision" in prompt
    assert "may belong to different people" in prompt
    assert "must not suggest scraping/reviewing profile content" in prompt
    assert "explicit account-owner confirmation" in prompt


class FakeLLM:
    def __init__(self, responses: list[LLMResponse]) -> None:
        self.responses = responses
        self.calls = 0
        self.saw_tool_result = False
        self.messages_seen = []

    async def complete(self, messages, tools):
        self.calls += 1
        self.messages_seen.extend(messages)
        self.saw_tool_result = self.saw_tool_result or any(
            message.get("role") == "tool" for message in messages
        )
        return self.responses.pop(0)


class RawFinalLLM:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    async def complete(self, messages, tools):
        import json

        return _agent_output_response(json.dumps(self.payload))


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


def _username_graph() -> tuple[GraphView, Entity]:
    store = MemoryEntityStore()
    username = Entity(
        type=EntityType.Username,
        value="ExampleSite:alice",
        attributes={
            "platform": "ExampleSite",
            "profile_url": "https://example.test/alice",
            "account_status": "exists",
        },
        sources=[
            Provenance(
                connector="usernames",
                source="whatsmyname",
                query="https://example.test/alice",
                raw_ref={"test": True},
            )
        ],
        confidence=0.5,
    )
    store.upsert_entity(username)
    return GraphView(store), username
