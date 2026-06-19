from __future__ import annotations

import json
import os
from typing import Any, Protocol

from pydantic import BaseModel, Field

from osint.agent.graph_view import GraphView
from osint.agent.schema import AgentOutput, ValidationResult
from osint.agent.tools import TOOL_DEFINITIONS, execute_tool
from osint.agent.validator import validate_agent_output


SYSTEM_PROMPT = """You are a grounded OSINT triage agent.
Use only the graph tools. Return final JSON matching AgentOutput.
Every finding must cite real entity or relationship IDs.
Do not propose collection as already executed; recommend next steps only."""


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class LLMResponse(BaseModel):
    tool_calls: list[ToolCall] = Field(default_factory=list)
    final_output: AgentOutput | None = None


class LLMClient(Protocol):
    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        ...


class AgentRunner:
    def __init__(self, client: LLMClient, max_tool_iterations: int = 5) -> None:
        self.client = client
        self.max_tool_iterations = max_tool_iterations

    async def run(self, graph: GraphView) -> ValidationResult:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(graph.summary(), sort_keys=True)},
        ]

        for _ in range(self.max_tool_iterations + 1):
            response = await self.client.complete(messages, TOOL_DEFINITIONS)
            if response.final_output is not None:
                return validate_agent_output(response.final_output, graph)

            if not response.tool_calls:
                break

            tool_results: list[dict[str, Any]] = []
            for call in response.tool_calls:
                tool_results.append(
                    {
                        "tool_call_id": call.id,
                        "name": call.name,
                        "result": execute_tool(graph, call.name, call.arguments),
                    }
                )
            messages.append({"role": "assistant", "tool_calls": [call.model_dump() for call in response.tool_calls]})
            messages.append({"role": "tool", "content": tool_results})

        return validate_agent_output(AgentOutput(), graph)


class AnthropicLLMClient:
    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        api_key: str | None = None,
        max_tokens: int = 4000,
    ) -> None:
        from anthropic import AsyncAnthropic

        self.client = AsyncAnthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.model = model
        self.max_tokens = max_tokens

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        system, anthropic_messages = _anthropic_messages(messages)
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            tools=tools,
            messages=anthropic_messages,
        )

        tool_calls: list[ToolCall] = []
        text_parts: list[str] = []
        for block in response.content:
            block_type = getattr(block, "type", None)
            if block_type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        name=block.name,
                        arguments=dict(block.input or {}),
                    )
                )
            elif block_type == "text":
                text_parts.append(block.text)

        if tool_calls:
            return LLMResponse(tool_calls=tool_calls)

        payload = json.loads("\n".join(text_parts))
        return LLMResponse(final_output=AgentOutput.model_validate(payload))


def _anthropic_messages(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    system = SYSTEM_PROMPT
    converted: list[dict[str, Any]] = []
    for message in messages:
        role = message["role"]
        if role == "system":
            system = str(message["content"])
        elif role == "tool":
            converted.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": item["tool_call_id"],
                            "content": json.dumps(item["result"], sort_keys=True),
                        }
                        for item in message["content"]
                    ],
                }
            )
        elif role == "assistant" and "tool_calls" in message:
            converted.append(
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": item["id"],
                            "name": item["name"],
                            "input": item.get("arguments", {}),
                        }
                        for item in message["tool_calls"]
                    ],
                }
            )
        else:
            converted.append({"role": role, "content": str(message["content"])})
    return system, converted
