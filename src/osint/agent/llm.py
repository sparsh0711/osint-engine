from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, Field

from osint.agent.graph_view import GraphView
from osint.agent.schema import (
    AgentOutput,
    Check,
    Finding,
    Priority,
    RecommendedAction,
    ValidationResult,
)
from osint.agent.tools import TOOL_DEFINITIONS, execute_tool
from osint.agent.validator import validate_agent_output


SYSTEM_PROMPT = """You are a grounded OSINT triage agent.
Use only the graph tools. Return final JSON matching AgentOutput.
Every finding must cite real entity or relationship IDs.
Do not propose collection as already executed; recommend next steps only.

Return ONLY this exact JSON shape, with no markdown fences:
{
  "findings": [
    {
      "id": "f1",
      "claim": "Concise factual claim grounded in the graph.",
      "rationale": "Why this matters, using only cited graph evidence.",
      "priority": "high",
      "supporting_entity_ids": ["entity-id-seen-from-tools"],
      "supporting_relationship_ids": ["relationship-id-seen-from-tools"],
      "checks": [
        {"entity_id": "entity-id-seen-from-tools", "attribute": "port", "expected": 443}
      ]
    }
  ],
  "recommended_actions": [
    {
      "action": "Suggested next collection or analysis step.",
      "target": "entity-id-or-value-seen-from-tools",
      "rationale": "Why this is the next step.",
      "authorization_required": "Authorize the target/range if needed, otherwise null"
    }
  ]
}

Rules:
- Every finding MUST include id, claim, rationale, priority, supporting_entity_ids, and supporting_relationship_ids.
- supporting_entity_ids MUST be a list of real entity IDs you saw via tools, never a single string.
- Every finding MUST cite at least one supporting_entity_ids or supporting_relationship_ids entry.
- priority MUST be one of: high, medium, low.
- recommended_actions MUST be a list; use action, target, rationale, authorization_required.
- If you cannot ground a finding in real IDs, do not include it."""

DEFAULT_OPENAI_BASE_URL = "http://localhost:11434/v1"
DEFAULT_OPENAI_MODEL = "qwen2.5:3b"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
DEFAULT_LLM_TIMEOUT = 300.0

logger = logging.getLogger(__name__)


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
                try:
                    result = execute_tool(graph, call.name, call.arguments)
                except Exception as exc:
                    logger.warning(
                        "agent_tool_call_failed",
                        extra={"tool": call.name, "error": str(exc)},
                    )
                    result = {"error": f"tool call failed: {exc}"}
                tool_results.append(
                    {
                        "tool_call_id": call.id,
                        "name": call.name,
                        "result": result,
                    }
                )
            messages.append({"role": "assistant", "tool_calls": [call.model_dump() for call in response.tool_calls]})
            messages.append({"role": "tool", "content": tool_results})

        return validate_agent_output(AgentOutput(), graph)


class AnthropicLLMClient:
    def __init__(
        self,
        model: str = DEFAULT_ANTHROPIC_MODEL,
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
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system,
                tools=tools,
                messages=anthropic_messages,
            )
        except Exception as exc:
            logger.warning("llm_anthropic_failed", exc_info=exc)
            return LLMResponse()

        tool_calls: list[ToolCall] = []
        text_parts: list[str] = []
        known_tools = {tool["name"] for tool in tools}
        for block in response.content:
            block_type = getattr(block, "type", None)
            if block_type == "tool_use":
                if block.name not in known_tools:
                    logger.warning("llm_tool_call_skipped", extra={"reason": "unknown tool", "tool": block.name})
                    continue
                if not isinstance(block.input, dict):
                    logger.warning("llm_tool_call_skipped", extra={"reason": "bad arguments", "tool": block.name})
                    continue
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        name=block.name,
                        arguments=dict(block.input),
                    )
                )
            elif block_type == "text":
                text_parts.append(block.text)

        if tool_calls:
            return LLMResponse(tool_calls=tool_calls)

        return _agent_output_response("\n".join(text_parts))


class OpenAICompatibleLLMClient:
    def __init__(
        self,
        base_url: str = DEFAULT_OPENAI_BASE_URL,
        model: str = DEFAULT_OPENAI_MODEL,
        api_key: str | None = None,
        max_tokens: int = 4000,
        timeout: float = DEFAULT_LLM_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key or "ollama"
        self.max_tokens = max_tokens
        self.client = httpx.AsyncClient(timeout=timeout)

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": _openai_messages(messages),
            "tools": [_openai_tool(tool) for tool in tools],
            "tool_choice": "auto",
            "max_tokens": self.max_tokens,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("llm_openai_compatible_failed", exc_info=exc)
            return LLMResponse()

        message = (body.get("choices") or [{}])[0].get("message") or {}
        tool_calls = _parse_openai_tool_calls(message.get("tool_calls"), tools)
        if tool_calls:
            return LLMResponse(tool_calls=tool_calls)

        return _agent_output_response(str(message.get("content") or ""))

    async def aclose(self) -> None:
        await self.client.aclose()


def create_llm_client(
    provider: str | None = None,
    model: str | None = None,
) -> LLMClient:
    provider = provider or os.environ.get("OSINT_LLM_PROVIDER", "openai_compatible")
    if provider == "anthropic":
        return AnthropicLLMClient(
            model=model or os.environ.get("OSINT_LLM_MODEL", DEFAULT_ANTHROPIC_MODEL),
            api_key=os.environ.get("OSINT_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"),
        )
    if provider == "openai_compatible":
        return OpenAICompatibleLLMClient(
            base_url=os.environ.get("OSINT_LLM_BASE_URL", DEFAULT_OPENAI_BASE_URL),
            model=model or os.environ.get("OSINT_LLM_MODEL", DEFAULT_OPENAI_MODEL),
            api_key=os.environ.get("OSINT_LLM_API_KEY"),
            timeout=_env_float("OSINT_LLM_TIMEOUT", DEFAULT_LLM_TIMEOUT),
        )
    logger.warning("unknown_llm_provider", extra={"provider": provider})
    return OpenAICompatibleLLMClient(
        model=model or DEFAULT_OPENAI_MODEL,
        timeout=_env_float("OSINT_LLM_TIMEOUT", DEFAULT_LLM_TIMEOUT),
    )


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        logger.warning("invalid_float_env", extra={"name": name, "value": value})
        return default


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


def _openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    converted: list[dict[str, Any]] = []
    for message in messages:
        role = message["role"]
        if role == "tool":
            for item in message["content"]:
                converted.append(
                    {
                        "role": "tool",
                        "tool_call_id": item["tool_call_id"],
                        "content": json.dumps(item["result"], sort_keys=True),
                    }
                )
        elif role == "assistant" and "tool_calls" in message:
            converted.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": item["id"],
                            "type": "function",
                            "function": {
                                "name": item["name"],
                                "arguments": json.dumps(item.get("arguments", {})),
                            },
                        }
                        for item in message["tool_calls"]
                    ],
                }
            )
        else:
            converted.append({"role": role, "content": str(message["content"])})
    return converted


def _openai_tool(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "parameters": tool.get("input_schema", {"type": "object"}),
        },
    }


def _parse_openai_tool_calls(
    raw_calls: Any,
    tools: list[dict[str, Any]],
) -> list[ToolCall]:
    if not isinstance(raw_calls, list):
        return []

    known_tools = {tool["name"] for tool in tools}
    parsed: list[ToolCall] = []
    for raw_call in raw_calls:
        function = raw_call.get("function") if isinstance(raw_call, dict) else None
        if not isinstance(function, dict):
            logger.warning("llm_tool_call_skipped", extra={"reason": "missing function"})
            continue
        name = function.get("name")
        if name not in known_tools:
            logger.warning("llm_tool_call_skipped", extra={"reason": "unknown tool", "tool": name})
            continue
        try:
            arguments = json.loads(function.get("arguments") or "{}")
        except json.JSONDecodeError:
            logger.warning("llm_tool_call_skipped", extra={"reason": "bad arguments", "tool": name})
            continue
        if not isinstance(arguments, dict):
            logger.warning("llm_tool_call_skipped", extra={"reason": "non-object arguments", "tool": name})
            continue
        parsed.append(
            ToolCall(
                id=str(raw_call.get("id") or f"tool-{len(parsed)}"),
                name=name,
                arguments=arguments,
            )
        )
    return parsed


def _agent_output_response(text: str) -> LLMResponse:
    _write_raw_final_output(text)
    try:
        payload = json.loads(_extract_json(text))
    except json.JSONDecodeError as exc:
        logger.warning("llm_final_output_unparseable", exc_info=exc)
        return LLMResponse()
    if not isinstance(payload, dict):
        logger.warning("llm_final_output_unparseable reason=top-level JSON is not an object")
        return LLMResponse()
    return LLMResponse(final_output=_coerce_agent_output(payload))


def _coerce_agent_output(payload: dict[str, Any]) -> AgentOutput:
    raw_findings = payload.get("findings", [])
    raw_actions = payload.get(
        "recommended_actions",
        payload.get("recommendations", payload.get("next_steps", [])),
    )
    if not isinstance(raw_findings, list):
        raw_findings = []
    if not isinstance(raw_actions, list):
        raw_actions = []

    findings: list[Finding] = []
    skipped_findings = 0
    for index, raw in enumerate(raw_findings, start=1):
        finding = _coerce_finding(raw, index)
        if finding is None:
            skipped_findings += 1
        else:
            findings.append(finding)

    actions: list[RecommendedAction] = []
    skipped_actions = 0
    for index, raw in enumerate(raw_actions, start=1):
        action = _coerce_recommended_action(raw, index)
        if action is None:
            skipped_actions += 1
        else:
            actions.append(action)

    logger.info(
        "llm_final_output_parse_summary "
        f"findings_returned={len(raw_findings)} "
        f"findings_parsed={len(findings)} "
        f"findings_skipped={skipped_findings} "
        f"recommended_actions_returned={len(raw_actions)} "
        f"recommended_actions_parsed={len(actions)} "
        f"recommended_actions_skipped={skipped_actions}"
    )
    return AgentOutput(findings=findings, recommended_actions=actions)


def _coerce_finding(raw: Any, index: int) -> Finding | None:
    if not isinstance(raw, dict):
        logger.warning(
            f"llm_finding_unparseable index={index} reason=finding is not an object raw_keys=[]"
        )
        return None

    item = dict(raw)
    _coerce_field(item, "claim", ("finding", "description", "summary", "text"), "finding", index)
    _coerce_field(item, "rationale", ("reason", "explanation"), "finding", index)
    _coerce_field(item, "priority", ("severity", "importance"), "finding", index)

    if "id" not in item or not isinstance(item.get("id"), str) or not item.get("id"):
        item["id"] = f"f{index}"
        logger.info(f"llm_output_field_coerced kind=finding index={index} field=id")

    if "priority" not in item or not _priority_value(item.get("priority")):
        item["priority"] = Priority.MEDIUM
        logger.info(f"llm_output_field_coerced kind=finding index={index} field=priority")
    else:
        item["priority"] = _priority_value(item["priority"])

    item["supporting_entity_ids"] = _supporting_ids(
        item.get("supporting_entity_ids"),
        item.get("entity_id"),
        "finding",
        index,
    )
    item["supporting_relationship_ids"] = _string_list(item.get("supporting_relationship_ids"))
    item["checks"] = _checks(item.get("checks"))

    try:
        return Finding.model_validate(item)
    except ValueError as exc:
        logger.warning(
            "llm_finding_unparseable "
            f"index={index} reason={str(exc)!r} raw_keys={sorted(raw.keys())}"
        )
        return None


def _coerce_recommended_action(raw: Any, index: int) -> RecommendedAction | None:
    if not isinstance(raw, dict):
        logger.warning(
            f"llm_recommended_action_unparseable index={index} reason=action is not an object raw_keys=[]"
        )
        return None

    item = dict(raw)
    _coerce_field(item, "action", ("step", "description", "summary", "text"), "recommended_action", index)
    _coerce_field(item, "rationale", ("reason", "explanation", "description", "summary"), "recommended_action", index)
    if "authorization_required" not in item:
        _coerce_field(item, "authorization_required", ("auth_required", "authorization", "scope_required"), "recommended_action", index)
    if "rationale" not in item:
        item["rationale"] = str(item.get("action", ""))
        logger.info(f"llm_output_field_coerced kind=recommended_action index={index} field=rationale")
    if "target" not in item:
        target = _target_from_text(str(item.get("action", "")))
        if target is not None:
            item["target"] = target
            logger.info(f"llm_output_field_coerced kind=recommended_action index={index} field=target")

    try:
        return RecommendedAction.model_validate(item)
    except ValueError as exc:
        logger.warning(
            "llm_recommended_action_unparseable "
            f"index={index} reason={str(exc)!r} raw_keys={sorted(raw.keys())}"
        )
        return None


def _coerce_field(
    item: dict[str, Any],
    canonical: str,
    variants: tuple[str, ...],
    kind: str,
    index: int,
) -> None:
    if canonical in item:
        return
    for variant in variants:
        if variant in item:
            item[canonical] = item[variant]
            logger.info(
                f"llm_output_field_coerced kind={kind} index={index} from={variant} to={canonical}"
            )
            return


def _write_raw_final_output(text: str) -> None:
    try:
        Path("gemini-raw-output.json").write_text(text, encoding="utf-8")
    except OSError as exc:
        logger.warning(f"llm_raw_output_capture_failed error={exc}")


def _priority_value(value: Any) -> Priority | None:
    if isinstance(value, Priority):
        return value
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in {"critical", "severe"}:
        return Priority.HIGH
    if normalized in {"moderate", "normal"}:
        return Priority.MEDIUM
    try:
        return Priority(normalized)
    except ValueError:
        return None


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _supporting_ids(value: Any, fallback: Any, kind: str, index: int) -> list[str]:
    ids = _string_list(value)
    if ids:
        return ids
    if isinstance(fallback, str) and fallback:
        logger.info(
            f"llm_output_field_coerced kind={kind} index={index} from=entity_id to=supporting_entity_ids"
        )
        return [fallback]
    return []


def _target_from_text(text: str) -> str | None:
    match = re.search(r"\b([0-9a-f]{16})\b", text)
    if match:
        return match.group(1)
    return None


def _checks(value: Any) -> list[Check]:
    if not isinstance(value, list):
        return []
    checks: list[Check] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            checks.append(Check.model_validate(item))
        except ValueError:
            continue
    return checks


def _extract_json(text: str) -> str:
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL)
    if fenced:
        return _balanced_json(fenced.group(1))

    return _balanced_json(text)


def _balanced_json(text: str) -> str:
    start = text.find("{")
    if start == -1:
        return text
    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text[start:], start=start):
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_string:
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return text[start:]
