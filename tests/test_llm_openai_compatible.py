from __future__ import annotations

import json

from osint.agent.llm import OpenAICompatibleLLMClient, create_llm_client
from osint.agent.tools import TOOL_DEFINITIONS


URL = "http://localhost:11434/v1/chat/completions"


async def test_openai_compatible_sends_tools_and_parses_tool_calls(respx_mock) -> None:
    route = respx_mock.post(URL).respond(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call_valid",
                                "type": "function",
                                "function": {
                                    "name": "get_entity",
                                    "arguments": "{\"entity_id\": \"entity-1\"}",
                                },
                            },
                            {
                                "id": "call_unknown",
                                "type": "function",
                                "function": {
                                    "name": "collect_more",
                                    "arguments": "{}",
                                },
                            },
                        ]
                    }
                }
            ]
        },
    )
    client = OpenAICompatibleLLMClient()

    try:
        response = await client.complete(
            [{"role": "user", "content": "inspect graph"}],
            TOOL_DEFINITIONS,
        )
    finally:
        await client.aclose()

    request_body = json.loads(route.calls.last.request.content)
    assert request_body["tools"][0]["type"] == "function"
    assert request_body["tools"][0]["function"]["name"] == TOOL_DEFINITIONS[0]["name"]
    assert response.tool_calls[0].id == "call_valid"
    assert response.tool_calls[0].name == "get_entity"
    assert response.tool_calls[0].arguments == {"entity_id": "entity-1"}
    assert len(response.tool_calls) == 1


async def test_openai_compatible_parses_fenced_final_json(respx_mock) -> None:
    respx_mock.post(URL).respond(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "content": (
                            "```json\n"
                            "{\"findings\": [], \"recommended_actions\": []}\n"
                            "```\nextra prose"
                        )
                    }
                }
            ]
        },
    )
    client = OpenAICompatibleLLMClient()

    try:
        response = await client.complete(
            [{"role": "user", "content": "final"}],
            TOOL_DEFINITIONS,
        )
    finally:
        await client.aclose()

    assert response.final_output is not None
    assert response.final_output.findings == []


async def test_openai_compatible_extracts_json_with_trailing_text(respx_mock) -> None:
    respx_mock.post(URL).respond(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "content": (
                            "Here is the result:\n"
                            "{\"findings\": [], \"recommended_actions\": []}\n"
                            "Done."
                        )
                    }
                }
            ]
        },
    )
    client = OpenAICompatibleLLMClient()

    try:
        response = await client.complete(
            [{"role": "user", "content": "final"}],
            TOOL_DEFINITIONS,
        )
    finally:
        await client.aclose()

    assert response.final_output is not None
    assert response.final_output.recommended_actions == []


async def test_openai_compatible_malformed_final_json_returns_empty_response(
    respx_mock,
) -> None:
    respx_mock.post(URL).respond(
        200,
        json={"choices": [{"message": {"content": "```json\n{not-json\n```"}}]},
    )
    client = OpenAICompatibleLLMClient()

    try:
        response = await client.complete(
            [{"role": "user", "content": "final"}],
            TOOL_DEFINITIONS,
        )
    finally:
        await client.aclose()

    assert response.tool_calls == []
    assert response.final_output is None


async def test_openai_compatible_timeout_comes_from_env(respx_mock, monkeypatch) -> None:
    route = respx_mock.post(URL).respond(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "content": "{\"findings\": [], \"recommended_actions\": []}"
                    }
                }
            ]
        },
    )
    monkeypatch.setenv("OSINT_LLM_TIMEOUT", "321")
    client = create_llm_client()

    try:
        response = await client.complete(
            [{"role": "user", "content": "final"}],
            TOOL_DEFINITIONS,
        )
    finally:
        await client.aclose()

    assert response.final_output is not None
    assert route.calls.last.request.extensions["timeout"]["read"] == 321.0
