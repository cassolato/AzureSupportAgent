"""Tests for the OpenAI-compatible provider's request payload construction."""
from typing import Any

import pytest

from app.agent.openai_provider import OpenAIProvider
from app.agent.provider import ToolSpec


class _FakeCompletions:
    """Captures the kwargs the provider sends and returns an empty stream."""

    def __init__(self) -> None:
        self.captured: dict[str, Any] = {}

    async def create(self, **kwargs: Any) -> Any:
        self.captured = kwargs

        async def _empty():
            return
            yield  # pragma: no cover - makes this an async generator

        return _empty()


class _FakeClient:
    def __init__(self) -> None:
        self.completions = _FakeCompletions()
        self.chat = self


def _provider() -> tuple[OpenAIProvider, _FakeCompletions]:
    prov = OpenAIProvider(provider="openai", api_key="test-key", model="gpt-4o")
    fake = _FakeClient()
    prov._client = fake  # type: ignore[assignment]
    return prov, fake.completions


async def _drain(prov: OpenAIProvider, tools: list[ToolSpec] | None) -> None:
    async for _ in prov.stream([{"role": "user", "content": "hi"}], tools):
        pass


@pytest.mark.asyncio
async def test_tools_key_omitted_when_none():
    # An explicit `tools: null` is rejected with a 400 by stricter OpenAI-compatible
    # endpoints, so the key must be absent rather than present-and-null.
    prov, completions = _provider()
    await _drain(prov, None)
    assert "tools" not in completions.captured


@pytest.mark.asyncio
async def test_tools_key_omitted_when_empty_list():
    prov, completions = _provider()
    await _drain(prov, [])
    assert "tools" not in completions.captured


@pytest.mark.asyncio
async def test_tools_key_present_and_well_formed_when_supplied():
    prov, completions = _provider()
    spec = ToolSpec(
        name="az_graph",
        description="Run a Resource Graph query",
        parameters={"type": "object", "properties": {"query": {"type": "string"}}},
    )
    await _drain(prov, [spec])
    tools = completions.captured.get("tools")
    assert tools is not None
    assert tools == [
        {
            "type": "function",
            "function": {
                "name": "az_graph",
                "description": "Run a Resource Graph query",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
            },
        }
    ]


@pytest.mark.asyncio
async def test_core_payload_fields_are_unchanged_for_toolless_calls():
    # Guard against the tools change accidentally dropping anything else.
    prov, completions = _provider()
    await _drain(prov, None)
    sent = completions.captured
    assert sent["model"] == "gpt-4o"
    assert sent["messages"] == [{"role": "user", "content": "hi"}]
    assert sent["stream"] is True
    assert sent["stream_options"] == {"include_usage": True}
    assert "max_tokens" in sent
