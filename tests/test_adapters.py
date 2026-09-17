import httpx
import pytest

from agentgate.adapters.http_tools import HTTPToolAdapter
from agentgate.adapters.mcp_proxy import register_mcp_tools
from agentgate.core.models import ToolDefinition
from agentgate.registry.tools import Registry


async def test_http_adapter_only_uses_configured_origin():
    seen = []

    async def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={"content": "synthetic"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = HTTPToolAdapter("https://tools.example", {"tools.example"}, client)
        assert await adapter.call("read_orders", {"user_id": "u-100"}) == {"content": "synthetic"}
        assert seen == ["https://tools.example/tools/read_orders"]
        with pytest.raises(ValueError):
            await adapter.call("../secrets", {})
        with pytest.raises(ValueError):
            HTTPToolAdapter("https://evil.example", {"tools.example"}, client)


async def test_mcp_allowlist_and_explicit_registration():
    class Session:
        async def call_tool(self, name, arguments):
            return type(
                "Result",
                (),
                {"isError": False, "content": [], "model_dump": lambda self, **kw: {"content": []}},
            )()

    registry = Registry()
    definition = ToolDefinition(
        name="read_orders",
        description="Synthetic",
        operation="read",
        risk_level="low",
        input_schema={"type": "object", "additionalProperties": False},
        output_schema=None,
    )
    with pytest.raises(ValueError):
        register_mcp_tools(registry, Session(), "unknown", {"trusted"}, {"read_orders": definition})
    register_mcp_tools(registry, Session(), "trusted", {"trusted"}, {"read_orders": definition})
    assert list(registry.tools) == ["read_orders"]


def test_registry_rejects_synchronous_handlers_that_cannot_be_timed_out():
    definition = ToolDefinition(
        name="read_orders",
        description="Synthetic",
        operation="read",
        risk_level="low",
        input_schema={"type": "object", "additionalProperties": False},
    )
    with pytest.raises(ValueError, match="async"):
        Registry().register(definition, lambda args: {})
