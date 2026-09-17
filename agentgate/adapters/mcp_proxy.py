"""Optional MCP session adapter. Discovery never grants authorization.

The operator supplies an already-connected official SDK ClientSession and explicit
versioned ToolDefinitions. No live MCP server is configured by the demo.
"""

from agentgate.core.models import ToolDefinition
from agentgate.registry.tools import Registry


def register_mcp_tools(
    registry: Registry,
    session,
    server_id: str,
    allowed_servers: set[str],
    approved_tools: dict[str, ToolDefinition],
):
    if server_id not in allowed_servers:
        raise ValueError("MCP server is not approved")
    for remote_name, definition in approved_tools.items():
        # Name/version/metadata are reviewed configuration, never inferred permissions.
        bound = definition.model_copy(update={"owner": server_id})

        async def call(arguments, name=remote_name):
            result = await session.call_tool(name, arguments=arguments)
            if result.isError:
                raise RuntimeError("MCP server reported tool failure")
            return {"content": result.model_dump(mode="json")["content"]}

        registry.register(bound, call)
