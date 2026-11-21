"""Synthetic manifest entry point using MCP's in-memory client."""

from wolfalibi.agent_mcp import require_mcp_version


def lookup(value: str) -> str:
    """Return a synthetic label."""
    return f"synthetic:{value}"


async def run(tools, fixtures):
    require_mcp_version()
    from mcp import Client
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("wolfalibi-synthetic")
    # The manifest runner already wrapped this callback with its probe.
    server.add_tool(tools["lookup"])
    async with Client(server) as client:
        result = await client.call_tool("lookup", {"value": fixtures["query"]})
    if result.is_error or result.structured_content != {"result": "synthetic:hello"}:
        raise RuntimeError("unexpected synthetic MCP result")
