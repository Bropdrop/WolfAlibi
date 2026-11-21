"""Opt-in observation for the pinned MCP Python SDK.

The adapter works on caller-supplied tool functions, servers and sessions.
The caller controls transports, and the SDK retains its own result and
logging behavior.
"""

from __future__ import annotations

from importlib import metadata
import inspect
from typing import Any, Callable, TYPE_CHECKING

from .agent_probe import AgentProbe

if TYPE_CHECKING:
    from mcp import Client, ClientSession
    from mcp.server.mcpserver import MCPServer


MCP_SDK_VERSION = "2.3.0"


class MCPAdapterError(RuntimeError):
    """The local MCP SDK cannot provide the qualified adapter API."""


def require_mcp_version() -> str:
    """Return the installed version if it matches the tested SDK pin."""
    try:
        installed = metadata.version("mcp")
    except metadata.PackageNotFoundError:
        raise MCPAdapterError(f"MCP Python SDK is missing. Install mcp=={MCP_SDK_VERSION}.") from None
    if installed != MCP_SDK_VERSION:
        raise MCPAdapterError(
            f"MCP Python SDK {installed} is unsupported. Install mcp=={MCP_SDK_VERSION}."
        )
    return installed


def register_mcp_tool(probe: AgentProbe, server: MCPServer, callback: Callable,
                      **tool_options: Any) -> Callable:
    """Wrap a function or bound method and register it with the supplied server.

    MCPServer handles argument validation, context injection and registration
    options. The probe observes only executions of the tool body.
    """
    require_mcp_version()
    from mcp.server.mcpserver import MCPServer

    if not isinstance(server, MCPServer):
        raise TypeError("server must be an MCPServer from the pinned SDK")
    if not (inspect.isfunction(callback) or inspect.ismethod(callback)):
        raise TypeError("callback must be a synchronous or asynchronous function or bound method")
    wrapped = probe.wrap(callback, surface="tool", operation="invoke")
    server.add_tool(wrapped, **tool_options)
    return wrapped


def wrap_mcp_call(probe: AgentProbe, session: Client | ClientSession) -> Callable:
    """Observe calls made on the supplied client or session.

    The caller manages transport and session lifetime. The original result or
    exception is returned unchanged. A returned tool error is still a
    successful return at this client callback boundary.
    """
    require_mcp_version()
    from mcp import Client, ClientSession

    if not isinstance(session, (Client, ClientSession)):
        raise TypeError("session must be a Client or ClientSession from the pinned SDK")
    return probe.wrap(session.call_tool, surface="tool", operation="invoke")
