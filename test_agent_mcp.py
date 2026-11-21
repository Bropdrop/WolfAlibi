"""Tests for the optional MCP adapter with synthetic in-memory tools."""

from __future__ import annotations

from importlib import metadata
import inspect
import json
import unittest
from unittest.mock import patch

from wolfalibi.agent_mcp import (
    MCPAdapterError,
    MCP_SDK_VERSION,
    register_mcp_tool,
    require_mcp_version,
    wrap_mcp_call,
)
from wolfalibi.agent_probe import AgentProbe, ProbeError

try:
    require_mcp_version()
except MCPAdapterError:
    _HAS_SDK = False
else:
    from mcp import Client, ClientSession
    from mcp.server.mcpserver import Context, MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp.types import ToolAnnotations
    _HAS_SDK = True


class MCPVersionTests(unittest.TestCase):
    def test_missing_sdk_reports_exact_pin(self):
        with patch("wolfalibi.agent_mcp.metadata.version",
                   side_effect=metadata.PackageNotFoundError("mcp")):
            with self.assertRaisesRegex(MCPAdapterError, f"mcp=={MCP_SDK_VERSION}"):
                require_mcp_version()

    def test_other_sdk_versions_are_unsupported(self):
        with patch("wolfalibi.agent_mcp.metadata.version", return_value="1.30.0"):
            with self.assertRaisesRegex(MCPAdapterError, "1.30.0 is unsupported"):
                require_mcp_version()


@unittest.skipUnless(_HAS_SDK, f"install mcp=={MCP_SDK_VERSION} for in-memory integration tests")
class MCPIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_registry_and_client_session_preserve_schema_and_values(self):
        server = MCPServer("synthetic-local")
        with AgentProbe(consent=True, agent_type="mcp") as server_probe:
            async def lookup(value: str, context: Context) -> str:
                """Return a synthetic value."""
                self.assertIsInstance(context, Context)
                return f"synthetic:{value}"

            wrapped = register_mcp_tool(
                server_probe, server, lookup, name="synthetic_lookup",
                title="Synthetic lookup", annotations=ToolAnnotations(read_only_hint=True),
                meta={"example/visibility": "synthetic"},
            )
            self.assertEqual(inspect.signature(wrapped), inspect.signature(lookup))
            self.assertTrue(inspect.iscoroutinefunction(wrapped))
            with AgentProbe(consent=True, agent_type="mcp") as client_probe:
                # The SDK constructs an in-memory connection for a supplied server.
                with patch("socket.socket.connect", side_effect=AssertionError("network use")):
                    async with Client(server) as client:
                        self.assertIsInstance(client.session, ClientSession)
                        listing = await client.session.list_tools()
                        self.assertEqual(len(listing.tools), 1)
                        tool = listing.tools[0]
                        self.assertEqual(tool.name, "synthetic_lookup")
                        self.assertEqual(tool.title, "Synthetic lookup")
                        self.assertEqual(tool.description, "Return a synthetic value.")
                        self.assertTrue(tool.annotations.read_only_hint)
                        self.assertEqual(tool.meta["example/visibility"], "synthetic")
                        self.assertEqual(set(tool.input_schema["properties"]), {"value"})
                        call = wrap_mcp_call(client_probe, client.session)
                        result = await call("synthetic_lookup", {"value": "synthetic-private-input"})
                        self.assertFalse(result.is_error)
                        self.assertEqual(result.structured_content,
                                         {"result": "synthetic:synthetic-private-input"})
            summary = json.dumps(client_probe.summary())
            self.assertNotIn("synthetic_lookup", summary)
            self.assertNotIn("synthetic-private-input", summary)
            self.assertEqual(client_probe.summary()["counts"], {"tool.invoke.success": 1})
        self.assertEqual(server_probe.summary()["counts"], {"tool.invoke.success": 1})

    async def test_sync_tool_error_preserves_sdk_result(self):
        server = MCPServer("synthetic-error")
        with (AgentProbe(consent=True, agent_type="mcp") as server_probe,
              AgentProbe(consent=True, agent_type="mcp") as client_probe):
            def refuse() -> str:
                raise ToolError("synthetic detail")

            wrapped = register_mcp_tool(server_probe, server, refuse)
            self.assertFalse(inspect.iscoroutinefunction(wrapped))
            with self.assertLogs("mcp.server.mcpserver.server", level="INFO") as sdk_log:
                async with Client(server) as client:
                    result = await wrap_mcp_call(client_probe, client)("refuse")
                    self.assertTrue(result.is_error)
                    self.assertIn("synthetic detail", result.content[0].text)
            self.assertIn("synthetic detail", "\n".join(sdk_log.output))
            self.assertNotIn("synthetic detail", json.dumps(server_probe.summary()))
            self.assertNotIn("synthetic detail", json.dumps(client_probe.summary()))
            self.assertEqual(server_probe.summary()["counts"], {"tool.invoke.error": 1})
            self.assertEqual(client_probe.summary()["counts"], {"tool.invoke.success": 1})

    async def test_closed_client_probe_refuses_before_dispatch(self):
        server = MCPServer("synthetic-closed")
        invoked = []

        @server.tool()
        def run() -> str:
            invoked.append(True)
            return "synthetic"

        probe = AgentProbe(consent=True, agent_type="mcp")
        async with Client(server) as client:
            call = wrap_mcp_call(probe, client)
            probe.close()
            with self.assertRaises(ProbeError):
                await call("run")
        self.assertEqual(invoked, [])
        self.assertEqual(probe.summary()["events"], 0)
