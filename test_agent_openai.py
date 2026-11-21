"""Qualification against a pinned SDK using only synthetic local tool calls."""

from importlib.metadata import PackageNotFoundError, version
import json
import socket
import unittest
from unittest.mock import patch

from wolfalibi.agent_openai import (
    OPENAI_AGENTS_VERSION, OpenAIAgentsUnavailable, observed_function_tool,
)
from wolfalibi.agent_probe import AgentProbe


try:
    _QUALIFIED_SDK_AVAILABLE = version("openai-agents") == OPENAI_AGENTS_VERSION
except PackageNotFoundError:
    _QUALIFIED_SDK_AVAILABLE = False

if _QUALIFIED_SDK_AVAILABLE:
    from agents import Agent, FunctionTool, RunConfig, RunContextWrapper, Runner
    from examples.agent_openai_sample import LocalFixtureModel


class SDKPrerequisiteTests(unittest.TestCase):
    def test_missing_and_unqualified_versions_fail_with_the_exact_pin(self):
        def tool():
            return "synthetic"

        with AgentProbe(consent=True, agent_type="openai-agents") as probe:
            with patch("wolfalibi.agent_openai.version", side_effect=PackageNotFoundError):
                with self.assertRaisesRegex(OpenAIAgentsUnavailable, "install openai-agents=="):
                    observed_function_tool(probe, tool)
            with patch("wolfalibi.agent_openai.version", return_value="0.0.0"):
                with self.assertRaisesRegex(OpenAIAgentsUnavailable, "required, found"):
                    observed_function_tool(probe, tool)
        self.assertEqual(probe.summary()["events"], 0)


@unittest.skipUnless(_QUALIFIED_SDK_AVAILABLE, f"optional openai-agents=={OPENAI_AGENTS_VERSION}")
class OpenAIAgentsAdapterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # An accidental hosted model fallback or trace upload fails the test.
        for method in ("connect", "connect_ex"):
            patcher = patch.object(socket.socket, method, side_effect=AssertionError(
                "the synthetic Agents SDK run cannot connect to a socket",
            ))
            guarded = patcher.start()
            self.addCleanup(patcher.stop)
            self.addCleanup(guarded.assert_not_called)

    async def _run(self, tool, arguments, expected_output, *, context=None):
        model = LocalFixtureModel(tool.name, arguments, expected_output)
        result = await Runner.run(
            Agent(name="Local SDK qualification", model=model, tools=[tool]),
            "synthetic-prompt", context=context, max_turns=2,
            run_config=RunConfig(tracing_disabled=True),
        )
        self.assertEqual(result.final_output, "Local fixture complete")
        self.assertEqual(model.turn, 2)

    async def test_sync_tool_preserves_schema_context_and_result(self):
        def contextual_tool(ctx: RunContextWrapper[dict[str, str]], value: str) -> str:
            """Read a synthetic value from context."""
            return ctx.context["prefix"] + value

        with AgentProbe(consent=True, agent_type="openai-agents") as probe:
            tool = observed_function_tool(
                probe, contextual_tool, surface="filesystem", operation="read",
                name_override="synthetic_label", description_override="Read the fixture.",
            )
            self.assertIsInstance(tool, FunctionTool)
            self.assertEqual(tool.name, "synthetic_label")
            self.assertEqual(tool.description, "Read the fixture.")
            self.assertEqual(set(tool.params_json_schema["properties"]), {"value"})
            self.assertEqual(tool.params_json_schema["properties"]["value"]["type"], "string")
            await self._run(tool, {"value": "synthetic-argument"}, "synthetic-prefix:synthetic-argument",
                            context={"prefix": "synthetic-prefix:"})
        summary = probe.summary()
        self.assertEqual(summary["counts"], {"filesystem.read.success": 1})
        self.assertEqual(summary["assurance"], "OBSERVATIONAL_ONLY")
        self.assertFalse(summary["nonaccess_proof"])
        for raw in ("synthetic-argument", "synthetic-prefix", "synthetic-prompt", "synthetic_label"):
            self.assertNotIn(raw, json.dumps(summary))

    async def test_async_callback_error_is_observed_and_sdk_formatter_receives_original(self):
        error = PermissionError("synthetic private denial")
        received = []

        async def denied_tool() -> str:
            """Raise a synthetic denial."""
            raise error

        def formatter(context, original_error):
            received.append(original_error)
            return "synthetic approved error response"

        with AgentProbe(consent=True, agent_type="openai-agents") as probe:
            tool = observed_function_tool(probe, denied_tool, failure_error_function=formatter)
            await self._run(tool, {}, "synthetic approved error response")
        self.assertEqual(len(received), 1)
        self.assertIs(received[0], error)
        self.assertEqual(probe.summary()["counts"], {"tool.invoke.denied": 1})
        self.assertNotIn(str(error), json.dumps(probe.summary()))

    async def test_sdk_input_rejection_does_not_count_as_callback_execution(self):
        def validated_tool(count: int) -> str:
            raise AssertionError("invalid SDK input must not invoke the callback")

        with AgentProbe(consent=True, agent_type="openai-agents") as probe:
            tool = observed_function_tool(probe, validated_tool)
            await self._run(tool, {"count": "invalid"}, "An error occurred while running the tool.")
        self.assertEqual(probe.summary()["counts"], {})


if __name__ == "__main__":
    unittest.main()
