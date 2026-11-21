"""Exercise the exact optional LangChain releases with local synthetic tools."""

import asyncio
from contextlib import ExitStack
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from wolfalibi.agent_langchain import (
    SUPPORTED_VERSIONS, LangChainUnsupported, langchain_status, langchain_tool,
)
from wolfalibi.agent_probe import AgentProbe, ProbeError


class LangChainAvailabilityTests(unittest.TestCase):
    def test_missing_or_unqualified_dependencies_are_explicitly_unsupported(self):
        from importlib.metadata import PackageNotFoundError

        probe = AgentProbe(consent=True, agent_type="langchain")
        with patch("wolfalibi.agent_langchain.version", side_effect=PackageNotFoundError):
            self.assertEqual(langchain_status()["outcome"], "UNSUPPORTED")
        versions = {**SUPPORTED_VERSIONS, "langchain-core": "99.0.0"}
        with patch("wolfalibi.agent_langchain.version", side_effect=versions.__getitem__):
            self.assertEqual(langchain_status()["installed"], versions)
            with self.assertRaises(LangChainUnsupported) as unsupported:
                langchain_tool(probe, func=lambda: None)
        self.assertEqual(unsupported.exception.outcome, "UNSUPPORTED")
        self.assertEqual(probe.summary()["events"], 0)

    def test_requires_an_explicit_probe(self):
        with self.assertRaises(ProbeError):
            AgentProbe(consent=False, agent_type="langchain")
        with self.assertRaises(TypeError):
            langchain_tool(None, func=lambda: None)


@unittest.skipUnless(langchain_status()["outcome"] == "SUPPORTED",
                     "optional LangChain integration is UNSUPPORTED on this installation")
class LangChainIntegrationTests(unittest.TestCase):
    def setUp(self):
        from langsmith import tracing_context

        stack = ExitStack()
        self.addCleanup(stack.close)
        self.connections = [
            stack.enter_context(patch.object(socket.socket, method,
                                             side_effect=AssertionError("unexpected connection")))
            for method in ("connect", "connect_ex")
        ]
        stack.enter_context(tracing_context(enabled=False))
        self.probe = AgentProbe(consent=True, agent_type="langchain")

    def tearDown(self):
        for connection in self.connections:
            connection.assert_not_called()

    def test_schema_invocation_and_native_validation(self):
        from langchain_core.tools import StructuredTool
        from pydantic import ValidationError

        def repeat(text: str, times: int = 2) -> str:
            """Repeat a synthetic string."""
            return text * times

        native = StructuredTool.from_function(repeat)
        observed = langchain_tool(self.probe, func=repeat, return_direct=True)
        self.assertEqual(observed.name, native.name)
        self.assertEqual(observed.description, native.description)
        self.assertEqual(observed.args_schema.model_json_schema(),
                         native.args_schema.model_json_schema())
        self.assertTrue(observed.return_direct)
        value = {"text": "pretend-input", "times": 3}
        self.assertEqual(observed.invoke(value), native.invoke(value))
        self.assertEqual(asyncio.run(observed.ainvoke(value)), native.invoke(value))
        with self.assertRaises(ValidationError):
            observed.invoke({"text": "invalid", "times": "not an integer"})
        self.assertEqual(self.probe.summary()["counts"], {"tool.invoke.success": 2})

    def test_langchain_runtime_config_is_injected_in_both_paths(self):
        from langchain_core.runnables import RunnableConfig

        def sync(value: str, config: RunnableConfig) -> str:
            """Echo a synthetic value with a configurable prefix."""
            return config["configurable"]["prefix"] + value

        async def asynchronous(value: str, config: RunnableConfig) -> str:
            """Echo a synthetic value with a configurable prefix."""
            return await asyncio.sleep(0, result=sync(value, config))

        tool = langchain_tool(self.probe, func=sync, coroutine=asynchronous)
        self.assertEqual(set(tool.args), {"value"})
        value, config = {"value": "fixture"}, {"configurable": {"prefix": "synthetic:"}}
        self.assertEqual(tool.invoke(value, config=config), "synthetic:fixture")
        self.assertEqual(asyncio.run(tool.ainvoke(value, config=config)), "synthetic:fixture")
        self.assertEqual(self.probe.summary()["counts"], {"tool.invoke.success": 2})

    def test_tool_call_follows_native_content_artifact_and_error_policies(self):
        from langchain_core.tools import ToolException

        failure = ToolException("fabricated error value")
        artifact = {"synthetic": "pretend private output"}

        def fetch(key: str):
            """Fetch a synthetic fixture."""
            if key == "missing":
                raise failure
            return "synthetic content", artifact

        tool = langchain_tool(self.probe, func=fetch, response_format="content_and_artifact")
        message = tool.invoke({"type": "tool_call", "id": "fake-1", "name": tool.name,
                               "args": {"key": "key-placeholder"}})
        self.assertEqual((message.content, message.artifact), ("synthetic content", artifact))
        with self.assertRaises(ToolException) as raised:
            tool.invoke({"key": "missing"})
        self.assertIs(raised.exception, failure)
        handled = langchain_tool(self.probe, func=fetch, response_format="content_and_artifact",
                                 handle_tool_error="synthetic fallback")
        self.assertEqual(handled.invoke({"key": "missing"}), "synthetic fallback")
        self.assertEqual(self.probe.summary()["counts"],
                         {"tool.invoke.error": 2, "tool.invoke.success": 1})
        self.probe.close()
        with tempfile.TemporaryDirectory() as temporary:
            report = self.probe.export_summary(Path(temporary) / "report.json").read_text()
        for sample in ("fabricated error value", "pretend private output", "synthetic content",
                       "key-placeholder", "synthetic fallback"):
            self.assertNotIn(sample, report)

    def test_async_callbacks_preserve_failure_and_cancellation(self):
        async def callback(mode: str) -> str:
            """Return a value or raise a synthetic signal."""
            if mode == "timeout":
                raise TimeoutError("synthetic timeout")
            if mode == "deny":
                raise PermissionError("synthetic deny")
            if mode == "cancel":
                await asyncio.sleep(60)
            return "synthetic answer"

        async def exercise():
            from asyncio import Event

            entered = Event()

            async def run(mode: str) -> str:
                """Exercise a synthetic asynchronous tool."""
                entered.set()
                return await callback(mode)

            tool = langchain_tool(self.probe, coroutine=run, surface="filesystem", operation="read")
            self.assertEqual(await tool.ainvoke({"mode": "ok"}), "synthetic answer")
            with self.assertRaises(TimeoutError):
                await tool.ainvoke({"mode": "timeout"})
            with self.assertRaises(PermissionError):
                await tool.ainvoke({"mode": "deny"})
            entered.clear()
            job = asyncio.create_task(tool.ainvoke({"mode": "cancel"}))
            await asyncio.wait_for(entered.wait(), 2)
            job.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await job

        asyncio.run(exercise())
        self.assertEqual(self.probe.summary()["counts"], {
            "filesystem.read.cancelled": 1, "filesystem.read.denied": 1,
            "filesystem.read.success": 1, "filesystem.read.timeout": 1,
        })
        self.assertEqual(self.probe.summary()["inflight"], 0)

    def test_langchain_agent_uses_the_registered_wrapper(self):
        from examples.agent_langchain_sample import lookup, run
        from langchain_core.messages import ToolMessage

        result = run({"lookup": langchain_tool(self.probe, func=lookup)}, {"query": "hello"})
        responses = [message for message in result["messages"] if isinstance(message, ToolMessage)]
        self.assertEqual([message.content for message in responses], ["synthetic:hello"])
        self.assertEqual(result["messages"][-1].content, "Synthetic task complete")
        self.probe.close()
        summary = self.probe.summary()
        self.assertEqual(summary["assurance"], "OBSERVATIONAL_ONLY")
        self.assertTrue(summary["complete_wrapped_calls"])
        self.assertFalse(summary["nonaccess_proof"])
        self.assertEqual(summary["counts"], {"tool.invoke.success": 1})
        for sample in ("Synthetic task", "hello", "synthetic:hello", "lookup"):
            self.assertNotIn(sample, json.dumps(summary))

    def test_closed_and_exhausted_probes_refuse_before_callback(self):
        calls = []
        probe = AgentProbe(consent=True, agent_type="langchain", max_calls=1)

        def count() -> int:
            """Return the number of synthetic invocations."""
            calls.append(1)
            return len(calls)

        tool = langchain_tool(probe, func=count)
        self.assertEqual(tool.invoke({}), 1)
        with self.assertRaises(ProbeError):
            tool.invoke({})
        probe.close()
        with self.assertRaises(ProbeError):
            tool.invoke({})
        self.assertEqual(calls, [1])
        self.assertEqual(probe.summary()["counts"], {"tool.invoke.success": 1})


if __name__ == "__main__":
    unittest.main()
