"""Stage 4 callback lifecycle and redaction tests with synthetic values."""

import asyncio
from concurrent.futures import CancelledError, Future
import inspect
import json
from pathlib import Path
import tempfile
from typing import Awaitable
import unittest

from wolfalibi.agent_probe import AgentProbe, ProbeError


class Stage4ProbeLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_sync_factory_reserves_capacity_until_awaitable_resolves(self):
        invocations = []

        async def evaluate(value):
            return value + 1

        def factory(value: int, /) -> Awaitable[int]:
            invocations.append(value)
            return evaluate(value)

        probe = AgentProbe(consent=True, max_calls=1)
        wrapped = probe.wrap(factory)
        self.assertEqual(inspect.signature(wrapped), inspect.signature(factory))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            pending = wrapped(3)
            self.assertEqual(invocations, [3])
            self.assertEqual(probe.summary()["events"], 0)
            self.assertEqual(probe.summary()["inflight"], 1)
            with self.assertRaises(ProbeError):
                wrapped(7)
            with self.assertRaises(ProbeError):
                probe.record(surface="tool", operation="invoke", outcome="success")
            with self.assertRaises(ProbeError):
                probe.close()
            with self.assertRaises(ProbeError):
                probe.export_summary(path)
            self.assertFalse(path.exists())
            self.assertEqual(await pending, 4)
            self.assertEqual(invocations, [3])
            probe.close()
            probe.export_summary(path)
            report = json.loads(path.read_text())
            self.assertEqual(report["counts"], {"tool.invoke.success": 1})
            self.assertEqual(report["inflight"], 0)
            self.assertTrue(report["complete_wrapped_calls"])

    async def test_async_callable_retains_signature_and_async_dispatch(self):
        class SyntheticTool:
            async def __call__(self, value: int, /, *, scale: int = 2) -> int:
                return value * scale

        tool = SyntheticTool()
        with AgentProbe(consent=True) as probe:
            wrapped = probe.wrap(tool, surface="database", operation="query")
            self.assertTrue(inspect.iscoroutinefunction(wrapped))
            self.assertEqual(inspect.signature(wrapped), inspect.signature(tool))
            self.assertIs(inspect.unwrap(wrapped), tool)
            self.assertEqual(await wrapped(9, scale=3), 27)
        self.assertEqual(probe.summary()["counts"], {"database.query.success": 1})

    async def test_never_started_async_callback_does_not_run_or_complete(self):
        invocations = []

        async def execute():
            invocations.append("synthetic")

        with AgentProbe(consent=True) as probe:
            never_started = probe.wrap(execute)()
            self.assertEqual(probe.summary()["inflight"], 0)
            never_started.close()
        self.assertEqual(invocations, [])
        self.assertEqual(probe.summary()["events"], 0)
        self.assertTrue(probe.summary()["complete_wrapped_calls"])

    async def test_never_awaited_sync_result_remains_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            probe = AgentProbe(consent=True)
            future = asyncio.get_running_loop().create_future()
            pending = probe.wrap(lambda: future)()
            future.set_result("synthetic unobserved response")
            pending.close()
            report = probe.summary()
            self.assertFalse(report["complete_wrapped_calls"])
            self.assertEqual(report["inflight"], 1)
            self.assertEqual(report["events"], 0)
            with self.assertRaises(ProbeError):
                probe.close()
            with self.assertRaises(ProbeError):
                probe.export_summary(path)
            self.assertFalse(path.exists())

    async def test_awaited_errors_preserve_exception_and_classify_outcomes(self):
        async def fail(exc):
            raise exc

        with AgentProbe(consent=True) as probe:
            wrapped = probe.wrap(lambda exc: fail(exc), surface="filesystem", operation="read")
            for error in (TimeoutError("synthetic timeout text"), PermissionError("synthetic denial text"),
                          RuntimeError("synthetic error text")):
                with self.subTest(kind=type(error).__name__):
                    with self.assertRaises(type(error)) as captured:
                        await wrapped(error)
                    self.assertIs(captured.exception, error)
        report = probe.summary()
        self.assertEqual(report["counts"], {
            "filesystem.read.timeout": 1, "filesystem.read.denied": 1, "filesystem.read.error": 1,
        })
        self.assertNotIn("synthetic", json.dumps(report))

    async def test_cancellation_after_callback_starts_counts_once(self):
        started = asyncio.Event()

        async def wait_for_cancel():
            started.set()
            await asyncio.Future()

        with AgentProbe(consent=True) as probe:
            wrapped = probe.wrap(lambda: wait_for_cancel())
            task = asyncio.create_task(wrapped())
            await asyncio.wait_for(started.wait(), timeout=2)
            self.assertEqual(probe.summary()["inflight"], 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(probe.summary()["counts"], {"tool.invoke.cancelled": 1})


class Stage4ProbeMetadataTests(unittest.TestCase):
    def test_synchronous_future_cancellation_is_classified(self):
        future = Future()
        future.cancel()
        with AgentProbe(consent=True) as probe:
            wrapped = probe.wrap(future.result)
            with self.assertRaises(CancelledError):
                wrapped()
        self.assertEqual(probe.summary()["counts"], {"tool.invoke.cancelled": 1})

    def test_manual_events_are_labeled_separately_from_wrapped_coverage(self):
        with AgentProbe(consent=True) as probe:
            probe.wrap(lambda: "synthetic return")()
            self.assertEqual(probe.summary()["manual_events"], 0)
            self.assertEqual(probe.summary()["coverage"], "EXPLICITLY_WRAPPED_CALLS_ONLY")
            probe.record(surface="tool", operation="invoke", outcome="success")
        report = probe.summary()
        self.assertEqual(report["events"], 2)
        self.assertEqual(report["manual_events"], 1)
        self.assertEqual(report["coverage"], "EXPLICITLY_WRAPPED_CALLS_AND_DECLARED_MANUAL_EVENTS")

    def test_categories_and_report_fields_refuse_unvalidated_values(self):
        class SyntheticCategory(str):
            pass

        with self.assertRaises(ValueError):
            AgentProbe(consent=True, agent_type=SyntheticCategory("custom"))
        with AgentProbe(consent=True) as probe:
            with self.assertRaises(ValueError):
                probe.wrap(lambda: None, surface=SyntheticCategory("tool"))
            with self.assertRaises(ValueError):
                probe.wrap(lambda: None, operation=[])
            with self.assertRaises(ValueError):
                probe.record(surface="tool", operation="invoke", outcome=[])
            for field in ("agent_type", "run_id", "max_calls"):
                with self.subTest(field=field), self.assertRaises(AttributeError):
                    setattr(probe, field, "synthetic private data")
        self.assertNotIn("synthetic", json.dumps(probe.summary()))


if __name__ == "__main__":
    unittest.main()
