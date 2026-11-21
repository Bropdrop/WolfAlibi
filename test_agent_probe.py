"""Only synthetic tests for the voluntary, observational agent integration SDK."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

from wolfalibi.agent_probe import AgentProbe, ProbeError


class AgentProbeTests(unittest.TestCase):
    def test_explicit_consent(self):
        for value in (False, None, 1, "true"):
            with self.subTest(value=value), self.assertRaises(ProbeError):
                AgentProbe(consent=value)

    def test_sync_return_value_and_counts(self):
        with AgentProbe(consent=True, agent_type="custom") as p:
            fn = p.wrap(lambda v: v * 2)
            self.assertEqual(fn(9), 18)
        self.assertEqual(p.summary()["counts"], {"tool.invoke.success": 1})
        self.assertTrue(p.summary()["complete_wrapped_calls"])
        self.assertFalse(p.summary()["nonaccess_proof"])

    def test_async_unchanged_result(self):
        async def source(x):
            return x + 2
        with AgentProbe(consent=True) as p:
            fn = p.wrap(source, surface="model", operation="request")
            self.assertEqual(asyncio.run(fn(8)), 10)
        self.assertEqual(p.summary()["counts"], {"model.request.success": 1})

    def test_does_not_serialize_exceptions_or_args(self):
        secret = "CUSTOMER_PRIVATE_KEY_NEVER_EXPORT"
        with AgentProbe(consent=True) as p:
            def failing(arg):
                raise RuntimeError(secret + arg)
            fn = p.wrap(failing)
            with self.assertRaises(RuntimeError):
                fn("RAW_PROMPT_DO_NOT_STORE")
        report = json.dumps(p.summary())
        self.assertNotIn(secret, report)
        self.assertNotIn("RAW_PROMPT_DO_NOT_STORE", report)
        self.assertEqual(p.summary()["counts"]["tool.invoke.error"], 1)

    def test_timeout_and_permission_categories(self):
        with AgentProbe(consent=True) as p:
            for err in (TimeoutError("hidden"), PermissionError("hidden")):
                def raises():
                    raise err
                with self.assertRaises(type(err)):
                    p.wrap(raises)()
        self.assertEqual(p.summary()["counts"], {"tool.invoke.denied": 1, "tool.invoke.timeout": 1})

    def test_reject_raw_resource_name(self):
        with AgentProbe(consent=True) as p:
            with self.assertRaises(ValueError):
                p.wrap(lambda: 1, surface="finance/customer-01")
            with self.assertRaises(ValueError):
                p.record(surface="tool", operation="invoke", outcome="account=123")

    def test_refuses_tool_after_closed(self):
        calls = []
        with AgentProbe(consent=True) as p:
            fn = p.wrap(lambda: calls.append(1))
        with self.assertRaises(ProbeError):
            fn()
        self.assertEqual(calls, [])

    def test_capacity_refuses_tool_before_execution(self):
        calls = []
        with AgentProbe(consent=True, max_calls=1) as p:
            fn = p.wrap(lambda: calls.append(1))
            fn()
            with self.assertRaises(ProbeError):
                fn()
        self.assertEqual(calls, [1])

    def test_concurrent_tools_count_complete(self):
        with AgentProbe(consent=True) as p:
            fn = p.wrap(lambda: 1)
            ts = [threading.Thread(target=lambda: [fn() for _ in range(100)]) for _ in range(6)]
            for t in ts: t.start()
            for t in ts: t.join()
        self.assertEqual(p.summary()["events"], 600)

    def test_inflight_close_refuses(self):
        started, proceed = threading.Event(), threading.Event()
        with AgentProbe(consent=True) as p:
            def slow():
                started.set()
                proceed.wait(timeout=5)
            fn = p.wrap(slow)
            t = threading.Thread(target=fn)
            t.start()
            self.assertTrue(started.wait(timeout=3))
            with self.assertRaises(ProbeError):
                p.close()
            proceed.set()
            t.join(timeout=3)
        self.assertTrue(p.summary()["complete_wrapped_calls"])

    def test_export_is_local_create_only_private_and_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "report.json")
            with AgentProbe(consent=True) as p:
                p.record(surface="network", operation="request", outcome="success", duration_ms=30)
            self.assertEqual(p.export_summary(path), path)
            data = path.read_text()
            self.assertEqual(json.loads(data)["duration_buckets_ms"], {"10-99": 1})
            self.assertFalse(json.loads(data)["network_upload"])
            self.assertFalse(os.stat(path).st_mode & 0o077)
            with self.assertRaises(FileExistsError):
                p.export_summary(path)

    def test_export_before_close_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = AgentProbe(consent=True)
            with self.assertRaises(ProbeError):
                p.export_summary(Path(d, "x.json"))
            p.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
