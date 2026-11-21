"""Synthetic Agent Lab controls for lifecycle, scope, and installed CLI."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from wolfalibi.agent_lab import ManifestError, SCHEMA_V2, run_manifest
from wolfalibi.receipts import verify_negative_access_receipt


def scoped(value):
    if value != "allowed":
        raise PermissionError("synthetic denied scope")
    return "synthetic result"


def retry(attempt):
    if attempt == 0:
        raise RuntimeError("synthetic transient error")
    return "synthetic retry result"


async def slow():
    await asyncio.sleep(10)


async def exercise(tools, fixtures):
    assert scoped("allowed") == "synthetic result"  # A direct call is outside the probe.
    for _ in range(2):
        assert tools["scoped"]("allowed") == "synthetic result"
    try:
        tools["scoped"](fixtures["substitute"])
    except PermissionError:
        pass
    else:
        raise AssertionError("synthetic scope was not enforced")
    try:
        tools["retry"](0)
    except RuntimeError:
        assert tools["retry"](1) == "synthetic retry result"
    try:
        await tools["slow"]()
    except TimeoutError:
        return
    raise AssertionError("synthetic timeout was not enforced")


async def pending_tool(tools, _):
    asyncio.create_task(tools["slow"]())
    await asyncio.sleep(0)


async def interrupted(_, __):
    raise asyncio.CancelledError("synthetic interrupt marker")


def unexpected(_, __):
    raise RuntimeError("synthetic exception marker")


def slow_sync(_, __):
    time.sleep(10)


def credential_boundary(tools, fixtures):
    result = tools["env"]()
    assert result == (fixtures["mode"] == "forwarded")


def has_credential():
    return os.environ.get("WOLFALIBI_TEST_CREDENTIAL") == "SYNTHETIC_TEST_TOKEN"


def noisy(tools, _):
    print("SYNTHETIC_PYTHON_LOG")
    os.write(1, b"SYNTHETIC_NATIVE_STDOUT\n")
    os.write(2, b"SYNTHETIC_NATIVE_STDERR\n")
    tools["scoped"]("allowed")


_ROOT = Path(__file__).resolve().parent


class Stage4ManifestTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.manifest = self.directory / "agent.json"
        self.report = self.directory / "report.json"

    def _tool(self, alias, fn=None, **extra):
        return {"alias": alias, "module": "test_agent_lab_stage4", "callable": fn or alias,
                "surface": "tool", "operation": "invoke", **extra}

    def _configure(self, entrypoint, tools=None, **extras):
        manifest = {
            "schema": SCHEMA_V2, "agent_type": "custom",
            "entrypoint": {"module": "test_agent_lab_stage4", "callable": entrypoint},
            "tools": tools or [self._tool("slow")], "fixtures": {}, **extras,
        }
        self.manifest.write_text(json.dumps(manifest))

    def _run(self):
        result = run_manifest(self.manifest, self.report, consent=True, allow_local_code=True)
        return result, json.loads(self.report.read_text())

    def _cli(self, *extra, env=None):
        command = [sys.executable, "wolfalibi_cli.py", "agent", "test",
                   "--manifest", str(self.manifest), "--output", str(self.report),
                   "--consent", "--allow-local-code", *extra]
        result = subprocess.run(command, cwd=_ROOT, env=env, text=True, capture_output=True,
                                timeout=15, check=False)
        return result, json.loads(result.stdout)

    def test_scope_denial_retry_duplicate_and_async_timeout(self):
        expected = {"tool.invoke.success": 3, "tool.invoke.error": 1,
                    "tool.invoke.denied": 1, "tool.invoke.timeout": 1}
        self._configure("exercise", [self._tool("scoped"), self._tool("retry"),
                                    self._tool("slow", timeout_ms=20)],
                        fixtures={"substitute": "SYNTHETIC_PRIVATE_SCOPE"},
                        expect_counts=expected)
        result, report = self._run()
        self.assertEqual(result["outcome"], "PASS", result)
        self.assertEqual(report["counts"], expected)
        self.assertEqual(report["declared_bindings"], 3)
        self.assertEqual(report["events"], 6)
        self.assertEqual(report["coverage"], "EXPLICITLY_WRAPPED_CALLS_ONLY")
        self.assertNotIn("SYNTHETIC_PRIVATE_SCOPE", self.report.read_text())

    def test_background_work_cancels_and_marks_boundary_incomplete(self):
        self._configure("pending_tool")
        result, report = self._run()
        self.assertEqual(result["outcome"], "INCOMPLETE")
        self.assertEqual(report["counts"], {"tool.invoke.cancelled": 1})
        self.assertEqual(report["inflight"], 0)

    def test_interruption_and_unexpected_error_redact_messages(self):
        for entrypoint, outcome in (("interrupted", "INTERRUPTED"), ("unexpected", "AGENT_ERROR")):
            with self.subTest(entrypoint=entrypoint):
                self._configure(entrypoint)
                result, report = self._run()
                self.assertEqual(result["outcome"], outcome)
                self.assertEqual(report["outcome"], outcome)
                self.assertNotIn("marker", self.report.read_text())
                self.report.unlink()

    def test_contract_digest_substitution_fails_before_import(self):
        self._configure("unexpected")
        with patch("wolfalibi.agent_lab.importlib.import_module") as load:
            with self.assertRaisesRegex(ManifestError, "changed"):
                run_manifest(self.manifest, self.report, consent=True, allow_local_code=True,
                             expected_manifest_sha256="00" * 32)
        load.assert_not_called()

    def test_observational_export_cannot_replay_as_a_broker_receipt(self):
        self._configure("unexpected")
        _, report = self._run()
        verification = verify_negative_access_receipt(
            report, broker_pub=b"b" * 32, witness_pub=b"w" * 32,
            challenge=b"c" * 32, policy={}, lo=b"a", hi=b"b", run_id="test",
            code_digest=b"d" * 32, epochs=(1, 1),
        )
        self.assertEqual(verification["outcome"], "REJECTED", verification)

    def test_cli_does_not_inherit_credentials_without_explicit_forwarding(self):
        environment = dict(os.environ, WOLFALIBI_TEST_CREDENTIAL="SYNTHETIC_TEST_TOKEN")
        for mode, options in (
            ("absent", []), ("forwarded", ["--credential-env", "WOLFALIBI_TEST_CREDENTIAL"]),
        ):
            with self.subTest(mode=mode):
                self._configure("credential_boundary", [self._tool("env", "has_credential")],
                                fixtures={"mode": mode})
                command, result = self._cli(*options, env=environment)
                self.assertEqual(command.returncode, 0, result)
                self.assertEqual(result["outcome"], "PASS")
                self.assertNotIn("SYNTHETIC_TEST_TOKEN", self.report.read_text())
                self.report.unlink()

    def test_cli_deadline_blocks_a_synchronous_worker_without_report(self):
        self._configure("slow_sync")
        command, result = self._cli("--process-timeout", "1")
        self.assertEqual(command.returncode, 2, result)
        self.assertEqual(result["outcome"], "TIMEOUT", result)
        self.assertFalse(self.report.exists())

    def test_installed_command_discards_worker_stdio_including_descriptor_writes(self):
        self._configure("noisy", [self._tool("scoped")])
        command, result = self._cli()
        self.assertEqual(command.returncode, 0, result)
        self.assertEqual(result["events"], 1)
        for raw in (command.stdout, command.stderr, self.report.read_text()):
            self.assertNotIn("SYNTHETIC_", raw)

    def test_research_export_requires_separate_consent_and_omits_run_identifiers(self):
        self._configure("credential_boundary", [self._tool("env", "has_credential")],
                        fixtures={"mode": "absent"})
        aggregate = self.directory / "research.json"
        command, result = self._cli("--research-output", str(aggregate))
        self.assertEqual(command.returncode, 2, result)
        self.assertFalse(self.report.exists())
        self.assertFalse(aggregate.exists())
        command, result = self._cli("--research-output", str(aggregate), "--research-consent")
        self.assertEqual(command.returncode, 0, result)
        self.assertEqual(result["research_export"], "CREATED")
        raw = aggregate.read_text()
        report = json.loads(self.report.read_text())
        self.assertNotIn(report["run_id"], raw)
        self.assertNotIn(result["manifest_sha256"], raw)
        self.assertNotIn(str(self.directory), raw)
        self.assertFalse(json.loads(raw)["provenance"]["automatic_sharing"])


if __name__ == "__main__":
    unittest.main()
