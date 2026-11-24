"""Real host harness IPC with scripted PTYs and fabricated signed evidence.

These tests exercise the actual prototype OwnerTerminal and Roles.public
implementations. They do not create Unix users, run sudo, boot a VM, invoke a
TPM or claim human consent. actual_human_approval remains NOT_RUN.
"""

from __future__ import annotations

import copy
import os
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from shirudo_adapter.model import canonical_json, digest, strict_json
from scripts import shirudo_prototype_host as host
from scripts.shirudo_real_lab import EnvironmentFailure, LabFailure

try:
    from .test_owner import OwnerFixture
except ImportError:
    from test_owner import OwnerFixture


class PrototypeHostCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wa-prototype-host-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Bypass provisioning, not a security check: only the public-file
        # method is exercised. No role account or privileged command runs.
        self.roles = object.__new__(host.Roles)
        self.roles.exchange = self.root / "public"
        self.roles.exchange.mkdir(mode=0o755)


class PublicExchangeTests(PrototypeHostCase):
    def test_publication_is_atomic_and_file_is_complete_before_it_is_visible(self):
        target = self.roles.exchange / "bundle.json"
        value = {"schema": "test-public-only", "data": "x" * 200_000}
        flushed = threading.Event()
        release = threading.Event()
        real_fsync = os.fsync

        def paused_fsync(fd):
            real_fsync(fd)
            flushed.set()
            if not release.wait(3):
                raise AssertionError("Test did not release completed public file")

        with patch.object(host.os, "fsync", side_effect=paused_fsync):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.roles.public, "bundle.json", value)
                try:
                    self.assertTrue(flushed.wait(3))
                    self.assertFalse(os.path.lexists(target))
                    staged = list(self.roles.exchange.iterdir())
                    self.assertEqual(len(staged), 1)
                    self.assertEqual(stat.S_IMODE(staged[0].stat().st_mode), 0o600)
                finally:
                    release.set()
                self.assertEqual(future.result(timeout=3), target)
        self.assertEqual(target.read_bytes(), canonical_json(value) + b"\n")
        self.assertEqual(strict_json(target.read_bytes(), host.MAX_PUBLIC), value)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(list(self.roles.exchange.iterdir()), [target])

    def test_existing_regular_file_or_symlink_is_never_replaced(self):
        existing = self.roles.public("existing.json", {"first": True})
        before = existing.read_bytes()
        with self.assertRaises(FileExistsError):
            self.roles.public("existing.json", {"replacement": True})
        self.assertEqual(existing.read_bytes(), before)
        link = self.roles.exchange / "link.json"
        link.symlink_to(existing)
        with self.assertRaises(FileExistsError):
            self.roles.public("link.json", {"replacement": True})
        self.assertTrue(link.is_symlink())
        self.assertEqual(existing.read_bytes(), before)
        self.assertEqual({p.name for p in self.roles.exchange.iterdir()}, {"existing.json", "link.json"})

    def test_public_name_and_size_limits_apply_before_any_file_is_created(self):
        for name in ("../escape.json", "nested/name.json", "CAPITAL.json", ".hidden", "x" * 129):
            with self.subTest(name=name), self.assertRaises(LabFailure) as raised:
                self.roles.public(name, {})
            self.assertEqual(raised.exception.code, "PUBLIC_FILENAME")
        with self.assertRaises(LabFailure) as raised:
            self.roles.public("oversized.json", b"x" * (host.MAX_PUBLIC + 1))
        self.assertEqual(raised.exception.code, "PUBLIC_SIZE")
        self.assertEqual(list(self.roles.exchange.iterdir()), [])


class PrototypeOwnerDriverTests(PrototypeHostCase):
    def setUp(self):
        super().setUp()
        self.f = OwnerFixture(self.root / "owner-fixture")

    def start(self, name="case", *, bundle_timeout=3):
        intent = self.f.intent()
        intent_path = self.roles.public(name + "-intent.json", intent)
        bundle_name = name + "-bundle.json"
        argv = [sys.executable, "-m", "shirudo_adapter.owner_cli", "approve",
                "--state", str(self.f.state), "--intent", str(intent_path),
                "--bundle", str(self.roles.exchange / bundle_name),
                "--ready-timeout", "5", "--bundle-timeout", str(bundle_timeout)]
        try:
            terminal = host.OwnerTerminal(argv)
        except (PermissionError, OSError) as exc:
            if os.environ.get("GITHUB_ACTIONS") == "true":
                raise
            self.skipTest(f"Local PTY unavailable; mandatory CI exercises this driver: {exc}")
        self.addCleanup(terminal.close)
        terminal.wait_prompt("Type READY", timeout=5)
        terminal.send("READY")
        ready = terminal.event(timeout=5)
        self.assertEqual(ready["status"], "READY")
        self.assertEqual(ready["request_id"], intent["request_id"])
        self.assertEqual(ready["intent_sha256"], digest(intent))
        self.assertEqual(ready["profile_sha256"], digest(self.f.profile))
        self.assertIsNotNone(terminal.process.stdout)
        self.assertFalse(os.isatty(terminal.process.stdout.fileno()))
        return terminal, intent, ready, bundle_name

    def bundle(self, intent, ready):
        self.f.now = time.time_ns() // 1_000_000
        _, _, bundle = self.f.material(intent, ready)
        return bundle

    def grant_count(self):
        with sqlite3.connect(self.f.state / "journal.sqlite3") as conn:
            return conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0]

    def test_real_driver_events_and_atomic_bundle_produce_one_verifiable_counter_effect(self):
        terminal, intent, ready, bundle_name = self.start()
        bundle = self.bundle(intent, ready)
        path = self.roles.public(bundle_name, bundle)
        self.assertEqual(strict_json(path.read_bytes(), host.MAX_PUBLIC), bundle)
        awaiting = terminal.event(timeout=5)
        self.assertEqual(awaiting["status"], "AWAITING_APPROVAL")
        self.assertEqual(awaiting["bundle_sha256"], digest(bundle))
        self.assertEqual(awaiting["operation_id"], bundle["action_challenge"]["payload"]["operation_id"])
        self.assertEqual(awaiting["approval_phrase"], "APPROVE " + awaiting["operation_id"][-12:])
        # Reply immediately to the actual event; a later TTY flush would lose
        # this valid input and make the real harness intermittently time out.
        terminal.send(awaiting["approval_phrase"])
        result = terminal.event(timeout=5)
        self.assertEqual(result["status"], "GRANT_ISSUED")
        self.assertEqual(terminal.process.wait(timeout=5), 0)
        self.assertEqual([event["status"] for event in terminal.records],
                         ["READY", "AWAITING_APPROVAL", "GRANT_ISSUED"])
        self.assertIn(b"Type READY", terminal.transcript)
        self.assertEqual(self.grant_count(), 1)
        self.f.now = time.time_ns() // 1_000_000
        request = {"operation_id": result["operation_id"], "grant": result["grant"], "assessment": bundle["assessment"]}
        committed = self.f.gate.execute(request)
        self.assertEqual(committed["result"], "COMMITTED")
        repeated = self.f.gate.execute(request)
        self.assertEqual(repeated["result"], "ALREADY_COMMITTED")
        self.assertEqual(committed["receipt"], repeated["receipt"])

    def test_actual_owner_decline_has_exact_reason_and_no_persisted_grant(self):
        terminal, intent, ready, bundle_name = self.start()
        self.roles.public(bundle_name, self.bundle(intent, ready))
        self.assertEqual(terminal.event(timeout=5)["status"], "AWAITING_APPROVAL")
        terminal.send("NO")
        result = terminal.event(timeout=5)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", "OWNER_DECLINED"))
        self.assertEqual(terminal.process.wait(timeout=5), 1)
        self.assertEqual(self.grant_count(), 0)

    def test_tampered_assessment_is_blocked_before_final_prompt(self):
        terminal, intent, ready, bundle_name = self.start()
        bundle = self.bundle(intent, ready)
        tampered = copy.deepcopy(bundle)
        tampered["assessment"]["signature"] = "0" * 128
        self.roles.public(bundle_name, tampered)
        result = terminal.event(timeout=5)
        self.assertEqual((result["status"], result["reason"]), ("BLOCKED", "INVALID_SIGNATURE"))
        self.assertEqual(terminal.process.wait(timeout=5), 2)
        self.assertEqual([event["status"] for event in terminal.records], ["READY", "BLOCKED"])
        self.assertEqual(self.grant_count(), 0)

    def test_missing_bundle_times_out_with_exact_reason(self):
        terminal, _, _, _ = self.start(bundle_timeout=1)
        result = terminal.event(timeout=3)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", "BUNDLE_TIMEOUT"))
        self.assertEqual(terminal.process.wait(timeout=5), 1)
        self.assertEqual(self.grant_count(), 0)

    def test_forged_json_event_or_unbounded_output_does_not_become_a_grant(self):
        # The actual event reader is bounded even if its trusted child fails.
        for program, code in (("print('[]',flush=True)", "OWNER_EVENT"),
                              ("import sys;sys.stdout.write('x'*1025);sys.stdout.flush()", "OWNER_OUTPUT_LIMIT")):
            with self.subTest(code=code), patch.object(host, "MAX_PUBLIC", 1024):
                with host.OwnerTerminal([sys.executable, "-c", program]) as terminal:
                    with self.assertRaises(LabFailure) as raised:
                        terminal.event(timeout=3)
                    self.assertEqual(raised.exception.code, code)
        self.assertEqual(self.grant_count(), 0)

    def test_driver_timeout_closes_its_process_group(self):
        terminal = host.OwnerTerminal([sys.executable, "-c", "import time;time.sleep(10)"])
        with self.assertRaises(EnvironmentFailure) as raised:
            terminal.event(timeout=0.1)
        self.assertEqual(raised.exception.code, "OWNER_EVENT_TIMEOUT")
        terminal.close()
        self.assertIsNotNone(terminal.process.poll())


class RoleCommandShapeTests(unittest.TestCase):
    def test_limit_is_raised_after_sudo_and_before_dropping_to_each_role(self):
        roles = object.__new__(host.Roles)
        roles.python = "/trusted/python"
        roles.base = Path("/var/lib/wolfalibi-prototype/test")
        for role, module in host.MODULES.items():
            with self.subTest(role=role):
                argv = roles.argv(role, ["identity"])
                self.assertEqual(argv[:5], ["sudo", "-n", "prlimit", "--memlock=unlimited:unlimited", "--"])
                self.assertEqual(argv[5:9], ["setpriv", "--reuid=" + host.USERS[role],
                                            "--regid=" + host.USERS[role], "--init-groups"])
                self.assertEqual(argv[9:14], ["/trusted/python", "-I", "-B", "-m", module])
                self.assertEqual(argv[-2:], ["--state", str(roles.base / role / "state")])


if __name__ == "__main__":
    unittest.main()
