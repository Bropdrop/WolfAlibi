"""Explicit disposable-CI sudo/UID/PTY regression; excluded from discovery.

Run only with the existing disposable-CI guards on the selected Ubuntu runner:
    python -m unittest tests.prototype_sudo_probe -v

This creates and removes one temporary Unix account and its private fixture
state. All evidence is fabricated; the owner key is created and used only in
processes under that account. No TPM, VM, genuine assessment, target effect,
or actual human approval is claimed.
"""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from scripts import shirudo_prototype_host as host
from shirudo_adapter.model import canonical_json, digest, strict_json
from shirudo_adapter.receipt import verify_record

FIXTURE_SOURCE_FILES = ("test_owner.py", "test_action_gate.py", "support.py")


# This helper retains fabricated authority keys within the separate test UID.
# Only public records cross its bounded JSON pipe. The real owner CLI alone
# issues a grant, and the helper later reads the private journal's row count.
FIXTURE_HELPER = r"""
import json, os, sqlite3, sys, time
from pathlib import Path
# Resolve the installed adapter before adding the public fixture-only path.
# The private runner checkout is never an import path for this role.
import shirudo_adapter
sys.path.insert(0, sys.argv[1])
import test_owner, test_action_gate, support
if any(Path(module.__file__).parent != Path(sys.argv[1])
       for module in (test_owner, test_action_gate, support)):
    raise SystemExit('Unexpected public fixture module source')
from test_owner import OwnerFixture
from shirudo_adapter.model import canonical_json, strict_json
fixture = OwnerFixture(Path(sys.argv[2]))
intent = fixture.intent()
def emit(value):
    print(canonical_json(value).decode('ascii'), flush=True)
def receive():
    return strict_json(sys.stdin.buffer.readline(16385), 16384)
emit({'uid':os.geteuid(), 'state':str(fixture.state), 'intent':intent,
      'owner_identity':fixture.owner.public_identity()})
message = receive()
if message.get('status') == 'READY':
    fixture.now = time.time_ns() // 1000000
    _, _, bundle = fixture.material(intent, message)
    emit(bundle)
    message = receive()
if message != {'command':'finish'}:
    raise SystemExit(3)
with sqlite3.connect(fixture.state / 'journal.sqlite3') as connection:
    count = connection.execute('SELECT COUNT(*) FROM grants').fetchone()[0]
with sqlite3.connect('file:' + str(fixture.gate.path / 'journal.sqlite3') + '?mode=ro', uri=True) as connection:
    counter = connection.execute('SELECT value FROM counter WHERE id=1').fetchone()[0]
    committed = connection.execute("SELECT COUNT(*) FROM operations WHERE status='COMMITTED'").fetchone()[0]
emit({'uid':os.geteuid(), 'recorded_grants':count, 'counter':counter, 'committed_operations':committed,
      'scope':'FABRICATED_TERMINAL_REGRESSION', 'actual_human_approval':'NOT_RUN'})
"""


class PublicFixture:
    def __init__(self, argv):
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.buffer, self.errors = bytearray(), bytearray()
        for stream in (self.process.stdout, self.process.stderr):
            os.set_blocking(stream.fileno(), False)

    def send(self, value):
        raw = canonical_json(value) + b"\n"
        if len(raw) > 16384:
            raise AssertionError("Oversized public fixture request")
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def receive(self, timeout=10):
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(self.process.stderr, selectors.EVENT_READ, "stderr")
            while time.monotonic() < deadline:
                if b"\n" in self.buffer:
                    line, _, self.buffer = self.buffer.partition(b"\n")
                    return strict_json(bytes(line), host.MAX_PUBLIC)
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    data = os.read(key.fd, 16384)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    target = self.buffer if key.data == "stdout" else self.errors
                    if len(target) + len(data) > host.MAX_PUBLIC:
                        raise AssertionError("Unbounded fixture output")
                    target.extend(data)
                if not selector.get_map() and b"\n" not in self.buffer:
                    break
        raise AssertionError("Public fixture output unavailable: " +
                             bytes(self.errors[-2048:]).decode("utf-8", "replace"))

    def close(self):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            # The owning test's cleanup kills only its dedicated CI account.
            pass
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


class ActualSudoOwnerTerminalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No skipped/fake PASS: an explicitly requested probe requires CI.
        run = host.selected_run()
        if os.geteuid() == 0 or shutil.which("sudo") is None:
            raise RuntimeError("This probe requires the nonroot disposable CI administrator and sudo")
        cls.user = "wa-ttyprobe-" + format(os.getpid(), "x")
        cls.base = Path("/var/lib") / f"wolfalibi-ttyprobe-{run}-{os.getpid()}"
        cls.exchange = Path("/var/tmp") / f"wolfalibi-ttyprobe-{run}-{os.getpid()}"
        if os.path.lexists(cls.base) or os.path.lexists(cls.exchange):
            raise RuntimeError("Probe paths must be new")
        cls.created_user = False
        cls.addClassCleanup(cls.cleanup)
        cls.run_command(["sudo", "-n", "useradd", "--system", "--user-group", "--no-create-home",
                         "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", cls.user])
        cls.created_user = True
        cls.run_command(["sudo", "-n", "install", "-d", "-m", "0755", "-o", "root", "-g", "root", str(cls.base)])
        cls.run_command(["sudo", "-n", "install", "-d", "-m", "0700", "-o", cls.user, "-g", cls.user, str(cls.base / "owner")])
        cls.public_sources = cls.base / "public-fixtures"
        cls.run_command(["sudo", "-n", "install", "-d", "-m", "0755", "-o", "root", "-g", "root", str(cls.public_sources)])
        info = cls.public_sources.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o755:
            raise AssertionError("Public fixture source directory is not root-owned 0755")
        manifest = {}
        for name in FIXTURE_SOURCE_FILES:
            source, destination = host.ROOT / "tests" / name, cls.public_sources / name
            original = host.read_bounded_file(source, host.MAX_PUBLIC)
            cls.run_command(["sudo", "-n", "install", "-m", "0444", "-o", "root", "-g", "root", str(source), str(destination)])
            copied = host.read_bounded_file(destination, host.MAX_PUBLIC)
            info = destination.lstat()
            expected = hashlib.sha256(original).hexdigest()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1
                    or copied != original or hashlib.sha256(copied).hexdigest() != expected):
                raise AssertionError("Public fixture copy verification failed: " + name)
            manifest[name] = {"bytes": len(copied), "sha256": expected, "mode": "0444"}
        if {path.name for path in cls.public_sources.iterdir()} != set(FIXTURE_SOURCE_FILES):
            raise AssertionError("Unexpected public fixture source entry")
        print(json.dumps({"probe": "public-fixture-source-staging", "result": "PASS",
                          "adapter_source": "INSTALLED_PACKAGE", "files": manifest}, sort_keys=True))
        cls.exchange.mkdir(mode=0o755)
        cls.uid = int(cls.run_command(["id", "-u", cls.user]).stdout)
        if cls.uid <= 0 or cls.uid == os.geteuid():
            raise RuntimeError("Probe account must have a separate nonroot UID")

    @classmethod
    def run_command(cls, argv, *, accepted=(0,)):
        result = subprocess.run(argv, capture_output=True, timeout=20)
        if result.returncode not in accepted:
            raise AssertionError("Probe administration failed: " + str(argv[0]) + ": " +
                                 result.stderr[-2048:].decode("utf-8", "replace"))
        return result

    @classmethod
    def cleanup(cls):
        if cls.created_user:
            cls.run_command(["sudo", "-n", "pkill", "-KILL", "-u", cls.user], accepted=(0, 1))
        cls.run_command(["sudo", "-n", "rm", "-rf", "--", str(cls.base), str(cls.exchange)])
        if cls.created_user:
            cls.run_command(["sudo", "-n", "userdel", cls.user])

    def setUp(self):
        self.patch = patch.dict(host.USERS, {"owner": self.user})
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.roles = object.__new__(host.Roles)
        self.roles.python = str(Path(sys.executable).resolve())
        self.roles.base, self.roles.exchange = self.base, self.exchange
        self.name = self._testMethodName
        self.fixture_root = self.base / "owner" / self.name
        self.prefix = self.roles.argv("owner", ["identity"])[:9]
        self.helper = PublicFixture([*self.prefix, self.roles.python, "-I", "-B", "-c",
            FIXTURE_HELPER, str(self.public_sources), str(self.fixture_root)])
        self.addCleanup(self.helper.close)
        self.public = self.helper.receive()
        self.assertEqual(self.public["uid"], self.uid)
        self.assertEqual(self.public["state"], str(self.fixture_root / "owner-state"))
        self.intent_path = self.roles.public(self.name + "-intent.json", self.public["intent"])
        self.bundle_path = self.exchange / (self.name + "-bundle.json")

    def approval(self, *, handoff):
        args = self.roles.argv("owner", ["approve", "--intent", str(self.intent_path),
            "--bundle", str(self.bundle_path), "--ready-timeout", "10", "--bundle-timeout", "10"], terminal=handoff)
        # The synthetic fixture chooses owner-state rather than provision's
        # state basename. The sudo/limit/UID/launcher chain is unchanged.
        args[-1] = self.public["state"]
        return args

    def finish_fixture(self, expected_grants):
        self.helper.send({"command": "finish"})
        result = self.helper.receive()
        self.assertEqual(result, {"uid": self.uid, "recorded_grants": expected_grants,
            "counter": 0, "committed_operations": 0,
            "scope": "FABRICATED_TERMINAL_REGRESSION", "actual_human_approval": "NOT_RUN"})
        self.assertEqual(self.helper.process.wait(timeout=5), 0)
        return result

    def test_old_pipe_chain_is_background_and_owner_rejects_it(self):
        observe = ("import json,os;fd=os.open('/dev/tty',os.O_RDWR);"
                   "print(json.dumps({'uid':os.geteuid(),'process_group':os.getpgrp(),"
                   "'foreground_group':os.tcgetpgrp(fd),'is_tty':os.isatty(fd)}),flush=True)")
        with host.OwnerTerminal([*self.prefix, self.roles.python, "-I", "-c", observe]) as terminal:
            observed = terminal.event(timeout=10)
            self.assertEqual(terminal.process.wait(timeout=5), 0)
        self.assertEqual(observed["uid"], self.uid)
        self.assertIs(observed["is_tty"], True)
        self.assertNotEqual(observed["process_group"], observed["foreground_group"],
                            "The selected CI sudo topology did not reproduce the background-group condition")
        with host.OwnerTerminal(self.approval(handoff=False)) as terminal:
            denied = terminal.event(timeout=10)
            self.assertEqual((denied["status"], denied["reason"]), ("BLOCKED", "TERMINAL_REQUIRED"))
            self.assertEqual(terminal.process.wait(timeout=5), 2)
        counts = self.finish_fixture(0)
        print(json.dumps({"probe": "original-sudo-background-condition", "result": "PASS",
                          "terminal_observation": observed, "owner_result": denied, **counts}, sort_keys=True))

    def test_handoff_forwards_ready_and_final_approval_under_separate_uid(self):
        with host.OwnerTerminal(self.approval(handoff=True)) as terminal:
            terminal.wait_prompt("Type READY", timeout=10)
            terminal.send("READY")
            ready = terminal.event(timeout=10)
            self.assertEqual(ready["status"], "READY")
            self.assertEqual(ready["intent_sha256"], digest(self.public["intent"]))
            self.helper.send(ready)
            bundle = self.helper.receive()
            self.roles.public(self.bundle_path.name, bundle)
            awaiting = terminal.event(timeout=10)
            self.assertEqual(awaiting["status"], "AWAITING_APPROVAL")
            self.assertEqual(awaiting["bundle_sha256"], digest(bundle))
            terminal.send(awaiting["approval_phrase"])
            issued = terminal.event(timeout=10)
            self.assertEqual((issued["status"], issued["effect"]), ("GRANT_ISSUED", "NOT_ESTABLISHED"))
            self.assertEqual(terminal.process.wait(timeout=5), 0)
            self.assertEqual([r["status"] for r in terminal.records], ["READY", "AWAITING_APPROVAL", "GRANT_ISSUED"])
            grant = verify_record(issued["grant"], self.public["owner_identity"]["public_key"])
            self.assertEqual(grant["operation_id"], awaiting["operation_id"])
            self.assertEqual(grant["attestation_receipt_sha256"], digest(bundle["assessment"]))
            self.assertFalse(os.isatty(terminal.process.stdout.fileno()))
            self.assertIn(b"Type READY", terminal.transcript)
            self.assertIn(awaiting["approval_phrase"].encode("ascii"), terminal.transcript)
        counts = self.finish_fixture(1)
        print(json.dumps({"probe": "separate-owner-sudo-terminal-handoff", "result": "PASS",
            "events": ["READY", "AWAITING_APPROVAL", "GRANT_ISSUED"],
            "owner_signature_verified": True, **counts}, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
