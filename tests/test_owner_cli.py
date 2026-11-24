"""Scripted PTY boundary tests: actual_human_approval is explicitly NOT_RUN.

All signed evidence is fabricated by OwnerFixture. Real PTYs exercise the
foreground terminal, framing, consent sequencing, deadlines and frozen inputs.
No passing result here claims a human decision or actual TPM verification.
"""

from __future__ import annotations

import json
import os
import pty
import select
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from shirudo_adapter.model import canonical_json, digest

try:
    from .test_owner import OwnerFixture
except ImportError:
    from test_owner import OwnerFixture


REPOSITORY = Path(__file__).resolve().parents[1]
MODULE = "shirudo_adapter.owner_cli"
LAUNCHER = """
import fcntl, os, sys, termios
fd = int(sys.argv.pop(1))
fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
from shirudo_adapter.owner_cli import main
try:
    raise SystemExit(main())
finally:
    os.close(fd)
"""


class OwnerTerminal:
    """Scripted test driver; input comes from this test, not a person."""

    def __init__(self, case, fixture, *, ready_timeout=5, bundle_timeout=5, existing=False):
        self.case, self.fixture = case, fixture
        self.intent = fixture.intent()
        self.intent_path = fixture.root / "intent.json"
        self.intent_path.write_bytes(canonical_json(self.intent))
        self.bundle_path = fixture.root / "fresh-bundle.json"
        if existing:
            self.bundle_path.write_bytes(b"{}")
        try:
            self.master, slave = pty.openpty()
        except (PermissionError, OSError) as exc:
            # The production workflow must never treat missing PTYs as a pass.
            if os.environ.get("GITHUB_ACTIONS") == "true":
                raise
            case.skipTest(f"This local environment cannot allocate a PTY; mandatory CI exercises it: {exc}")
        try:
            self.process = subprocess.Popen([
                sys.executable, "-c", LAUNCHER, str(slave), "approve", "--state", str(fixture.state),
                "--intent", str(self.intent_path), "--bundle", str(self.bundle_path),
                "--ready-timeout", str(ready_timeout), "--bundle-timeout", str(bundle_timeout),
            ], cwd=REPOSITORY, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
               pass_fds=(slave,), start_new_session=True, bufsize=0)
        finally:
            os.close(slave)
        self.output = bytearray()
        self.terminal = bytearray()
        case.addCleanup(self.close)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.process.stdout.close()
        self.process.stderr.close()
        if self.master is not None:
            os.close(self.master)
            self.master = None

    def send(self, line):
        os.write(self.master, line.encode("ascii"))

    def prompt(self, marker=b"Type READY", timeout=5):
        deadline = time.monotonic() + timeout
        while marker not in self.terminal:
            remaining = deadline - time.monotonic()
            self.case.assertGreater(remaining, 0, bytes(self.terminal))
            self.case.assertTrue(select.select([self.master], [], [], remaining)[0], bytes(self.terminal))
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                chunk = b""
            self.case.assertTrue(chunk, "Owner process closed its terminal before the prompt")
            self.terminal.extend(chunk)
            self.case.assertLess(len(self.terminal), 32_768)

    def event(self, timeout=5):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.output:
            remaining = deadline - time.monotonic()
            self.case.assertGreater(remaining, 0, bytes(self.output))
            self.case.assertTrue(select.select([self.process.stdout], [], [], remaining)[0], bytes(self.output))
            chunk = os.read(self.process.stdout.fileno(), 16_384)
            self.case.assertTrue(chunk, "Owner exited without a complete public JSON event")
            self.output.extend(chunk)
            self.case.assertLess(len(self.output), 131_072)
        line, _, rest = self.output.partition(b"\n")
        self.output = bytearray(rest)
        return json.loads(line)

    def ready(self):
        self.prompt()
        self.send("READY\n")
        result = self.event()
        self.case.assertEqual(result["status"], "READY", result)
        self.case.assertEqual(result["request_id"], self.intent["request_id"])
        return result

    def material(self, ready):
        self.fixture.now = time.time_ns() // 1_000_000
        _, _, bundle = self.fixture.material(self.intent, ready)
        return bundle

    def publish(self, bundle):
        staged = self.fixture.root / "bundle-staged.json"
        staged.write_bytes(canonical_json(bundle))
        staged.replace(self.bundle_path)

    def fresh_prompt(self):
        ready = self.ready()
        bundle = self.material(ready)
        self.publish(bundle)
        awaiting = self.event()
        self.case.assertEqual(awaiting["status"], "AWAITING_APPROVAL", awaiting)
        return awaiting, bundle

    def exit(self, expected, timeout=5):
        self.case.assertEqual(self.process.wait(timeout=timeout), expected)
        self.case.assertEqual(self.process.stderr.read(), b"")


class OwnerCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wa-owner-cli-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.f = OwnerFixture(self.root / "fixture")

    def count(self, fixture=None):
        fixture = fixture or self.f
        with sqlite3.connect(fixture.state / "journal.sqlite3") as conn:
            return conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0]

    def invoke(self, *args, stdin=b"", timeout=5):
        result = subprocess.run([sys.executable, "-m", MODULE, *map(str, args)],
            cwd=REPOSITORY, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, timeout=timeout, check=False)
        self.assertLess(len(result.stdout), 131_072)
        return result, [json.loads(line) for line in result.stdout.splitlines()]

    def test_init_identity_profile_review_and_grant_lookup_are_public_json(self):
        state = self.root / "new-state"
        result, events = self.invoke("init", "--state", state)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(events[0]["status"], "INITIALIZED")
        self.assertEqual(set(events[0]["identity"]), {"schema", "owner_instance_id", "public_key", "profile_sha256"})
        profile_path = self.root / "profile.json"
        profile_path.write_bytes(canonical_json(self.f.profile))
        result, events = self.invoke("pin-profile", "--state", self.f.state, "--profile", profile_path)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(events[0]["status"], "PROFILE_PINNED")
        intent_path = self.root / "intent.json"
        intent_path.write_bytes(canonical_json(self.f.intent()))
        result, events = self.invoke("review", "--state", self.f.state, "--intent", intent_path)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(events[0]["authorization"], "NONE")
        result, events = self.invoke("grant", "--state", self.f.state, "--operation-id", "11" * 16)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(events[0]["reason"], "UNKNOWN_OPERATION")

    def test_piped_confirmation_without_controlling_terminal_is_rejected(self):
        intent_path = self.root / "intent.json"
        intent_path.write_bytes(canonical_json(self.f.intent()))
        result, events = self.invoke("approve", "--state", self.f.state, "--intent", intent_path,
            "--bundle", self.root / "bundle.json", stdin=b"READY\nAPPROVE anything\n")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(events[0]["reason"], "TERMINAL_REQUIRED")
        self.assertEqual(self.count(), 0)

    def test_no_yes_option_and_no_unknown_provisioning_flags(self):
        result, events = self.invoke("approve", "--state", self.f.state, "--intent", "unused",
            "--bundle", "/unused", "--yes")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(events, [])
        self.assertIn(b"unrecognized arguments", result.stderr)

    def test_scripted_ready_and_concrete_approval_return_bound_grant(self):
        terminal = OwnerTerminal(self, self.f)
        awaiting, bundle = terminal.fresh_prompt()
        terminal.send(awaiting["approval_phrase"] + "\n")
        result = terminal.event()
        self.assertEqual(result["status"], "GRANT_ISSUED")
        self.assertEqual(result["grant"]["payload"]["attestation_receipt_sha256"], digest(bundle["assessment"]))
        terminal.exit(0)
        self.assertEqual(self.count(), 1)
        invocation, events = self.invoke("grant", "--state", self.f.state, "--operation-id", result["operation_id"])
        self.assertEqual(invocation.returncode, 0)
        self.assertEqual(events[0]["grant"], result["grant"])

    def test_declining_ready_creates_no_authority(self):
        terminal = OwnerTerminal(self, self.f)
        terminal.prompt()
        terminal.send("NO\n")
        result = terminal.event()
        self.assertEqual((result["status"], result["reason"]), ("DENIED", "OWNER_DECLINED"))
        terminal.exit(1)
        self.assertEqual(self.count(), 0)

    def test_wrong_final_phrase_does_not_sign(self):
        terminal = OwnerTerminal(self, self.f)
        terminal.fresh_prompt()
        terminal.send("APPROVE wrong\n")
        self.assertEqual(terminal.event()["reason"], "OWNER_DECLINED")
        terminal.exit(1)
        self.assertEqual(self.count(), 0)

    def test_ready_timeout_and_bundle_timeout_emit_no_grant(self):
        terminal = OwnerTerminal(self, self.f, ready_timeout=1)
        terminal.prompt()
        self.assertEqual(terminal.event(timeout=3)["reason"], "APPROVAL_TIMEOUT")
        terminal.exit(1)
        second = OwnerTerminal(self, self.f, bundle_timeout=1)
        second.ready()
        self.assertEqual(second.event(timeout=3)["reason"], "BUNDLE_TIMEOUT")
        second.exit(1)
        self.assertEqual(self.count(), 0)

    def test_final_prompt_expires_instead_of_refreshing_the_challenge(self):
        short = OwnerFixture(self.root / "short", ttl=3)
        terminal = OwnerTerminal(self, short)
        terminal.fresh_prompt()
        result = terminal.event(timeout=4)
        self.assertEqual(result["reason"], "APPROVAL_TIMEOUT")
        terminal.exit(1)
        self.assertEqual(self.count(short), 0)

    def test_prequeued_approval_is_flushed_before_concrete_prompt(self):
        terminal = OwnerTerminal(self, self.f)
        ready = terminal.ready()
        bundle = terminal.material(ready)
        phrase = "APPROVE " + bundle["action_challenge"]["payload"]["operation_id"][-12:]
        terminal.send(phrase + "\n")
        terminal.publish(bundle)
        self.assertEqual(terminal.event()["status"], "AWAITING_APPROVAL")
        terminal.send("NO\n")
        result = terminal.event()
        self.assertEqual(result["reason"], "OWNER_DECLINED")
        terminal.exit(1)
        self.assertEqual(self.count(), 0)

    def test_bundle_existing_before_ready_or_during_review_is_rejected(self):
        existing = OwnerTerminal(self, self.f, existing=True)
        self.assertEqual(existing.event()["reason"], "BUNDLE_EXISTS")
        existing.exit(2)
        existing.bundle_path.unlink()
        during = OwnerTerminal(self, self.f)
        during.prompt()
        during.bundle_path.write_bytes(b"{}")
        during.send("READY\n")
        self.assertEqual(during.event()["reason"], "BUNDLE_EXISTS")
        during.exit(2)
        self.assertEqual(self.count(), 0)

    def test_replaced_public_files_after_prompt_cannot_change_frozen_grant(self):
        terminal = OwnerTerminal(self, self.f)
        awaiting, bundle = terminal.fresh_prompt()
        original_digest = digest(bundle["assessment"])
        terminal.bundle_path.write_bytes(b'{"untrusted":"replacement"}')
        terminal.intent_path.write_bytes(b'{"target_id":"replacement"}')
        terminal.send(awaiting["approval_phrase"] + "\n")
        result = terminal.event()
        self.assertEqual(result["grant"]["payload"]["attestation_receipt_sha256"], original_digest)
        terminal.exit(0)

    def test_duplicate_json_or_symlink_bundle_never_reaches_final_confirmation(self):
        terminal = OwnerTerminal(self, self.f)
        terminal.ready()
        terminal.bundle_path.write_bytes(b'{"schema":1,"schema":2}')
        self.assertEqual(terminal.event()["reason"], "DUPLICATE_JSON_KEY")
        terminal.exit(2)
        terminal.bundle_path.unlink()
        second = OwnerTerminal(self, self.f)
        second.ready()
        second.bundle_path.symlink_to(self.root / "missing")
        self.assertEqual(second.event()["reason"], "BUNDLE_PATH")
        second.exit(2)
        self.assertEqual(self.count(), 0)

    def test_bounded_confirmation_line_and_terminal_eof_are_denials(self):
        terminal = OwnerTerminal(self, self.f)
        terminal.prompt()
        terminal.send("R" * 129 + "\n")
        self.assertEqual(terminal.event()["reason"], "APPROVAL_INVALID")
        terminal.exit(1)
        second = OwnerTerminal(self, self.f)
        second.prompt()
        second.send("\x04")
        self.assertEqual(second.event()["reason"], "APPROVAL_EOF")
        second.exit(1)
        self.assertEqual(self.count(), 0)

    def test_boot_policy_command_produces_only_narrow_provisioning_envelope(self):
        anchors, trust, manifest = self.f.provisioning()
        paths = {}
        for name, document in (("anchor", anchors), ("trust", trust), ("manifest", manifest)):
            paths[name] = self.root / (name + ".json")
            paths[name].write_bytes(canonical_json(document))
        result, events = self.invoke("sign-boot-policy", "--state", self.f.state,
            "--anchor", paths["anchor"], "--trust", paths["trust"], "--manifest", paths["manifest"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(events[0]["status"], "BOOT_POLICY_SIGNED")
        self.assertEqual(events[0]["action_authorization"], "NONE")
        self.assertEqual(events[0]["boot_policy"]["payload"]["scope"], "LAB_IMMUTABLE_GATE_BOOTSTRAP")
        self.assertEqual(self.count(), 0)


if __name__ == "__main__":
    unittest.main()
