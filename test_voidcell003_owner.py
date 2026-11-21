"""Local owner controls. These tests exercise one UID and never qualify gateway custody."""

import json
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import time
import unittest
from unittest.mock import patch

import test_voidcell002 as baseline
from wolfalibi.voidcell003_owner import inspect_crash, observe, serve_trial
from wolfalibi.voidcell002_transport import CONNECTION_TIMEOUT_SECONDS
from wolfalibi.voidcell_records import dispatch_digest


def crash_at_owner_boundary(state, retained, packet):
    def deliver(target, **kwargs):
        target.dispatch(packet)

    # Exercise the real fault point with a target-local packet in this single-UID fixture.
    with patch("wolfalibi.voidcell003_owner.serve", deliver):
        serve_trial(state, retained, None, crash_after_commit=True, revision=None)


def export(name, record):
    directory = os.environ.get("WOLFALIBI_VOIDCELL003_OWNER_EVIDENCE")
    if directory:
        with (Path(directory) / name).open("x", encoding="utf-8") as output:
            json.dump(record, output, sort_keys=True)


class OwnerControls(unittest.TestCase):
    def setUp(self):
        self.fixture = baseline.Voidcell002TargetTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.ctx = multiprocessing.get_context("spawn")

    def test_owner_endpoint_denies_gateway_role_with_stable_counter(self):
        f = self.fixture
        directory = f.root / "endpoint"
        directory.mkdir(mode=0o711)
        directory.chmod(0o711)
        endpoint = directory / "target.sock"
        with f._target() as target:
            packet = f._packet(target)
        ready = self.ctx.Event()
        process = self.ctx.Process(target=baseline._serve_fixture,
                                   args=(f.state, f.anchor, endpoint, f.gateway_uid, ready))
        process.start()
        try:
            self.assertTrue(ready.wait(10))
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as idle:
                idle.connect(str(endpoint))
                started = time.monotonic()
                record = observe(endpoint, process.pid, packet)
                elapsed = time.monotonic() - started
            self.assertEqual(record["outcome"], "OBSERVED", record)
            self.assertEqual(record["attempted_dispatch_sha256"], dispatch_digest(packet))
            self.assertEqual(record["owner_status_after"]["effect_count"], 0)
            self.assertLess(elapsed, CONNECTION_TIMEOUT_SECONDS)
            self.assertEqual(observe(endpoint, os.getpid())["outcome"], "BLOCKED")
            export("owner.json", dict(record, idle_connections=1, elapsed_seconds=elapsed,
                                      read_deadline_seconds=CONNECTION_TIMEOUT_SECONDS))
        finally:
            if process.is_alive():
                os.kill(process.pid, signal.SIGINT)
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join()
            process.close()

    def test_disposable_target_dies_after_commit_and_rejects_reopen(self):
        f = self.fixture
        with f._target() as target:
            prior = target.status()["anchor"]["anchor_sha256"]
            operation = target.scope["operation_id"]
            packet = f._packet(target)
        with self.assertRaisesRegex(ValueError, "expected exactly one"):
            inspect_crash(f.state, f.anchor, prior, operation)
        child = self.ctx.Process(target=crash_at_owner_boundary, args=(f.state, f.anchor, packet))
        child.start()
        try:
            child.join(10)
            self.assertEqual(child.exitcode, 73)
            record = inspect_crash(f.state, f.anchor, prior, operation)
            self.assertEqual(record["outcome"], "FAIL_STOP_OBSERVED", record)
            self.assertEqual(record["dispatch_sha256"], dispatch_digest(packet))
            with self.assertRaisesRegex(ValueError, "pre-trial reference"):
                inspect_crash(f.state, f.anchor, "00" * 32, operation)
            export("crash.json", dict(record, process_exitcode=child.exitcode))
        finally:
            if child.is_alive():
                child.kill()
                child.join()
            child.close()
