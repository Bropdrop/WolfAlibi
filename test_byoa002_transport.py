"""Offline experiments against live local gateway processes and a recording test target."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import threading
import unittest

from wolfalibi.byoa_qualification_cli import _new_key
from wolfalibi import byoa002_transport as transport


class LedgerControls:
    """Record protected method entry independently of client and socket results."""
    def __init__(self):
        self.dispatches = []
        self.inquiries = []
        self.changed = threading.Event()

    def dispatch(self, packet, *, peer, live):
        if not live() or packet != {"fictional": "record"}:
            return {"outcome": "DENIED"}
        self.dispatches.append(peer)
        self.changed.set()
        return {"outcome": "RECORDED_FOR_TRANSPORT_TEST"}

    def reconcile(self, packet, *, peer, live):
        if not live() or packet != {"fictional": "record"}:
            return {"outcome": "DENIED"}
        self.inquiries.append(peer)
        return {"outcome": "HISTORICAL_TRANSPORT_TEST"}


@contextmanager
def gateway(path):
    with subprocess.Popen([sys.executable, "-I", str(transport.GATEWAY), str(path)], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
        try:
            if not select.select([proc.stdout], [], [], 5)[0]:
                raise RuntimeError("gateway startup deadline")
            first = proc.stdout.readline()
            if not first:
                proc.wait(timeout=2)
                raise RuntimeError("gateway startup failed: " + proc.stderr.read())
            yield proc, json.loads(first)["peer"]
        finally:
            if proc.poll() is None:
                try:
                    proc.stdin.write('{"action":"quit"}\n')
                    proc.stdin.flush()
                    proc.wait(timeout=2)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    proc.kill()


def command(proc, obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()
    if not select.select([proc.stdout], [], [], 5)[0]:
        raise RuntimeError("gateway test response deadline")
    return json.loads(proc.stdout.readline())


class SocketTests(unittest.TestCase):
    def setUp(self):
        if not sys.platform.startswith("linux") or os.geteuid() == 0:
            self.skipTest("live unprivileged Linux gateway required")
        tmp = tempfile.TemporaryDirectory(prefix="qv-socket-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        endpoint_dir = self.root / "endpoint"
        endpoint_dir.mkdir(mode=0o700)
        self.endpoint = endpoint_dir / "target.sock"
        self.target = LedgerControls()
        self.pins = {"expected_target_pid": os.getpid(), "expected_target_uid": os.geteuid()}

    def start_server(self, peer):
        stop, ready = threading.Event(), threading.Event()
        errors = []

        def main():
            try:
                transport.serve(self.target, self.endpoint, gateway_peer=peer, on_ready=ready.set, stop_event=stop)
            except Exception as exc:
                errors.append(str(exc))

        thread = threading.Thread(target=main)
        thread.start()

        def finish():
            stop.set()
            thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

        self.addCleanup(finish)
        self.assertTrue(ready.wait(3), errors)

    def rpc(self, proc, action, **pins):
        return command(proc, {"action": action, "packet": {"fictional": "record"}, **self.pins, **pins})

    def test_kernel_enrolled_gateway_and_true_restart_on_ambiguous_delivery(self):
        with gateway(self.endpoint) as (original, expected):
            self.assertEqual(transport.measure_gateway(original.pid, self.endpoint), expected)
            self.start_server(expected)
            self.assertEqual(self.rpc(original, "lose-reply")["outcome"], "UNKNOWN")
            self.assertTrue(self.target.changed.wait(2))
        self.assertEqual(self.target.dispatches, [expected])
        with gateway(self.endpoint) as (replacement, new_identity):
            self.assertNotEqual(new_identity["pid"], expected["pid"])
            self.assertEqual(self.rpc(replacement, "dispatch")["outcome"], "DENIED")
            self.assertEqual(self.rpc(replacement, "reconcile")["outcome"], "HISTORICAL_TRANSPORT_TEST")
        self.assertEqual(self.target.dispatches, [expected])
        self.assertEqual(self.target.inquiries, [new_identity])

    def test_wrong_live_source_and_target_pin_are_refused_before_effect(self):
        with gateway(self.endpoint) as (proc, expected):
            self.start_server(expected)
            self.assertEqual(self.rpc(proc, "dispatch", expected_target_pid=proc.pid)["outcome"], "BLOCKED")
            # The test process shares this UID but its executable arguments and script differ.
            result = transport.request(self.endpoint, "dispatch", {"fictional": "record"}, **self.pins)
            self.assertEqual(result["outcome"], "DENIED")
            self.assertEqual(self.target.dispatches, [])
            self.assertEqual(self.rpc(proc, "dispatch")["outcome"], "RECORDED_FOR_TRANSPORT_TEST")
        self.assertEqual(len(self.target.dispatches), 1)

    def test_same_uid_is_unsupported_for_owned_files_without_open_attempts(self):
        with gateway(self.endpoint) as (proc, expected):
            key_dir, ledger_dir = self.root / "keys", self.root / "ledger"
            key_dir.mkdir(mode=0o700)
            ledger_dir.mkdir(mode=0o700)
            key, database = key_dir / "target.seed", ledger_dir / "ledger.sqlite"
            signer = _new_key(key_dir, "target")
            database.touch(mode=0o600)
            inventory = transport.make_inventory(key, database, signer, expected)
            self.assertEqual(inventory["payload"]["gateway"], expected)
            result = command(proc, {"action": "custody", **self.pins, "target_pub": signer.pub.hex(),
                                    "inventory": inventory})
            self.assertEqual(result["outcome"], "UNSUPPORTED")
            self.assertNotIn("file_opens", result)
            database.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "inventory"):
                transport.make_inventory(key, database, signer, expected)


    def test_owner_control_cli_emits_measured_peer_and_authenticated_denial(self):
        controls = [sys.executable, "-I", str(transport.GATEWAY.with_name("byoa002_peer_control.py"))]
        with gateway(self.endpoint) as (proc, expected):
            args = ["measure", "--gateway-pid", str(proc.pid), "--gateway-uid", str(os.geteuid()),
                    "--socket", str(self.endpoint)]
            run = subprocess.run(controls + args, capture_output=True, text=True, check=True, timeout=5)
            self.assertEqual(json.loads(run.stdout), {"outcome": "MEASURED", "observer_uid": os.geteuid(),
                                                       "peer": expected})
            self.start_server(expected)
            packet_path = self.root / "public-packet.json"
            packet_path.write_text('{"fictional":"record"}')
            args = ["wrong-peer", "--target-pid", str(os.getpid()), "--target-uid", str(os.geteuid()),
                    "--packet", str(packet_path), "--socket", str(self.endpoint)]
            run = subprocess.run(controls + args, capture_output=True, text=True, check=True, timeout=5)
            observed = json.loads(run.stdout)
            self.assertEqual(observed["attempt"]["outcome"], "DENIED")
            self.assertEqual(observed["sender_uid"], os.geteuid())
            self.assertEqual(self.target.dispatches, [])

    def test_owner_inventory_reports_actual_own_key_and_nested_ledger_without_custody_claim(self):
        with gateway(self.endpoint) as (_, expected):
            private = self.root / "owner"
            ledger = private / "ledger"
            private.mkdir(mode=0o700)
            ledger.mkdir(mode=0o700)
            signer = _new_key(private, "target")
            wrong = _new_key(private, "other")
            db = ledger / "ledger.sqlite"
            db.touch(mode=0o600)
            with self.assertRaisesRegex(ValueError, "signing key"):
                transport.make_inventory(private / "target.seed", db, wrong, expected)
            inv = transport.make_inventory(private / "target.seed", db, signer, expected)["payload"]
            record = inv["files"]["ledger"]
            # An owner can open its own files. These low-level observations confer no custody.
            observed = transport._gateway_file_opens(record, "ledger", os.geteuid())
            self.assertEqual([r["outcome"] for r in observed.values()], ["OPENED", "OPENED"])
            self.assertEqual(observed["ledger.write"]["pinned_ancestor"], str(ledger))
            self.assertEqual(db.stat().st_size, 0)
            record["directories"][-2]["ino"] = "0"
            with self.assertRaisesRegex(ValueError, "kernel directory"):
                transport._gateway_file_opens(record, "ledger", os.geteuid())
