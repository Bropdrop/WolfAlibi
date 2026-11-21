"""Kill a disposable payment target on either side of the actual SQLite commit."""

from contextlib import closing
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from examples.quorvane_finance_demo import fixture
from wolfalibi.finance_records import digest
from wolfalibi.finance_verify import verify_admission
from wolfalibi.finance_target import FinanceTarget
from wolfalibi.finance_transport import serve


def serve_until_crash(state, anchor, endpoint, phase):
    def crash():
        print("crash-point", flush=True)
        os.kill(os.getpid(), signal.SIGKILL)

    with FinanceTarget(state, anchor) as target:
        if phase == "before-commit":
            intent_written = False

            def trace(statement):
                nonlocal intent_written
                sql = statement.lstrip().upper()
                if sql.startswith("INSERT INTO EFFECTS"):
                    intent_written = True
                elif sql == "COMMIT" and intent_written:
                    # The trace precedes SQLite executing the COMMIT.
                    crash()

            target._db.set_trace_callback(trace)
        elif phase == "before-checkpoint":
            target._anchor.advance = lambda _target: crash()
        else:
            raise ValueError("unknown crash point")
        serve(target, endpoint, on_ready=lambda: print("ready", flush=True))


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "requires the Linux caller fixture")
class PaymentCrashTests(unittest.TestCase):
    def crash_during_dispatch(self, resource, phase):
        packet = resource.invoke("sign")["packet"]
        resource.stop_target()
        proc = subprocess.Popen(
            [sys.executable, "-m", "test_finance_crash", str(resource.target_state),
             str(resource.anchor), str(resource.endpoint), phase],
            cwd=Path(__file__).resolve().parent, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        )
        resource.target = proc
        try:
            self.assertTrue(select.select([proc.stdout], [], [], 8)[0], "target did not start")
            self.assertEqual(proc.stdout.readline(), b"ready\n")
            socket_info = resource.endpoint.lstat()
            sent = resource.invoke()
            self.assertEqual(sent["packet"], packet)
            self.assertEqual(sent["result"]["outcome"], "UNKNOWN", sent["result"])
            self.assertNotIn("receipt", sent["result"])
            self.assertEqual(proc.wait(timeout=8), -signal.SIGKILL)
            self.assertEqual(proc.stdout.read(), b"crash-point\n")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=8)
            proc.stdout.close()
            resource.target = None

        # The owner removes only its fixture socket after confirming process death.
        stale = resource.endpoint.lstat()
        self.assertTrue(stat.S_ISSOCK(stale.st_mode))
        self.assertEqual((stale.st_dev, stale.st_ino, stale.st_uid),
                         (socket_info.st_dev, socket_info.st_ino, os.geteuid()))
        resource.endpoint.unlink()
        return packet

    def test_process_death_before_commit_leaves_no_intent_and_reconcile_fences(self):
        with TemporaryDirectory() as tmp, fixture(tmp) as resource:
            packet = self.crash_during_dispatch(resource, "before-commit")
            resource.start_target()
            fenced = resource.invoke("reconcile", packet=packet)["result"]
            self.assertEqual(fenced["outcome"], "DENIED")
            self.assertNotIn("receipt", fenced)
            late = resource.invoke()["result"]
            self.assertEqual(late["outcome"], "DENIED")
            resource.stop_target()
            self.assertEqual(resource.offline_status()["intent_count"], 0)

    def test_process_death_after_commit_retains_intent_and_receipt_but_blocks_reopen(self):
        with TemporaryDirectory() as tmp, fixture(tmp) as resource:
            checkpoint = resource.retained_anchor()
            packet = self.crash_during_dispatch(resource, "before-checkpoint")
            self.assertEqual(resource.retained_anchor(), checkpoint)
            ledger = (resource.target_state / "ledger.sqlite").as_uri() + "?mode=ro"
            with closing(sqlite3.connect(ledger, uri=True)) as db:
                effects = db.execute("SELECT outcome, dispatch_digest, receipt FROM effects").fetchall()
                decisions = db.execute("SELECT receipt FROM decisions").fetchall()
            self.assertEqual(len(effects), 1)
            self.assertEqual(len(decisions), 1)
            outcome, dispatch_hash, saved = effects[0]
            self.assertEqual((outcome, dispatch_hash), ("INTENT_RECORDED", digest(packet)))
            stored_receipt = json.loads(saved)["receipt"]
            audit = json.loads(decisions[0][0])
            self.assertEqual((audit["packet"], audit["receipt"]), (packet, stored_receipt))
            historic = verify_admission(resource.expectations, {"packet": packet, "receipt": stored_receipt})
            self.assertEqual(historic["effect"], "PENDING_EXTERNAL_SETTLEMENT")
            with self.assertRaises(RuntimeError):
                with FinanceTarget(resource.target_state, resource.anchor):
                    self.fail("unanchored intent was admitted on reopen")


if __name__ == "__main__":
    if len(sys.argv) == 5:
        serve_until_crash(*sys.argv[1:])
    else:
        unittest.main()
