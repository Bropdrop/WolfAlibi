import json
import os
import shutil
import sqlite3
import unittest
from contextlib import closing

import test_byoa002_custody as prior
from wolfalibi.byoa002_custody import verify_history
from wolfalibi.byoa002_enrollment import digest as target_digest


class ClosureTests(unittest.TestCase):
    setUpClass = classmethod(prior.CustodyTests.setUpClass.__func__)
    setUp = prior.CustodyTests.setUp
    open = prior.CustodyTests.open
    packet = prior.CustodyTests.packet
    dispatch = prior.CustodyTests.dispatch
    recover = prior.CustodyTests.recover
    count = prior.CustodyTests.count
    restore = prior.CustodyTests.restore
    crash = prior.baseline.TargetAuthorityTests.crash

    def history(self):
        with closing(self.journal.connect()) as db:
            return [json.loads(raw) for raw, in db.execute("SELECT record FROM history ORDER BY seq")]

    def assert_blocked(self):
        with self.open() as service:
            result = self.dispatch(service)
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertNotIn("record", result)

    def test_target_only_restore(self):
        with self.open() as service:
            self.assertEqual(self.dispatch(service)["outcome"], "RELEASED")
        self.restore()
        self.assert_blocked()
        self.assertEqual((self.count(), self.verifier.head()["generation"]), (0, 1))

    def test_verifier_only_restore(self):
        with self.open() as service:
            self.assertEqual(self.dispatch(service)["outcome"], "RELEASED")
        shutil.rmtree(self.verifier_state)
        shutil.copytree(self.template, self.verifier_state)
        self.verifier = prior.baseline.VerifierPrincipal(self.verifier_state, self.verifier_key, self.enrollment)
        with self.open() as service:
            repeat = self.dispatch(service)
            inquiry = self.recover(service)
        self.assertEqual(repeat["outcome"], "DENIED")
        self.assertEqual(inquiry["outcome"], "BLOCKED")
        self.assertNotIn("record", repeat)
        self.assertNotIn("record", inquiry)
        self.assertEqual((self.count(), self.verifier.head()["generation"]), (1, 0))

    def test_stale_signed_generation_same_state(self):
        backup = self.root / "retained"
        with self.open() as service:
            self.assertEqual(service.revoke(self.grant, self.expected, self.q)["outcome"], "REVOKED")
            shutil.copyfile(self.journal.path, backup)
            self.assertEqual(service.revoke(self.grant, self.expected, self.q)["outcome"], "REVOKED")
        records = self.history()
        self.assertEqual(records[-1]["payload"]["after"], records[-2]["payload"]["after"])
        shutil.copyfile(backup, self.journal.path)
        self.assert_blocked()
        self.assertEqual(self.count(), 0)

    def test_conflicting_historical_reference(self):
        with self.open() as service:
            self.assertEqual(self.dispatch(service)["outcome"], "RELEASED")
        records = self.history()
        with closing(sqlite3.connect(self.db)) as db:
            head = json.loads(db.execute("SELECT receipt FROM decisions WHERE id=0").fetchone()[0])
        args = dict(enrollment=self.journal.enrollment, public_key=self.target_key.pub)
        self.assertEqual(verify_history(records, expected_head=head, **args)["outcome"], "PASS")
        conflicting = dict(head, digest="00"*32)
        with self.assertRaises(ValueError):
            verify_history(records, expected_head=conflicting, **args)

    def test_journal_commit_interruption(self):
        pid = os.fork()
        if pid == 0:
            try:
                connect = self.journal.connect

                def instrument():
                    db = connect()
                    publishing = False

                    def trace(sql):
                        nonlocal publishing
                        if sql.startswith("INSERT INTO history"):
                            publishing = True
                        if publishing and sql == "COMMIT":
                            os._exit(79)
                    db.set_trace_callback(trace)
                    return db

                self.journal.connect = instrument
                with self.open() as service:
                    self.dispatch(service)
            finally:
                os._exit(3)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 79)
        self.assertEqual((self.count(), len(self.history()), self.verifier.head()["generation"]), (0, 1, 0))
        with self.open() as service:
            self.assertEqual(self.dispatch(service)["outcome"], "RELEASED")
        self.assertEqual(self.count(), 1)

    def test_target_commit_interruption(self):
        self.crash("sqlite")
        self.assertEqual((self.count(), len(self.history()), self.verifier.head()["generation"]), (0, 2, 0))
        self.assert_blocked()
        self.assertEqual(self.count(), 0)

    def test_local_anchor_interruption(self):
        self.crash("anchor")
        self.assertEqual((self.count(), len(self.history()), self.verifier.head()["generation"]), (1, 2, 0))
        with self.assertRaises(prior.baseline.LedgerDivergence):
            self.open()


    def test_publication_records_consumption(self):
        def unavailable(*args):
            raise OSError("retention interrupted")

        with self.open(retain=unavailable) as service:
            result = self.dispatch(service)
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertNotIn("record", result)
        self.assertEqual(self.count(), 1)
        record = self.history()[-1]
        self.assertEqual((record["payload"]["action"], record["payload"]["subject"]),
                         ("consume", target_digest(self.q)))

    def test_committed_target_retains_published_head(self):
        with self.open() as service:
            self.assertEqual(service.revoke(self.grant, self.expected, self.q)["outcome"], "REVOKED")
        with closing(sqlite3.connect(self.db)) as db:
            head = json.loads(db.execute("SELECT receipt FROM decisions WHERE id=0").fetchone()[0])
        self.assertEqual(head["digest"], target_digest(self.history()[-1]))

    def test_equal_state_conflicting_signed_histories(self):
        alternate = prior.target.issue_owner_grant(
            self.expected, self.enrollment, self.q, self.owner,
            expires_at=self.grant["payload"]["expires_at"] - 1)
        initial = self.root / "initial-journal"
        retained = self.root / "retained-journal"
        shutil.copyfile(self.journal.path, initial)
        with self.open() as service:
            for grant in (self.grant, alternate):
                self.assertEqual(service.revoke(grant, self.expected, self.q)["outcome"], "REVOKED")
        first = self.history()[-1]
        shutil.copyfile(self.journal.path, retained)
        self.restore()
        shutil.copyfile(initial, self.journal.path)
        with self.open() as service:
            for grant in (alternate, self.grant):
                self.assertEqual(service.revoke(grant, self.expected, self.q)["outcome"], "REVOKED")
        second = self.history()[-1]
        self.assertEqual(first["payload"]["after"], second["payload"]["after"])
        self.assertEqual(first["payload"]["generation"], second["payload"]["generation"])
        self.assertNotEqual(target_digest(first), target_digest(second))
        shutil.copyfile(retained, self.journal.path)
        self.assert_blocked()
        self.assertEqual(self.count(), 0)

    def test_retention_lost_before_handoff(self):
        def retain_then_interrupt(*args):
            ack = self.verifier.retain(*args)
            shutil.rmtree(self.verifier_state)
            shutil.copytree(self.template, self.verifier_state)
            return ack

        with self.open(retain=retain_then_interrupt) as service:
            result = self.dispatch(service)
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertNotIn("record", result)
        restarted = prior.baseline.VerifierPrincipal(self.verifier_state, self.verifier_key, self.enrollment)
        self.assertEqual((self.count(), len(self.history()), restarted.head()["generation"]), (1, 2, 0))

    def test_ack_commit_before_reply(self):
        retained = []

        def lose_reply(*args):
            retained.append(self.verifier.retain(*args))
            raise OSError("interrupted after durable verifier commit")

        with self.open(retain=lose_reply) as service:
            result = self.dispatch(service)
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertNotIn("record", result)
        with self.open() as service:
            historical = self.recover(service)
        self.assertEqual(historical["outcome"], "RECONCILED")
        self.assertEqual(historical["ack"], retained[0])
        self.assertNotIn("record", historical)
        self.assertEqual((self.count(), len(self.history()), self.verifier.head()["generation"]), (1, 2, 1))
