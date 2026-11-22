import json
import shutil
import unittest
from contextlib import closing
from unittest.mock import patch

import test_byoa002_target as baseline
from wolfalibi import byoa002_target as target
from wolfalibi.byoa002_custody import Journal, inspect_history, verify_history


class CustodyTests(unittest.TestCase):
    setUpClass = classmethod(baseline.TargetAuthorityTests.setUpClass.__func__)
    packet = baseline.TargetAuthorityTests.packet
    dispatch = baseline.TargetAuthorityTests.dispatch
    recover = baseline.TargetAuthorityTests.recover
    count = baseline.TargetAuthorityTests.count
    open = baseline.TargetAuthorityTests.open

    def setUp(self):
        baseline.TargetAuthorityTests.setUp(self)
        self.state = self.root / "qualified"
        self.state.mkdir(mode=0o700)
        self.db = self.state / "ledger" / "ledger.sqlite"
        self.journal = Journal(self.root / "custody.sqlite", self.target_key, self.enrollment)
        self.journal.initialize()
        target.initialize_target(self.state, self.target_key, self.enrollment, journal=self.journal)
        self.snapshot = shutil.copytree(self.state, self.root / "initial")

    def restore(self):
        shutil.rmtree(self.state)
        shutil.copytree(self.snapshot, self.state)

    def test_commit_recovery_and_restoration(self):
        with self.open(journal=self.journal) as service:
            released = self.dispatch(service)
        self.assertEqual(released["outcome"], "RELEASED", released)
        with self.open(journal=self.journal) as service:
            reply = self.recover(service)
        self.assertEqual(reply["receipt"], released["receipt"])
        self.assertEqual(reply["ack"], released["ack"])
        self.assertNotIn("record", reply)
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.verifier.head(), released["ack"]["payload"]["head"])
        self.restore()
        shutil.rmtree(self.verifier_state)
        shutil.copytree(self.template, self.verifier_state)
        self.verifier = baseline.VerifierPrincipal(self.verifier_state, self.verifier_key, self.enrollment)
        with self.open(journal=self.journal) as service:
            denied = self.dispatch(service)
        self.assertEqual(denied["outcome"], "BLOCKED")
        self.assertIn("disagrees with target", denied["reason"])
        self.assertEqual(self.count(), 0)

    def test_revoked_history(self):
        with self.open(journal=self.journal) as service:
            self.assertEqual(service.revoke(self.grant, self.expected, self.q)["outcome"], "REVOKED")
        with self.open(journal=self.journal) as service:
            self.assertEqual(self.dispatch(service)["outcome"], "DENIED")
        self.restore()
        with self.open(journal=self.journal) as service:
            self.assertEqual(self.dispatch(service)["outcome"], "BLOCKED")
        self.assertEqual(self.count(), 0)

    def test_detached_expectation(self):
        with self.open(journal=self.journal) as service:
            self.assertEqual(self.dispatch(service)["outcome"], "RELEASED")
        with closing(self.journal.connect()) as db:
            records = [json.loads(raw) for raw, in db.execute("SELECT record FROM history ORDER BY seq")]
        enrollment, key = self.journal.enrollment, self.target_key.pub
        head = inspect_history(records, enrollment, key)
        self.assertEqual(head["generation"], 1)
        args = dict(enrollment=enrollment, public_key=key, expected_head=head)
        self.assertEqual(verify_history(records, **args)["present_authority"], "NOT_ISSUED")
        with self.assertRaises(ValueError):
            verify_history(records[:1], **args)

    def test_unavailable_reference(self):
        self.journal.path.unlink()
        with self.open(journal=self.journal) as service:
            self.assertEqual(self.dispatch(service)["outcome"], "BLOCKED")
        self.assertEqual(self.count(), 0)

    def test_interrupted_after_publication(self):
        original = self.journal.compare

        def interrupt(state, *, transition=None):
            result = original(state, transition=transition)
            if transition:
                raise OSError("interruption after durable publication")
            return result

        with self.open(journal=self.journal) as service, patch.object(self.journal, "compare", interrupt):
            self.assertEqual(self.dispatch(service)["outcome"], "BLOCKED")
        self.assertEqual(self.count(), 0)
        with self.open(journal=self.journal) as service:
            result = self.dispatch(service)
        self.assertIn("disagrees with target", result["reason"])
        self.assertEqual(self.count(), 0)
