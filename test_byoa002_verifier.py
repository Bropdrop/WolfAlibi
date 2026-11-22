"""Verifier state controls. Receipts here are deliberate synthetic target attestations."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from alibi import Signer
from wolfalibi import byoa002_verifier as v
from wolfalibi.byoa002_enrollment import FIXED, PRINCIPALS, TRIAL_ROLES
from wolfalibi.byoa002_target import _receipt_terms, _RECEIPT
from wolfalibi.byoa_attestation import make_expectations
from wolfalibi.byoa_bundle import load_bundle
from wolfalibi.byoa_cell import cell_contract
from wolfalibi.clearance_records import _sign


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        bundle = load_bundle(root / "examples/qualification001/agent.json")
        cls.contract = cell_contract(bundle, "unissued-example", b"1" * 32, 1200)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="review-verifier-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        keys = {name: Signer() for name in PRINCIPALS}
        trial = {name: Signer().pub for name in TRIAL_ROLES}
        self.verifier, self.target = keys["verifier_pub"], keys["target_pub"]
        self.e = make_expectations(deepcopy(self.contract), expected_witness_state_digest=b"W" * 32, now=1000, **trial)
        profile = self.e["contract"]["profile"]
        self.enrolled = {**FIXED, **{k: s.pub.hex() for k, s in keys.items()},
                         "trial_pins": {k: pub.hex() for k, pub in trial.items()},
                         "trial_witness_sha256": self.e["expected_witness_state_digest"],
                         "owner_uid": 1000, "policy_epoch": 1, "revision": {"commit": "21"*20, "tree": "23"*20},
                         "manifest_sha256": profile["byoa"]["manifest_sha256"], "profile_sha256": v.digest(profile),
                         "gateway": {"pid": 321, "start_ticks": 400, "uid": 1000, "gid": 1000,
                                     "boot_id": "82310c90-b389-48d7-a785-162b04d0721c",
                                     "exe_sha256": "11"*32, "argv_sha256": "12"*32, "source_sha256": "13"*32}}
        self.initial = v.initialize_verifier(self.path, enrollment=self.enrolled)
        self.store = self.open()
        self.e["contract"].update(self.store.fresh(now=1000))

    def open(self, **kwargs):
        return v.VerifierPrincipal(self.path, self.verifier, self.enrolled, **kwargs)

    def receipt(self, q, *, expected=None, different=False, stamp=1004):
        terms = _receipt_terms(self.e if expected is None else expected, self.enrolled, q,
                               grant_hash="32"*32, request_hash=("77" if different else "33")*32,
                               report_hash="34"*32, committed_at=stamp)
        return _sign(self.target, _RECEIPT, terms)

    def issue(self, expected=None):
        return self.store.issue(self.e if expected is None else expected, now=1000)

    def next_trial(self, now=1000):
        altered = deepcopy(self.e)
        altered["contract"].update(self.store.fresh(now=now))
        return altered

    def test_verifier_rejects_an_unreserved_pair(self):
        supplied = deepcopy(self.e)
        supplied["contract"].update(challenge="47"*32, run_id="producer-controlled-run")
        with self.assertRaisesRegex(ValueError, "unused verifier-generated pair"):
            self.open().issue(supplied, now=1000)
        self.assertEqual(self.store.head(), self.initial)

    def test_issue_persists_unique_run_and_nonce_across_restart(self):
        q = self.issue()
        again = self.open()
        self.assertEqual(again.check_pending(self.e, q, now=1002), q["payload"])
        for field in ("run_id", "challenge"):
            duplicate = self.next_trial(now=1002)
            duplicate["contract"][field] = self.e["contract"][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                again.issue(duplicate, now=1002)
        with self.assertRaises(FileExistsError):
            v.initialize_verifier(self.path, enrollment=self.enrolled)

    def test_success_advance_replay_refusal_exact_retrieval(self):
        q = self.issue()
        r = self.receipt(q)
        ack = self.store.retain(self.e, q, r, now=1006)
        end = {"generation": 1, "digest": v.digest(r)}
        self.assertEqual(self.store.head(), end)
        again = self.open(expected_head=end)
        self.assertEqual(again.reconcile(self.e, q, r), ack)
        for action in (lambda: again.check_pending(self.e, q, now=1007),
                       lambda: again.retain(self.e, q, r, now=1007),
                       lambda: again.reconcile(self.e, q, self.receipt(q, different=True))):
            with self.assertRaises(ValueError):
                action()

    def test_ack_requires_exact_retained_receipt(self):
        q = self.issue()
        ack = self.store.retain(self.e, q, self.receipt(q), now=1005)
        # Both receipts were signed by the enrolled target for this challenge.
        # Only one was accepted and included in the verifier's acknowledgment.
        with self.assertRaisesRegex(ValueError, "acknowledgment differs"):
            v.verify_ack(ack, expected=self.e, enrollment=self.enrolled, challenge=q, receipt=self.receipt(q, different=True))

    def test_competing_submissions_are_serialized_across_connections(self):
        q = self.issue()
        a, b = self.receipt(q), self.receipt(q, different=True)

        def submit(r):
            try:
                return self.open().retain(self.e, q, r, now=1006)
            except ValueError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, (a, b)))
        self.assertEqual(sum(x is not None for x in results), 1)
        winner = a if results[0] is not None else b
        self.assertEqual(self.store.head(), {"generation": 1, "digest": v.digest(winner)})

    def test_stale_issued_head_cannot_advance_and_fresh_successor_can(self):
        first = self.issue()
        later = self.next_trial()
        stale = self.issue(later)
        self.store.retain(self.e, first, self.receipt(first), now=1009)
        with self.assertRaisesRegex(ValueError, "stale head"):
            self.store.retain(later, stale, self.receipt(stale, expected=later), now=1010)
        later = self.next_trial(now=1010)
        q = self.store.issue(later, now=1010)
        r = self.receipt(q, expected=later, stamp=1010)
        ack = self.store.retain(later, q, r, now=1011)
        self.assertEqual(q["payload"]["previous"]["generation"], 1)
        self.assertEqual(ack["payload"]["head"]["generation"], 2)
        self.assertEqual(self.open().reconcile(self.e, first, self.receipt(first))["payload"]["head"]["generation"], 1)

    def test_expiry_then_clock_rewind_does_not_reactivate_an_issued_challenge(self):
        q = self.issue()
        with self.assertRaisesRegex(ValueError, "validity interval"):
            self.store.check_pending(self.e, q, now=1200)
        with self.assertRaisesRegex(ValueError, "clock moved backwards"):
            self.open().retain(self.e, q, self.receipt(q), now=1190)
        self.assertEqual(self.store.head(), self.initial)

    def test_target_future_commitment_and_early_verifier_signature_are_refused(self):
        q = self.issue()
        r = self.receipt(q, stamp=1100)
        with self.assertRaisesRegex(ValueError, "predates"):
            self.store.retain(self.e, q, r, now=1050)
        early = v._signed(self.verifier, v._A, v._ack_payload(q, r, 1050))
        with self.assertRaisesRegex(ValueError, "predates"):
            v.verify_ack(early, expected=self.e, enrollment=self.enrolled, challenge=q, receipt=r)
        self.assertEqual(self.store.head(), self.initial)

    def test_changing_expected_pins_and_substituting_verifier_key_invalidates_historical_issuance(self):
        q = self.issue()
        for enrolled in (dict(self.enrolled, policy_epoch=2), dict(self.enrolled, verifier_pub=Signer().pub.hex())):
            with self.assertRaises(ValueError):
                v.verify_challenge(q, expected=self.e, enrollment=enrolled, now=1004)
        with self.assertRaises(ValueError):
            v.verify_challenge(q, expected=self.next_trial(), enrollment=self.enrolled, now=1004)

    def test_preapproval_refuses_substitution_of_the_trial_witness_anchor(self):
        changed = dict(self.e, expected_witness_state_digest="99" * 32)
        with self.assertRaises(ValueError):
            self.store.issue(changed, now=1000)
        self.assertEqual(self.store.head(), self.initial)
        self.assertEqual(self.issue()["payload"]["expectations_sha256"], v.digest(self.e))

    def test_rejected_untrusted_proposal_does_not_consume_pending_challenge(self):
        q = self.issue()
        good = self.receipt(q)
        changed = dict(good, signature="cd"*64)
        with self.assertRaises(ValueError):
            self.store.retain(self.e, q, changed, now=1006)
        self.assertEqual(self.store.head(), self.initial)
        self.assertEqual(self.store.retain(self.e, q, good, now=1007)["payload"]["receipt_sha256"], v.digest(good))

    def test_committed_but_uncheckpointed_acceptance_is_fail_stop(self):
        q = self.issue()
        with patch.object(v, "_durable_write", side_effect=OSError("interrupted checkpoint")):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                self.store.retain(self.e, q, self.receipt(q), now=1006)
        with self.assertRaisesRegex(ValueError, "checkpoint differs"):
            self.open()

    @unittest.skipUnless(hasattr(os, "fork"), "requires a disposable child process")
    def test_process_death_after_sql_commit_prevents_ack_reissue(self):
        q = self.issue()
        r = self.receipt(q)
        child = os.fork()
        if child == 0:
            try:
                with patch.object(v, "_durable_write", side_effect=lambda *_: os._exit(91)):
                    self.store.retain(self.e, q, r, now=1006)
            finally:
                os._exit(92)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 91)
        database = sqlite3.connect((self.path / v._DB).as_uri() + "?mode=ro", uri=True)
        try:
            self.assertEqual(database.execute("SELECT generation,head FROM configuration").fetchone(), (1, v.digest(r)))
            self.assertEqual(database.execute("SELECT count(*) FROM challenges WHERE ack IS NOT NULL").fetchone(), (1,))
        finally:
            database.close()
        with self.assertRaisesRegex(ValueError, "checkpoint differs"):
            self.store.reconcile(self.e, q, r)

    def test_db_rollback_and_joint_rollback_have_distinct_retention_limits(self):
        q = self.issue()
        db, checkpoint = self.path / v._DB, self.path / v._CHECKPOINT
        early_db, early_checkpoint = db.read_bytes(), checkpoint.read_bytes()
        ack = self.store.retain(self.e, q, self.receipt(q), now=1006)
        latest = ack["payload"]["head"]
        db.write_bytes(early_db)
        with self.assertRaisesRegex(ValueError, "checkpoint differs"):
            self.open()
        checkpoint.write_bytes(early_checkpoint)
        with self.assertRaisesRegex(ValueError, "last observed head"):
            self.store.check_pending(self.e, q, now=1010)
        with self.assertRaisesRegex(ValueError, "externally retained"):
            self.open(expected_head=latest)
        # No purely local test can distinguish a consistent older snapshot.
        self.assertEqual(self.open().head(), self.initial)

    def test_checkpoint_absence_is_an_availability_failure(self):
        q = self.issue()
        os.unlink(self.path / v._CHECKPOINT)
        with self.assertRaisesRegex(ValueError, "unavailable"):
            self.store.check_pending(self.e, q, now=1004)
