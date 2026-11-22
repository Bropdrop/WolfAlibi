"""Decision tests use a real measured trial; peer fixtures test policy, not OS custody."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
import os
from pathlib import Path
import shutil
import sqlite3
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from alibi import DurableWitness, Signer
from wolfalibi import byoa002_target as target
from wolfalibi.byoa002_enrollment import FIXED, TRIAL_ROLES, digest
from wolfalibi.byoa002_verifier import VerifierPrincipal, initialize_verifier
from wolfalibi.byoa_attestation import make_expectations, sign_trial
from wolfalibi.byoa_bundle import load_bundle
from wolfalibi.byoa_cell import cell_contract, run_cell
from wolfalibi.byoa_effect_gate import (
    ReadGate, enroll_read_authorities, initialize_read_target, issue_read_grant,
)
from wolfalibi.clearance_records import _sign
from wolfalibi.solitary_preflight import preflight
from wolfalibi.voidcell002_anchor import LedgerDivergence


class TargetAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0 or preflight()["outcome"] != "READY":
            raise unittest.SkipTest("requires unprivileged Linux measured-worker profile")
        cls.owner, cls.target_key, cls.operator, cls.verifier_key = (Signer() for _ in range(4))
        keys = {name: Signer() for name in TRIAL_ROLES}
        bundle = load_bundle(Path(__file__).parent / "examples/qualification001/agent.json")
        cls.peer = {"uid": os.geteuid(), "gid": os.getegid(), "pid": 480, "start_ticks": 81231,
                    "boot_id": "9e73cfa2-a017-4ab1-8846-9df860af0202",
                    "exe_sha256": "10"*32, "source_sha256": "11"*32, "argv_sha256": "12"*32}
        temp = TemporaryDirectory(prefix="q2-trial-")
        cls.addClassCleanup(temp.cleanup)
        root = Path(temp.name)
        worker, read, cls.template = [root / n for n in ("worker", "target", "verifier")]
        for directory in (worker, read, cls.template):
            directory.mkdir(mode=0o700)
        with DurableWitness(root / "witness.json", keys["witness_pub"]) as witness:
            now = int(time.time())
            contract = cell_contract(bundle, "pending", bytes(32), now + 290)
            cls.enrollment = {
                **FIXED, "operator_pub": cls.operator.pub.hex(), "owner_pub": cls.owner.pub.hex(),
                "target_pub": cls.target_key.pub.hex(), "verifier_pub": cls.verifier_key.pub.hex(),
                "trial_pins": {k: s.pub.hex() for k, s in keys.items()},
                "trial_witness_sha256": witness.state_digest.hex(),
                "gateway": cls.peer, "owner_uid": os.geteuid(), "policy_epoch": 1,
                "revision": {"commit": "1f"*20, "tree": "2e"*20},
                "profile_sha256": digest(contract["profile"]),
                "manifest_sha256": contract["profile"]["byoa"]["manifest_sha256"],
            }
            initialize_verifier(cls.template, enrollment=cls.enrollment)
            with VerifierPrincipal(cls.template, cls.verifier_key, cls.enrollment) as v:
                contract.update(v.fresh())
                cls.expected = make_expectations(contract, **{k: s.pub for k, s in keys.items()},
                                                 expected_witness_state_digest=witness.state_digest, now=now)
                cls.q = v.issue(cls.expected)
            cls.grant = target.issue_owner_grant(cls.expected, cls.enrollment, cls.q, cls.owner)
            initialize_read_target(read, keys["target_pub"])
            enroll_read_authorities(read, target_signer=keys["target_pub"],
                                    **{k: cls.expected[k] for k in TRIAL_ROLES if k != "target_pub"})
            permission = issue_read_grant(cls.expected, keys["owner_pub"])
            with ReadGate(read, cls.expected, permission, keys["target_pub"],
                          witness_state=witness.state_anchor) as gate:
                trial = run_cell(worker, bundle=bundle, contract=contract, signer=keys["broker_pub"],
                                 witness=witness, supervisor=keys["supervisor_pub"], consent=True,
                                 expected_witness_state_digest=witness.state_digest, read_gate=gate)
                if trial["outcome"] != "COMPLETED":
                    raise AssertionError(trial)
                cls.report = sign_trial(cls.expected, trial["envelope"], trial["observation"],
                                        keys["supervisor_pub"], grant=permission, admission=gate.decision)

    def setUp(self):
        tmp = TemporaryDirectory(prefix="q2-target-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state, self.verifier_state = self.root / "o", self.root / "v"
        self.state.mkdir(mode=0o700)
        shutil.copytree(self.template, self.verifier_state)
        self.verifier = VerifierPrincipal(self.verifier_state, self.verifier_key, self.enrollment)
        target.initialize_target(self.state, self.target_key, self.enrollment)
        self.db = self.state / "ledger" / "ledger.sqlite"

    def open(self, **callbacks):
        return target.Target(self.state, self.target_key, self.enrollment,
                             **{"check_pending": self.verifier.check_pending, "retain": self.verifier.retain,
                                "reconcile_head": self.verifier.reconcile, **callbacks})

    def packet(self, action="dispatch", *, peer=None):
        req = target.sign_request(action, self.expected, self.enrollment, self.q, self.grant,
                                  self.report, self.operator, recovery_peer=peer)
        return {"expected": self.expected, "challenge": self.q, "grant": self.grant,
                "report": self.report, "request": req}

    def count(self):
        with closing(sqlite3.connect(self.db)) as db:
            return db.execute("SELECT count(*) FROM effects").fetchone()[0]

    def dispatch(self, service, *, packet=None, peer=None, live=lambda: True):
        return service.dispatch(packet or self.packet(), peer=peer or self.peer, live=live)

    def recover(self, service, *, peer=None, request_peer=None):
        return service.reconcile(self.packet("reconcile", peer=request_peer), peer=peer or self.peer,
                                 live=lambda: True)

    def test_positive_commits_one_retained_target_record(self):
        with self.open() as service:
            result = self.dispatch(service)
        self.assertEqual(result["outcome"], "RELEASED", result)
        self.assertEqual(digest(result["record"]), result["receipt"]["payload"]["response_sha256"])
        self.assertEqual(self.count(), 1)
        checked = target.verify_release(**self.packet(), enrollment=self.enrollment,
                                        receipt=result["receipt"], ack=result["ack"])
        self.assertEqual(checked["present_authority"], "NOT_ISSUED")
        self.assertEqual(checked["recipient_delivery"], "NOT_ESTABLISHED")

    def test_owner_signature_alternative_key_is_refused(self):
        packet = self.packet()
        packet["grant"] = _sign(Signer(), target._GRANT, self.grant["payload"])
        # Endorse the exact changed grant as the genuine operator.
        terms = target._request_terms("dispatch", self.expected, self.enrollment, self.q,
                                      packet["grant"], self.report, self.peer)
        packet["request"] = _sign(self.operator, target._REQUEST, terms)
        with self.open() as service:
            result = self.dispatch(service, packet=packet)
        self.assertEqual(result["outcome"], "DENIED", result)
        self.assertEqual(self.count(), 0)

    def test_missing_trial_or_different_operator_and_policy_are_denied(self):
        cases = []
        bad = deepcopy(self.packet())
        del bad["report"]["payload"]["execution"]["supervisor_record"]
        bad["request"] = target.sign_request("dispatch", self.expected, self.enrollment, self.q,
                                              self.grant, bad["report"], self.operator)
        cases.append(bad)
        bad = deepcopy(self.packet())
        bad["request"] = _sign(Signer(), target._REQUEST, bad["request"]["payload"])
        cases.append(bad)
        bad = deepcopy(self.packet())
        bad["request"]["payload"]["policy_epoch"] += 1
        bad["request"] = _sign(self.operator, target._REQUEST, bad["request"]["payload"])
        cases.append(bad)
        with self.open() as service:
            for packet in cases:
                self.assertEqual(self.dispatch(service, packet=packet)["outcome"], "DENIED")
        self.assertEqual(self.count(), 0)

    def test_unenrolled_gateway_and_nonlive_sender_cannot_commit(self):
        with self.open() as service:
            for identity in (dict(self.peer, pid=560), dict(self.peer, uid=self.peer["uid"] + 1),
                             dict(self.peer, exe_sha256="ef"*32)):
                self.assertEqual(self.dispatch(service, peer=identity)["outcome"], "DENIED")
            self.assertEqual(self.dispatch(service, live=lambda: False)["outcome"], "DENIED")
        self.assertEqual(self.count(), 0)

    def test_duplicate_dispatch_withholds_record(self):
        with self.open() as service:
            self.assertEqual(self.dispatch(service)["outcome"], "RELEASED")
            second = self.dispatch(service)
        self.assertEqual(second["outcome"], "DENIED")
        self.assertNotIn("record", second)
        self.assertEqual(self.count(), 1)

    def test_simultaneous_dispatch_has_one_commit_and_one_handoff(self):
        with self.open() as service, ThreadPoolExecutor(max_workers=3) as pool:
            answers = list(pool.map(lambda _: self.dispatch(service), range(3)))
        self.assertCountEqual([r["outcome"] for r in answers], ["RELEASED", "DENIED", "DENIED"])
        self.assertEqual(sum("record" in r for r in answers), 1)
        self.assertEqual(self.count(), 1)

    def test_lost_reply_restart_recovers_only_original_receipt(self):
        with self.open() as service:
            released = self.dispatch(service)
        original = released["receipt"]
        replacement = dict(self.peer, pid=300, start_ticks=92231)
        with self.open() as service:
            self.assertEqual(self.dispatch(service, peer=replacement)["outcome"], "DENIED")
            self.assertEqual(self.recover(service, peer=replacement)["outcome"], "DENIED")
            recovery = self.recover(service, peer=replacement, request_peer=replacement)
        self.assertEqual(recovery, {"outcome": "RECONCILED", "receipt": original, "ack": released["ack"]})
        self.assertEqual(self.count(), 1)

    def test_revoked_before_dispatch_and_after_restart_stays_denied(self):
        with self.open() as service:
            self.assertEqual(service.revoke(self.grant, self.expected, self.q)["outcome"], "REVOKED")
        with self.open() as service:
            self.assertIn("revoked", self.dispatch(service)["reason"])
        self.assertEqual(self.count(), 0)

    def test_revocation_while_verifier_retains_withholds_body(self):
        def retain(*args):
            ack = self.verifier.retain(*args)
            self.assertEqual(service.revoke(self.grant, self.expected, self.q)["outcome"], "REVOKED")
            return ack
        with self.open(retain=retain) as service:
            result = self.dispatch(service)
            historical = self.recover(service)
        self.assertEqual(result["outcome"], "DENIED")
        self.assertNotIn("record", result)
        self.assertEqual(historical["outcome"], "RECONCILED")
        self.assertNotIn("record", historical)
        self.assertEqual(self.count(), 1)

    def test_expiration_then_target_clock_rollback_stays_blocked(self):
        expiry = self.expected["contract"]["expires_at"]
        with self.open() as service:
            with patch.object(service._ledger, "_clock", return_value=expiry):
                self.assertEqual(self.dispatch(service)["outcome"], "DENIED")
            with patch.object(service._ledger, "_clock", return_value=expiry - 1):
                self.assertEqual(self.dispatch(service)["reason"], "TARGET_CLOCK_REGRESSION")
        self.assertEqual(self.count(), 0)

    def test_missing_witness_before_dispatch_refuses_commit(self):
        with self.open(check_pending=lambda *_: None) as service:
            result = self.dispatch(service)
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertEqual(self.count(), 0)

    def test_target_commit_before_retention_withholds_body(self):
        def unavailable(*_):
            raise OSError("disconnected local verifier")
        with self.open(retain=unavailable) as service:
            result = self.dispatch(service)
        with self.open() as service:
            self.assertEqual(self.recover(service)["outcome"], "BLOCKED")
            self.assertEqual(self.dispatch(service)["outcome"], "DENIED")
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertNotIn("record", result)
        self.assertEqual(self.count(), 1)

    def test_corrupt_verifier_ack_cannot_release(self):
        def alter(*args):
            ack = self.verifier.retain(*args)
            return dict(ack, signature="00"*64)
        with self.open(retain=alter) as service:
            result = self.dispatch(service)
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertNotIn("record", result)
        self.assertEqual(self.count(), 1)

    def test_target_ledger_restore_without_checkpoint_is_fenced(self):
        saved = self.root / "prior.sqlite"
        shutil.copyfile(self.db, saved)
        with self.open() as service:
            self.assertEqual(self.dispatch(service)["outcome"], "RELEASED")
        shutil.copyfile(saved, self.db)
        with self.assertRaises(LedgerDivergence):
            self.open()

    def test_target_and_checkpoint_restore_still_need_live_pending_verifier(self):
        snapshot = self.root / "prior-state"
        shutil.copytree(self.state, snapshot)
        with self.open() as service:
            self.assertEqual(self.dispatch(service)["outcome"], "RELEASED")
        shutil.rmtree(self.state)
        shutil.copytree(snapshot, self.state)
        with self.open() as service:
            result = self.dispatch(service)
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertIn("consumed", result["reason"])
        self.assertEqual(self.count(), 0)

    def crash(self, boundary):
        pid = os.fork()
        if pid == 0:
            try:
                with self.open() as service:
                    if boundary == "sqlite":
                        def trace(statement):
                            if statement == "COMMIT":
                                os._exit(77)
                        service._ledger._db.set_trace_callback(trace)
                    else:
                        service._ledger._anchor.advance = lambda *_: os._exit(77)
                    self.dispatch(service)
            finally:
                os._exit(3)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 77)

    def test_process_death_before_sql_commit_rolls_back_decision(self):
        self.crash("sqlite")
        self.assertEqual(self.count(), 0)
        with self.open() as service:
            self.assertEqual(self.recover(service)["outcome"], "DENIED")
        self.assertEqual(self.verifier.head()["generation"], 0)

    def test_process_death_after_sql_commit_before_anchor_is_fail_stop(self):
        self.crash("anchor")
        self.assertEqual(self.count(), 1)
        with self.assertRaises(LedgerDivergence):
            self.open()
        self.assertEqual(self.verifier.head()["generation"], 0)

    def test_narrower_owner_expiration_while_qualification_current(self):
        expiry = self.q["payload"]["issued_at"] + 30
        grant = target.issue_owner_grant(self.expected, self.enrollment, self.q, self.owner, expires_at=expiry)
        packet = self.packet()
        packet.update(grant=grant, request=target.sign_request("dispatch", self.expected, self.enrollment,
                                                               self.q, grant, self.report, self.operator))
        with self.open() as service, patch.object(service._ledger, "_clock", return_value=expiry):
            answer = self.dispatch(service, packet=packet)
        self.assertEqual(answer["outcome"], "DENIED")
        self.assertIn("owner grant validity", answer["reason"])
        self.assertEqual(self.count(), 0)

    def test_joint_store_restore_requires_a_separately_retained_head(self):
        # Two disposable snapshots include their signed checkpoints and the pending challenge.
        prior_target = self.root / "before-target"
        prior_verifier = self.root / "before-verifier"
        shutil.copytree(self.state, prior_target)
        shutil.copytree(self.verifier_state, prior_verifier)
        packet = self.packet()
        observed_bodies = []

        def complete_and_compare_stores(service):
            released = self.dispatch(service, packet=packet)
            self.assertEqual(released["outcome"], "RELEASED", released)
            observed_bodies.append(released["record"])
            self.assertEqual(self.count(), 1)
            self.assertEqual(self.verifier.head(), released["ack"]["payload"]["head"])
            recovered = self.recover(service)
            self.assertEqual(recovered, {"outcome": "RECONCILED", "receipt": released["receipt"],
                                         "ack": released["ack"]})
            self.assertEqual(digest(released["record"]), released["receipt"]["payload"]["response_sha256"])
            return released["ack"]["payload"]["head"]

        with self.verifier, self.open() as service:
            saved_head = complete_and_compare_stores(service)
        self.assertEqual(saved_head["generation"], 1)

        # Cold-start both roles on their complete pre-disclosure snapshots.
        self.state, self.verifier_state = prior_target, prior_verifier
        self.db = self.state / "ledger" / "ledger.sqlite"
        with self.assertRaisesRegex(ValueError, "externally retained head"):
            VerifierPrincipal(self.verifier_state, self.verifier_key, self.enrollment, expected_head=saved_head)
        self.assertEqual(self.count(), 0)

        # Without that outside reference, both old signed snapshots are locally consistent.
        self.verifier = VerifierPrincipal(self.verifier_state, self.verifier_key, self.enrollment)
        with self.verifier, self.open() as service:
            self.assertEqual(self.verifier.head()["generation"], 0)
            restored_head = complete_and_compare_stores(service)
        self.assertEqual(restored_head["generation"], 1)
        self.assertEqual(len(observed_bodies), 2)
        self.assertEqual(observed_bodies[0], observed_bodies[1])
        self.assertEqual(self.count(), 1)
