"""Scoped read-authority tests with actual Linux workers and disposable target ledgers."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import signal
import sqlite3
from tempfile import TemporaryDirectory
from threading import Barrier
import time
import unittest
from unittest.mock import patch

from alibi import Broker, DurableWitness, OPS, Signer
from wolfalibi import byoa_effect_gate as target
from wolfalibi.byoa_attestation import make_expectations
from wolfalibi.byoa_bundle import load_bundle
from wolfalibi.byoa_cell import cell_contract, run_cell
from wolfalibi.solitary_preflight import preflight
from wolfalibi.voidcell002_anchor import LedgerAnchor, LedgerDivergence


class OwnerReadGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ready = preflight()
        if ready["outcome"] != "READY":
            raise unittest.SkipTest(f"Linux read qualification unavailable: {ready['reason']}")

    def setUp(self):
        temp = TemporaryDirectory(prefix="byoa-read-")
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        self.state = self.work / "target"
        self.state.mkdir(mode=0o700)
        self.broker, self.supervisor, self.owner, self.target, self.witness_key = (Signer() for _ in range(5))
        self.witness = DurableWitness(self.work / "witness.json", self.witness_key)
        self.addCleanup(self.witness.close)
        self.initial = self.witness.state_digest
        self.bundle = load_bundle(Path(__file__).parent / "examples/qualification001/agent.json")
        self.now = int(time.time())
        self.contract = cell_contract(self.bundle, "synthetic-read", os.urandom(32), self.now + 180)
        self.pins = make_expectations(
            self.contract, broker_pub=self.broker.pub, witness_pub=self.witness_key.pub,
            supervisor_pub=self.supervisor.pub, owner_pub=self.owner.pub, target_pub=self.target.pub,
            expected_witness_state_digest=self.initial, now=self.now,
        )
        self.grant = target.issue_read_grant(self.pins, self.owner)
        target.initialize_read_target(self.state, self.target)
        self.roles = {name: self.pins[name] for name in ("owner_pub", "supervisor_pub", "broker_pub", "witness_pub")}

    def enroll(self):
        target.enroll_read_authorities(self.state, target_signer=self.target, **self.roles)

    def gate(self, *, pins=None, grant=None):
        return target.ReadGate(self.state, pins or self.pins, grant or self.grant, self.target,
                               witness_state=self.witness.state_anchor)

    def trial(self, gate):
        return run_cell(self.work, bundle=self.bundle, contract=self.contract, signer=self.broker,
                        supervisor=self.supervisor, witness=self.witness, consent=True,
                        expected_witness_state_digest=self.initial, read_gate=gate)

    def recover(self):
        return target.recover_read_admission(self.state, self.pins, self.grant, self.target)

    def test_target_requires_permanent_independently_supplied_roles(self):
        with self.assertRaisesRegex(ValueError, "retained authority enrollment"):
            self.gate()
        self.enroll()
        with self.assertRaisesRegex(ValueError, "already enrolled"):
            self.enroll()
        for key in self.roles:
            with self.subTest(key=key):
                other = Signer()
                changed = dict(self.pins, **{key: other.pub.hex()})
                signed = target.issue_read_grant(changed, other if key == "owner_pub" else self.owner)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.gate(pins=changed, grant=signed)
        self.assertIsNone(self.recover())

    def test_modified_approval_or_target_identity_has_no_admission(self):
        self.enroll()
        for field, replacement in (("run_id", "other"), ("challenge", "ef" * 32), ("expires_at", self.now + 200)):
            different = deepcopy(self.pins)
            different["contract"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.gate(pins=different)
        with self.assertRaisesRegex(ValueError, "target signing identity"):
            target.ReadGate(self.state, self.pins, self.grant, Signer(), witness_state=self.witness.state_anchor)
        self.assertIsNone(self.recover())

    def test_revocation_between_preflight_and_release_persists_and_blocks_read(self):
        self.enroll()
        with self.gate() as gate:
            target.revoke_read_grant(self.state, self.pins, self.grant, self.target)
            result = self.trial(gate)
            self.assertEqual(result["outcome"], "BLOCKED", result)
            self.assertIn("revoked", result["reason"])
            self.assertIsNone(gate.decision)
        self.assertIsNone(self.recover())
        self.assert_not_read()

    def test_expiry_then_earlier_clock_cannot_reenable_a_grant(self):
        self.enroll()
        with patch.object(target._ReadLedger, "_clock", return_value=self.contract["expires_at"]):
            with self.assertRaisesRegex(ValueError, "validity window"):
                self.gate()
        with self.assertRaisesRegex(ValueError, "CLOCK_REGRESSION"):
            self.gate()
        self.assertIsNone(self.recover())

    def test_target_reopens_exact_original_admission_without_redispatch(self):
        self.enroll()
        with self.gate() as gate:
            result = self.trial(gate)
            self.assertEqual(result["outcome"], "COMPLETED", result)
            original = gate.decision
        snapshot = result["envelope"]["supervisor_record"]["payload"]["snapshot"]
        verified = target.verify_read_admission(self.pins, self.grant, original, snapshot)
        self.assertEqual(verified["outcome"], "VERIFIED_HISTORICAL_READ_ADMISSION")
        self.assertEqual(self.recover(), original)
        self.assertEqual(self.recover(), original)
        with target._ReadLedger(self.state, self.target) as ledger:
            self.assertEqual(ledger.status()["admission_count"], 1)
        changed = deepcopy(original)
        changed["admission"]["payload"]["outcome"] = "SETTLED"
        with self.assertRaises(ValueError):
            target.verify_read_admission(self.pins, self.grant, changed, snapshot)
        changed = deepcopy(snapshot)
        changed["identity"]["worker_start_ticks"] += 1
        with self.assertRaises(ValueError):
            target.verify_read_admission(self.pins, self.grant, original, changed)

    def test_two_preflight_gates_cannot_duplicate_committed_read(self):
        self.enroll()
        with self.gate() as first, self.gate() as second:
            result = self.trial(first)
            self.assertEqual(result["outcome"], "COMPLETED", result)
            with self.assertRaises((OSError, RuntimeError)):
                target.revoke_read_grant(self.state, self.pins, self.grant, self.target)
            self.assertIsNone(second.decision)
        # Even if a local controller restores its own witness to the original
        # genesis, the separately retained target admission still fences reuse.
        with DurableWitness(self.work / "other-witness.json", self.witness_key) as restored:
            with self.assertRaisesRegex(ValueError, "already admitted"):
                target.ReadGate(self.state, self.pins, self.grant, self.target, witness_state=restored.state_anchor)
        self.assertEqual(self.recover(), first.decision)

    def test_concurrent_duplicate_workers_admit_only_one_read(self):
        self.enroll()
        # Both separate local controllers present the same grant and initial
        # signed witness state. Only the resource target is shared.
        start = Barrier(2)
        def run(gate, witness):
            start.wait(timeout=5)
            with gate:
                return run_cell(self.work, bundle=self.bundle, contract=self.contract, signer=self.broker,
                                supervisor=self.supervisor, witness=witness, consent=True,
                                expected_witness_state_digest=self.initial, read_gate=gate)

        with DurableWitness(self.work / "duplicate-witness.json", self.witness_key) as second_witness:
            peers = [(self.gate(), self.witness),
                     (target.ReadGate(self.state, self.pins, self.grant, self.target,
                                      witness_state=second_witness.state_anchor), second_witness)]
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(run, gate, witness) for gate, witness in peers]
                results = [future.result(timeout=20) for future in futures]
        self.assertEqual(sorted(result["outcome"] for result in results), ["BLOCKED", "COMPLETED"], results)
        with target._ReadLedger(self.state, self.target) as ledger:
            self.assertEqual(ledger.status()["admission_count"], 1)
        protected_event = Broker._frame({"t": "e", "seq": 2, "m": OPS["r"], "k": b"protected.txt".hex()})
        journals = list(self.work.glob("stage3-*/broker.wal"))
        refused = next(r["reason"] for r in results if r["outcome"] == "BLOCKED")
        self.assertIn(refused, {"broker signing identity already has a live writer", "challenge already admitted",
                                "required live process, target checkpoint or witness state unavailable"})
        # A competing broker rejected before opening its WAL has no journal.
        self.assertIn(len(journals), (1, 2))
        self.assertEqual(sum(path.read_bytes().count(protected_event) for path in journals), 1)

    def test_simultaneous_target_admissions_from_one_live_endpoint_serialize(self):
        self.enroll()
        reserve = target.ReadGate.__call__
        outcomes = []
        both_ready = Barrier(2)
        with self.gate() as main, self.gate() as other:
            def contend(gate, contract, snapshot, pidfd):
                both_ready.wait(timeout=5)
                try:
                    reserve(gate, contract, snapshot, pidfd)
                except ValueError as exc:
                    return str(exc)
                return "READ_ADMITTED"

            def simultaneous(gate, contract, snapshot, pidfd):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    tasks = [pool.submit(contend, contender, contract, snapshot, pidfd)
                             for contender in (main, other)]
                    outcomes.extend(task.result(timeout=5) for task in tasks)
                if outcomes.count("READ_ADMITTED") != 1:
                    raise ValueError("resource failed to select one admission")
            with patch.object(target.ReadGate, "__call__", simultaneous):
                result = self.trial(main)
                self.assertEqual(result["outcome"], "COMPLETED", result)
        self.assertEqual(sorted(outcomes), sorted(["READ_ADMITTED",
                         "required live process, target checkpoint or witness state unavailable"]))
        with target._ReadLedger(self.state, self.target) as ledger:
            self.assertEqual(ledger.status()["admission_count"], 1)
        winner = main.decision if main.decision is not None else other.decision
        self.assertIsNotNone(winner)
        self.assertEqual(self.recover(), winner)

    def test_older_ledger_cannot_recover_against_later_checkpoint(self):
        self.enroll()
        database = self.state / "ledger/ledger.sqlite"
        earlier = database.read_bytes()
        with self.gate() as gate:
            run = self.trial(gate)
            self.assertEqual(run["outcome"], "COMPLETED", run)
        database.write_bytes(earlier)
        with self.assertRaises(LedgerDivergence):
            self.recover()

    def assert_not_read(self):
        wals = list(self.work.glob("stage3-*/broker.wal"))
        self.assertEqual(len(wals), 1)
        fixture_read = Broker._frame({"t": "e", "seq": 2, "m": OPS["r"], "k": b"protected.txt".hex()})
        self.assertNotIn(fixture_read, wals[0].read_bytes())

    def _die_during_transaction(self, at):
        self.enroll()
        # Run the real measured trial in an expendable supervisor process. The
        # target and supervisor share a UID/process in this profile.
        pid = os.fork()
        if pid == 0:
            try:
                original_open = target._ReadLedger._open_ledger
                original_advance = LedgerAnchor.advance

                def trace_first_commit(ledger, pins, create):
                    original_open(ledger, pins, create)
                    inserting = False

                    def trace(sql):
                        nonlocal inserting
                        if sql.startswith("INSERT INTO effects"):
                            inserting = True
                        if inserting and sql == "COMMIT" and at == "before_commit":
                            os.kill(os.getpid(), signal.SIGKILL)
                    ledger._db.set_trace_callback(trace)

                def before_checkpoint(anchor, ledger):
                    if (at == "before_checkpoint" and not ledger._db.in_transaction
                            and ledger.recorded(self.contract["challenge"]) is not None):
                        os.kill(os.getpid(), signal.SIGKILL)
                    return original_advance(anchor, ledger)

                with patch.object(target._ReadLedger, "_open_ledger", trace_first_commit), \
                        patch.object(LedgerAnchor, "advance", before_checkpoint), self.gate() as gate:
                    self.trial(gate)
                os._exit(90)
            except BaseException:
                os._exit(91)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
        self.assert_not_read()
        with closing(sqlite3.connect(self.state / "ledger/ledger.sqlite")) as db:
            return db.execute("SELECT receipt FROM effects").fetchall()

    def test_actual_death_before_sql_commit_retains_no_admission_or_read(self):
        self.assertEqual(self._die_during_transaction("before_commit"), [])
        self.assertIsNone(self.recover())

    def test_actual_death_after_commit_before_checkpoint_is_fail_stop(self):
        rows = self._die_during_transaction("before_checkpoint")
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0][0])["admission"]["payload"]["outcome"], "READ_ADMITTED")
        with self.assertRaises(LedgerDivergence):
            self.recover()
