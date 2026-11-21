"""Local synthetic freshness and continuity tests for the Stage 3.5 store."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from alibi import Broker, DurableWitness, H, OPS, Signer
from wolfalibi import stage3, stage35_verifier
from wolfalibi.stage3_evidence import run_marker, verify_execution
from wolfalibi.stage35_verifier import VerifierStore, VerifierStoreError


class VerifierStoreTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="wolfalibi-stage35-verifier-")
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.path = self.directory / "verifier.sqlite"
        self.broker = Signer()
        self.witness = Signer()
        self.fixture = b"stage 3.5 verifier synthetic fixture"
        self.contract = self._contract("first", 1)
        self.evidence, self.prior, self.terminal = self._history(self.contract)

    def _contract(self, run, nonce):
        return {
            "run_id": run,
            "challenge": bytes([nonce] * 32).hex(),
            "expires_at": 200,
            "profile": {"test": "in-process synthetic broker transcript"},
            "key": "protected.txt",
            "fixture_sha256": H(self.fixture).hex(),
        }

    def _history(self, contract):
        # Deliberately separate fixture and witness state per history. The
        # verifier store tests consume authenticated test transcripts locally.
        trial = self.directory / contract["run_id"]
        trial.mkdir()
        resource = trial / "resources"
        resource.mkdir()
        (resource / contract["key"]).write_bytes(self.fixture)
        journal = trial / "broker.wal"
        with DurableWitness(trial / "witness.json", self.witness) as witness, \
                Broker(resource, self.broker, witness, journal=journal) as broker:
            genesis = witness.state_digest
            prior = witness.state_anchor()
            with broker._operation():
                broker._record(run_marker(contract), OPS["r"])
            start = stage3._checkpoint(broker, broker.seal())
            after_start = witness.state_anchor()
            self.assertEqual(broker.read(contract["key"]), self.fixture)
            observations = {
                "direct_denied": True, "canary_closed": True,
                "response_sha256": contract["fixture_sha256"],
                "child_exit": 0, "channel_eof": True,
            }
            evidence = stage3._signed_evidence(broker, witness, journal, contract, prior,
                                               observations, start, after_start)
            return evidence, genesis, witness.state_digest

    def _references(self, head):
        return {self.witness.pub: head}

    def _bootstrap(self):
        return VerifierStore(self.path, bootstrap_heads=self._references(self.prior))

    def _open(self, head):
        return VerifierStore(self.path, expected_heads=self._references(head))

    def _issue(self, store, contract=None):
        return store.issue(contract=self.contract if contract is None else contract,
                           broker_pub=self.broker.pub, witness_pub=self.witness.pub, now=100)

    def _accept(self, store, **overrides):
        args = {
            "evidence": self.evidence,
            "challenge": self.contract["challenge"],
            "now": 150,
        }
        args.update(overrides)
        return store.accept(**args)

    def test_issued_challenge_and_accepted_head_survive_reopening(self):
        with self._bootstrap() as store:
            self.assertEqual(self._issue(store)["outcome"], "ISSUED")
            self.assertEqual(self._issue(store)["outcome"], "REJECTED")
        with self._open(self.prior) as store:
            accepted = self._accept(store)
            self.assertEqual(accepted["outcome"], "VERIFIED", accepted)
            self.assertEqual(accepted["assurance"], "BROKER_ONLY")
            self.assertEqual(accepted["confinement"], "BLOCKED")
            self.assertEqual(store.head(self.witness.pub), self.terminal)
            self.assertEqual(self._accept(store)["outcome"], "REJECTED")
        with self._open(self.terminal) as store:
            self.assertEqual(self._accept(store)["outcome"], "REJECTED")
            self.assertEqual(store.head(self.witness.pub), self.terminal)
        with self.assertRaises(VerifierStoreError):
            self._open(self.prior)

    def test_invalid_incomplete_and_expired_envelopes_leave_challenge_pending(self):
        with self._bootstrap() as store:
            self.assertEqual(self._issue(store)["outcome"], "ISSUED")
            checks = [
                ({"challenge": "99" * 32}, "REJECTED"),
                ({"now": 99}, "REJECTED"),
                ({"now": self.contract["expires_at"]}, "REJECTED"),
                ({"evidence": None}, "BLOCKED"),
                ({"evidence": {**self.evidence, "broker_signature": "00" * 64}}, "REJECTED"),
            ]
            for overrides, outcome in checks:
                with self.subTest(outcome=outcome, overrides=overrides.keys()):
                    self.assertEqual(self._accept(store, **overrides)["outcome"], outcome)
                    self.assertEqual(store.head(self.witness.pub), self.prior)
            self.assertEqual(self._accept(store)["outcome"], "VERIFIED")

    def test_expiry_is_checked_again_inside_transaction(self):
        with self._bootstrap() as store:
            self.assertEqual(self._issue(store)["outcome"], "ISSUED")
            expiry = self.contract["expires_at"]
            with patch.object(stage35_verifier.time, "time", side_effect=[expiry - 1, expiry]):
                expired = self._accept(store, now=None)
            self.assertEqual(expired["outcome"], "REJECTED", expired)
            self.assertEqual(store.head(self.witness.pub), self.prior)
            self.assertEqual(self._accept(store)["outcome"], "VERIFIED")

    def test_issued_contract_and_verification_input_are_snapshotted(self):
        submitted = deepcopy(self.evidence)

        def edit_caller_copy(envelope, **references):
            submitted["broker_signature"] = "00" * 64
            return verify_execution(envelope, **references)

        with self._bootstrap() as store:
            self.assertEqual(self._issue(store)["outcome"], "ISSUED")
            self.contract["profile"]["test"] = "changed after issuance"
            with patch.object(stage35_verifier, "verify_execution", edit_caller_copy):
                self.assertEqual(self._accept(store, evidence=submitted)["outcome"], "VERIFIED")
            self.assertEqual(submitted["broker_signature"], "00" * 64)

    def test_open_without_a_database_blocks_instead_of_creating_one(self):
        with self.assertRaisesRegex(VerifierStoreError, "cannot open verifier database"):
            self._open(self.prior)
        self.assertFalse(self.path.exists())

    def _race(self, contenders):
        ready = Barrier(len(contenders), timeout=5)

        def check_before_either_can_commit(*args, **kwargs):
            result = verify_execution(*args, **kwargs)
            ready.wait()
            return result

        def submit(contender):
            evidence, contract = contender
            with self._open(self.prior) as store:
                return self._accept(store, evidence=evidence, challenge=contract["challenge"])

        with patch.object(stage35_verifier, "verify_execution", check_before_either_can_commit), \
                ThreadPoolExecutor(max_workers=len(contenders)) as pool:
            return list(pool.map(submit, contenders))

    def test_two_concurrent_copies_of_same_challenge_accept_once(self):
        with self._bootstrap() as store:
            self.assertEqual(self._issue(store)["outcome"], "ISSUED")
        contender = (self.evidence, self.contract)
        results = self._race([contender, contender])
        self.assertCountEqual([outcome["outcome"] for outcome in results], ["VERIFIED", "REJECTED"])
        with self._open(self.terminal) as store:
            self.assertEqual(self._accept(store)["outcome"], "REJECTED")

    def test_competing_authenticated_histories_can_advance_one_shared_head_once(self):
        second = self._contract("second", 2)
        second_evidence, second_prior, second_terminal = self._history(second)
        self.assertEqual(self.prior, second_prior)
        self.assertNotEqual(self.terminal, second_terminal)
        for evidence, contract in ((self.evidence, self.contract), (second_evidence, second)):
            independent_check = verify_execution(
                evidence, contract=contract, broker_pub=self.broker.pub, witness_pub=self.witness.pub,
                expected_witness_state_digest=self.prior, now=150,
            )
            self.assertEqual(independent_check["outcome"], "VERIFIED", independent_check)
        with self._bootstrap() as store:
            self.assertEqual(self._issue(store)["outcome"], "ISSUED")
            self.assertEqual(self._issue(store, second)["outcome"], "ISSUED")
        results = self._race([(self.evidence, self.contract), (second_evidence, second)])
        self.assertCountEqual([outcome["outcome"] for outcome in results], ["VERIFIED", "REJECTED"])
        winner, = (result for result in results if result["outcome"] == "VERIFIED")
        with self._open(bytes.fromhex(winner["witness_state_digest"])) as store:
            for evidence, contract in ((self.evidence, self.contract), (second_evidence, second)):
                self.assertEqual(self._accept(store, evidence=evidence,
                                              challenge=contract["challenge"])["outcome"], "REJECTED")

    def test_sqlite_fault_rolls_back_challenge_consumption_and_head_update(self):
        with self._bootstrap() as store:
            self.assertEqual(self._issue(store)["outcome"], "ISSUED")
        with sqlite3.connect(self.path) as fault:
            fault.execute("""
                CREATE TRIGGER synthetic_io_failure BEFORE UPDATE ON witness_heads
                BEGIN SELECT RAISE(ABORT, 'synthetic acceptance interruption'); END
            """)
        with self._open(self.prior) as store:
            interrupted = self._accept(store)
            self.assertEqual(interrupted["outcome"], "BLOCKED", interrupted)
            self.assertIn("synthetic acceptance interruption", interrupted["reason"])
            self.assertEqual(store.head(self.witness.pub), self.prior)
        with sqlite3.connect(self.path) as fault:
            fault.execute("DROP TRIGGER synthetic_io_failure")
        with self._open(self.prior) as store:
            self.assertEqual(self._accept(store)["outcome"], "VERIFIED")
            self.assertEqual(store.head(self.witness.pub), self.terminal)

    def test_process_exit_before_commit_keeps_both_updates_unapplied(self):
        with self._bootstrap() as store:
            self.assertEqual(self._issue(store)["outcome"], "ISSUED")
        script = """
import json, os, sys
from wolfalibi.stage35_verifier import VerifierStore

path, witness, expected, challenge = sys.argv[1:]
with VerifierStore(path, expected_heads={bytes.fromhex(witness): bytes.fromhex(expected)}) as store:
    def exit_before_commit(sql):
        if sql == "COMMIT":
            os._exit(73)
    store._connection.set_trace_callback(exit_before_commit)
    store.accept(json.load(sys.stdin), challenge=challenge, now=150)
"""
        child = subprocess.run(
            [sys.executable, "-c", script, str(self.path), self.witness.pub.hex(),
             self.prior.hex(), self.contract["challenge"]],
            cwd=Path(__file__).resolve().parent, input=json.dumps(self.evidence),
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(child.returncode, 73, child.stderr)
        with self._open(self.prior) as store:
            self.assertEqual(store.head(self.witness.pub), self.prior)
            self.assertEqual(self._accept(store)["outcome"], "VERIFIED")
            self.assertEqual(store.head(self.witness.pub), self.terminal)

    def test_older_database_snapshot_is_rejected_against_retained_head(self):
        snapshot = self.directory / "prior.sqlite"
        with self._bootstrap() as store:
            self.assertEqual(self._issue(store)["outcome"], "ISSUED")
        shutil.copyfile(self.path, snapshot)
        with self._open(self.prior) as store:
            self.assertEqual(self._accept(store)["outcome"], "VERIFIED")
        with self.assertRaisesRegex(VerifierStoreError, "independently retained heads"):
            VerifierStore(snapshot, expected_heads=self._references(self.terminal))
        with self.assertRaises(VerifierStoreError):
            self._bootstrap()


if __name__ == "__main__":
    unittest.main()
