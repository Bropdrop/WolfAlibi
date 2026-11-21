"""Local synthetic qualification for the Stage 3 single-read trial."""

import copy
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from alibi import Broker, DurableWitness, H, JournalError, Signer, canon, dec_entry
from wolfalibi import stage3
from wolfalibi.stage3_evidence import run_marker, verify_execution
from wolfalibi.stage3_worker import UnsupportedWorker


class Stage3ProtocolTests(unittest.TestCase):
    def test_invalid_requests_have_no_broker_side_effects(self):
        contract = {"run_id": "protocol-test", "challenge": "a1" * 32,
                    "key": stage3.FIXTURE_KEY, "fixture_sha256": H(stage3.FIXTURE_BYTES).hex()}
        request = {
            "type": "read", "run_id": contract["run_id"], "challenge": contract["challenge"],
            "seq": 1, "key": contract["key"], "direct_denied": True, "canary_closed": True,
        }
        changes = (
            {"type": "write"},
            {"run_id": "different-run"},
            {"challenge": "a2" * 32},
            {"key": "./" + contract["key"]},
            {"key": "alias.txt"},
            {"canary_closed": False},
            {"direct_denied": False},
        )
        for changed in changes:
            with self.subTest(changed=changed):
                broker = Mock(spec=Broker)
                supervisor, worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                with supervisor, worker:
                    worker.send(canon(dict(request, **changed)))
                    with self.assertRaises(stage3.TrialBlocked):
                        stage3._serve(supervisor, broker, contract, time.monotonic() + 2)
                    self.assertEqual(broker.mock_calls, [])
                    supervisor.close()
                    worker.settimeout(2)
                    self.assertEqual(worker.recv(1024), b"")


class Stage3ExecutionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="wolfalibi-stage3-test-")
        self.addCleanup(directory.cleanup)
        self.state_dir = Path(directory.name)
        self.signer = Signer()
        self.witness_signer = Signer()

    def _contract(self):
        try:
            return stage3.trial_contract("synthetic-run", bytes(range(32)), int(time.time()) + 120)
        except UnsupportedWorker as exc:
            self.skipTest(str(exc))

    def _run(self, contract, witness, expected_digest, **options):
        result = stage3.run_trial(
            self.state_dir, contract=contract, signer=self.signer, witness=witness,
            expected_witness_state_digest=expected_digest, **options,
        )
        if result["outcome"] == "UNSUPPORTED":
            self.skipTest(result["reason"])
        return result

    def _verify(self, evidence, contract, expected_digest, **overrides):
        references = {
            "contract": contract,
            "broker_pub": self.signer.pub,
            "witness_pub": self.witness_signer.pub,
            "expected_witness_state_digest": expected_digest,
            "now": int(time.time()),
        }
        references.update(overrides)
        return verify_execution(evidence, **references)

    def _witness(self):
        return DurableWitness(self.state_dir / "witness.json", self.witness_signer)

    def _successful_run(self, contract):
        with self._witness() as witness:
            initial = witness.state_digest
            result = self._run(contract, witness, initial)
            self.assertEqual(result["outcome"], "COMPLETED", result)
            return result, initial, witness.state_digest

    def test_real_worker_reads_only_via_broker_and_witnesses_two_boundaries(self):
        contract = self._contract()
        result, initial, terminal = self._successful_run(contract)
        evidence = result["evidence"]
        ok = self._verify(evidence, contract, initial)
        self.assertEqual(ok["outcome"], "VERIFIED", ok)
        self.assertEqual(ok["assurance"], "BROKER_ONLY")
        self.assertEqual(ok["confinement"], "BLOCKED")
        self.assertEqual(ok["witness_state_digest"], terminal.hex())
        self.assertEqual(ok["observations"], {
            "direct_denied": True, "canary_closed": True, "child_exit": 0,
            "response_sha256": H(stage3.FIXTURE_BYTES).hex(), "channel_eof": True,
        })
        run_dir = Path(result["run_dir"])
        self.assertEqual((run_dir / "resources" / stage3.FIXTURE_KEY).read_bytes(),
                         stage3.FIXTURE_BYTES)
        self.assertEqual((run_dir / "broker.wal").read_bytes().hex(), evidence["journal_hex"])
        payload = evidence["payload"]
        self.assertEqual(dec_entry(bytes.fromhex(payload["start"]["leaves"][0]))[0],
                         run_marker(contract))
        self.assertEqual(dec_entry(bytes.fromhex(payload["end"]["leaves"][0]))[0],
                         stage3.FIXTURE_KEY.encode())

    def _assert_incomplete_after_release(self, mode):
        contract = self._contract()
        with self._witness() as witness, patch.object(stage3, "_send", wraps=stage3._send) as send:
            result = self._run(contract, witness, witness.state_digest, _worker_mode=mode)
            self.assertEqual(result["outcome"], "BLOCKED", result)
            self.assertNotIn("evidence", result)
            send.assert_called_once()
            self.assertEqual(witness.state_anchor()["anchor"]["generation"], 1)
            run_dir = Path(result["run_dir"])
            with Broker(run_dir / "resources", self.signer, witness,
                        journal=run_dir / "broker.wal") as recovery:
                self.assertEqual(recovery.seq, 2)
                self.assertEqual(list(recovery.sealed), [0])
                self.assertIn(stage3.FIXTURE_KEY.encode(), recovery.cur)

    def test_duplicate_request_gets_no_second_release_or_terminal_evidence(self):
        self._assert_incomplete_after_release("duplicate")

    def test_worker_termination_after_release_preserves_unsealed_read(self):
        self._assert_incomplete_after_release("terminate")

    def test_open_worker_endpoint_blocks_terminal_evidence_after_exit(self):
        contract = self._contract()
        real_launch = stage3.launch
        held_endpoints = []

        def launch_with_open_endpoint(endpoint, *args, **kwargs):
            held = endpoint.dup()
            self.addCleanup(held.close)
            held_endpoints.append(held)
            return real_launch(endpoint, *args, **kwargs)

        with self._witness() as witness, patch.object(
                stage3, "launch", side_effect=launch_with_open_endpoint):
            result = self._run(contract, witness, witness.state_digest, timeout=1)
            self.assertEqual(result["outcome"], "BLOCKED", result)
            self.assertIn("worker socket remained open after exit", result["reason"])
            self.assertNotIn("evidence", result)
            self.assertEqual(witness.state_anchor()["anchor"]["generation"], 1)
        self.assertEqual(len(held_endpoints), 1)

    def test_interrupted_read_journal_write_releases_no_bytes(self):
        contract = self._contract()
        original = Broker._jwrite

        def fail_read_record(broker, record):
            if record.get("t") == "e" and record.get("seq") == 2:
                raise OSError("synthetic read WAL interruption")
            return original(broker, record)

        with self._witness() as witness, patch.object(Broker, "_jwrite", fail_read_record), \
                patch.object(stage3, "_send", wraps=stage3._send) as send:
            result = self._run(contract, witness, witness.state_digest)
            self.assertEqual(result["outcome"], "BLOCKED", result)
            self.assertIn("synthetic read WAL interruption", result["reason"])
            self.assertNotIn("evidence", result)
            send.assert_not_called()
            self.assertEqual(witness.state_anchor()["anchor"]["generation"], 1)

    def test_offline_verifier_blocks_missing_and_rejects_conflicting_evidence(self):
        contract = self._contract()
        result, initial, _ = self._successful_run(contract)
        evidence = result["evidence"]
        missing_wal = dict(evidence)
        del missing_wal["journal_hex"]
        self.assertEqual(self._verify(missing_wal, contract, initial)["outcome"], "BLOCKED")
        altered_wal = dict(evidence, journal_hex=evidence["journal_hex"][:-2])
        self.assertEqual(self._verify(altered_wal, contract, initial)["outcome"], "REJECTED")
        incomplete = dict(evidence, witness_state_chain=evidence["witness_state_chain"][:-1])
        self.assertEqual(self._verify(incomplete, contract, initial)["outcome"], "BLOCKED")
        altered = copy.deepcopy(evidence)
        altered["payload"]["observations"]["channel_eof"] = False
        self.assertEqual(self._verify(altered, contract, initial)["outcome"], "REJECTED")
        self.assertEqual(self._verify(evidence, contract, None)["outcome"], "BLOCKED")

    def test_offline_verifier_rejects_wrong_or_expired_challenge(self):
        contract = self._contract()
        result, initial, _ = self._successful_run(contract)
        evidence = result["evidence"]
        wrong = dict(contract, challenge="a4" * 32)
        self.assertEqual(self._verify(evidence, wrong, initial)["outcome"], "REJECTED")
        expired = self._verify(evidence, contract, initial, now=contract["expires_at"])
        self.assertEqual(expired["outcome"], "REJECTED")

    def test_changed_launcher_manifest_blocks_before_worker_starts(self):
        contract = self._contract()
        changed = dict(contract, profile=dict(contract["profile"], worker_sha256="ff" * 32))
        with self._witness() as witness, patch.object(stage3, "launch") as launch:
            result = self._run(changed, witness, witness.state_digest)
            self.assertEqual(result["outcome"], "BLOCKED", result)
            self.assertIn("profile differs", result["reason"])
            self.assertNotIn("evidence", result)
            launch.assert_not_called()
            self.assertEqual(witness.state_anchor()["anchor"]["generation"], 0)

    def test_retained_terminal_digest_blocks_a_witness_rollback(self):
        contract = self._contract()
        state_path = self.state_dir / "witness.json"
        with self._witness() as witness:
            initial = witness.state_digest
            old_state = state_path.read_bytes()
            result = self._run(contract, witness, initial)
            self.assertEqual(result["outcome"], "COMPLETED", result)
            retained = bytes.fromhex(
                self._verify(result["evidence"], contract, initial)["witness_state_digest"])
        state_path.write_bytes(old_state)
        with self.assertRaises(JournalError):
            DurableWitness(state_path, self.witness_signer, expected_state_digest=retained)
        with self._witness() as rolled_back:
            blocked = self._run(contract, rolled_back, retained)
            self.assertEqual(blocked["outcome"], "BLOCKED", blocked)
            self.assertNotIn("evidence", blocked)
        self.assertEqual(self._verify(result["evidence"], contract, retained)["outcome"],
                         "REJECTED")

    def test_missing_launcher_prerequisite_is_explicit(self):
        contract = {
            "run_id": "unsupported", "challenge": "a5" * 32,
            "expires_at": int(time.time()) + 120, "profile": {"synthetic": True},
            "key": stage3.FIXTURE_KEY, "fixture_sha256": H(stage3.FIXTURE_BYTES).hex(),
        }
        with self._witness() as witness, patch.object(
                stage3, "worker_profile", side_effect=UnsupportedWorker("synthetic missing launcher")):
            result = stage3.run_trial(
                self.state_dir, contract=contract, signer=self.signer, witness=witness,
                expected_witness_state_digest=witness.state_digest,
            )
            self.assertEqual(result["outcome"], "UNSUPPORTED", result)
            self.assertIn("synthetic missing launcher", result["reason"])
            self.assertNotIn("evidence", result)


if __name__ == "__main__":
    unittest.main()
