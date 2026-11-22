"""Live Linux integration controls for the selected-source Solitary admission gate."""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import signal
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from alibi import Broker, DurableWitness, Signer
from wolfalibi import byoa_cell, stage3
from wolfalibi.byoa_attestation import make_expectations
from wolfalibi.byoa_bundle import Bundle, load_bundle
from wolfalibi.byoa_effect_gate import ReadGate, enroll_read_authorities, initialize_read_target, issue_read_grant
from wolfalibi.solitary_evidence import verify_solitary
from wolfalibi.stage35_measure import MeasurementBlocked

SAMPLE = Path(__file__).resolve().parent / "examples/qualification001/agent.json"


class SelectedCellTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="byoa-cell-")
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name)
        self.bundle = load_bundle(SAMPLE)
        self.broker, self.supervisor, self.owner, self.target = (Signer() for _ in range(4))
        self.witness = DurableWitness(self.state / "witness.json", Signer())
        self.addCleanup(self.witness.close)
        self.prior = self.witness.state_digest

    def contract(self, bundle):
        try:
            return byoa_cell.cell_contract(bundle, "approved-demo", bytes(range(32)), int(time.time()) + 90)
        except stage3.UnsupportedWorker as exc:
            self.skipTest(f"UNSUPPORTED static Solitary runtime: {exc}")

    def gate(self, contract):
        expected = make_expectations(
            contract, broker_pub=self.broker.pub, witness_pub=self.witness.signer.pub,
            supervisor_pub=self.supervisor.pub, owner_pub=self.owner.pub, target_pub=self.target.pub,
            expected_witness_state_digest=self.prior, now=int(time.time()),
        )
        directory = self.state / "target"
        directory.mkdir(mode=0o700)
        initialize_read_target(directory, self.target)
        enroll_read_authorities(directory, owner_pub=expected["owner_pub"], broker_pub=expected["broker_pub"],
                                supervisor_pub=expected["supervisor_pub"], witness_pub=expected["witness_pub"],
                                target_signer=self.target)
        return ReadGate(directory, expected, issue_read_grant(expected, self.owner), self.target,
                        witness_state=self.witness.state_anchor)

    def trial(self, bundle, contract, gate, consent=True):
        return byoa_cell.run_cell(
            self.state, bundle=bundle, contract=contract, signer=self.broker,
            supervisor=self.supervisor, witness=self.witness, expected_witness_state_digest=self.prior,
            read_gate=gate, consent=consent,
        )

    def test_real_selected_python_callback_runs_in_measured_cell(self):
        contract = self.contract(self.bundle)
        with self.gate(contract) as gate:
            result = self.trial(self.bundle, contract, gate)
            self.assertIsNotNone(gate.decision, result)
        self.assertEqual(result["outcome"], "COMPLETED", result)
        envelope = result["envelope"]
        verified = verify_solitary(
            envelope, contract=contract, broker_pub=self.broker.pub, witness_pub=self.witness.signer.pub,
            supervisor_pub=self.supervisor.pub, expected_witness_state_digest=self.prior, now=int(time.time()),
        )
        self.assertEqual(verified["outcome"], "VERIFIED", verified)
        snapshot = envelope["supervisor_record"]["payload"]["snapshot"]
        self.assertEqual(snapshot["executable"]["argv_source_sha256"], contract["profile"]["worker_sha256"])
        self.assertEqual(contract["profile"]["byoa"], self.bundle.identity())
        self.assertEqual(verified["measurement"], "SIGNED_SUPERVISOR_SNAPSHOT")
        self.assertEqual(result["observation"]["summary"]["counts"], {"filesystem.read.success": 1})
        self.assertTrue(all(verified["closure"].values()))

    def test_changed_source_approval_is_refused_before_launcher(self):
        contract = self.contract(self.bundle)
        changed = deepcopy(contract)
        changed["profile"]["byoa"]["source_sha256"] = "01" * 32
        with self.gate(contract) as gate, patch.object(byoa_cell, "_launch_profile") as launcher:
            result = self.trial(self.bundle, changed, gate)
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertNotIn("envelope", result)
        launcher.assert_not_called()

    def test_missing_required_measurement_blocks_before_admission_and_read(self):
        contract = self.contract(self.bundle)
        with self.gate(contract) as gate, \
                patch.object(byoa_cell, "measure_worker", side_effect=MeasurementBlocked("unavailable")), \
                patch.object(Broker, "read", autospec=True) as read:
            result = self.trial(self.bundle, contract, gate)
            self.assertIsNone(gate.decision)
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertIn("unavailable", result["reason"])
        self.assertNotIn("envelope", result)
        read.assert_not_called()

    def test_consent_must_be_explicit_even_at_python_entrypoint(self):
        contract = self.contract(self.bundle)
        with patch.object(byoa_cell, "_launch_profile") as launcher:
            for consent in (False, 1):
                result = self.trial(self.bundle, contract, None, consent=consent)
                self.assertEqual(result["outcome"], "BLOCKED")
                self.assertIn("consent", result["reason"])
        launcher.assert_not_called()

    def test_no_authority_never_spawns_worker(self):
        contract = self.contract(self.bundle)
        with patch.object(byoa_cell, "_launch_profile") as launcher:
            result = self.trial(self.bundle, contract, None)
        self.assertEqual(result["outcome"], "BLOCKED")
        launcher.assert_not_called()

    def test_post_admission_decline_keeps_read_but_no_terminal_receipt(self):
        # Another explicitly selected local package accepts a different fictional fixture.
        # Run that package only through the same live measured path.
        source = self.bundle.source.replace(b"Stage 3", b"Stage X")
        doc = json.loads(self.bundle.manifest)
        doc["files"]["agent.py"] = sha256(source).hexdigest()
        alternative = Bundle(json.dumps(doc).encode("ascii"), source)
        contract = self.contract(alternative)
        self.assertNotEqual(contract["profile"]["worker_sha256"], self.contract(self.bundle)["profile"]["worker_sha256"])
        with self.gate(contract) as gate:
            result = self.trial(alternative, contract, gate)
            self.assertIsNotNone(gate.decision, result)
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertNotIn("envelope", result)
        self.assertEqual(self.witness.state_anchor()["anchor"]["generation"], 1)
        run_dir = Path(result["run_dir"])
        with Broker(run_dir / "resources", self.broker, self.witness, journal=run_dir / "broker.wal") as recovered:
            self.assertEqual(recovered.seq, 2)
            self.assertEqual(list(recovered.sealed), [0])
            self.assertIn(stage3.FIXTURE_KEY.encode(), recovered.cur)

    def test_missing_observation_prevents_seal_even_when_worker_exited(self):
        contract = self.contract(self.bundle)
        receive = stage3._receive_closed
        removed = []

        def lose_observation(channel, deadline):
            packet = receive(channel, deadline)
            if packet.startswith(byoa_cell.OBSERVATION_PREFIX):
                removed.append(True)
                return b""
            return packet

        with self.gate(contract) as gate, patch.object(stage3, "_receive_closed", side_effect=lose_observation):
            result = self.trial(self.bundle, contract, gate)
        self.assertEqual(removed, [True])
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertNotIn("envelope", result)
        self.assertEqual(self.witness.state_anchor()["anchor"]["generation"], 1)

    def test_worker_death_after_read_wal_before_data_has_no_terminal_receipt(self):
        contract = self.contract(self.bundle)
        measure, send = byoa_cell.measure_worker, stage3._send
        worker_fds = []

        def hold_worker(*args, **kwargs):
            snapshot = measure(*args, **kwargs)
            fd = os.pidfd_open(snapshot["identity"]["worker_pid"])
            self.addCleanup(os.close, fd)
            worker_fds.append(fd)
            return snapshot

        def terminate_before_reply(channel, packet, deadline):
            self.assertEqual(packet["type"], "data")
            self.assertEqual(len(worker_fds), 1)
            fd = worker_fds[0]
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            waiter = select.poll()
            waiter.register(fd, select.POLLIN)
            self.assertTrue(any(event & select.POLLIN for _, event in waiter.poll(2000)))
            return send(channel, packet, deadline)

        with self.gate(contract) as gate, patch.object(byoa_cell, "measure_worker", hold_worker), \
                patch.object(stage3, "_send", terminate_before_reply):
            result = self.trial(self.bundle, contract, gate)
            self.assertIsNotNone(gate.decision, result)
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertNotIn("envelope", result)
        self.assertEqual(self.witness.state_anchor()["anchor"]["generation"], 1)
        run_dir = Path(result["run_dir"])
        with Broker(run_dir / "resources", self.broker, self.witness, journal=run_dir / "broker.wal") as recovered:
            self.assertEqual(recovered.seq, 2)
            self.assertEqual(list(recovered.sealed), [0])
            self.assertIn(stage3.FIXTURE_KEY.encode(), recovered.cur)
