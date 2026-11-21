"""Synthetic local integration tests for the fixed BYOA Solitary profile.

The profile runs its checked-in synthetic worker, including when the tests
interrupt the worker or suppress a final lifecycle observation.
"""

from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import select
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

from alibi import Broker, DurableWitness, H, OPS, Signer, dec_entry
from wolfalibi import solitary, solitary_cli, stage3
from wolfalibi.solitary import run_solitary, solitary_contract
from wolfalibi.solitary_evidence import verify_solitary
from wolfalibi.solitary_worker import CONTROL_RESULTS, LIMITS
from wolfalibi.stage3_evidence import run_marker
from wolfalibi.stage3_worker import UnsupportedWorker
from wolfalibi.stage35_verifier import VerifierStore


_EXPECTED_CONTROLS = {
    "ambient_canary_absent": True,
    "scratch_roundtrip": True,
    "file_size_cap_enforced": True,
    "new_socket_denied": True,
    "fork_denied": True,
    "protected_write_denied": True,
    "exec_denied": True,
}
_EXPECTED_CLOSURE = {
    "launcher_reaped": True,
    "worker_pidfd_exited": True,
    "peer_hangup": True,
    "broker_drained": True,
}


class BYOASolitaryIntegrationTests(unittest.TestCase):
    """Exercise the public contract, launch, evidence, and verifier boundary."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="wolfalibi-byoa-solitary-")
        self.addCleanup(directory.cleanup)
        self.state_dir = Path(directory.name)

    def _contract(self, label):
        """Build the fixed contract or explicitly report a static prerequisite."""
        now = int(time.time())
        try:
            contract = solitary_contract(
                f"byoa-solitary-{label}", bytes(range(32)), now + 120,
            )
        except UnsupportedWorker as exc:
            # This is deliberately the sole skip path.  Once the local static
            # prerequisite check succeeds, a live launch failure is a test
            # failure rather than a host-specific pass.
            self.skipTest(f"UNSUPPORTED static Solitary prerequisite: {exc}")

        profile = contract["profile"]["solitary"]
        self.assertEqual(contract["key"], stage3.FIXTURE_KEY)
        self.assertEqual(contract["fixture_sha256"], H(stage3.FIXTURE_BYTES).hex())
        self.assertEqual(CONTROL_RESULTS, _EXPECTED_CONTROLS)
        self.assertEqual(profile["control_results"], _EXPECTED_CONTROLS)
        self.assertEqual(profile["limits"], LIMITS)
        self.assertIn("seccomp", profile)
        return contract, now

    def _live_trial(self, label):
        contract, now = self._contract(label)
        broker, supervisor, witness_signer = Signer(), Signer(), Signer()
        witness_path = self.state_dir / f"{label}-witness.json"
        with DurableWitness(witness_path, witness_signer) as witness:
            initial = witness.state_digest
            result = run_solitary(
                self.state_dir, contract=contract, signer=broker, witness=witness,
                supervisor=supervisor, expected_witness_state_digest=initial,
            )
            terminal = witness.state_digest

        # Do not convert a dynamic launch/measurement/lifecycle problem into a
        # skip after the fixed profile has already been qualified locally.
        self.assertEqual(result["outcome"], "COMPLETED", result)
        references = {
            "contract": contract,
            "broker_pub": broker.pub,
            "witness_pub": witness_signer.pub,
            "supervisor_pub": supervisor.pub,
            "expected_witness_state_digest": initial,
            "now": now,
        }
        return result, references, terminal

    def test_live_worker_admission_and_signed_observations_are_distinct(self):
        result, references, terminal = self._live_trial("observed")
        envelope = result["envelope"]
        verified = verify_solitary(envelope, **references)
        self.assertEqual(verified["outcome"], "VERIFIED", verified)
        self.assertEqual(verified["assurance"], "BROKER_ONLY")
        self.assertEqual(verified["confinement"], "BLOCKED")
        self.assertEqual(verified["witness_state_digest"], terminal.hex())

        evidence = envelope["evidence"]
        self.assertEqual(evidence["payload"]["observations"], {
            "direct_denied": True,
            "canary_closed": True,
            "response_sha256": H(stage3.FIXTURE_BYTES).hex(),
            "child_exit": 0,
            "channel_eof": True,
        })

        # The following values are signed worker *self-reports*.  They are
        # tested as claimed controls, not promoted to supervisor observations.
        record = envelope["supervisor_record"]["payload"]
        self.assertEqual(record["worker_self_report"], _EXPECTED_CONTROLS)
        self.assertTrue(record["worker_self_report"]["scratch_roundtrip"])
        for name in (
                "file_size_cap_enforced", "new_socket_denied", "fork_denied",
                "protected_write_denied", "exec_denied"):
            with self.subTest(self_report=name):
                self.assertTrue(record["worker_self_report"][name])

        # These fields are separate signed supervisor observations.  Their
        # provenance is intentionally not conflated with the worker controls.
        self.assertEqual(record["observed_limits"], LIMITS)
        self.assertEqual(record["closure"], _EXPECTED_CLOSURE)
        snapshot = record["snapshot"]
        self.assertEqual(snapshot["credentials"]["seccomp_mode"], 2)
        kernel = snapshot["solitary_kernel"]
        self.assertEqual(kernel["environment_keys"], ["PWD"])
        self.assertGreater(kernel["worker_seccomp_filters"],
                           kernel["launcher_seccomp_filters"])
        self.assertEqual(verified["worker_self_report"], _EXPECTED_CONTROLS)
        self.assertEqual(verified["observed_limits"], LIMITS)
        self.assertEqual(verified["closure"], _EXPECTED_CLOSURE)

        # Broker admission is a distinct, witnessed fact: exactly the run
        # marker and one authorized synthetic read form the signed transcript.
        payload = evidence["payload"]
        start_key, start_event = dec_entry(bytes.fromhex(payload["start"]["leaves"][0]))
        end_key, end_event = dec_entry(bytes.fromhex(payload["end"]["leaves"][0]))
        self.assertEqual(start_key, run_marker(references["contract"]))
        self.assertEqual(start_event, (OPS["r"], 1, 1))
        self.assertEqual(end_key, stage3.FIXTURE_KEY.encode("utf-8"))
        self.assertEqual(end_event, (OPS["r"], 1, 2))

        # This is a local synthetic postcondition, not an assertion about an
        # arbitrary host resource.  It checks that the protected fixture was
        # unchanged while the worker reported write denial.
        resources = Path(result["run_dir"]) / "resources"
        self.assertEqual((resources / stage3.FIXTURE_KEY).read_bytes(), stage3.FIXTURE_BYTES)
        self.assertEqual(sorted(item.name for item in resources.iterdir()), [stage3.FIXTURE_KEY])

    def test_completed_envelope_rejects_tampering_and_wrong_external_references(self):
        result, references, _ = self._live_trial("tamper")
        envelope = result["envelope"]

        altered_control = deepcopy(envelope)
        altered_control["supervisor_record"]["payload"]["worker_self_report"]["fork_denied"] = False
        self.assertEqual(verify_solitary(altered_control, **references)["outcome"], "REJECTED")

        altered_limits = deepcopy(envelope)
        altered_limits["supervisor_record"]["payload"]["observed_limits"]["RLIMIT_CPU"][0] += 1
        self.assertEqual(verify_solitary(altered_limits, **references)["outcome"], "REJECTED")

        altered_effect = deepcopy(envelope)
        altered_effect["evidence"]["payload"]["observations"]["direct_denied"] = False
        self.assertEqual(verify_solitary(altered_effect, **references)["outcome"], "REJECTED")

        wrong_contract = deepcopy(references["contract"])
        wrong_contract["challenge"] = "a5" * 32
        self.assertEqual(verify_solitary(
            envelope, **{**references, "contract": wrong_contract},
        )["outcome"], "REJECTED")
        self.assertEqual(verify_solitary(
            envelope, **{**references, "supervisor_pub": Signer().pub},
        )["outcome"], "REJECTED")
        self.assertEqual(verify_solitary(
            envelope, **{**references, "expected_witness_state_digest": b"\xff" * 32},
        )["outcome"], "REJECTED")

    def test_verifier_store_enrolls_measured_solitary_and_refuses_replay(self):
        contract, now = self._contract("store")
        broker, supervisor, witness_signer = Signer(), Signer(), Signer()
        store_path = self.state_dir / "solitary-verifier.sqlite"
        with DurableWitness(self.state_dir / "store-witness.json", witness_signer) as witness:
            initial = witness.state_digest
            with VerifierStore(store_path, bootstrap_heads={witness_signer.pub: initial}) as store:
                issued = store.issue(
                    contract=contract, broker_pub=broker.pub, witness_pub=witness_signer.pub,
                    supervisor_pub=supervisor.pub, now=now,
                )
                self.assertEqual(issued["outcome"], "ISSUED", issued)
                self.assertEqual(issued["expected_witness_state_digest"], initial.hex())

                result = run_solitary(
                    self.state_dir, contract=contract, signer=broker, witness=witness,
                    supervisor=supervisor, expected_witness_state_digest=initial,
                )
                self.assertEqual(result["outcome"], "COMPLETED", result)
                envelope = result["envelope"]
                accepted = store.accept(
                    envelope["evidence"], challenge=contract["challenge"],
                    supervisor_record=envelope["supervisor_record"], now=now,
                )
                self.assertEqual(accepted["outcome"], "VERIFIED", accepted)
                self.assertEqual(accepted["measurement"], "SIGNED_SUPERVISOR_SNAPSHOT")
                self.assertEqual(store.head(witness_signer.pub), witness.state_digest)
                replay = store.accept(
                    envelope["evidence"], challenge=contract["challenge"],
                    supervisor_record=envelope["supervisor_record"], now=now,
                )
                self.assertEqual(replay["outcome"], "REJECTED", replay)

    def test_fault_injected_incomplete_close_never_emits_an_envelope(self):
        contract, _ = self._contract("incomplete-close")
        broker, supervisor, witness_signer = Signer(), Signer(), Signer()
        with DurableWitness(self.state_dir / "close-witness.json", witness_signer) as witness:
            initial = witness.state_digest
            # The live fixed worker still runs normally.  Only the final
            # supervisor lifecycle observation is faulted, so there is no
            # supported claim that the peer exited and the broker drained.
            with patch.object(solitary, "_exited", return_value=False), \
                    patch.object(solitary, "sign_envelope", wraps=solitary.sign_envelope) as sign:
                result = run_solitary(
                    self.state_dir, contract=contract, signer=broker, witness=witness,
                    supervisor=supervisor, expected_witness_state_digest=initial,
                )
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertIn("closed worker lifecycle", result["reason"])
        self.assertNotIn("envelope", result)
        self.assertNotIn("evidence", result)
        sign.assert_not_called()

    def test_worker_termination_after_durable_read_before_send_prevents_seal(self):
        contract, _ = self._contract("interrupted")
        broker, supervisor, witness_signer = Signer(), Signer(), Signer()
        measure, send = solitary.measure_worker, stage3._send
        worker_pidfd = None

        def retain_identity(*args, **kwargs):
            nonlocal worker_pidfd
            snapshot = measure(*args, **kwargs)
            worker_pidfd = os.pidfd_open(snapshot["identity"]["worker_pid"])
            self.addCleanup(os.close, worker_pidfd)
            return snapshot

        def interrupt(channel, packet, deadline):
            signal.pidfd_send_signal(worker_pidfd, signal.SIGKILL)
            poll = select.poll()
            poll.register(worker_pidfd, select.POLLIN)
            self.assertTrue(poll.poll(2000), "synthetic worker did not exit")
            return send(channel, packet, deadline)

        with DurableWitness(self.state_dir / "interrupted-witness.json", witness_signer) as witness:
            with patch.object(solitary, "measure_worker", side_effect=retain_identity), \
                    patch.object(stage3, "_send", side_effect=interrupt) as attempted:
                result = run_solitary(
                    self.state_dir, contract=contract, signer=broker, witness=witness,
                    supervisor=supervisor, expected_witness_state_digest=witness.state_digest,
                )
            attempted.assert_called_once()
            self.assertEqual(result["outcome"], "BLOCKED", result)
            self.assertNotIn("envelope", result)
            self.assertEqual(witness.state_anchor()["anchor"]["generation"], 1)
            run_dir = Path(result["run_dir"])
            with Broker(run_dir / "resources", broker, witness, journal=run_dir / "broker.wal") as recovered:
                self.assertEqual(recovered.seq, 2)
                self.assertEqual(list(recovered.sealed), [0])
                self.assertIn(stage3.FIXTURE_KEY.encode(), recovered.cur)

    def test_cli_requires_consent_before_preflight_launch_or_state_creation(self):
        """The fixed CLI must not initialize a trial merely to inspect consent."""
        manifest = self.state_dir / "synthetic-manifest.json"
        manifest.write_text(json.dumps({
            "schema": "wolfalibi.byoa.solitary.manifest.v1",
            "profile": "solitary-synthetic",
            "fixture": "protected.txt",
        }), encoding="utf-8")
        state = self.state_dir / "no-consent-state"
        with patch.object(solitary_cli, "preflight") as preflight, \
                patch.object(solitary_cli, "solitary_contract") as contract, \
                patch.object(solitary_cli, "run_solitary") as launch, \
                redirect_stdout(io.StringIO()):
            from wolfalibi_cli import main
            status = main([
                "byoa", "test", "--manifest", str(manifest),
                "--state-dir", str(state), "--run-id", "no-consent",
            ])
        self.assertEqual(status, 2)
        self.assertFalse(state.exists())
        preflight.assert_not_called()
        contract.assert_not_called()
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
