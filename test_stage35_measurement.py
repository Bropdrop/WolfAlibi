"""Local controls for the Stage 3.5 measurement and declared fixture catalog."""

import copy
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from alibi import DurableWitness, Signer
from wolfalibi import stage3, stage35
from wolfalibi.stage3_worker import UnsupportedWorker
from wolfalibi.stage35_verifier import VerifierStore


class MeasuredTrialTests(unittest.TestCase):
    def _trial(self, root, key):
        now = int(time.time())
        try:
            contract = stage35.measured_contract("synthetic-measured", bytes(range(32)), now + 120,
                                                 key=key)
        except UnsupportedWorker as exc:
            self.skipTest(f"UNSUPPORTED: {exc}")
        broker, supervisor = Signer(), Signer()
        with DurableWitness(root / "witness.json", Signer()) as witness:
            references = dict(
                supervisor_pub=supervisor.pub, contract=contract, broker_pub=broker.pub,
                witness_pub=witness.signer.pub, expected_witness_state_digest=witness.state_digest,
                now=now,
            )
            result = stage35.run_measured_trial(
                root, contract=contract, signer=broker, witness=witness, supervisor=supervisor,
                expected_witness_state_digest=references["expected_witness_state_digest"],
            )
        return result, references

    def test_two_declared_paths_with_kernel_observations_and_pinned_signatures(self):
        layouts = {
            stage3.FIXTURE_KEY: ["."],
            "reports/summary.txt": [".", "reports"],
        }
        for key, directories in layouts.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                result, references = self._trial(Path(directory), key)
                self.assertEqual(result["outcome"], "COMPLETED", result)
                record, evidence = result["supervisor_record"], result["evidence"]
                verified = stage35.verify_measured_trial(evidence, record, **references)
                self.assertEqual(verified["outcome"], "VERIFIED", verified)
                self.assertEqual(verified["assurance"], "BROKER_ONLY")
                self.assertEqual(verified["confinement"], "BLOCKED")
                self.assertEqual(verified["scope"]["key"], key)
                self.assertEqual(verified["scope"]["directories"], directories)
                self.assertTrue(verified["observations"]["direct_denied"])
                self.assertTrue(verified["observations"]["canary_closed"])

                missing = stage35.verify_measured_trial(evidence, None, **references)
                self.assertEqual(missing["outcome"], "BLOCKED")
                tampered = copy.deepcopy(record)
                tampered["payload"]["phase"] = "AFTER_READ"
                self.assertEqual(stage35.verify_measured_trial(
                    evidence, tampered, **references)["outcome"], "REJECTED")
                wrong_key = {**references, "supervisor_pub": Signer().pub}
                self.assertEqual(stage35.verify_measured_trial(
                    evidence, record, **wrong_key)["outcome"], "REJECTED")

                snapshot = record["payload"]["worker"]
                contract = references["contract"]
                for section, field, value in (
                    ("executable", "sha256", "0" * 64),
                    ("credentials", "no_new_privs", 0),
                    ("descriptors", "3", {"kind": "socket"}),
                    ("invocation", "challenge", "0" * 64),
                ):
                    with self.subTest(section=section):
                        inconsistent = copy.deepcopy(snapshot)
                        inconsistent[section][field] = value
                        with self.assertRaises(stage35.MeasurementBlocked):
                            stage35.verify_measurement_record(inconsistent, contract)

    def test_unavailable_supervisor_snapshot_prevents_data_release(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                stage35, "measure_worker", side_effect=stage35.MeasurementBlocked("test prerequisite")), \
                patch.object(stage3, "_send") as send:
            result, _ = self._trial(Path(directory), stage3.FIXTURE_KEY)
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertIn("supervisor measurement unavailable", result["reason"])
        self.assertNotIn("evidence", result)
        send.assert_not_called()

    def test_issued_measured_challenge_requires_the_pinned_snapshot_for_consumption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, refs = self._trial(root, stage3.FIXTURE_KEY)
            self.assertEqual(result["outcome"], "COMPLETED", result)
            prior, witness = refs["expected_witness_state_digest"], refs["witness_pub"]
            with VerifierStore(root / "verify.sqlite", bootstrap_heads={witness: prior}) as store:
                contract = refs["contract"]
                issued = store.issue(contract=contract, broker_pub=refs["broker_pub"],
                                     witness_pub=witness, supervisor_pub=refs["supervisor_pub"],
                                     now=refs["now"])
                self.assertEqual(issued["outcome"], "ISSUED")
                args = dict(challenge=contract["challenge"], now=refs["now"])
                evidence = result["evidence"]
                self.assertEqual(store.accept(evidence, **args)["outcome"], "BLOCKED")
                forged = {**result["supervisor_record"], "signature": "00" * 64}
                self.assertEqual(store.accept(evidence, supervisor_record=forged,
                                              **args)["outcome"], "REJECTED")
                self.assertEqual(store.head(witness), prior)
                args["supervisor_record"] = result["supervisor_record"]
                accepted = store.accept(evidence, **args)
                self.assertEqual(accepted["outcome"], "VERIFIED", accepted)
                self.assertEqual(accepted["measurement"], "SIGNED_SUPERVISOR_SNAPSHOT")
                self.assertEqual(len(accepted["accepted_envelope_sha256"]), 64)
                self.assertEqual(store.accept(evidence, **args)["outcome"], "REJECTED")

    def test_extra_alias_and_single_path_permissions_block_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / stage3.FIXTURE_KEY
            fixture.write_bytes(stage3.FIXTURE_BYTES)
            fixture.chmod(0o400)
            self.assertEqual(stage35.inspect_layout(root, stage3.FIXTURE_KEY)["links"], 1)
            for kind in ("symlink", "hardlink"):
                with self.subTest(kind=kind):
                    alias = root / "synthetic-alias"
                    if kind == "symlink":
                        alias.symlink_to(fixture)
                    else:
                        os.link(fixture, alias)
                    with self.assertRaises(stage3.TrialBlocked):
                        stage35.inspect_layout(root, stage3.FIXTURE_KEY)
                    alias.unlink()
            fixture.chmod(0o600)
            with self.assertRaises(stage3.TrialBlocked):
                stage35.inspect_layout(root, stage3.FIXTURE_KEY)


if __name__ == "__main__":
    unittest.main()
