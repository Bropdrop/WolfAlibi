"""Stage 2 adversarial regressions using synthetic local fixtures only.

These tests exercise the narrow claims introduced after the Stage 1 delivery:
external witness-state continuity, explicitly bound receipt metadata, alias
refusal, and a reproducible Linux confinement probe. None is a universal
nonaccess or sandbox certification.
"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from alibi import (Broker, DurableWitness, H, JournalError, NotEmpty, Signer,
                   Witness, _sandbox, subtree)
from wolfalibi.isolation import (ASSURANCE_BLOCKED, boundary_descriptor,
                                 confinement_manifest, policy_digest,
                                 isolation_status, probe_confinement, run_isolated)
from wolfalibi.receipts import EvidenceRun, verify_negative_access_receipt


BROKER_SEED = bytes(range(32))
WITNESS_SEED = bytes(range(32, 64))
RESOURCE_IDENTITY = {
    "kind": "filesystem-path-v1",
    "normalization": "root-relative-posix-realpath-v1",
    "root_binding": "synthetic-stage2-fixture",
}
EXECUTION_BOUNDARY = {
    "type": "WOLFALIBI_UNCONFINED_SYNTHETIC_V1",
    "outcome": "NOT_ATTEMPTED",
    "assurance": "BLOCKED",
    "meaning": "receipt binding only; no real-agent confinement claim",
}
POLICY = {"actor": "synthetic-stage2-agent", "resource_model": "brokered-filesystem-v1"}


class Stage2ReceiptAdversarialTests(unittest.TestCase):
    def _broker(self, root, state, journal):
        witness = DurableWitness(state, Signer(WITNESS_SEED))
        broker = Broker(root, Signer(BROKER_SEED), witness, journal=journal)
        return broker, witness

    def _receipt(self, broker, witness, run_id, challenge):
        start_state = witness.state_digest
        run = EvidenceRun(
            broker,
            run_id=run_id,
            challenge=challenge,
            policy=POLICY,
            code_digest=H(b"synthetic-stage2-artifact"),
            receipt_version=2,
            resource_identity=RESOURCE_IDENTITY,
            execution_boundary=EXECUTION_BOUNDARY,
        )
        run.begin()
        broker.read("docs/notes.txt")
        receipt = run.finish_negative(*subtree("finance"))
        expected = {
            "broker_pub": broker.signer.pub,
            "witness_pub": witness.signer.pub,
            "challenge": challenge,
            "policy": POLICY,
            "lo": subtree("finance")[0],
            "hi": subtree("finance")[1],
            "run_id": run_id,
            "code_digest": H(b"synthetic-stage2-artifact"),
            "epochs": (run.start_epoch, run.start_epoch),
            "resource_identity": RESOURCE_IDENTITY,
            "execution_boundary": EXECUTION_BOUNDARY,
            "expected_witness_state_digest": start_state,
        }
        return receipt, expected

    def test_v2_receipt_requires_external_boundary_and_continuity_references(self):
        with tempfile.TemporaryDirectory(prefix="stage2-receipt-") as root:
            _sandbox(root)
            broker, witness = self._broker(root, os.path.join(root, "witness.json"),
                                           os.path.join(root, "events.wal"))
            try:
                receipt, expected = self._receipt(broker, witness, "stage2-v2", b"fresh-challenge")
                verified = verify_negative_access_receipt(receipt, **expected)
                self.assertEqual(verified["outcome"], "VERIFIED")
                self.assertEqual(verified["assurance"], "BROKER_ONLY")
                self.assertIn("witness_state_digest", verified)

                missing = dict(expected)
                missing.pop("execution_boundary")
                self.assertEqual(verify_negative_access_receipt(receipt, **missing)["outcome"], "BLOCKED")
                wrong_boundary = dict(expected, execution_boundary={
                    **EXECUTION_BOUNDARY, "outcome": "SUBSTITUTED"})
                self.assertEqual(verify_negative_access_receipt(
                    receipt, **wrong_boundary)["outcome"], "REJECTED")
                replayed = dict(expected, challenge=b"different-fresh-challenge")
                self.assertEqual(verify_negative_access_receipt(receipt, **replayed)["outcome"], "REJECTED")
            finally:
                broker.close()
                witness.close()

    def test_externally_retained_anchor_detects_state_and_journal_rollback(self):
        """A state/journal rollback branches away from a later retained anchor."""
        with tempfile.TemporaryDirectory(prefix="stage2-rollback-") as root:
            _sandbox(root)
            state, journal = os.path.join(root, "witness.json"), os.path.join(root, "events.wal")
            broker, witness = self._broker(root, state, journal)
            try:
                first, first_expected = self._receipt(broker, witness, "rollback-first", b"challenge-1")
                first_verified = verify_negative_access_receipt(first, **first_expected)
                self.assertEqual(first_verified["outcome"], "VERIFIED")
                state_after_first = Path(state).read_bytes()
                journal_after_first = Path(journal).read_bytes()
            finally:
                broker.close()
                witness.close()

            broker, witness = self._broker(root, state, journal)
            try:
                later, later_expected = self._receipt(broker, witness, "rollback-later", b"challenge-2")
                later_verified = verify_negative_access_receipt(later, **later_expected)
                self.assertEqual(later_verified["outcome"], "VERIFIED")
                later_anchor = bytes.fromhex(later_verified["witness_state_digest"])
            finally:
                broker.close()
                witness.close()

            # This simulates a privileged local rollback of both stores. It is
            # intentionally detected only because a verifier retained the
            # later anchor elsewhere.
            Path(state).write_bytes(state_after_first)
            Path(journal).write_bytes(journal_after_first)
            with self.assertRaises(JournalError):
                DurableWitness(state, Signer(WITNESS_SEED), expected_state_digest=later_anchor)
            broker, witness = self._broker(root, state, journal)
            try:
                branched, branched_expected = self._receipt(
                    broker, witness, "rollback-branch", b"challenge-branch")
                self.assertEqual(verify_negative_access_receipt(
                    branched, **branched_expected)["outcome"], "VERIFIED")
                rejected = dict(branched_expected, expected_witness_state_digest=later_anchor)
                self.assertEqual(verify_negative_access_receipt(
                    branched, **rejected)["outcome"], "REJECTED")
            finally:
                broker.close()
                witness.close()


class ResourceAliasAdversarialTests(unittest.TestCase):
    def test_symlink_alias_is_committed_under_the_resolved_target(self):
        with tempfile.TemporaryDirectory(prefix="stage2-symlink-") as root:
            _sandbox(root)
            os.symlink("../finance/q3.xlsx", os.path.join(root, "docs", "innocent.xlsx"))
            broker = Broker(root, Signer(), Witness())
            try:
                self.assertEqual(broker.read("docs/innocent.xlsx"), b"REVENUE ...")
                broker.seal()
                with self.assertRaises(NotEmpty):
                    broker.prove_empty(*subtree("finance"), 0, 0)
            finally:
                broker.close()

    def test_hard_link_alias_is_refused_before_bytes_or_truncation(self):
        with tempfile.TemporaryDirectory(prefix="stage2-hardlink-") as root:
            _sandbox(root)
            target = Path(root, "finance", "q3.xlsx")
            alias = Path(root, "docs", "q3-alias.xlsx")
            os.link(target, alias)
            broker = Broker(root, Signer(), Witness())
            try:
                with self.assertRaisesRegex(PermissionError, "hard-link"):
                    broker.read("docs/q3-alias.xlsx")
                with self.assertRaisesRegex(PermissionError, "hard-link"):
                    broker.write("docs/q3-alias.xlsx", b"synthetic overwrite")
                self.assertEqual(target.read_bytes(), b"REVENUE ...")
                broker.seal()
                with self.assertRaises(NotEmpty):
                    broker.prove_empty(b"docs/q3-alias.xlsx", b"docs/q3-alias.xlsx\0", 0, 0)
            finally:
                broker.close()


class LinuxConfinementAdversarialTests(unittest.TestCase):
    def test_missing_launcher_is_explicitly_unsupported(self):
        with patch("wolfalibi.isolation.sys.platform", "linux"), \
             patch("wolfalibi.isolation.shutil.which", return_value=None):
            status = isolation_status()
        self.assertEqual(status["outcome"], "UNSUPPORTED")
        self.assertEqual(status["assurance"], ASSURANCE_BLOCKED)
        self.assertIn("not installed", status["reason"])

    def test_synthetic_probe_reports_only_narrow_observations(self):
        with tempfile.TemporaryDirectory(prefix="stage2-isolation-work-") as work, \
             tempfile.TemporaryDirectory(prefix="stage2-isolation-marker-") as protected:
            marker = Path(protected, "synthetic-marker.txt")
            marker.write_text("synthetic marker")
            try:
                manifest = confinement_manifest(work)
            except ValueError:
                manifest = None
            if manifest is not None:
                self.assertEqual(manifest["broker_ipc"], "ABSENT")
                self.assertEqual(manifest["receipt_assurance"], ASSURANCE_BLOCKED)
                self.assertEqual(len(policy_digest(manifest)), 64)
            direct = run_isolated(["/usr/bin/test", "!", "-e", str(marker)], work)
            self.assertEqual(direct["assurance"], ASSURANCE_BLOCKED)
            self.assertIn(direct["outcome"], {"COMPLETED", "UNSUPPORTED", "BLOCKED"})
            if "manifest_digest" in direct:
                self.assertEqual(boundary_descriptor(direct)["assurance"], ASSURANCE_BLOCKED)
            probe = probe_confinement(work, marker)
            self.assertEqual(probe["assurance"], ASSURANCE_BLOCKED)
            self.assertIn(probe["outcome"], {"DEMONSTRATED", "UNSUPPORTED", "BLOCKED"})
            if probe["outcome"] == "DEMONSTRATED":
                self.assertTrue(probe["observed"]["synthetic_host_marker_absent"])
                self.assertTrue(probe["observed"]["synthetic_parent_fd_not_inherited"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
