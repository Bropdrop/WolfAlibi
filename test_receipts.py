"""Receipt and durable-witness regressions using synthetic local resources."""
import copy
import os
import tempfile
import unittest
from unittest.mock import patch

from alibi import (DOM_B, DOM_RB, EMPTY, DurableWitness, H, NotEmpty, Signer,
                   Witness, WitnessRefused, Broker, JournalError, canon)
from wolfalibi.receipts import (EvidenceRun, RECEIPT_TYPE, ReceiptError,
                                verify_negative_access_receipt)
from alibi import _sandbox, subtree


BROKER_SEED = bytes(range(32))
WITNESS_SEED = bytes(range(32, 64))


class DurableWitnessTests(unittest.TestCase):
    def test_live_state_lease_blocks_second_local_owner(self):
        with tempfile.TemporaryDirectory(prefix="receipt-witness-lease-") as root:
            state = os.path.join(root, "witness-state.json")
            first = DurableWitness(state, Signer(WITNESS_SEED))
            try:
                with self.assertRaises(JournalError):
                    DurableWitness(state, Signer(WITNESS_SEED))
            finally:
                first.close()
            replacement = DurableWitness(state, Signer(WITNESS_SEED))
            replacement.close()

    def test_persisted_head_refuses_a_restart_fork(self):
        with tempfile.TemporaryDirectory(prefix="receipt-witness-") as root:
            _sandbox(root)
            state = os.path.join(root, "witness-state.json")
            broker_signer = Signer(BROKER_SEED)
            witness = DurableWitness(state, Signer(WITNESS_SEED))
            broker = Broker(root, broker_signer, witness)
            broker.read("docs/notes.txt")
            broker.seal()
            broker.close()
            witness.close()

            restarted = DurableWitness(state, Signer(WITNESS_SEED))
            try:
                clean = {
                    "v": 1, "broker": broker_signer.pub.hex(), "epoch": 0,
                    "prev": "00" * 32, "size": 0, "root": EMPTY.hex(),
                    "events": 0, "seq_lo": 1, "seq_hi": 0,
                }
                signature = broker_signer.sign(DOM_B, canon(clean))
                with self.assertRaises(WitnessRefused):
                    restarted.cosign(clean, signature, [])
            finally:
                restarted.close()

    def test_state_is_persisted_before_checkpoint_signature_escapes(self):
        with tempfile.TemporaryDirectory(prefix="receipt-witness-fault-") as root:
            _sandbox(root)
            witness = DurableWitness(os.path.join(root, "state.json"), Signer(WITNESS_SEED))
            broker = Broker(root, Signer(BROKER_SEED), witness)
            try:
                broker.read("docs/notes.txt")
                with patch("alibi.os.replace", side_effect=OSError("synthetic rename failure")):
                    with self.assertRaises(OSError):
                        broker.seal()
                self.assertEqual(witness.heads, {})
            finally:
                broker.close()
                witness.close()


class ReceiptTests(unittest.TestCase):
    def test_receipts_refuse_missing_durable_prerequisites(self):
        with tempfile.TemporaryDirectory(prefix="receipt-prereq-") as root:
            _sandbox(root)
            durable = DurableWitness(os.path.join(root, "witness.json"), Signer(WITNESS_SEED))
            memory_broker = Broker(root, Signer(BROKER_SEED), durable)
            try:
                with self.assertRaises(ReceiptError):
                    EvidenceRun(memory_broker, run_id="no-journal", challenge=b"challenge",
                                policy={}, code_digest=H(b"code"))
            finally:
                memory_broker.close()
                durable.close()

            journal_broker = Broker(root, Signer(BROKER_SEED), Witness(),
                                    journal=os.path.join(root, "events.wal"))
            try:
                with self.assertRaises(ReceiptError):
                    EvidenceRun(journal_broker, run_id="no-durable-witness", challenge=b"challenge",
                                policy={}, code_digest=H(b"code"))
            finally:
                journal_broker.close()

    def _receipt(self):
        root = tempfile.TemporaryDirectory(prefix="receipt-run-")
        _sandbox(root.name)
        broker_signer = Signer(BROKER_SEED)
        witness = DurableWitness(os.path.join(root.name, "witness.json"), Signer(WITNESS_SEED))
        broker = Broker(root.name, broker_signer, witness,
                        journal=os.path.join(root.name, "events.wal"))
        policy = {
            "actor": "synthetic-test-agent",
            "resource_model": "brokered-filesystem-v1",
            "effect": "negative-access-receipt",
        }
        challenge = b"fresh-synthetic-challenge-001"
        code_digest = H(b"synthetic-agent-artifact")
        run = EvidenceRun(broker, run_id="synthetic-run-001", challenge=challenge,
                          policy=policy, code_digest=code_digest)
        run.begin()
        broker.read("docs/notes.txt")
        receipt = run.finish_negative(*subtree("finance"))
        return root, broker, witness, receipt, policy, challenge, code_digest

    def test_roundtrip_requires_all_external_reference_values(self):
        root, broker, witness, receipt, policy, challenge, code_digest = self._receipt()
        self.addCleanup(root.cleanup)
        self.addCleanup(broker.close)
        self.addCleanup(witness.close)
        self.assertEqual(receipt["payload"]["type"], RECEIPT_TYPE)
        expected = dict(
            broker_pub=broker.signer.pub,
            witness_pub=witness.signer.pub,
            challenge=challenge,
            policy=policy,
            lo=subtree("finance")[0], hi=subtree("finance")[1],
            run_id="synthetic-run-001", code_digest=code_digest, epochs=(1, 1),
        )
        verified = verify_negative_access_receipt(receipt, **expected)
        self.assertEqual(verified["outcome"], "VERIFIED")
        self.assertEqual(verified["assurance"], "BROKER_ONLY")

        wrong_challenge = verify_negative_access_receipt(
            receipt, **{**expected, "challenge": b"replayed-challenge"})
        self.assertEqual(wrong_challenge["outcome"], "REJECTED")
        wrong_policy = verify_negative_access_receipt(
            receipt, **{**expected, "policy": {"actor": "substituted"}})
        self.assertEqual(wrong_policy["outcome"], "REJECTED")
        wrong_epoch = verify_negative_access_receipt(
            receipt, **{**expected, "epochs": (0, 1)})
        self.assertEqual(wrong_epoch["outcome"], "REJECTED")
        tampered = copy.deepcopy(receipt)
        tampered["payload"]["interval"]["end_epoch"] = 2
        self.assertEqual(verify_negative_access_receipt(tampered, **expected)["outcome"], "REJECTED")

        # Even a newly signed receipt cannot substitute its signed start
        # boundary with the run's end checkpoint: the offline verifier checks
        # the boundary signature, epoch, hash, and sequence linkage itself.
        spliced = copy.deepcopy(receipt)
        end_record = receipt["payload"]["evidence"]["epochs"][0]
        spliced["payload"]["start_boundary"] = {
            "cp": end_record["cp"], "sig": end_record["sig"], "wsig": end_record["wsig"],
        }
        broker_signature = broker.signer.sign(DOM_RB, canon(spliced["payload"]))
        spliced["broker_signature"] = broker_signature.hex()
        spliced["witness_signature"] = witness.cosign_receipt(
            spliced["payload"], broker_signature).hex()
        self.assertEqual(verify_negative_access_receipt(spliced, **expected)["outcome"], "REJECTED")
        self.assertIn(H(canon(receipt["payload"])).hex(), witness.receipt_hashes)

    def test_access_in_the_protected_range_refuses_receipt_creation(self):
        with tempfile.TemporaryDirectory(prefix="receipt-not-empty-") as root:
            _sandbox(root)
            witness = DurableWitness(os.path.join(root, "witness.json"), Signer(WITNESS_SEED))
            broker = Broker(root, Signer(BROKER_SEED), witness,
                            journal=os.path.join(root, "events.wal"))
            try:
                run = EvidenceRun(broker, run_id="synthetic-run-002", challenge=b"another-challenge",
                                  policy={"actor": "synthetic"}, code_digest=H(b"code"))
                run.begin()
                broker.read("finance/q3.xlsx")
                with self.assertRaises(NotEmpty):
                    run.finish_negative(*subtree("finance"))
            finally:
                broker.close()
                witness.close()

    def test_v1_empty_policy_remains_verifiable_for_compatibility(self):
        with tempfile.TemporaryDirectory(prefix="receipt-empty-policy-") as root:
            _sandbox(root)
            witness = DurableWitness(os.path.join(root, "witness.json"), Signer(WITNESS_SEED))
            broker = Broker(root, Signer(BROKER_SEED), witness,
                            journal=os.path.join(root, "events.wal"))
            try:
                run = EvidenceRun(broker, run_id="empty-policy", challenge=b"empty-policy-challenge",
                                  policy={}, code_digest=H(b"empty-policy-code"))
                run.begin()
                broker.read("docs/notes.txt")
                receipt = run.finish_negative(*subtree("finance"))
                result = verify_negative_access_receipt(
                    receipt, broker_pub=broker.signer.pub, witness_pub=witness.signer.pub,
                    challenge=b"empty-policy-challenge", policy={}, lo=subtree("finance")[0],
                    hi=subtree("finance")[1], run_id="empty-policy",
                    code_digest=H(b"empty-policy-code"), epochs=(1, 1))
                self.assertEqual(result["outcome"], "VERIFIED")
            finally:
                broker.close()
                witness.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
