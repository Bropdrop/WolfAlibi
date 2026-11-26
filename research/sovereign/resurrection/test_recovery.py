import unittest
from research.sovereign.resurrection.verify import (
    PHASES,
    transition,
    retained,
    revocations,
)
from research.wt_swarm.review import Mismatch
from shirudo_adapter.model import digest


class ColdRecovery(unittest.TestCase):
    def activate(self, steps=PHASES, boot="fresh", epoch=8, state="live"):
        transition(
            steps,
            dict(boot="fresh", epoch=8, snapshot=digest({})),
            boot,
            epoch,
            {},
            "live",
            state,
        )

    def test_complete(self):
        self.activate()

    def test_skipped_verification(self):
        with self.assertRaisesRegex(Mismatch, "RECONCILIATION_REQUIRED"):
            self.activate(steps=["ACTIVE"])

    def test_old_epoch(self):
        with self.assertRaisesRegex(Mismatch, "STALE_EPOCH"):
            self.activate(epoch=7)

    def test_old_incarnation(self):
        with self.assertRaisesRegex(Mismatch, "INCARNATION"):
            self.activate(boot="old")

    def test_restored_volume(self):
        with self.assertRaisesRegex(Mismatch, "RESTORED_STATE"):
            self.activate(state="old")

    def test_unobserved_intent(self):
        with self.assertRaisesRegex(Mismatch, "FALSE_OUTCOME"):
            retained(dict(state="NOT_COMMITTED"), "UNRESOLVED", None)

    def test_history(self):
        with self.assertRaisesRegex(Mismatch, "ORIGINAL_RECEIPT"):
            retained(dict(state="COMMITTED", receipt="other"), "COMMITTED", "original")

    def test_lost_revocation(self):
        with self.assertRaisesRegex(Mismatch, "OFFLINE_REVOCATION"):
            revocations({"revoked_grants": []}, {"revoked"})
