"""Process-local state qualification for the synthetic sector gate."""

import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from unittest.mock import patch

from wolfalibi import sector_profiles as sector


class SectorGateStateTests(unittest.TestCase):
    def setUp(self):
        self.owner = sector.fake_owner()
        self.agent_pub = sector.public_key(sector.fake_owner())
        self.gate = sector.SyntheticSectorGate(
            owner_pub=sector.public_key(self.owner), agent_pub=self.agent_pub,
            tenant="synthetic-bank",
        )

    def payment(self, amount=4500):
        return {
            "profile": "FIN_PAYMENT_INITIATION_V0",
            "action": "fin.payment.initiate",
            "tenant": "synthetic-bank",
            "resource": "synthetic-payment-intents",
            "agent_pub": self.agent_pub.hex(),
            "request_id": "payment-1",
            "args": {
                "account_ref": "account-A", "payee_ref": "payee-A",
                "amount_minor": amount, "currency": "CAD",
            },
        }

    def grant(self, payment, *, grant_id="grant-1", expires_at=1060):
        return sector.make_grant(
            self.owner, payment, grant_id=grant_id, role="account_owner",
            not_before=1000, expires_at=expires_at,
        )

    def concurrent_payments(self, *payments):
        barrier = Barrier(len(payments))
        verify = sector.verify_grant
        grants = [self.grant(payment, grant_id=f"grant-{index}")
                  for index, payment in enumerate(payments)]

        def verify_then_wait(*args, **kwargs):
            grant_id = verify(*args, **kwargs)
            barrier.wait(timeout=5)
            return grant_id

        with patch.object(sector, "verify_grant", side_effect=verify_then_wait):
            with ThreadPoolExecutor(max_workers=len(payments)) as pool:
                evaluations = [
                    pool.submit(self.gate.evaluate, payment, grant=grant, now=1000)
                    for payment, grant in zip(payments, grants)
                ]
                return [work.result(timeout=5) for work in evaluations]

    def test_concurrent_identical_requests_create_one_intent(self):
        responses = self.concurrent_payments(self.payment(), self.payment())

        self.assertEqual(len(self.gate.intents), 1)
        self.assertCountEqual(
            [response["reason"] for response in responses],
            ["SIGNED_SCOPE_CURRENT", "HISTORICAL_INTENT_ONLY"],
        )
        self.assertCountEqual([response["repeat"] for response in responses], [False, True])

    def test_concurrent_conflicting_requests_cannot_replace_winner(self):
        responses = self.concurrent_payments(self.payment(), self.payment(amount=9000))

        self.assertCountEqual(
            [response["reason"] for response in responses],
            ["SIGNED_SCOPE_CURRENT", "IDEMPOTENCY_KEY_CONFLICT"],
        )
        winner = next(index for index, response in enumerate(responses)
                      if response["outcome"] == "ALLOWED_SYNTHETIC")
        self.assertEqual(len(self.gate.intents), 1)
        self.assertEqual(self.gate.intents["payment-1"][1], f"grant-{winner}")

    def test_revocation_completed_during_verification_blocks_intent(self):
        payment = self.payment()
        grant = self.grant(payment)
        verify = sector.verify_grant
        verified = Event()
        resume = Event()

        def verify_then_wait(*args, **kwargs):
            grant_id = verify(*args, **kwargs)
            verified.set()
            if not resume.wait(timeout=5):
                raise AssertionError("verification did not resume")
            return grant_id

        with patch.object(sector, "verify_grant", side_effect=verify_then_wait):
            with ThreadPoolExecutor(max_workers=2) as pool:
                attempt = pool.submit(self.gate.evaluate, payment, grant=grant, now=1000)
                try:
                    self.assertTrue(verified.wait(timeout=5))
                    pool.submit(self.gate.revoke, "grant-1").result(timeout=5)
                finally:
                    resume.set()
                result = attempt.result(timeout=5)

        self.assertEqual(result["reason"], "OWNER_GRANT_REVOKED")
        self.assertEqual(self.gate.intents, {})

    def test_older_inflight_sample_cannot_admit_after_expiry_observed(self):
        payment = self.payment()
        grant = self.grant(payment, expires_at=1001)
        verify = sector.verify_grant
        verified = Event()
        resume = Event()

        def pause_valid_verification(*args, **kwargs):
            grant_id = verify(*args, **kwargs)
            verified.set()
            if not resume.wait(timeout=5):
                raise AssertionError("verification did not resume")
            return grant_id

        with patch.object(sector, "verify_grant", side_effect=pause_valid_verification):
            with ThreadPoolExecutor(max_workers=2) as pool:
                early = pool.submit(self.gate.evaluate, payment, grant=grant, now=1000)
                try:
                    self.assertTrue(verified.wait(timeout=5))
                    late = pool.submit(self.gate.evaluate, payment, grant=grant, now=1001)
                    self.assertEqual(late.result(timeout=5)["outcome"], "DENIED")
                finally:
                    resume.set()
                result = early.result(timeout=5)

        self.assertEqual(result["reason"], "TRUSTED_TIME_REGRESSION")
        self.assertEqual(self.gate.intents, {})

    def test_intent_and_revocation_snapshots_cannot_change_policy_state(self):
        payment = self.payment()
        grant = self.grant(payment)
        self.gate.evaluate(payment, grant=grant, now=1000)
        ledger = self.gate.intents
        ledger.clear()

        repeat = self.gate.evaluate(payment, grant=grant, now=1000)
        self.assertEqual(repeat["reason"], "HISTORICAL_INTENT_ONLY")
        self.assertEqual(len(self.gate.intents), 1)

        self.gate.revoke("grant-1")
        revoked_snapshot = set(self.gate.revoked_grants)
        revoked_snapshot.clear()
        for name, value in (
            ("agent_pub", sector.public_key(sector.fake_owner()).hex()),
            ("owner_pub", sector.public_key(sector.fake_owner())),
            ("tenant", "other-tenant"),
            ("revoked_grants", revoked_snapshot),
            ("intents", ledger),
        ):
            with self.subTest(attribute=name), self.assertRaises(AttributeError):
                setattr(self.gate, name, value)
        result = self.gate.evaluate(payment, grant=grant, now=1000)
        self.assertEqual(result["reason"], "OWNER_GRANT_REVOKED")

    def test_historical_intent_requires_current_grant_and_time(self):
        payment = self.payment()
        grant = self.grant(payment, expires_at=1001)
        self.gate.evaluate(payment, grant=grant, now=1000)
        original = self.gate.intents

        expired = self.gate.evaluate(payment, grant=grant, now=1001)
        replay = self.gate.evaluate(payment, grant=grant, now=1000)
        renewed = self.gate.evaluate(
            payment, grant=self.grant(payment, grant_id="renewal"), now=1001,
        )
        self.assertEqual(expired["outcome"], "DENIED")
        self.assertFalse(expired["repeat"])
        self.assertEqual(replay["reason"], "TRUSTED_TIME_REGRESSION")
        self.assertEqual(renewed["reason"], "HISTORICAL_INTENT_ONLY")
        self.assertTrue(renewed["repeat"])
        self.assertEqual(self.gate.intents, original)

    def test_supplied_settlement_claim_does_not_change_pending_intent(self):
        payment = self.payment()
        grant = self.grant(payment)
        self.gate.evaluate(payment, grant=grant, now=1000)
        original = self.gate.intents
        candidates = (
            dict(payment, action="fin.payment.settle"),
            dict(payment, args=dict(payment["args"], settlement="SETTLED")),
        )
        for request in candidates:
            with self.subTest(action=request["action"]):
                result = self.gate.evaluate(request, grant=grant, now=1000)
                self.assertEqual(result["reason"], "INVALID_OR_OUT_OF_SCOPE_REQUEST")
                self.assertEqual(result["effect"], "NONE")
        repeat = self.gate.evaluate(payment, grant=grant, now=1000)
        self.assertEqual(repeat["effect"], "PENDING_EXTERNAL_SETTLEMENT")
        self.assertEqual(self.gate.intents, original)


if __name__ == "__main__":
    unittest.main()
