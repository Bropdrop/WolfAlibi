"""Synthetic adversarial policy tests; no network, records, or payment effects."""
import copy
import unittest

from wolfalibi.sector_profiles import (
    SyntheticSectorGate, fake_owner, public_key, make_grant,
    validate_request, ProfileError,
)


class SectorProfilesTests(unittest.TestCase):
    def setUp(self):
        self.owner = fake_owner()
        self.agent = fake_owner()
        self.owner_pub = public_key(self.owner)
        self.agent_pub = public_key(self.agent)
        self.gate = SyntheticSectorGate(owner_pub=self.owner_pub, agent_pub=self.agent_pub, tenant="school-01")
        self.now = 1000

    def req(self, action, *, request_id="req-1", tenant="school-01", **changed):
        profile = "EDU_STUDENT_DATA_READ_V0" if action.startswith("edu.") else "FIN_PAYMENT_INITIATION_V0"
        resources = {"edu.tutor.respond": "synthetic-lessons", "edu.student_record.read": "synthetic-student-records",
                     "fin.balance.read": "synthetic-balances", "fin.payment.initiate": "synthetic-payment-intents"}
        args = {"edu.tutor.respond": {"lesson": "math"},
                "edu.student_record.read": {"student_ref": "student-A", "purpose": "approved-support"},
                "fin.balance.read": {"account_ref": "acct-A"},
                "fin.payment.initiate": {"account_ref": "acct-A", "payee_ref": "payee-A", "amount_minor": 4500, "currency": "CAD"}}
        return dict(profile=profile, action=action, tenant=tenant, resource=resources[action],
                    agent_pub=self.agent_pub.hex(), request_id=request_id, args=args[action], **changed)

    def grant(self, request, *, grant_id="grant-1", role=None, expiry=None):
        role = role or ("school_officer" if request["action"] == "edu.student_record.read" else "account_owner")
        return make_grant(self.owner, request, grant_id=grant_id, role=role,
                          not_before=self.now, expires_at=expiry or self.now+60)

    def test_tutor_allowed_without_sensitive_record_grant(self):
        value = self.gate.evaluate(self.req("edu.tutor.respond"), now=self.now)
        self.assertEqual(value["outcome"], "ALLOWED_SYNTHETIC")
        self.assertEqual(value["effect"], "SYNTHETIC_RESPONSE")

    def test_student_record_denied_without_owner_grant(self):
        self.assertEqual(self.gate.evaluate(self.req("edu.student_record.read"), now=self.now)["outcome"], "DENIED")

    def test_student_record_accepted_only_under_exact_school_grant(self):
        request = self.req("edu.student_record.read")
        value = self.gate.evaluate(request, grant=self.grant(request), now=self.now)
        self.assertEqual(value["effect"], "SYNTHETIC_READ")
        self.assertEqual(value["certification"], "NOT_ISSUED")

    def test_tutor_request_cannot_be_retargeted_to_student_record_route(self):
        request = self.req("edu.tutor.respond")
        request["resource"] = "synthetic-student-records"
        self.assertEqual(self.gate.evaluate(request, now=self.now)["outcome"], "DENIED")

    def test_teacher_grant_cannot_be_reused_for_other_student(self):
        a = self.req("edu.student_record.read")
        b = copy.deepcopy(a); b["args"]["student_ref"] = "student-B"
        self.assertEqual(self.gate.evaluate(b, grant=self.grant(a), now=self.now)["outcome"], "DENIED")

    def test_teacher_grant_cannot_be_reused_for_different_tenant(self):
        a = self.req("edu.student_record.read")
        b = copy.deepcopy(a); b["tenant"] = "other-school"
        self.assertEqual(self.gate.evaluate(b, grant=self.grant(a), now=self.now)["outcome"], "DENIED")

    def test_balance_read_requires_scope_specific_grant(self):
        request = self.req("fin.balance.read")
        self.assertEqual(self.gate.evaluate(request, now=self.now)["outcome"], "DENIED")
        self.assertEqual(self.gate.evaluate(request, grant=self.grant(request), now=self.now)["effect"], "SYNTHETIC_READ")

    def test_balance_grant_cannot_authorize_payment(self):
        balance = self.req("fin.balance.read")
        payment = self.req("fin.payment.initiate")
        self.assertEqual(self.gate.evaluate(payment, grant=self.grant(balance), now=self.now)["outcome"], "DENIED")
        self.assertEqual(self.gate.intents, {})

    def test_payment_requires_exact_signed_owner_authorization(self):
        payment = self.req("fin.payment.initiate")
        self.assertEqual(self.gate.evaluate(payment, now=self.now)["outcome"], "DENIED")
        value = self.gate.evaluate(payment, grant=self.grant(payment), now=self.now)
        self.assertEqual(value["effect"], "PENDING_EXTERNAL_SETTLEMENT")
        self.assertEqual(len(self.gate.intents), 1)

    def test_payment_is_never_mislabeled_as_settled(self):
        payment = self.req("fin.payment.initiate")
        response = self.gate.evaluate(payment, grant=self.grant(payment), now=self.now)
        self.assertNotIn("SETTLED", str(response))
        self.assertEqual(response["production"], "BLOCKED")

    def test_idempotent_identical_payment_returns_historical_intent(self):
        payment = self.req("fin.payment.initiate")
        grant = self.grant(payment)
        self.gate.evaluate(payment, grant=grant, now=self.now)
        repeat = self.gate.evaluate(payment, grant=grant, now=self.now)
        self.assertTrue(repeat["repeat"])
        self.assertEqual(len(self.gate.intents), 1)

    def test_conflicting_payment_request_id_denied(self):
        a = self.req("fin.payment.initiate")
        self.gate.evaluate(a, grant=self.grant(a), now=self.now)
        b = copy.deepcopy(a); b["args"]["amount_minor"] += 1
        self.assertEqual(self.gate.evaluate(b, grant=self.grant(b,grant_id="grant-2"), now=self.now)["reason"], "IDEMPOTENCY_KEY_CONFLICT")
        self.assertEqual(len(self.gate.intents), 1)

    def test_cross_payee_substitution_rejected(self):
        payment = self.req("fin.payment.initiate")
        substitute = copy.deepcopy(payment); substitute["args"]["payee_ref"] = "payee-B"
        self.assertEqual(self.gate.evaluate(substitute, grant=self.grant(payment), now=self.now)["outcome"], "DENIED")

    def test_expired_grant_denied(self):
        payment = self.req("fin.payment.initiate")
        grant = self.grant(payment, expiry=self.now+1)
        self.assertEqual(self.gate.evaluate(payment, grant=grant, now=self.now+1)["outcome"], "DENIED")

    def test_revoked_grant_denied(self):
        payment = self.req("fin.payment.initiate")
        grant = self.grant(payment)
        self.gate.revoke("grant-1")
        self.assertEqual(self.gate.evaluate(payment, grant=grant, now=self.now)["reason"], "OWNER_GRANT_REVOKED")

    def test_wrong_owner_signature_denied(self):
        payment = self.req("fin.payment.initiate")
        other = fake_owner()
        bad = make_grant(other, payment, grant_id="grant-2", role="account_owner", not_before=1000, expires_at=1020)
        self.assertEqual(self.gate.evaluate(payment, grant=bad, now=self.now)["outcome"], "DENIED")

    def test_wrong_agent_identity_denied(self):
        payment = self.req("fin.payment.initiate")
        foreign = copy.deepcopy(payment); foreign["agent_pub"] = public_key(fake_owner()).hex()
        self.assertEqual(self.gate.evaluate(foreign, grant=self.grant(foreign), now=self.now)["reason"], "TENANT_OR_AGENT_MISMATCH")

    def test_wrong_currency_and_invalid_amount_rejected(self):
        for amount, currency in ((0, "CAD"), (True, "CAD"), (1000001, "CAD"), (200, "USD")):
            with self.subTest(amount=amount,currency=currency):
                req = self.req("fin.payment.initiate")
                req["args"] = dict(req["args"], amount_minor=amount,currency=currency)
                self.assertEqual(self.gate.evaluate(req, now=self.now)["outcome"], "DENIED")

    def test_unknown_action_profile_and_extra_fields_rejected(self):
        req = self.req("edu.tutor.respond")
        for changed in ({"action": "edu.student_record.modify"}, {"profile": "FIN_PAYMENT_INITIATION_V0"}, {"secret": "hidden"}):
            with self.subTest(changed=changed):
                candidate = {**req, **changed}
                self.assertEqual(self.gate.evaluate(candidate, now=self.now)["outcome"], "DENIED")

    def test_unsigned_forged_role_is_rejected(self):
        payment = self.req("fin.payment.initiate")
        grant = self.grant(payment)
        grant["payload"]["role"] = "school_officer"
        self.assertEqual(self.gate.evaluate(payment, grant=grant, now=self.now)["outcome"], "DENIED")

    def test_bad_signature_and_extra_grant_field_rejected(self):
        payment = self.req("fin.payment.initiate")
        grant = self.grant(payment)
        grant["signature"] = "00" * 64
        self.assertEqual(self.gate.evaluate(payment, grant=grant, now=self.now)["outcome"], "DENIED")
        grant = self.grant(payment); grant["payload"]["certified"] = True
        self.assertEqual(self.gate.evaluate(payment, grant=grant, now=self.now)["outcome"], "DENIED")

    def test_no_infrastructure_io_or_certification_in_any_report(self):
        payment = self.req("fin.payment.initiate")
        result = self.gate.evaluate(payment, grant=self.grant(payment), now=self.now)
        self.assertEqual(result["assurance"], "SIMULATED_POLICY_ONLY")
        self.assertEqual(result["qualification"], "NOT_ASSESSED")
        self.assertEqual(result["certification"], "NOT_ISSUED")
        self.assertEqual(result["confinement"], "BLOCKED")
        self.assertNotIn("data", result)

    def test_invalid_clock_blocks(self):
        self.assertEqual(self.gate.evaluate(self.req("edu.tutor.respond"), now=1.5)["outcome"], "BLOCKED")

    def test_invalid_grant_role_refused_at_issuance(self):
        with self.assertRaises(ProfileError):
            self.grant(self.req("fin.payment.initiate"), role="school_officer")


if __name__ == "__main__":
    unittest.main(verbosity=2)
