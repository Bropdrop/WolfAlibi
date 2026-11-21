"""Synthetic controls for exact grant scope and input snapshot semantics."""

from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wolfalibi import sector_profiles as sector


class SectorGrantScopeTests(unittest.TestCase):
    def setUp(self):
        self.owner = sector.fake_owner()
        self.owner_pub = sector.public_key(self.owner)
        self.agent_pub = sector.public_key(sector.fake_owner()).hex()
        self.now = 1_000

    def _request(self, action):
        resources = {
            "edu.tutor.respond": ("synthetic-lessons", {"lesson": "math"}),
            "edu.student_record.read": (
                "synthetic-student-records", {"student_ref": "student-A", "purpose": "approved-support"},
            ),
            "fin.balance.read": ("synthetic-balances", {"account_ref": "account-A"}),
            "fin.payment.initiate": (
                "synthetic-payment-intents",
                {"account_ref": "account-A", "payee_ref": "payee-A", "amount_minor": 42, "currency": "CAD"},
            ),
        }
        resource, args = resources[action]
        profile = "EDU_STUDENT_DATA_READ_V0" if action.startswith("edu.") else "FIN_PAYMENT_INITIATION_V0"
        return {
            "profile": profile, "action": action, "tenant": "synthetic-tenant", "resource": resource,
            "agent_pub": self.agent_pub, "request_id": "synthetic-request", "args": args,
        }

    def _make(self, request, *, role="account_owner", start=None, end=None, owner=None):
        return sector.make_grant(self.owner if owner is None else owner, request, grant_id="signed-grant",
                                 role=role, not_before=self.now if start is None else start,
                                 expires_at=self.now + 30 if end is None else end)

    def _verify(self, grant, request, *, now=None, expected_owner=None):
        return sector.verify_grant(grant, request,
                                   expected_owner_pub=self.owner_pub if expected_owner is None else expected_owner,
                                   now=self.now if now is None else now)

    def _signed_fixture(self, request, *, role, start, end):
        payload = {
            "type": "QUORVANE_SECTOR_LAB_GRANT_V1", "audience": sector.AUDIENCE,
            "grant_id": "signed-fixture", "scope_sha256": sector._hash(request),
            "role": role, "not_before": start, "expires_at": end,
        }
        return {"payload": payload, "signature": self.owner.sign(sector.GRANT_DOMAIN + sector._canon(payload)).hex()}

    def test_request_arguments_are_snapshotted_before_other_validation(self):
        request = self._request("edu.student_record.read")
        stable = deepcopy(request)
        original = sector._key

        def validate_key(value):
            request["args"]["student_ref"] = "other-synthetic-student"
            request["tenant"] = "other-synthetic-tenant"
            return original(value)

        with patch.object(sector, "_key", side_effect=validate_key):
            result = sector.validate_request(request)
        self.assertNotEqual(request, stable)
        self.assertEqual(result, stable)

    def test_verifier_returns_id_from_authenticated_payload_snapshot(self):
        request = self._request("fin.payment.initiate")
        grant = self._make(request)
        original_public = sector.Ed25519PublicKey.from_public_bytes(self.owner_pub)

        def verify_then_update_caller(signature, message):
            original_public.verify(signature, message)
            grant["payload"]["grant_id"] = "subsequent-caller-edit"
            grant["signature"] = "00" * 64

        verifier = SimpleNamespace(verify=verify_then_update_caller)
        with patch.object(sector, "Ed25519PublicKey", SimpleNamespace(from_public_bytes=lambda _: verifier)):
            self.assertEqual(self._verify(grant, request), "signed-grant")
        self.assertEqual(grant["payload"]["grant_id"], "subsequent-caller-edit")

    def test_tutor_is_not_a_grant_scope(self):
        request = self._request("edu.tutor.respond")
        with self.assertRaisesRegex(sector.ProfileError, "does not accept an owner grant"):
            self._make(request, role=None)
        signed = self._signed_fixture(request, role=None, start=self.now, end=self.now + 20)
        with self.assertRaisesRegex(sector.ProfileError, "does not accept an owner grant"):
            self._verify(signed, request)

    def test_correctly_signed_grant_cannot_make_an_invalid_request_valid(self):
        request = self._request("fin.balance.read")
        request["resource"] = "synthetic-payment-intents"
        signed = self._signed_fixture(request, role="account_owner", start=self.now, end=self.now + 20)
        with self.assertRaisesRegex(sector.ProfileError, "balance scope"):
            self._verify(signed, request)

    def test_education_and_finance_grants_bind_exact_scope(self):
        student = self._request("edu.student_record.read")
        payment = self._request("fin.payment.initiate")
        cases = (
            (student, "school_officer", [
                dict(student, request_id="another-request"),
                dict(student, tenant="different-school"),
                dict(student, args=dict(student["args"], student_ref="student-B")),
                dict(student, args=dict(student["args"], purpose="other-purpose")),
            ]),
            (payment, "account_owner", [
                self._request("fin.balance.read"),
                dict(payment, agent_pub=sector.public_key(sector.fake_owner()).hex()),
                dict(payment, args=dict(payment["args"], account_ref="account-B")),
                dict(payment, args=dict(payment["args"], payee_ref="payee-B")),
                dict(payment, args=dict(payment["args"], amount_minor=43)),
            ]),
        )
        for original, role, replacements in cases:
            grant = self._make(original, role=role)
            self.assertEqual(self._verify(grant, original), "signed-grant")
            for changed in replacements:
                with self.subTest(action=original["action"], changed=changed):
                    with self.assertRaises(sector.ProfileError):
                        self._verify(grant, changed)

    def test_grant_validity_is_bounded_and_half_open(self):
        request = self._request("fin.balance.read")
        grant = self._make(request, start=self.now, end=self.now + 300)
        for now in (self.now, self.now + 299):
            self.assertEqual(self._verify(grant, request, now=now), "signed-grant")
        for now in (self.now - 1, self.now + 300, -1, True, 2**63):
            with self.subTest(now=now), self.assertRaises(sector.ProfileError):
                self._verify(grant, request, now=now)
        for start, end in ((self.now, self.now + 301), (-1, 1), (2**63 - 1, 2**63), (True, 2)):
            with self.subTest(start=start, end=end):
                with self.assertRaises(sector.ProfileError):
                    self._make(request, start=start, end=end)
                signed = self._signed_fixture(request, role="account_owner", start=start, end=end)
                with self.assertRaises(sector.ProfileError):
                    self._verify(signed, request, now=0 if start == -1 else start)

    def test_signature_requires_the_pinned_owner_and_canonical_hex(self):
        request = self._request("fin.balance.read")
        grant = self._make(request)
        foreign = sector.fake_owner()
        for candidate, owner in (
                (self._make(request, owner=foreign), self.owner_pub),
                (grant, sector.public_key(foreign)),
                (dict(grant, signature=grant["signature"].upper()), self.owner_pub),
                (dict(grant, signature=grant["signature"] + "00"), self.owner_pub),
        ):
            with self.assertRaises(sector.ProfileError):
                self._verify(candidate, request, expected_owner=owner)

    def test_public_profile_description_cannot_change_enforced_routes(self):
        request = self._request("edu.student_record.read")
        request["profile"] = "FIN_PAYMENT_INITIATION_V0"
        with patch.dict(sector.PROFILES, {"FIN_PAYMENT_INITIATION_V0": (request["action"],)}):
            with self.assertRaisesRegex(sector.ProfileError, "outside the declared sector profile"):
                sector.validate_request(request)


if __name__ == "__main__":
    unittest.main()
