"""Portable disclosure checks against separately supplied synthetic trust pins."""

from copy import deepcopy
import unittest

from alibi import Signer, canon
from wolfalibi import finance_records as finance, history_records as history
from wolfalibi.history_settlement import SYNTHETIC_SETTLED, sign_settlement, sign_source, verify_settlement
from wolfalibi.history_verify import DISCLOSURE_DOMAIN, disclosure_payload, verify_history


class HistoryVerificationTests(unittest.TestCase):
    def setUp(self):
        self.owner, self.supervisor, self.witness, self.target, self.caller = (Signer() for _ in range(5))
        self.discloser, self.auditor = Signer(), Signer()
        self.challenge = "bb" * 32
        self.finance_scope = {
            "tenant": finance.TENANT, "account": finance.ACCOUNT, "operation": finance.OPERATION,
            "target_pub": self.target.pub.hex(), "request_id": "fixture-intent-a", "currency": finance.CURRENCY,
            "payee": "fictional-supplier", "amount_minor": 4500, "policy_epoch": 1, "run_id": "original-run",
            "challenge": "aa" * 32, "caller_pub": self.caller.pub.hex(),
        }
        peer = {
            "pid": 123, "uid": 1000, "gid": 1000, "start_ticks": 42,
            "boot_id": "e71b9418-275a-4617-9364-e12b208ddd43", "exe_sha256": "11" * 32,
            "argv_sha256": "22" * 32, "source_sha256": "33" * 32,
        }
        self.qualification = finance.qualify(self.supervisor, self.witness, self.finance_scope, peer, 1000, 1030)
        finance_pins = {
            "scope": self.finance_scope, "target_pub": self.target.pub.hex(), "owner_pub": self.owner.pub.hex(),
            "supervisor_pub": self.supervisor.pub.hex(), "witness_pub": self.witness.pub.hex(), "peer": peer,
            "witness_head": finance.digest(self.qualification),
        }
        self.expected = {
            "finance": finance_pins, "history_pub": self.discloser.pub.hex(), "auditor_pub": self.auditor.pub.hex(),
            "anchor_sha256": "cc" * 32, "challenge": self.challenge,
        }
        original = self.make_original(self.finance_scope)
        request = self.make_request(self.finance_scope, self.auditor, self.challenge)
        self.evidence = {"original": original, "request": request, "attestation": self.attest(original, request)}

    def make_original(self, scope):
        grant = finance.owner_grant(self.owner, scope, "finance-origin-grant", 1000, 1040)
        packet = finance.dispatch(self.caller, scope, grant, self.qualification)
        return {"packet": packet, "receipt": finance.receipt(self.target, scope, packet, 1010)}

    def make_request(self, finance_scope, auditor, challenge, *, start=1100, end=1140):
        scope = history.inquiry_scope(finance_scope)
        grant = history.issue_grant(self.owner, scope, auditor.pub, "history-owner-grant", start, end)
        return history.sign_inquiry(auditor, scope, grant, challenge)

    def signed_disclosure(self, payload, signer=None):
        signer = self.discloser if signer is None else signer
        return {"payload": payload, "signature": signer.sign(DISCLOSURE_DOMAIN, canon(payload)).hex()}

    def attest(self, original, request, *, checked_at=1120):
        return self.signed_disclosure(disclosure_payload(
            self.expected["finance"], self.expected["anchor_sha256"], request, original, checked_at,
        ))

    def test_fresh_disclosure_verifies_a_pending_intent_after_original_grant_expiry(self):
        verified = verify_history(self.expected, self.evidence, challenge=self.challenge)
        self.assertEqual(verified["outcome"], "VERIFIED")
        self.assertEqual(verified["verified"], "HISTORICAL_INTENT_DISCLOSURE")
        self.assertEqual(verified["effect"], finance.PENDING)
        self.assertEqual(verified["settlement"], "UNESTABLISHED")
        self.assertEqual(verified["authorized_at"], 1120)
        self.assertEqual(verified["grant_id"], "history-owner-grant")
        self.assertEqual(verified["receipt_sha256"], finance.digest(self.evidence["original"]["receipt"]))
        self.assertEqual(verified["anchor_sha256"], self.expected["anchor_sha256"])
        self.assertEqual(verified["assurance"], "SIMULATED_POLICY_ONLY")

    def test_altered_original_packet_or_receipt_fails_under_a_new_disclosure_signature(self):
        for changed_section in ("packet", "receipt"):
            original = deepcopy(self.evidence["original"])
            if changed_section == "packet":
                original["packet"]["scope"]["amount_minor"] += 1
            else:
                original["receipt"]["signature"] = "00" * 64
            signed = self.attest(original, self.evidence["request"])
            changed = dict(self.evidence, original=original, attestation=signed)
            with self.subTest(changed_section=changed_section), self.assertRaises(ValueError):
                verify_history(self.expected, changed, challenge=self.challenge)

    def test_a_genuine_disclosure_signature_cannot_change_a_bound_reference(self):
        payload = self.evidence["attestation"]["payload"]
        for key in ("anchor_sha256", "original_receipt_sha256", "finance_expectations_sha256", "inquiry_sha256"):
            signed = self.signed_disclosure(dict(payload, **{key: "00" * 32}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_history(self.expected, dict(self.evidence, attestation=signed), challenge=self.challenge)
        replaced_anchor = dict(self.expected, anchor_sha256="dd" * 32)
        with self.assertRaises(ValueError):
            verify_history(replaced_anchor, self.evidence, challenge=self.challenge)

    def test_disclosure_and_finance_signer_pins_and_roles_are_independent(self):
        with self.assertRaises(ValueError):
            verify_history(dict(self.expected, history_pub=Signer().pub.hex()), self.evidence, challenge=self.challenge)
        for role in ("owner_pub", "supervisor_pub", "target_pub", "witness_pub"):
            pins = dict(self.expected["finance"], **{role: Signer().pub.hex()})
            with self.subTest(role=role), self.assertRaises(ValueError):
                verify_history(dict(self.expected, finance=pins), self.evidence, challenge=self.challenge)
        same_role = self.signed_disclosure(self.evidence["attestation"]["payload"], signer=self.target)
        with self.assertRaisesRegex(ValueError, "distinct keys"):
            verify_history(dict(self.expected, history_pub=self.target.pub.hex()),
                           dict(self.evidence, attestation=same_role), challenge=self.challenge)

    def test_owner_approved_replacement_auditor_still_needs_the_external_pin(self):
        other = Signer()
        request = self.make_request(self.finance_scope, other, self.challenge)
        changed = dict(self.evidence, request=request, attestation=self.attest(self.evidence["original"], request))
        with self.assertRaisesRegex(ValueError, "unexpected auditor credential"):
            verify_history(self.expected, changed, challenge=self.challenge)
        pinned = dict(self.expected, auditor_pub=other.pub.hex())
        self.assertEqual(verify_history(pinned, changed, challenge=self.challenge)["outcome"], "VERIFIED")

    def test_replaced_challenge_needs_a_fresh_proof_and_differs_from_the_finance_challenge(self):
        other = "ee" * 32
        with self.assertRaises(ValueError):
            verify_history(self.expected, self.evidence, challenge=other)
        with self.assertRaises(ValueError):
            verify_history(dict(self.expected, challenge=other), self.evidence, challenge=other)
        original_challenge = self.finance_scope["challenge"]
        request = self.make_request(self.finance_scope, self.auditor, original_challenge)
        changed = dict(self.evidence, request=request, attestation=self.attest(self.evidence["original"], request))
        with self.assertRaisesRegex(ValueError, "own challenge"):
            verify_history(dict(self.expected, challenge=original_challenge), changed, challenge=original_challenge)

    def test_a_second_genuine_intent_or_inquiry_cannot_replace_the_pinned_scope(self):
        scope = dict(self.finance_scope, request_id="fixture-intent-b")
        original = self.make_original(scope)
        request = self.make_request(scope, self.auditor, self.challenge)
        for replacement, inquiry in ((original, request), (self.evidence["original"], request)):
            changed = {"original": replacement, "request": inquiry, "attestation": self.attest(replacement, inquiry)}
            with self.subTest(original_changed=replacement is original), self.assertRaises(ValueError):
                verify_history(self.expected, changed, challenge=self.challenge)

    def test_re_signed_disclosure_time_must_follow_finance_and_fit_the_inquiry_grant(self):
        original = self.evidence["original"]
        request = self.make_request(self.finance_scope, self.auditor, self.challenge, start=1000, end=1140)
        base = self.attest(original, request)["payload"]
        signed = self.signed_disclosure(dict(base, authorized_at=1009))
        with self.assertRaisesRegex(ValueError, "predates"):
            verify_history(self.expected, dict(self.evidence, request=request, attestation=signed), challenge=self.challenge)
        for time in (1099, 1140, True):
            payload = dict(self.evidence["attestation"]["payload"], authorized_at=time)
            with self.subTest(time=time), self.assertRaises(ValueError):
                verify_history(self.expected, dict(self.evidence, attestation=self.signed_disclosure(payload)),
                               challenge=self.challenge)

    def test_a_separate_synthetic_settlement_never_upgrades_the_pending_disclosure(self):
        original = self.evidence["original"]
        source, authority = Signer(), Signer()
        source_record = sign_source(source, finance_receipt=original["receipt"], scope=self.finance_scope,
                                    reference="fictional-settlement-1", settled_at=1110,
                                    observed_outcome=SYNTHETIC_SETTLED)
        settlement = sign_settlement(authority, source_record=source_record, source_pub=source.pub)
        checked = verify_settlement(
            source_record, settlement, finance_pins=self.expected["finance"], finance_evidence=original,
            history_pub=bytes.fromhex(self.expected["history_pub"]),
            auditor_pub=bytes.fromhex(self.expected["auditor_pub"]),
            source_pub=source.pub, authority_pub=authority.pub, expected_reference="fictional-settlement-1",
            expected_source_sha256=finance.digest(source_record),
        )
        self.assertEqual(checked["settlement_effect"], SYNTHETIC_SETTLED)
        self.assertEqual(checked["initiation_effect"], finance.PENDING)
        verified = verify_history(self.expected, self.evidence, challenge=self.challenge)
        self.assertEqual((verified["effect"], verified["settlement"]), (finance.PENDING, "UNESTABLISHED"))
        with self.assertRaises(ValueError):
            verify_history(self.expected, dict(self.evidence, settlement=settlement), challenge=self.challenge)
        payload = dict(self.evidence["attestation"]["payload"], disposition=SYNTHETIC_SETTLED)
        with self.assertRaises(ValueError):
            verify_history(self.expected, dict(self.evidence, attestation=self.signed_disclosure(payload)),
                           challenge=self.challenge)
