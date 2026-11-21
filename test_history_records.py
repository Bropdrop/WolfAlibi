"""Read-only history authority controls using local synthetic keys and data."""

import copy
import unittest

from alibi import Signer
from wolfalibi import finance_records as finance
from wolfalibi import history_records as history


class HistoryRecordTests(unittest.TestCase):
    def setUp(self):
        self.owner, self.auditor, self.target, self.caller = (Signer() for _ in range(4))
        self.finance_scope = {
            "tenant": finance.TENANT, "account": finance.ACCOUNT, "operation": finance.OPERATION,
            "target_pub": self.target.pub.hex(), "request_id": "fixture-intent-a", "currency": finance.CURRENCY,
            "payee": "fictional-supplier", "amount_minor": 4500, "policy_epoch": 1, "run_id": "original-run",
            "challenge": "12" * 32, "caller_pub": self.caller.pub.hex(),
        }
        self.scope = history.inquiry_scope(self.finance_scope)
        self.challenge = "34" * 32
        self.grant = history.issue_grant(self.owner, self.scope, self.auditor.pub, "inquiry-1", 1000, 1040)
        self.request = history.sign_inquiry(self.auditor, self.scope, self.grant, self.challenge)

    def check(self, request=None, **changes):
        expected = {"scope": self.scope, "owner_pub": self.owner.pub, "challenge": self.challenge, "now": 1010}
        return history.check_inquiry(self.request if request is None else request, **(expected | changes))

    def test_inquiry_authority_is_for_the_exact_historical_intent(self):
        self.assertEqual(self.scope, {
            "tenant": finance.TENANT, "account": finance.ACCOUNT, "operation": finance.OPERATION,
            "target_pub": self.target.pub.hex(), "request_id": "fixture-intent-a", "purpose": history.PURPOSE,
        })
        self.assertEqual(self.check(), "inquiry-1")
        self.assertEqual(self.check(now=1000), "inquiry-1")
        self.assertEqual(self.check(now=1039), "inquiry-1")

    def test_scope_validation_rejects_other_targets_purposes_and_intent_ids(self):
        for changed in (dict(self.scope, request_id="fixture-intent-b"),
                        dict(self.scope, target_pub=Signer().pub.hex()),
                        dict(self.scope, purpose=finance.OPERATION),
                        dict(self.scope, tenant="fictional-other-bank"),
                        dict(self.scope, account="fictional-savings")):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.check(scope=changed)
        with self.assertRaises(ValueError):
            history.validate_scope(dict(self.scope, payee="fictional-supplier"))

    def test_inquiry_proof_binds_the_external_challenge(self):
        replacement = "35" * 32
        freshly_signed = history.sign_inquiry(self.auditor, self.scope, self.grant, replacement)
        with self.assertRaises(ValueError):
            self.check(freshly_signed)
        with self.assertRaises(ValueError):
            self.check(dict(self.request, challenge=replacement), challenge=replacement)
        with self.assertRaises(ValueError):
            history.sign_inquiry(self.auditor, self.scope, self.grant, "FF" * 32)

    def test_inquiry_proof_binds_the_exact_owner_grant(self):
        replacement = history.issue_grant(self.owner, self.scope, self.auditor.pub, "inquiry-2", 1000, 1040)
        with self.assertRaises(ValueError):
            self.check(dict(self.request, grant=replacement))
        other_owner = Signer()
        grant = history.issue_grant(other_owner, self.scope, self.auditor.pub, "inquiry-1", 1000, 1040)
        signed = history.sign_inquiry(self.auditor, self.scope, grant, self.challenge)
        with self.assertRaises(ValueError):
            self.check(signed)

    def test_auditor_proves_possession_and_roles_are_distinct(self):
        with self.assertRaises(ValueError):
            history.sign_inquiry(self.caller, self.scope, self.grant, self.challenge)
        for key in (self.owner.pub, self.target.pub):
            with self.subTest(key=key.hex()), self.assertRaises(ValueError):
                history.issue_grant(self.owner, self.scope, key, "inquiry-2", 1000, 1040)
        with self.assertRaises(ValueError):
            history.issue_grant(self.target, self.scope, self.auditor.pub, "inquiry-2", 1000, 1040)

    def test_history_grants_are_current_and_lifetime_is_bounded(self):
        for now in (999, 1040, True):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.check(now=now)
        for start, end in ((1000, 1000), (1000, 1000 + history.MAX_GRANT_SECONDS + 1), (True, 1000)):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                history.issue_grant(self.owner, self.scope, self.auditor.pub, "new-inquiry", start, end)

    def test_original_payment_authorization_and_dispatch_confer_no_history_access(self):
        supervisor, witness = Signer(), Signer()
        peer = {
            "pid": 123, "uid": 1000, "gid": 1000, "start_ticks": 42,
            "boot_id": "e71b9418-275a-4617-9364-e12b208ddd43", "exe_sha256": "11" * 32,
            "argv_sha256": "22" * 32, "source_sha256": "33" * 32,
        }
        qualification = finance.qualify(supervisor, witness, self.finance_scope, peer, 1000, 1040)
        payment_grant = finance.owner_grant(self.owner, self.finance_scope, "orig-grant", 1000, 1040)
        packet = finance.dispatch(self.caller, self.finance_scope, payment_grant, qualification)
        self.assertEqual(finance.check_packet(
            packet, expected_scope=self.finance_scope, owner_pub=self.owner.pub, supervisor_pub=supervisor.pub,
            witness_pub=witness.pub, peer=peer, now=1010, witness_head=finance.digest(qualification),
        ), "orig-grant")
        with self.assertRaises(ValueError):
            self.check(packet)
        with self.assertRaises(ValueError):
            self.check(dict(self.request, grant=payment_grant))
        with self.assertRaises(ValueError):
            history.sign_inquiry(self.auditor, self.scope, payment_grant, self.challenge)

    def test_signed_carrier_is_closed_and_detached(self):
        with self.assertRaises(ValueError):
            self.check(dict(self.request, action="initiate"))
        mutated = copy.deepcopy(self.request)
        mutated["auditor_proof"]["payload"]["type"] = "QUORVANE_FINANCE_CALLER_DISPATCH_V1"
        with self.assertRaises(ValueError):
            self.check(mutated)
        self.grant["payload"]["grant_id"] = "mutated-grant"
        self.assertEqual(self.check(), "inquiry-1")
