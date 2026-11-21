"""Strict synthetic finance record and historical verifier controls."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from alibi import Signer, canon
from wolfalibi import education_records, finance_records as records
from wolfalibi.finance_verify import main, verify_admission


class FinanceRecordTests(unittest.TestCase):
    def setUp(self):
        self.owner, self.supervisor, self.witness, self.target, self.caller = (Signer() for _ in range(5))
        self.scope = {
            "tenant": records.TENANT, "account": records.ACCOUNT, "currency": records.CURRENCY,
            "operation": records.OPERATION, "target_pub": self.target.pub.hex(), "policy_epoch": 1,
            "run_id": "synthetic-finance-run", "challenge": "21" * 32, "caller_pub": self.caller.pub.hex(),
            "request_id": "synthetic-payment-01", "payee": "fictional-library", "amount_minor": 2500,
        }
        self.peer = {
            "pid": 35, "uid": 1000, "gid": 1000, "start_ticks": 702,
            "boot_id": "e71b9418-275a-4617-9364-e12b208ddd43", "exe_sha256": "51" * 32,
            "argv_sha256": "52" * 32, "source_sha256": "53" * 32,
        }
        self.qualification = records.qualify(
            self.supervisor, self.witness, records.run_scope(self.scope), self.peer, 1000, 1030,
        )
        self.grant = records.owner_grant(self.owner, self.scope, "fictional-owner-grant", 1000, 1040)
        self.packet = records.dispatch(self.caller, self.scope, self.grant, self.qualification)
        self.receipt = records.receipt(self.target, self.scope, self.packet, 1020)
        self.expected = {
            "scope": self.scope, "target_pub": self.target.pub.hex(), "owner_pub": self.owner.pub.hex(),
            "supervisor_pub": self.supervisor.pub.hex(), "witness_pub": self.witness.pub.hex(),
            "peer": self.peer, "witness_head": records.digest(self.qualification),
        }
        self.evidence = {"packet": self.packet, "receipt": self.receipt}

    def check(self, packet=None, **changes):
        inputs = {
            "expected_scope": records.run_scope(self.scope), "owner_pub": self.owner.pub,
            "supervisor_pub": self.supervisor.pub, "witness_pub": self.witness.pub,
            "peer": self.peer, "now": 1020, "witness_head": bytes.fromhex(self.expected["witness_head"]),
        }
        return records.check_packet(self.packet if packet is None else packet, **(inputs | changes))

    def test_external_pins_verify_a_historical_pending_intent(self):
        self.assertEqual(self.check(), "fictional-owner-grant")
        payload = records.verify_receipt(self.receipt, target_pub=self.target.pub, scope=self.scope, packet=self.packet)
        verdict = verify_admission(self.expected, self.evidence)
        self.assertEqual(payload["outcome"], "PENDING_EXTERNAL_SETTLEMENT")
        self.assertEqual(verdict["outcome"], "VERIFIED")
        self.assertEqual(verdict["verified"], "HISTORICAL_SYNTHETIC_PAYMENT_INTENT")
        self.assertEqual(verdict["effect"], "PENDING_EXTERNAL_SETTLEMENT")
        self.assertEqual(verdict["idempotency_key"], records.idempotency_key(self.scope))
        self.assertEqual(verdict["business_sha256"], records.business_digest(self.scope))
        self.assertEqual(verdict["certification"], "NOT_ISSUED")

    def test_immutable_business_digests_are_independent_of_run_and_epoch(self):
        renewed = dict(self.scope, run_id="renewed", challenge="22" * 32,
                       caller_pub=Signer().pub.hex(), policy_epoch=2)
        self.assertNotEqual(records.run_scope(renewed), records.run_scope(self.scope))
        self.assertEqual(records.idempotency_key(renewed), records.idempotency_key(self.scope))
        self.assertEqual(records.business_digest(renewed), records.business_digest(self.scope))
        for field, value in (("amount_minor", 2600), ("payee", "fictional-utilities")):
            changed = self.scope | {field: value}
            with self.subTest(field=field):
                self.assertEqual(records.idempotency_key(changed), records.idempotency_key(self.scope))
                self.assertNotEqual(records.business_digest(changed), records.business_digest(self.scope))
        changed_id = dict(self.scope, request_id="different-payment")
        self.assertNotEqual(records.idempotency_key(changed_id), records.idempotency_key(self.scope))

    def test_one_qualification_covers_the_run_but_each_payment_needs_exact_owner_grant(self):
        for field, value in (("amount_minor", 2600), ("payee", "fictional-utilities"), ("request_id", "pay-two")):
            scope = self.scope | {field: value}
            with self.subTest(field=field):
                reused = records.dispatch(self.caller, scope, self.grant, self.qualification)
                with self.assertRaisesRegex(ValueError, "exact payment scope"):
                    self.check(reused)
                grant = records.owner_grant(self.owner, scope, "new-owner-grant", 1000, 1040)
                approved = records.dispatch(self.caller, scope, grant, self.qualification)
                self.assertEqual(self.check(approved), "new-owner-grant")
                with self.assertRaisesRegex(ValueError, "expected payment scope"):
                    self.check(approved, expected_scope=self.scope)

    def test_the_finance_profile_and_request_values_are_closed(self):
        changes = {
            "tenant": ("fictional-other-bank",), "account": ("fictional-savings",),
            "operation": ("fin.balance.read",), "currency": ("USD",),
            "payee": ("another-vendor", "fictional-", "fictional-" + "a" * 55),
            "amount_minor": (False, 0, records.MAX_AMOUNT_MINOR + 1), "policy_epoch": (True, 0),
        }
        for field, alternatives in changes.items():
            for value in alternatives:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    records.validate_scope(self.scope | {field: value})
        with self.assertRaises(ValueError):
            records.validate_run_scope(self.scope)

    def test_changed_run_or_role_or_measurement_does_not_authorize_payment(self):
        for field, alternative in (
            ("expected_scope", records.run_scope(dict(self.scope, challenge="23" * 32))),
            ("peer", dict(self.peer, source_sha256="00" * 32)),
            ("witness_head", "00" * 32), ("witness_pub", self.owner.pub),
            ("supervisor_pub", Signer().pub), ("owner_pub", Signer().pub),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(**{field: alternative})

    def test_target_supplied_time_checks_both_validity_windows(self):
        self.assertEqual(records.check_admission_time(self.packet, 1029), 1030)
        for time in (999, 1030, True):
            with self.subTest(time=time), self.assertRaises(ValueError):
                self.check(now=time)
        with self.assertRaises(ValueError):
            records.receipt(self.target, self.scope, self.packet, 1030)

    def test_historical_verification_requires_finance_specific_owner_signature(self):
        education_scope = {
            "tenant": "fictional-school", "student": "fictional-aster", "purpose": education_records.PURPOSE,
            "operation": education_records.OPERATION, "policy_version": education_records.POLICY_VERSION,
            **{field: self.scope[field] for field in ("target_pub", "run_id", "challenge", "caller_pub", "request_id")},
        }
        grant = education_records.owner_grant(self.owner, education_scope, "school-grant", 1000, 1040)
        packet = records.dispatch(self.caller, self.scope, grant, self.qualification)
        signed = records.receipt(self.target, self.scope, packet, 1020)
        with self.assertRaises(ValueError):
            verify_admission(self.expected, {"packet": packet, "receipt": signed})

    def test_historical_verifier_refuses_added_settlement_evidence_and_signed_fields(self):
        with self.assertRaises(ValueError):
            verify_admission(self.expected, dict(self.evidence, settlement="SETTLED"))
        for payload in (dict(self.receipt["payload"], outcome="SETTLED"),
                        dict(self.receipt["payload"], settlement_id="fictional-settlement")):
            signed = {"payload": payload, "signature": self.target.sign(records._TARGET_DOMAIN, canon(payload)).hex()}
            with self.subTest(payload=payload), self.assertRaisesRegex(ValueError, "exact pending intent"):
                verify_admission(self.expected, dict(self.evidence, receipt=signed))

    def test_cli_requires_exact_separate_challenge(self):
        with TemporaryDirectory(prefix="finance-records-test-") as root:
            expectations = Path(root, "expectations.json")
            artifact = Path(root, "artifact.json")
            expectations.write_bytes(canon(self.expected))
            artifact.write_bytes(canon({"evidence": self.evidence}))
            argv = ["finance_verify", "--expectations", str(expectations), "--evidence", str(artifact)]
            for challenge, code, outcome in ((self.scope["challenge"], 0, "VERIFIED"), ("20" * 32, 2, "REJECTED")):
                buffer = io.StringIO()
                with self.subTest(challenge=challenge), patch("sys.argv", argv + ["--challenge", challenge]):
                    with redirect_stdout(buffer):
                        self.assertEqual(main(), code)
                    self.assertEqual(json.loads(buffer.getvalue())["outcome"], outcome)
