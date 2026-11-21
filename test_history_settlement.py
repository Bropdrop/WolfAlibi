"""Offline synthetic controls for the distinct settlement evidence phase."""

from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from alibi import Signer, canon
from wolfalibi import finance_records, history_records, history_settlement as settlement
from wolfalibi.education_records import _sign
from wolfalibi.finance_verify import verify_admission
from wolfalibi.history_verify import DISCLOSURE_DOMAIN, disclosure_payload


class HistorySettlementTests(unittest.TestCase):
    def setUp(self):
        self.owner, self.supervisor, self.witness, self.target, self.caller = (Signer() for _ in range(5))
        self.history, self.auditor = Signer(), Signer()
        self.source, self.authority = Signer(), Signer()
        self.reference = "fictional-settlement-source-event"
        self.scope = {
            "tenant": finance_records.TENANT, "account": finance_records.ACCOUNT,
            "currency": finance_records.CURRENCY, "operation": finance_records.OPERATION,
            "target_pub": self.target.pub.hex(), "policy_epoch": 1, "run_id": "synthetic-settlement-run",
            "challenge": "f1" * 32, "caller_pub": self.caller.pub.hex(),
            "request_id": "fictional-payment-01", "payee": "fictional-library", "amount_minor": 2500,
        }
        peer = {
            "pid": 35, "uid": 1000, "gid": 1000, "start_ticks": 702,
            "boot_id": "e71b9418-275a-4617-9364-e12b208ddd43", "exe_sha256": "51" * 32,
            "argv_sha256": "52" * 32, "source_sha256": "53" * 32,
        }
        qualification = finance_records.qualify(self.supervisor, self.witness, self.scope, peer, 1000, 1030)
        grant = finance_records.owner_grant(self.owner, self.scope, "fictional-grant", 1000, 1040)
        packet = finance_records.dispatch(self.caller, self.scope, grant, qualification)
        self.finance_evidence = {"packet": packet, "receipt": finance_records.receipt(self.target, self.scope, packet, 1020)}
        self.finance_pins = {
            "scope": self.scope, "target_pub": self.target.pub.hex(), "owner_pub": self.owner.pub.hex(),
            "supervisor_pub": self.supervisor.pub.hex(), "witness_pub": self.witness.pub.hex(),
            "peer": peer, "witness_head": finance_records.digest(qualification),
        }
        self.observation = self.make_source()
        self.approval = self.approve(self.observation)
        self.source_pin = finance_records.digest(self.observation)

    def make_source(self, **changes):
        options = {
            "finance_receipt": self.finance_evidence["receipt"], "scope": self.scope,
            "reference": self.reference, "settled_at": 1035, "observed_outcome": settlement.SYNTHETIC_SETTLED,
        }
        return settlement.sign_source(self.source, **(options | changes))

    def approve(self, observation):
        return settlement.sign_settlement(self.authority, source_record=observation, source_pub=self.source.pub)

    def verify(self, observation=None, approval=None, **changes):
        options = {
            "finance_pins": self.finance_pins, "finance_evidence": self.finance_evidence,
            "history_pub": self.history.pub, "auditor_pub": self.auditor.pub,
            "source_pub": self.source.pub, "authority_pub": self.authority.pub,
            "expected_reference": self.reference, "expected_source_sha256": self.source_pin,
        }
        return settlement.verify_settlement(
            self.observation if observation is None else observation,
            self.approval if approval is None else approval, **(options | changes),
        )

    def verify_with_source_pin(self, observation, approval=None):
        endorsed = self.approve(observation) if approval is None else approval
        return self.verify(observation, endorsed, expected_source_sha256=finance_records.digest(observation))

    def test_both_external_roles_verify_only_the_separate_synthetic_phase(self):
        original = deepcopy(self.finance_evidence)
        result = self.verify()
        self.assertEqual(result["outcome"], "SETTLEMENT_VERIFIED")
        self.assertEqual(result["verified"], "HISTORICAL_SYNTHETIC_SETTLEMENT")
        self.assertEqual(result["settlement_effect"], settlement.SYNTHETIC_SETTLED)
        self.assertEqual(result["initiation_effect"], finance_records.PENDING)
        self.assertEqual(result["initiation_sha256"], finance_records.digest(original["receipt"]))
        self.assertEqual(result["business_sha256"], finance_records.business_digest(self.scope))
        self.assertEqual(result["source_sha256"], self.source_pin)
        self.assertEqual(result["settlement_sha256"], finance_records.digest(self.approval))
        self.assertEqual(result["reference"], self.reference)
        self.assertEqual(result["settled_at"], 1035)
        self.assertEqual(result["production"], "BLOCKED")
        self.assertEqual(result["certification"], "NOT_ISSUED")
        self.assertEqual(self.finance_evidence, original)
        self.assertEqual(verify_admission(self.finance_pins, self.finance_evidence)["effect"], finance_records.PENDING)

    def test_initiation_and_delivery_states_cannot_be_signed_as_settlement_observations(self):
        for status in (finance_records.PENDING, "UNKNOWN", "RECONCILED", "SETTLED", None):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "did not attest"):
                self.make_source(observed_outcome=status)
        with self.assertRaises(ValueError):
            self.approve(self.finance_evidence["receipt"])
        with self.assertRaises(ValueError):
            self.verify({}, {})

    def test_wrong_reference_and_contradictory_authentic_observation_fail_the_retained_pins(self):
        with self.assertRaisesRegex(ValueError, "independently pinned reference"):
            self.verify(expected_reference="fictional-different-reference")
        conflicting = self.make_source(settled_at=1036)
        self.assertEqual(conflicting["payload"]["reference"], self.reference)
        with self.assertRaisesRegex(ValueError, "independently pinned digest"):
            self.verify(conflicting, self.approve(conflicting))

    def test_authority_signature_must_endorse_the_exact_source_even_if_both_signed(self):
        second_observation = self.make_source(settled_at=1036)
        with self.assertRaisesRegex(ValueError, "did not approve the exact"):
            self.verify_with_source_pin(second_observation, self.approval)
        with self.assertRaises(ValueError):
            self.verify(approval=self.observation)

    def test_same_business_receipt_with_different_signature_is_not_the_original_intent(self):
        other_receipt = finance_records.receipt(self.target, self.scope, self.finance_evidence["packet"], 1021)
        observed = self.make_source(finance_receipt=other_receipt)
        self.assertEqual(self.observation["payload"]["business_sha256"], observed["payload"]["business_sha256"])
        with self.assertRaisesRegex(ValueError, "verified original payment intent"):
            self.verify_with_source_pin(observed)

    def test_valid_source_and_authority_signatures_do_not_override_payment_terms(self):
        for changes in ({"payee": "fictional-school"}, {"amount_minor": 5000}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "verified original payment intent"):
                self.verify_with_source_pin(self.make_source(scope=self.scope | changes))

    def test_settlement_cannot_claim_time_before_or_at_initiation(self):
        for time in (1019, 1020):
            with self.subTest(time=time), self.assertRaisesRegex(ValueError, "after the original payment intent"):
                self.verify_with_source_pin(self.make_source(settled_at=time))

    def test_signatures_and_exact_schemas_are_independently_checked(self):
        for field in ("source_pub", "authority_pub"):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "signature"):
                self.verify(**{field: Signer().pub})
        overbroad_source = _sign(self.source, settlement._SOURCE_DOMAIN,
                                 dict(self.observation["payload"], actual_funds_moved=True))
        with self.assertRaisesRegex(ValueError, "settlement source fields"):
            self.verify(overbroad_source, expected_source_sha256=finance_records.digest(overbroad_source))
        overbroad_approval = _sign(self.authority, settlement._SETTLEMENT_DOMAIN,
                                   dict(self.approval["payload"], actual_funds_moved=True))
        with self.assertRaisesRegex(ValueError, "did not approve the exact"):
            self.verify(approval=overbroad_approval)

    def test_finance_keys_and_source_cannot_act_as_the_settlement_authority(self):
        for reused in (self.owner, self.supervisor, self.witness, self.target, self.caller):
            with self.subTest(role=reused.pub.hex()[:8]):
                approved = settlement.sign_settlement(reused, source_record=self.observation, source_pub=self.source.pub)
                with self.assertRaisesRegex(ValueError, "distinct keys"):
                    self.verify(approval=approved, authority_pub=reused.pub)
                source = _sign(reused, settlement._SOURCE_DOMAIN, self.observation["payload"])
                approved = settlement.sign_settlement(self.authority, source_record=source, source_pub=reused.pub)
                with self.assertRaisesRegex(ValueError, "distinct keys"):
                    self.verify(source, approved, source_pub=reused.pub, expected_source_sha256=finance_records.digest(source))
        with self.assertRaisesRegex(ValueError, "distinct keys"):
            settlement.sign_settlement(self.source, source_record=self.observation, source_pub=self.source.pub)

    def test_pinned_inquiry_credentials_cannot_sign_source_or_settlement_evidence(self):
        for role, reused in (("history", self.history), ("auditor", self.auditor)):
            with self.subTest(role=role, settlement_role="authority"):
                approved = settlement.sign_settlement(reused, source_record=self.observation, source_pub=self.source.pub)
                with self.assertRaisesRegex(ValueError, "distinct keys"):
                    self.verify(approval=approved, authority_pub=reused.pub)
            with self.subTest(role=role, settlement_role="source"):
                source = _sign(reused, settlement._SOURCE_DOMAIN, self.observation["payload"])
                approved = settlement.sign_settlement(self.authority, source_record=source, source_pub=reused.pub)
                with self.assertRaisesRegex(ValueError, "distinct keys"):
                    self.verify(source, approved, source_pub=reused.pub, expected_source_sha256=finance_records.digest(source))

    def test_inquiry_roles_require_well_formed_separate_external_pins(self):
        for name in ("history_pub", "auditor_pub"):
            for invalid in (None, b"short", self.history.pub.hex()):
                with self.subTest(name=name, pin_type=type(invalid).__name__), self.assertRaisesRegex(ValueError, "key"):
                    self.verify(**{name: invalid})
        with self.assertRaisesRegex(ValueError, "distinct keys"):
            self.verify(auditor_pub=self.history.pub)

    def test_settlement_signatures_cannot_make_an_untrusted_original_intent_valid(self):
        forged = deepcopy(self.finance_evidence)
        forged["receipt"]["signature"] = "00" * 64
        observed = self.make_source(finance_receipt=forged["receipt"])
        with self.assertRaisesRegex(ValueError, "signature"):
            self.verify(observed, self.approve(observed), finance_evidence=forged,
                        expected_source_sha256=finance_records.digest(observed))

    def test_cli_verifies_both_phases_and_requires_both_external_pin_sets(self):
        challenge = "f2" * 32
        anchor = "f3" * 32
        scope = history_records.inquiry_scope(self.scope)
        grant = history_records.issue_grant(self.owner, scope, self.auditor.pub, "fictional-history-grant", 1060, 1090)
        request = history_records.sign_inquiry(self.auditor, scope, grant, challenge)
        disclosure = disclosure_payload(self.finance_pins, anchor, request, self.finance_evidence, 1070)
        attestation = _sign(self.history, DISCLOSURE_DOMAIN, disclosure)
        history_pins = {
            "finance": self.finance_pins, "history_pub": self.history.pub.hex(), "auditor_pub": self.auditor.pub.hex(),
            "anchor_sha256": anchor, "challenge": challenge,
        }
        settlement_pins = {
            "source_pub": self.source.pub.hex(), "authority_pub": self.authority.pub.hex(),
            "expected_reference": self.reference, "expected_source_sha256": self.source_pin,
        }
        artifact = {
            "evidence": {"original": self.finance_evidence, "request": request, "attestation": attestation},
            "experimental_evidence": {"source_record": self.observation, "settlement_record": self.approval},
        }
        wrong_history = deepcopy(artifact)
        wrong_history["evidence"]["attestation"]["signature"] = "00" * 64
        wrong_source_pins = dict(settlement_pins, expected_source_sha256="f4" * 32)
        with TemporaryDirectory(prefix="history-settlement-cli-") as directory:
            history_file = Path(directory) / "history-pins.json"
            settlement_file = Path(directory) / "settlement-pins.json"
            evidence_file = Path(directory) / "evidence.json"
            history_file.write_bytes(canon(history_pins))
            options = ["--history-expectations", str(history_file), "--settlement-expectations", str(settlement_file),
                       "--evidence", str(evidence_file), "--challenge"]
            cases = (
                ("valid", challenge, settlement_pins, artifact, 0, "SETTLEMENT_VERIFIED"),
                ("wrong challenge", "f4" * 32, settlement_pins, artifact, 2, "REJECTED"),
                ("wrong source pin", challenge, wrong_source_pins, artifact, 2, "REJECTED"),
                ("forged disclosure", challenge, settlement_pins, wrong_history, 2, "REJECTED"),
            )
            for label, supplied_challenge, pins, evidence, expected_code, expected_outcome in cases:
                with self.subTest(label=label):
                    settlement_file.write_bytes(canon(pins))
                    evidence_file.write_bytes(canon(evidence))
                    output = StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(settlement.main(options + [supplied_challenge]), expected_code)
                    self.assertEqual(json.loads(output.getvalue())["outcome"], expected_outcome)


if __name__ == "__main__":
    unittest.main()
