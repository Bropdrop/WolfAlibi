"""Offline tests of the fixed Public Lab 002 observation boundary."""

import hashlib
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from scripts import finance_challenge_cases as cases


ROOT = Path(__file__).resolve().parent
LAB = ROOT / "public_lab"


class FinancialChallengeCasesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = json.loads((LAB / "financial/cases.json").read_bytes())
        cls.rows = {row["id"]: row for row in manifest["cases"]}
        cls.trusted = {}
        for profile in ("finance", "history"):
            directory = LAB / "vectors" / profile
            cls.trusted[profile] = {
                "genuine": json.loads((directory / "genuine.json").read_bytes()),
                "pins": json.loads((directory / "pins.json").read_bytes()),
                "challenge": (directory / "challenge.txt").read_text(encoding="ascii").strip(),
            }

    def observe(self, identifier, *, raw=None, row=None):
        case = self.rows[identifier] if row is None else row
        if raw is None:
            raw = (ROOT / case["fixture"]).read_bytes()
        return cases.observe(case, raw, self.trusted)

    def test_all_fixed_specimens_match_hash_reason_phase_and_outcome(self):
        for identifier, row in self.rows.items():
            with self.subTest(case=identifier):
                raw = (ROOT / row["fixture"]).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row["sha256"])
                actual = self.observe(identifier, raw=raw)
                self.assertEqual({k: actual[k] for k in ("outcome", "reason")}, row["expected"])
                self.assertEqual(actual["phase"], row["expected_phase"])

    def test_observations_ignore_the_reviewers_claim_of_success(self):
        forged = dict(self.rows["A01"], expected={"outcome": "VERIFIED", "reason": "approved"})
        self.assertEqual(self.observe("A01", row=forged), self.observe("A01"))

    def test_expired_packet_preserves_historical_proof(self):
        observed = self.observe("C01")
        self.assertEqual(observed["outcome"], "REJECTED")
        detail = observed["details"]
        self.assertEqual(detail["canonical"]["verified"], "HISTORICAL_SYNTHETIC_PAYMENT_INTENT")
        self.assertLess(detail["canonical"]["authorized_at"], detail["synthetic_check_time"])
        self.assertEqual(detail["operational_authority"], "NOT_ISSUED")

    def test_parallel_verifications_run_on_two_distinct_threads(self):
        identities = set()
        verify = cases.finance_verify.verify_admission

        def record(*args):
            identities.add(threading.get_ident())
            return verify(*args)

        with patch.object(cases.finance_verify, "verify_admission", side_effect=record):
            observed = self.observe("B02")
        self.assertEqual(observed["details"]["verifications"], 2)
        self.assertEqual(observed["details"]["schedule"], "parallel")
        self.assertEqual(len(identities), 2)

    def test_disagreeing_rechecks_cannot_claim_one_consistent_observation(self):
        genuine = self.observe("P01")["details"]["canonical"]
        with patch.object(cases.finance_verify, "verify_admission",
                          side_effect=[genuine, dict(genuine, settlement="SETTLED")]):
            observed = self.observe("B01")
        self.assertEqual(observed["outcome"], "UNEXPECTED_RESULT")
        self.assertEqual(len(observed["details"]["observations"]), 2)

    def test_unexpected_settlement_certification_or_authority_is_observable(self):
        genuine = self.observe("P01")["details"]["canonical"]
        for extra in ({"settlement": "SETTLED"}, {"certification": "ISSUED"}, {"authorized": True},
                      {"outcome": "VERIFIED", "authorized_at": float(genuine["authorized_at"])}):
            with self.subTest(extra=extra), patch.object(cases.finance_verify, "verify_admission",
                                                         return_value=dict(genuine, **extra)):
                observed = self.observe("P01")
                self.assertEqual(observed["outcome"], "UNEXPECTED_RESULT")
                self.assertEqual(observed["details"]["canonical"], dict(genuine, **extra))

    def test_format_refusals_do_not_invoke_a_financial_verifier(self):
        with patch.object(cases.finance_verify, "verify_admission") as verifier:
            for row in ("E05", "E08", "E09", "E10"):
                self.assertEqual(self.observe(row)["phase"], "wire_format")
            errors = ((b"\xff", "fixture is not UTF-8"), (b"[]", "fixture must be a JSON object"),
                      (b'{"evidence":{},"sidecar":null}', "expected exactly one evidence wrapper"))
            for raw, reason in errors:
                with self.subTest(reason=reason):
                    observed = self.observe("P01", raw=raw)
                    self.assertEqual(observed["outcome"], "INPUT_REFUSED")
                    self.assertEqual(observed["reason"], reason)
        verifier.assert_not_called()

    def test_unexpected_library_or_parser_exceptions_are_not_domain_refusals(self):
        for error in (ValueError("library initialization failed"), RuntimeError("interrupted")):
            with self.subTest(error=type(error).__name__), patch.object(cases.finance_verify, "verify_admission",
                                                                        side_effect=error):
                with self.assertRaises(type(error)):
                    self.observe("A01")
        with patch.object(cases.json, "loads", side_effect=RuntimeError("parser failed")):
            with self.assertRaises(RuntimeError):
                self.observe("E05")

    def test_coverage_exclusions_do_not_invoke_a_verifier(self):
        with patch.object(cases, "_verify") as verifier:
            for row, expected in (("F04", "UNSUPPORTED"), ("F05", "NOT_ASSESSED")):
                observed = self.observe(row)
                self.assertEqual(observed["phase"], "coverage")
                self.assertEqual(observed["outcome"], expected)
                self.assertNotIn("details", observed)
        verifier.assert_not_called()
