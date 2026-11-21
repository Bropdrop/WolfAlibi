"""External synthetic submissions use fixed public pins and a genuine control."""

from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import financial_receipt_check as checker


class SubmittedReceiptTests(unittest.TestCase):
    def test_each_original_and_its_changed_copy(self):
        for profile in ("finance", "history"):
            for name, outcome in (("genuine", "VERIFIED"), ("tampered", "REJECTED")):
                with self.subTest(profile=profile, name=name):
                    path = checker.ROOT / f"public_lab/vectors/{profile}/{name}.json"
                    report = checker.check(profile, path)
                    self.assertEqual(report["outcome"], outcome)
                    self.assertEqual(report["submitted_sha256"], sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(report["settlement"], "UNESTABLISHED")
                    self.assertEqual(report["operational_authority"], "NOT_ISSUED")

    def test_own_copy_reformatted_but_same_signed_document(self):
        original = checker.ROOT / "public_lab/vectors/finance/genuine.json"
        with TemporaryDirectory() as tmp:
            path = Path(tmp, "copy.json")
            path.write_text(json.dumps(json.loads(original.read_bytes())), encoding="utf-8")
            report = checker.check("finance", path)
            self.assertEqual(report["outcome"], "VERIFIED")
            self.assertNotEqual(report["submitted_sha256"], sha256(original.read_bytes()).hexdigest())

    def test_bad_wrapper_is_a_wire_format_refusal(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp, "bad.json")
            path.write_bytes(b'{"evidence":{}, "evidence":{}}')
            report = checker.check("finance", path)
            self.assertEqual((report["outcome"], report["observation"]["phase"]), ("INPUT_REFUSED", "wire_format"))

    def test_missing_or_oversized_inputs_are_operational_failures(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp, "private-local-path.json")
            missing = checker.check("finance", path)
            self.assertEqual((missing["outcome"], missing["phase"]), ("BLOCKED", "local_input"))
            self.assertNotIn(str(path), json.dumps(missing))
            path.write_bytes(b" " * (checker.MAX_BYTES + 1))
            self.assertEqual(checker.check("history", path)["outcome"], "BLOCKED")

    def test_broken_positive_control_blocks_before_reading_submission(self):
        with patch("scripts.finance_challenge_cases.observe", return_value={"outcome": "REJECTED"}):
            report = checker.check("finance", "does-not-exist.json")
        self.assertEqual((report["phase"], report["outcome"]), ("preflight", "BLOCKED"))
        self.assertNotIn("submitted_sha256", report)

    def test_verifier_exception_does_not_count_as_a_denial(self):
        from scripts.finance_challenge_cases import observe

        def observation(case, raw, trusted):
            if raw == b"{}":
                raise RuntimeError("untrusted-text")
            return observe(case, raw, trusted)

        with TemporaryDirectory() as tmp:
            path = Path(tmp, "review.json")
            path.write_bytes(b"{}")
            with patch("scripts.finance_challenge_cases.observe", side_effect=observation):
                report = checker.check("finance", path)
        self.assertEqual((report["phase"], report["outcome"]), ("verification", "BLOCKED"))
        self.assertNotIn("untrusted-text", json.dumps(report))
