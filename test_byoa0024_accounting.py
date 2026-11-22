"""A nonzero process result supplies no security evidence by itself."""
from subprocess import CompletedProcess
import unittest

from mutation_test import ORACLES, designated_failure


class LegacyAccountingTests(unittest.TestCase):
    def result(self):
        test, marker = ORACLES["M3"]
        return CompletedProcess([], 1, "", "=" * 70 + f"\nFAIL: {test} (test_alibi.Crypto)\n"
                                f"AssertionError: mismatch {marker}\nRan 1 test in 0.1s\nFAILED (failures=1)\n")

    def test_only_designated_assertion_counts(self):
        positive = self.result()
        self.assertTrue(designated_failure(positive, "M3", 1))
        for needle in ORACLES["M3"]:
            altered = self.result()
            altered.stderr = altered.stderr.replace(needle, "unrelated")
            self.assertFalse(designated_failure(altered, "M3", 1))

    def test_incomplete_or_crashed_process_has_no_credit(self):
        for code in (0, 2, -9, 124):
            result = self.result()
            result.returncode = code
            self.assertFalse(designated_failure(result, "M3", 1))
        for summary in ("FAILED (failures=1, errors=1)", "FAILED (failures=1, skipped=1)"):
            result = self.result()
            result.stderr = result.stderr.replace("FAILED (failures=1)", summary)
            self.assertFalse(designated_failure(result, "M3", 1))
