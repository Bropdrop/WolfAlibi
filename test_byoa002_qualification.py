"""Qualification runner controls for complete, attributable source mutation detections."""

from copy import deepcopy
import unittest

from scripts.mutate_byoa002 import caught


class MutationAccountingTests(unittest.TestCase):
    def setUp(self):
        self.clean = {"tests": 1, "module_sha256": "original", "failures": 0, "assertions": [],
                      "errors": [], "skips": [], "expected_failures": 0, "unexpected_successes": 0, "loader_errors": []}
        self.altered = dict(self.clean, module_sha256="altered", failures=1,
                            assertions=[{"test": "control", "type": "AssertionError", "message": "observed wrong result"}])

    def detected(self, initial, altered):
        return caught(initial, altered, "original", "altered", "control")

    def test_positive_reference_and_only_the_designated_assertion_count(self):
        self.assertTrue(self.detected(self.clean, self.altered))
        for key, value in (("test", "different"), ("type", "RuntimeError")):
            row = deepcopy(self.altered)
            row["assertions"][0][key] = value
            self.assertFalse(self.detected(self.clean, row))

    def test_crash_skip_or_wrong_module_never_counts(self):
        for key, value in (("tests", 0), ("errors", ["crashed"]), ("skips", ["unsupported"]), ("module_sha256", "original"),
                           ("expected_failures", 1), ("unexpected_successes", 1), ("loader_errors", ["unavailable"])):
            with self.subTest(field=key):
                self.assertFalse(self.detected(self.clean, dict(self.altered, **{key: value})))

    def test_unchanged_or_preexisting_failures_are_not_mutation_detections(self):
        self.assertFalse(self.detected(self.clean, self.clean))
        self.assertFalse(self.detected(dict(self.clean, failures=1), self.altered))
