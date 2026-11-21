"""Regression checks for evidence accounting in the exact-tree qualification tool."""

import json
from pathlib import Path
import unittest

from scripts import qualify_financial_lab as qualify


FINANCIAL = Path(__file__).resolve().parent / "public_lab" / "financial"


class QualificationReportTests(unittest.TestCase):
    def setUp(self):
        self.matrix = json.loads((FINANCIAL / "cases.json").read_bytes())
        self.report = json.loads((FINANCIAL / "results.json").read_bytes())

    def test_packaged_full_report_agrees_with_manifest(self):
        qualify.check_matrix(self.report, self.matrix)

    def test_duplicate_row_cannot_replace_missing_observation(self):
        self.report["cases"][-1] = self.report["cases"][0]
        with self.assertRaisesRegex(ValueError, "partial, duplicate"):
            qualify.check_matrix(self.report, self.matrix)

    def test_partial_execution_does_not_qualify(self):
        self.report["summary"]["executed"] -= 1
        with self.assertRaisesRegex(ValueError, "totals disagree"):
            qualify.check_matrix(self.report, self.matrix)

    def test_unsupported_case_cannot_contribute_a_pass(self):
        row = next(r for r in self.report["cases"] if r["result"] == "UNASSESSED")
        row["result"] = "MATCH"
        with self.assertRaisesRegex(ValueError, "invalid score"):
            qualify.check_matrix(self.report, self.matrix)

    def test_fake_settlement_cannot_pass_the_positive_control(self):
        positive = next(row for row in self.report["cases"] if row["id"] == "P01")
        positive["observed"]["details"]["settlement"] = "SYNTHETIC_SETTLED"
        with self.assertRaisesRegex(ValueError, "genuine scoped historical claim"):
            qualify.check_matrix(self.report, self.matrix)

    def test_claim_upgrade_blocks_even_if_all_cases_match(self):
        self.report["cross_uid_custody"] = "QUALIFIED"
        with self.assertRaisesRegex(ValueError, "assurance label"):
            qualify.check_matrix(self.report, self.matrix)
