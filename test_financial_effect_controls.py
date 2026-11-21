"""Check typed Linux target observations separately from receipt-only verification."""

import json
from tempfile import TemporaryDirectory
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import financial_effect_controls as controls


class TargetProfiles(unittest.TestCase):
    def test_unsupported_host_never_reports_an_observed_denial(self):
        with patch.object(controls, "_linux_controls", return_value=False):
            result = controls.run("B-T01")
        self.assertEqual(result["outcome"], "UNSUPPORTED")
        self.assertEqual(result["controls"], [])
        self.assertEqual(result["production"], "BLOCKED")

    def test_fixture_inventory_checked_before_launch(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / controls.FIXTURE
            path.parent.mkdir(parents=True)
            path.write_text("{}")
            with patch.object(controls, "ROOT", Path(temp)), patch.object(controls, "_run_case") as launch:
                result = controls.run()
                self.assertEqual(result["outcome"], "BLOCKED")
                self.assertEqual(result["controls"], [])
                launch.assert_not_called()

    def test_unknown_case_does_not_fall_back_to_another_case(self):
        self.assertEqual(controls.run("B-UNKNOWN")["outcome"], "BLOCKED")

    @unittest.skipUnless(controls._linux_controls(), "requires the Linux financial target fixture")
    def test_wrong_observed_value_is_failure_and_infrastructure_errors_are_blocked(self):
        with patch.dict(controls.CONTROLS, {"B-T04": lambda _: {"count_after": True}}):
            result = controls.run("B-T04")
        self.assertEqual(result["outcome"], "FAIL")
        self.assertEqual(result["controls"][0]["observed"], {"count_after": True})

        def incomplete(_resource):
            raise RuntimeError("simulated instrumentation interruption")

        with patch.dict(controls.CONTROLS, {"B-T04": incomplete}):
            result = controls.run("B-T04")
        self.assertEqual(result["outcome"], "BLOCKED")
        self.assertIsNone(result["controls"][0]["observed"])
        self.assertEqual(result["controls"][0]["error_type"], "RuntimeError")


@unittest.skipUnless(controls._linux_controls(), "requires the Linux financial target fixture")
class LinuxTargetEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = controls.run()
        cls.results = {row["id"]: row for row in cls.report["controls"]}

    def observed(self, case):
        row = self.results[case]
        self.assertEqual(row["outcome"], "PASS", row)
        self.assertEqual(json.dumps(row["observed"], sort_keys=True), json.dumps(row["expected"], sort_keys=True))
        return row["observed"]

    def test_complete_local_run_and_unsupported_custody(self):
        self.assertEqual(self.report["outcome"], "PASS", self.report)
        self.assertEqual(list(self.results), ["B-T01", "B-T02", "B-T03", "B-T04", "C-T01", "C-T02", "C-T03", "F-T01"])
        self.assertEqual(self.report["cross_uid_custody"], "UNSUPPORTED")
        self.assertEqual(self.report["certification"], "NOT_ISSUED")
        self.assertEqual(self.report["confinement"], "BLOCKED")

    def test_duplicate_and_conflicting_operations_preserve_original_intent(self):
        duplicate = self.observed("B-T01")
        self.assertEqual(duplicate["initial_pair"], ["HISTORICAL_INTENT", "INTENT_RECORDED"])
        self.assertIs(duplicate["same_receipts"], True)
        self.assertEqual(duplicate["intent_count"], 1)
        conflict = self.observed("B-T02")
        self.assertEqual(conflict["conflict"], {"outcome": "DENIED", "reason": "REQUEST_ID_CONFLICT"})
        self.assertIs(conflict["original_reconciled"], True)

    def test_ambiguous_delivery_returns_archived_receipt(self):
        row = self.observed("B-T03")
        self.assertEqual(row["delivery"], {"outcome": "UNKNOWN", "response_read": False})
        self.assertEqual(row["replies"], ["RECONCILED", "RECONCILED"])
        self.assertIs(row["same_archived_receipt"], True)
        self.assertEqual(row["intent_count"], 1)
        self.assertEqual(row["effect"], "PENDING_EXTERNAL_SETTLEMENT")

    def test_historical_verification_leaves_stopped_authority_unchanged(self):
        row = self.observed("B-T04")
        self.assertIs(row["ledger_unchanged"], True)
        self.assertIs(row["checkpoint_unchanged"], True)
        self.assertEqual((row["count_before"], row["count_after"]), (1, 1))

    def test_live_authorization_remains_distinct_from_historical_evidence(self):
        expired = self.observed("C-T01")
        revoked = self.observed("C-T02")
        auditor = self.observed("C-T03")
        self.assertEqual((expired["count_after_expired"], expired["count_after_positive"]), (0, 1))
        self.assertEqual(revoked["history"], "HISTORICAL_SYNTHETIC_PAYMENT_INTENT")
        self.assertEqual(revoked["live"], {"outcome": "DENIED", "reason": "OWNER_GRANT_REVOKED"})
        self.assertEqual(auditor["historical_settlement"], "UNESTABLISHED")
        self.assertEqual((auditor["count_after_auditor"], auditor["count_after_positive"]), (0, 1))

    def test_retained_checkpoint_rejects_old_sqlite_view_then_original_reopens(self):
        row = self.observed("F-T01")
        self.assertEqual(row["old_ledger"], "REJECTED_LEDGER_DIVERGENCE")
        self.assertIs(row["checkpoint_preserved"], True)
        self.assertEqual((row["clean_reopen"], row["restored_reopen"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
