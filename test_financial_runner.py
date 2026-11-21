"""Integrity, error accounting, and positive controls for the public review harness."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts import finance_challenge as lab


class FinancialRunnerTests(unittest.TestCase):
    def copy_inputs(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name in [*lab.BASE_DIGESTS, lab.MATRIX]:
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(lab.ROOT / name, dest)
        for name in ("public_lab/vectors", lab.VECTOR_DIR):
            shutil.copytree(lab.ROOT / name, root / name)
        return root

    def assert_blocked(self, report, reason):
        self.assertEqual(report["outcome"], "BLOCKED", report)
        self.assertIn(reason, report["reason"])

    def test_complete_run_matches_every_declared_case_in_order(self):
        matrix = json.loads((lab.ROOT / lab.MATRIX).read_text())
        report = lab.run()
        self.assertEqual(report["outcome"], "PASS", report.get("reason"))
        rows = report["cases"]
        self.assertEqual([item["id"] for item in rows], [item["id"] for item in matrix["cases"]])
        self.assertEqual(report["summary"]["executed"], len(rows))
        self.assertEqual(report["summary"]["scheduled"], len(rows))
        self.assertEqual(report["summary"]["errors"], 0)
        for item, declared in zip(rows, matrix["cases"], strict=True):
            self.assertEqual((item["fixture"], item["sha256"]), (declared["fixture"], declared["sha256"]))
            self.assertEqual(item["expected"], declared["expected"])
            for key in ("outcome", "reason"):
                self.assertEqual(item["observed"][key], declared["expected"][key], item["id"])
            self.assertEqual(item["observed"]["phase"], declared["expected_phase"], item["id"])
            unsupported = declared["expected"]["outcome"] in {"UNSUPPORTED", "NOT_ASSESSED"}
            self.assertEqual(item["result"], "UNASSESSED" if unsupported else "MATCH")
        for key, value in lab.LABELS.items():
            self.assertEqual(report[key], value)

    def test_selecting_one_challenge_runs_both_positive_controls(self):
        report = lab.run("A01")
        self.assertEqual(report["outcome"], "SELECTED", report.get("reason"))
        self.assertEqual({row["id"] for row in report["cases"]}, {"P01", "P02", "A01"})
        self.assertEqual(report["summary"]["matched"], 3)

    def test_unknown_selector_blocks(self):
        self.assert_blocked(lab.run("absent"), "unknown financial challenge id")

    def test_negative_case_cannot_pass_if_its_verifier_rejects_everything(self):
        rejection = {"outcome": "REJECTED", "reason": "receipt differs from the exact payment scope",
                     "phase": "canonical_verifier"}
        with patch.object(lab, "_observe", return_value=rejection):
            report = lab.run("A01")
        self.assert_blocked(report, "differed or could not run")
        self.assertGreaterEqual(report["summary"]["mismatched"], 2)

    def test_unexpected_parser_dependency_and_runtime_errors_are_runner_errors(self):
        for exc in (json.JSONDecodeError("unexpected parser exception", "", 0),
                    ImportError("missing crypto provider"), RuntimeError("interrupted verifier")):
            with self.subTest(type=type(exc).__name__), patch.object(lab, "_observe", side_effect=exc):
                report = lab.run("A01")
                self.assert_blocked(report, "could not run")
                self.assertEqual(report["summary"]["errors"], 3)
                self.assertTrue(all(row["observed"]["outcome"] == "ERROR" for row in report["cases"]))

    def test_unsupported_result_on_expected_runnable_case_blocks_the_profile(self):
        unsupported = {"outcome": "UNSUPPORTED", "reason": "test platform unavailable", "phase": "host"}
        with patch.object(lab, "_observe", return_value=unsupported):
            report = lab.run("A01")
        self.assert_blocked(report, "could not run")
        self.assertFalse(any(case["result"] == "MATCH" for case in report["cases"]))

    def test_wrong_expected_result_reason_or_phase_is_not_counted_as_pass(self):
        rows, fixtures = lab._catalog(lab.ROOT)
        trusted = lab.trusted_baseline(lab.ROOT)
        row = next(r for r in rows if r["id"] == "A01")
        for altered in (dict(row, expected={"outcome": "REJECTED", "reason": "unrelated refusal"}),
                        dict(row, expected_phase="unexpected-layer")):
            result = lab._run_row(altered, fixtures[row["fixture"]], trusted)
            self.assertEqual(result["result"], "MISMATCH")

    def test_receipt_validity_cannot_be_upgraded_to_settlement_or_certification(self):
        rows, fixtures = lab._catalog(lab.ROOT)
        trusted = lab.trusted_baseline(lab.ROOT)
        row = next(r for r in rows if r["id"] == "P01")
        genuine = lab._observe(row, fixtures[row["fixture"]], trusted)
        for field, value in (("effect", "SETTLED"), ("certification", "ISSUED"), ("assurance", "VERIFIED")):
            changed = deepcopy(genuine)
            changed["details"]["canonical"][field] = value
            with self.subTest(field=field), patch.object(lab, "_observe", return_value=changed):
                result = lab._run_row(row, fixtures[row["fixture"]], trusted)
                self.assertEqual(result["result"], "MISMATCH")

    def test_modified_manifest_pins_and_recorded_expectations_block(self):
        for relative in (lab.MATRIX, "public_lab/manifest.json", "public_lab/reports/verification.json",
                         "public_lab/vectors/history/pins.json"):
            with self.subTest(path=relative):
                root = self.copy_inputs()
                file = root / relative
                file.write_bytes(file.read_bytes() + b"\n")
                report = lab.run(root=root)
                self.assert_blocked(report, "inventory digest differs")
                self.assertEqual(report["cases"], [])

    def test_extra_or_missing_vector_blocks_even_a_selected_control(self):
        for mode in ("extra", "missing"):
            with self.subTest(mode=mode):
                root = self.copy_inputs()
                directory = root / lab.VECTOR_DIR
                if mode == "extra":
                    (directory / "unreviewed.json").write_bytes(b"{}")
                else:
                    next(path for path in directory.rglob("*") if path.is_file()).unlink()
                report = lab.run("P01", root=root)
                self.assertEqual(report["outcome"], "BLOCKED")
                self.assertEqual(report["cases"], [])

    def test_changed_vector_cannot_be_whitelisted_by_updating_local_matrix(self):
        root = self.copy_inputs()
        matrix = root / lab.MATRIX
        doc = json.loads(matrix.read_bytes())
        row = next(row for row in doc["cases"] if row["fixture"].startswith(lab.VECTOR_DIR + "/"))
        fixture = root / row["fixture"]
        fixture.write_bytes(b"{}")
        row["sha256"] = lab._sha(fixture.read_bytes())
        matrix.write_text(json.dumps(doc), encoding="utf8")
        self.assert_blocked(lab.run(root=root), "inventory digest differs")

    def test_partial_duplicate_and_out_of_order_execution_block(self):
        report = lab.run("A01")
        planned = list(report["cases"])
        for observed in (planned[:-1], [planned[0], planned[0], planned[-1]], list(reversed(planned))):
            with self.subTest(ids=[item["id"] for item in observed]):
                with self.assertRaisesRegex(lab.ReviewError, "incomplete or out-of-order"):
                    lab._summarize({"cases": observed}, planned)

    def test_stale_or_partial_git_pins_block(self):
        root = lab.ROOT
        actual_head = f"{'a' * 40} {'b' * 40} {lab.BASE_COMMIT}"
        with patch.object(lab, "_git", side_effect=[str(root), actual_head]):
            self.assert_blocked(lab.run(expect_commit="0" * 40, expect_tree="b" * 40), "stale revision")
        self.assert_blocked(lab.run(expect_tree="b" * 40), "both full lowercase")

    def test_archive_with_no_git_cannot_be_reported_as_exact_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            report = lab.run(root=Path(directory), expect_commit="a" * 40, expect_tree="b" * 40)
        self.assertEqual(report["outcome"], "BLOCKED")
        self.assertEqual(report["provenance"]["mode"], "UNVERIFIED")

    def test_repeat_and_concurrent_checks_each_execute_twice(self):
        from threading import Barrier
        from scripts import finance_challenge_cases as cases

        rows, fixtures = lab._catalog(lab.ROOT)
        trusted = lab.trusted_baseline(lab.ROOT)
        for mode in ("repeat", "parallel"):
            row = next(item for item in rows if item["mode"] == mode)
            verify = cases._one
            both_ready = Barrier(2)

            def witnessed_call(*args):
                if mode == "parallel":
                    both_ready.wait(timeout=3)
                return verify(*args)

            with self.subTest(mode=mode), patch.object(cases, "_one", side_effect=witnessed_call) as invocation:
                observed = lab._run_row(row, fixtures[row["fixture"]], trusted)
                self.assertEqual(observed["result"], "MATCH", observed["observed"])
                self.assertEqual(invocation.call_count, 2)
                incomplete = deepcopy(observed["observed"])
                incomplete["details"]["verifications"] = 1
                with patch.object(lab, "_observe", return_value=incomplete):
                    self.assertEqual(lab._run_row(row, fixtures[row["fixture"]], trusted)["result"], "MISMATCH")

    def test_unexpected_canonical_success_is_preserved_as_a_mismatch(self):
        from wolfalibi import finance_verify
        rows, fixtures = lab._catalog(lab.ROOT)
        trusted = lab.trusted_baseline(lab.ROOT)
        row = next(item for item in rows if item["id"] == "A01")
        fake_approval = dict(trusted["finance"]["canonical"], effect="SETTLED")
        with patch.object(finance_verify, "verify_admission", return_value=fake_approval):
            record = lab._run_row(row, fixtures[row["fixture"]], trusted)
        self.assertEqual(record["result"], "MISMATCH")
        self.assertEqual(record["observed"]["outcome"], "UNEXPECTED_RESULT")
        self.assertEqual(record["observed"]["details"]["canonical"], fake_approval)
