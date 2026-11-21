"""Local public lab checks against the published synthetic vectors."""

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import public_lab
from wolfalibi.education_verify import verify_admission


class PublicLabTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parent / "public_lab"
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="wolfalibi-public-lab-"))).resolve()
        self.lab = self.root / "public_lab"
        shutil.copytree(source / "vectors", self.lab / "vectors")
        shutil.copy2(source / "manifest.json", self.lab / "manifest.json")
        self.manifest = json.loads((self.lab / "manifest.json").read_bytes())
        self.enterContext(patch.object(public_lab, "ROOT", self.root))

    def vector(self, case):
        return self.lab / "vectors" / case

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_manifest(self):
        (self.lab / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def replace(self, case, name, data, *, repin=False):
        path = self.vector(case) / name
        path.write_bytes(data)
        if repin:
            entry = next(entry for entry in self.manifest["experiments"] if entry["id"] == case)
            entry["files"][name] = self.digest(path)
            self.write_manifest()

    def test_all_fixed_cases_verify_the_genuine_and_semantically_reject_the_tampered(self):
        report = public_lab.verify()
        self.assertEqual(report["outcome"], "PASS", report)
        self.assertEqual(report["manifest_sha256"], self.digest(self.lab / "manifest.json"))
        cases = {item["id"]: item for item in report["cases"]}
        self.assertEqual(list(cases), ["education", "finance", "history"])
        for item in cases.values():
            self.assertEqual(item["integrity"], "VERIFIED")
            self.assertEqual(item["genuine"]["outcome"], "VERIFIED")
            self.assertEqual(item["tampered"]["outcome"], "REJECTED")
        self.assertEqual(cases["education"]["genuine"]["verified"], "HISTORICAL_SYNTHETIC_ADMISSION")
        self.assertEqual(cases["finance"]["genuine"]["effect"], "PENDING_EXTERNAL_SETTLEMENT")
        self.assertEqual(cases["history"]["genuine"]["settlement"], "UNESTABLISHED")

    def test_cli_selects_one_case_and_prints_json(self):
        stream = io.StringIO()
        with patch.object(sys, "path", list(sys.path)), redirect_stdout(stream):
            self.assertEqual(public_lab.main(["verify", "--case", "finance"]), 0)
        report = json.loads(stream.getvalue())
        self.assertEqual(report["selected_case"], "finance")
        self.assertEqual([item["id"] for item in report["cases"]], ["finance"])

    def test_artifact_hash_mismatch_never_reaches_the_verifier(self):
        path = self.vector("finance") / "tampered.json"
        self.replace("finance", "tampered.json", path.read_bytes() + b"\n")
        with patch.object(public_lab.importlib, "import_module") as loader:
            report = public_lab.verify("finance")
        loader.assert_not_called()
        self.assertEqual(report["outcome"], "BLOCKED")
        self.assertIn("SHA-256 mismatch", report["cases"][0]["reason"])

    def test_repinning_invalid_json_cannot_turn_it_into_a_successful_denial(self):
        self.replace("history", "tampered.json", b'{"evidence":', repin=True)
        item = public_lab.verify("history")["cases"][0]
        self.assertEqual(item["integrity"], "VERIFIED")
        self.assertEqual(item["tampered"]["outcome"], "NOT_RUN")
        self.assertIn("invalid JSON", item["reason"])

    def test_repinning_a_missing_or_extra_field_is_not_the_fixed_tamper(self):
        path = self.vector("education") / "tampered.json"
        original = path.read_bytes()
        for variant in ("missing", "extra"):
            document = json.loads(original)
            response = document["evidence"]["response"]
            if variant == "missing":
                del response["support_level"]
            else:
                response["settlement"] = "SETTLED"
            self.replace("education", "tampered.json", json.dumps(document).encode(), repin=True)
            item = public_lab.verify("education")["cases"][0]
            with self.subTest(variant=variant):
                self.assertEqual(item["outcome"], "BLOCKED")
                self.assertEqual(item["tampered"]["outcome"], "NOT_RUN")
                self.assertIn("one-field substitution", item["reason"])

    def test_the_challenge_is_supplied_by_its_own_file_and_external_pins(self):
        self.replace("history", "challenge.txt", b"00" * 32 + b"\n", repin=True)
        item = public_lab.verify("history")["cases"][0]
        self.assertEqual(item["outcome"], "BLOCKED")
        self.assertIn("challenge differs from the external pins", item["reason"])

    def test_manifest_cannot_skip_or_relabel_a_fixed_case(self):
        experiments = self.manifest["experiments"][:]
        for invalid in (experiments[:-1], [*experiments[:-1], dict(experiments[-1], id="finance")],
                        [dict(experiments[0], claim="SYNTHETIC_SETTLED"), *experiments[1:]],
                        [dict(experiments[0], operation="fin.payment.settle"), *experiments[1:]],
                        [dict(experiments[0], tamper={"path": "/evidence/response"}), *experiments[1:]]):
            self.manifest["experiments"] = invalid
            self.write_manifest()
            report = public_lab.verify("education")
            with self.subTest(length=len(invalid)):
                self.assertEqual(report["outcome"], "BLOCKED")
                self.assertEqual(report["cases"], [])

    def test_missing_vector_cannot_count_as_rejection(self):
        (self.vector("education") / "tampered.json").unlink()
        report = public_lab.verify("education")
        self.assertEqual(report["outcome"], "BLOCKED")
        self.assertEqual(report["cases"][0]["tampered"]["outcome"], "NOT_RUN")

    def test_manifest_condition_status_cannot_upgrade_an_unqualified_claim(self):
        rows = self.manifest["conditions"]
        for condition in ("custody", "production", "confinement", "certification", "witness",
                          "freshness", "rollback", "power", "settlement"):
            self.manifest["conditions"] = [dict(row, status="TESTED") if row["id"] == condition else row for row in rows]
            self.write_manifest()
            with self.subTest(condition=condition):
                report = public_lab.verify("education")
                self.assertEqual(report["outcome"], "BLOCKED")
                self.assertEqual(report["cases"], [])
                self.assertIn(f"condition {condition} requires status", report["reason"])

    def test_manifest_requires_every_condition_once_and_a_valid_status(self):
        rows = self.manifest["conditions"]
        unavailable = {"custody", "production", "confinement", "certification"}
        variants = [
            ("omits conditions", [row for row in rows if row["id"] != condition]) for condition in unavailable
        ]
        variants.extend((
            ("duplicate manifest condition", [*rows, rows[0]]),
            ("unknown or duplicate", [*rows, dict(rows[0], id="different-claim")]),
            ("requires status", [dict(rows[0], status="VERIFIED"), *rows[1:]]),
        ))
        for reason, changed in variants:
            self.manifest["conditions"] = changed
            self.write_manifest()
            with self.subTest(reason=reason):
                report = public_lab.verify("finance")
                self.assertEqual(report["outcome"], "BLOCKED")
                self.assertIn(reason, report["reason"])

    def test_unavailable_verifier_cannot_count_as_rejection(self):
        with patch.object(public_lab.importlib, "import_module", side_effect=ImportError("unavailable")):
            item = public_lab.verify("education")["cases"][0]
        self.assertEqual(item["outcome"], "BLOCKED")
        self.assertEqual(item["tampered"]["outcome"], "NOT_RUN")

    def test_arbitrary_failure_on_the_valid_tamper_is_not_a_semantic_rejection(self):
        for failure in (KeyError("missing"), ValueError("unavailable"), OSError("unavailable"), 2):
            def verifier(pins, evidence):
                if evidence["response"]["support_level"] == "scheduled-check-in":
                    return verify_admission(pins, evidence)
                if isinstance(failure, Exception):
                    raise failure
                return failure

            with (self.subTest(failure=failure),
                  patch.object(public_lab.importlib, "import_module",
                               return_value=SimpleNamespace(verify_admission=verifier))):
                item = public_lab.verify("education")["cases"][0]
                self.assertEqual(item["genuine"]["outcome"], "VERIFIED")
                self.assertEqual(item["outcome"], "BLOCKED")
                self.assertIn("specified semantic rejection", item["reason"])

    def test_genuine_verified_without_the_exact_claim_is_blocked(self):
        def verifier(pins, evidence):
            return dict(verify_admission(pins, evidence), verified="SETTLEMENT_VERIFIED")

        with patch.object(public_lab.importlib, "import_module", return_value=SimpleNamespace(verify_admission=verifier)):
            item = public_lab.verify("education")["cases"][0]
        self.assertEqual(item["outcome"], "BLOCKED")
        self.assertEqual(item["tampered"]["outcome"], "NOT_RUN")
