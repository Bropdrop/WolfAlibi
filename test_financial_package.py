"""Reproduce the financial review archive and its offline, portable entry points."""

from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZIP_STORED, ZipFile

from scripts import build_financial_lab as bundle


ROOT = Path(__file__).resolve().parent


class FinancialPackageTests(unittest.TestCase):
    def test_reference_archive_and_all_inherited_review_bytes_are_immutable(self):
        raw = (ROOT / bundle.ORIGINAL_ZIP).read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), bundle.ORIGINAL_SHA256)
        with self.assertRaisesRegex(ValueError, "exact PR #35 archive"):
            bundle.base_entries(raw + b" ")
        with ZipFile(ROOT / bundle.ARCHIVE) as current:
            for name, data in bundle.base_entries(raw).items():
                with self.subTest(name=name):
                    self.assertEqual(current.read(name), data)

    def test_archive_inventory_has_exact_digest_and_safe_regular_members(self):
        with ZipFile(ROOT / bundle.ARCHIVE) as archive:
            entries = archive.infolist()
            inventory = json.loads(archive.read(bundle.INVENTORY))
            names = [entry.filename for entry in entries]
            self.assertEqual(names, sorted(set(names)))
            self.assertEqual(set(names) - {bundle.INVENTORY}, set(inventory["files"]))
            self.assertEqual(inventory["base"]["archive_sha256"], bundle.ORIGINAL_SHA256)
            for entry in entries:
                name = entry.filename
                path = PurePosixPath(name)
                with self.subTest(name=name):
                    self.assertFalse(path.is_absolute())
                    self.assertFalse(set(path.parts) & {"..", ".", ".git", "__pycache__"})
                    self.assertNotIn("\\", name)
                    self.assertNotIn(path.suffix.lower(), {".key", ".pem", ".db", ".sqlite", ".zip"})
                    self.assertEqual(entry.external_attr >> 16, 0o100644)
                    self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                    self.assertEqual(entry.compress_type, ZIP_STORED)
                    data = archive.read(entry)
                    if name != bundle.INVENTORY:
                        self.assertEqual(sha256(data).hexdigest(), inventory["files"][name])
                    if path.suffix.lower() in {".json", ".html", ".txt"}:
                        self.assertNotIn(b"PRIVATE KEY-----", data)

    def test_fresh_rebuild_and_standalone_verification_match_committed_bytes(self):
        with TemporaryDirectory(prefix="quorvane-financial-package-") as temporary:
            directory = Path(temporary)
            copy = directory / "copy.zip"
            self.command(ROOT / "scripts/build_financial_lab.py", "--archive", copy, cwd=directory)
            self.assertEqual(copy.read_bytes(), (ROOT / bundle.ARCHIVE).read_bytes())
            with ZipFile(copy) as archive:
                archive.extractall(directory)
            live = self.command(directory / "scripts/finance_challenge.py", "run", cwd=directory)
            self.assertEqual(live, (directory / bundle.REPORT).read_bytes())
            self.assertEqual(json.loads(live)["outcome"], "PASS")
            original = self.command(directory / "scripts/public_lab.py", "verify", cwd=directory)
            self.assertEqual(original, (directory / "public_lab/reports/verification.json").read_bytes())

    def test_foreign_or_unreviewed_paths_are_excluded_from_packaging(self):
        for name in (
            "../manifest.json", "public_lab/financial/vectors/unreviewed-input.json",
            "public_lab/financial/vectors/secrets.key", "public_lab/financial/vectors/A00.json/../A01.json",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "unexpected vector path"):
                bundle.vector_entries({"cases": [{"fixture": name}]}, {})

    def test_runner_failure_invalidates_build_even_if_stdout_claims_success(self):
        fake = b'{"outcome":"PASS"}'
        with patch.object(bundle.subprocess, "run", return_value=subprocess.CompletedProcess([], 2, fake, b"")):
            with self.assertRaisesRegex(ValueError, "challenge runner failed"):
                bundle.checked_run()
        with patch.object(bundle.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")):
            with self.assertRaisesRegex(ValueError, "completed result"):
                bundle.checked_run()

    def command(self, script, *args, cwd):
        result = subprocess.run([sys.executable, "-I", str(script), *map(str, args)], cwd=cwd,
                                capture_output=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-1500:])
        return result.stdout


if __name__ == "__main__":
    unittest.main()
