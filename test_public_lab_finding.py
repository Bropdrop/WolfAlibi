"""Hostile-boundary tests for the offline public-lab finding inbox."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest
from unittest.mock import patch


_ROOT = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "public_lab_finding_under_test", _ROOT / "scripts" / "public_lab_finding.py"
)
assert _SPEC is not None and _SPEC.loader is not None
FINDINGS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(FINDINGS)


class PublicLabFindingTests(unittest.TestCase):
    def setUp(self):
        self._temporary = TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.manifest = self.root / "public_lab" / "manifest.json"
        self.manifest.parent.mkdir()
        self.artifacts = {
            "education": {
                "genuine.json": hashlib.sha256(b"fictional education genuine").hexdigest(),
                "tampered.json": hashlib.sha256(b"fictional education tampered").hexdigest(),
            },
            "finance": {
                "genuine.json": hashlib.sha256(b"fictional finance genuine").hexdigest(),
                "tampered.json": hashlib.sha256(b"fictional finance tampered").hexdigest(),
            },
            "history": {
                "genuine.json": hashlib.sha256(b"fictional history genuine").hexdigest(),
                "tampered.json": hashlib.sha256(b"fictional history tampered").hexdigest(),
            },
        }
        manifest = {
            "schema": "quorvane.public-lab.manifest.v1",
            "experiments": [
                {"id": experiment, "files": files}
                for experiment, files in self.artifacts.items()
            ],
        }
        self.manifest.write_bytes(json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
        self.inbox = self.root / "review-inbox"
        self.finding_path = self.root / "finding.json"
        self.finding = {
            "schema": FINDINGS.FINDING_SCHEMA,
            "experiment": "education",
            "variant": "genuine",
            "artifact_sha256": self.artifacts["education"]["genuine.json"],
            "manifest_sha256": hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
            "environment": "synthetic local Linux fixture",
            "steps": "Ran the fictional education genuine vector offline.",
            "expected": "The independent verifier accepts the genuine vector.",
            "observed": "The verifier reported the expected synthetic result.",
        }
        self._write_finding(self.finding)

    def tearDown(self):
        self._temporary.cleanup()

    def _write_finding(self, finding, *, raw=None):
        if raw is None:
            raw = json.dumps(finding, indent=2, sort_keys=True).encode("utf-8")
        self.finding_path.write_bytes(raw)

    def _submit(self):
        return FINDINGS.submit_file(self.finding_path, self.inbox, manifest_path=self.manifest)

    def test_valid_submit_emits_typed_receipt_and_canonical_private_artifact(self):
        output = io.StringIO()
        with patch.object(FINDINGS, "DEFAULT_MANIFEST", self.manifest), redirect_stdout(output):
            status = FINDINGS.main([
                "submit", str(self.finding_path), "--inbox", str(self.inbox),
            ])
        self.assertEqual(status, 0)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["schema"], FINDINGS.RECEIPT_SCHEMA)
        self.assertEqual(receipt["outcome"], "ACCEPTED")
        self.assertEqual(receipt["artifact_sha256"], self.finding["artifact_sha256"])
        self.assertEqual(receipt["manifest_sha256"], self.finding["manifest_sha256"])
        self.assertEqual(receipt["stored_as"], receipt["finding_sha256"] + ".json")
        stored = self.inbox / receipt["stored_as"]
        self.assertEqual(stored.read_bytes(), FINDINGS._canonical(self.finding))
        self.assertEqual(stat.S_IMODE(stored.stat().st_mode), 0o600)

    def test_malformed_json_is_rejected_before_creating_an_inbox(self):
        duplicate_schema = (
            b'{"schema":"quorvane.public-lab.finding.v1",'
            b'"schema":"quorvane.public-lab.finding.v1"}'
        )
        self._write_finding(None, raw=duplicate_schema)
        with self.assertRaises(FINDINGS.FindingError) as raised:
            self._submit()
        self.assertEqual(raised.exception.code, "MALFORMED_FINDING")
        self.assertFalse(self.inbox.exists())

    def test_unhashable_selectors_and_lone_surrogates_are_typed_rejections(self):
        cases = {
            "experiment-list": dict(self.finding, experiment=["education"]),
            "variant-object": dict(self.finding, variant={"name": "genuine"}),
            "lone-surrogate": dict(self.finding, environment="\ud800"),
        }
        for label, malformed in cases.items():
            inbox = self.root / f"{label}-inbox"
            self._write_finding(malformed)
            output = io.StringIO()
            with self.subTest(label), patch.object(FINDINGS, "DEFAULT_MANIFEST", self.manifest), \
                 redirect_stdout(output):
                status = FINDINGS.main([
                    "submit", str(self.finding_path), "--inbox", str(inbox),
                ])
            self.assertEqual(status, 2)
            self.assertEqual(json.loads(output.getvalue()), {
                "schema": FINDINGS.RECEIPT_SCHEMA,
                "outcome": "REJECTED",
                "reason": "MALFORMED_FINDING",
            })
            self.assertFalse(inbox.exists())

    def test_stale_manifest_and_artifact_references_are_rejected(self):
        stale_manifest = dict(self.finding, manifest_sha256="0" * 64)
        with self.subTest("manifest"):
            self._write_finding(stale_manifest)
            with self.assertRaises(FINDINGS.FindingError) as raised:
                self._submit()
            self.assertEqual(raised.exception.code, "STALE_MANIFEST_REFERENCE")
            self.assertFalse(self.inbox.exists())

        stale_artifact = dict(self.finding, artifact_sha256="1" * 64)
        with self.subTest("artifact"):
            self._write_finding(stale_artifact)
            with self.assertRaises(FINDINGS.FindingError) as raised:
                self._submit()
            self.assertEqual(raised.exception.code, "STALE_ARTIFACT_REFERENCE")
            self.assertFalse(self.inbox.exists())

    def test_duplicate_is_idempotent_even_when_source_json_format_changes(self):
        accepted = self._submit()
        self._write_finding(self.finding, raw=json.dumps(self.finding, separators=(",", ":")).encode())
        duplicate = self._submit()
        self.assertEqual(accepted["outcome"], "ACCEPTED")
        self.assertEqual(duplicate["outcome"], "DUPLICATE")
        self.assertEqual(duplicate["finding_sha256"], accepted["finding_sha256"])
        self.assertEqual(list(self.inbox.glob("*.json")), [
            self.inbox / accepted["stored_as"],
        ])

    def test_conflicting_content_address_is_never_overwritten(self):
        self.inbox.mkdir(mode=0o700)
        content = FINDINGS._canonical(self.finding)
        name = hashlib.sha256(content).hexdigest() + ".json"
        conflict = self.inbox / name
        conflict.write_bytes(b'{"unrelated":"conflicting local content"}')
        before = conflict.read_bytes()
        with self.assertRaises(FINDINGS.FindingConflict) as raised:
            self._submit()
        self.assertEqual(raised.exception.code, "CONTENT_ADDRESS_CONFLICT")
        self.assertEqual(conflict.read_bytes(), before)

    def test_concurrent_identical_submits_publish_once(self):
        barrier = Barrier(2)

        def submit_after_barrier():
            barrier.wait()
            return self._submit()

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = [future.result() for future in (
                pool.submit(submit_after_barrier), pool.submit(submit_after_barrier)
            )]
        self.assertEqual(sorted((first["outcome"], second["outcome"])), ["ACCEPTED", "DUPLICATE"])
        self.assertEqual(first["finding_sha256"], second["finding_sha256"])
        self.assertEqual(len(list(self.inbox.iterdir())), 1)

    def test_symlinked_inbox_or_destination_is_rejected_without_following_it(self):
        target = self.root / "outside"
        target.mkdir(mode=0o700)
        os.symlink(target, self.inbox)
        with self.subTest("inbox"):
            with self.assertRaises(FINDINGS.FindingError) as raised:
                self._submit()
            self.assertEqual(raised.exception.code, "UNSAFE_INBOX")
            self.assertEqual(list(target.iterdir()), [])

        self.inbox.unlink()
        self.inbox.mkdir(mode=0o700)
        stored = FINDINGS._canonical(self.finding)
        destination = self.inbox / (hashlib.sha256(stored).hexdigest() + ".json")
        outside_file = target / "must-not-change"
        outside_file.write_bytes(b"outside")
        os.symlink(outside_file, destination)
        with self.subTest("destination"):
            with self.assertRaises(FINDINGS.FindingConflict) as raised:
                self._submit()
            self.assertEqual(raised.exception.code, "CONTENT_ADDRESS_CONFLICT")
            self.assertEqual(outside_file.read_bytes(), b"outside")

    def test_submission_never_uses_network_or_shell_interfaces(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network use")), \
             patch.object(subprocess, "run", side_effect=AssertionError("shell use")):
            receipt = self._submit()
        self.assertEqual(receipt["outcome"], "ACCEPTED")


if __name__ == "__main__":
    unittest.main()
