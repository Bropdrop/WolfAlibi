#!/usr/bin/env python3
"""Run synthetic qualification and emit an exact-source JSON report.

This command performs no upstream download, target connection or deployment.
It writes only the explicitly requested local report and optional transcript.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shirudo_adapter.model import UPSTREAM_COMMIT, canonical_json


def case_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from case_ids(item)
        else:
            yield item.id()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()
    paths = [ROOT / "pyproject.toml", ROOT / ".github/workflows/shirudo-adapter.yml"]
    for directory in ("shirudo_adapter", "tests", "scripts"):
        paths.extend((ROOT / directory).rglob("*.py"))
    source_hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in sorted(paths)}
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    test_ids = sorted(case_ids(suite))
    transcript = io.StringIO()
    result = unittest.TextTestRunner(stream=transcript, verbosity=2).run(suite)
    demo = subprocess.run([sys.executable, str(ROOT / "scripts/demo_shirudo.py")],
                          cwd=ROOT, capture_output=True, text=True, timeout=30)
    try:
        demo_result = json.loads(demo.stdout)
    except ValueError:
        demo_result = {"result": "INVALID_OUTPUT"}
    if type(demo_result) is not dict:
        demo_result = {"result": "INVALID_OUTPUT"}
    good_demo = (demo.returncode == 0 and type(demo_result) is dict and
                 demo_result.get("result") == "PASS" and
                 demo_result.get("assurance") == "SYNTHETIC" and
                 demo_result.get("real_upstream_verification") is False and
                 demo_result.get("current_authorization") is False)
    passed = result.testsRun > 0 and result.wasSuccessful() and not result.skipped and good_demo
    report = {
        "schema": "wolfalibi.shirudo.synthetic-qualification.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "result": "PASS" if passed else "FAIL",
        "scope": "SYNTHETIC_ADAPTER_QUALIFICATION_ONLY",
        "production_status": "BLOCKED",
        "real_upstream_attestation": "NOT_QUALIFIED",
        "upstream_source_reference": UPSTREAM_COMMIT,
        "source_files_sha256": source_hashes,
        "source_snapshot_sha256": hashlib.sha256(canonical_json(source_hashes)).hexdigest(),
        "environment": {"python": platform.python_version(), "system": platform.system(),
                        "cryptography": importlib.metadata.version("cryptography")},
        "unit_tests": {"run": result.testsRun, "failures": len(result.failures),
                       "errors": len(result.errors), "skipped": len(result.skipped),
                       "count_unit": "test methods; mutation subcases are not counted separately",
                       "ids": test_ids},
        "demo": {"exit_code": demo.returncode, "result": demo_result},
        "limitations": [
            "Synthetic fixtures do not demonstrate genuine TPM cryptographic verification.",
            "Competing service instances use threads; interruption is injected, not a power loss.",
            "No live target state, shield effectiveness, deployment or authorization is qualified.",
            "The source hashes identify local tested bytes, not independent execution provenance.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
    if args.log:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        args.log.write_text(transcript.getvalue(), encoding="utf-8")
    print(json.dumps({"result": report["result"], "tests": result.testsRun,
                      "failures": len(result.failures), "errors": len(result.errors),
                      "skipped": len(result.skipped), "demo": demo_result.get("result"),
                      "source_snapshot_sha256": report["source_snapshot_sha256"],
                      "production_status": report["production_status"]}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
