"""Build and check the deterministic Quorvane financial review package offline."""

import argparse
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import subprocess
import sys
from zipfile import ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_public_lab import replace_output


ORIGINAL_COMMIT = "1d6dddd654489ebdc3ddc028dc23b59d8d407281"
ORIGINAL_TREE = "20f161ffa00045d795fc7ee76740002d89c9506f"
ORIGINAL_ZIP = "public_lab/quorvane-public-lab-001.zip"
ORIGINAL_SHA256 = "0d14aeca661a8c01318ee55258e9198fb27cc1d8772e146b6dd296f7673342c7"

ARCHIVE = "public_lab/quorvane-public-lab-002.zip"
PAGE = "public_lab/financial/index.html"
REPORT = "public_lab/financial/results.json"
INVENTORY = "public_lab/financial/inventory.json"
MATRIX = "public_lab/financial/cases.json"
# List public inputs explicitly. Workspace files, local reports, and directories
# added by a reviewer must never silently become part of a public bundle.
REVIEW_FILES = (
    MATRIX, "public_lab/financial/README.md", "public_lab/REVIEW_SCOPE.md",
    "scripts/finance_challenge.py", "scripts/finance_challenge_cases.py",
    "scripts/financial_effect_controls.py", "public_lab/financial/controls/target.json",
    "test_financial_runner.py", "test_financial_effect_controls.py",
    "test_financial_challenge_cases.py",
    "scripts/financial_receipt_check.py", "test_financial_receipt_check.py",
)
TARGET_MODULES = (
    "clearance", "clearance_cli", "clearance_report", "education_fixture_caller",
    "education_target", "education_transport", "finance_fixture_caller", "finance_target",
    "finance_transport", "voidcell", "voidcell002", "voidcell002_anchor", "voidcell002_probe",
    "voidcell002_transport", "voidcell_records", "voidcell_service",
)
TARGET_FILES = (
    "examples/quorvane_education_demo.py", "examples/quorvane_finance_demo.py",
    *(f"wolfalibi/{module}.py" for module in TARGET_MODULES),
)
TARGET_SOURCES_SHA256 = "3fc459a6f6eeb3efbd3483f7117823eaa5ad922ca8d2998e422cca8bc18343fd"
VECTOR_NAME = re.compile(r"public_lab/financial/vectors/[A-F][0-9]{2}\.(?:json|txt)\Z")
BASE_INPUT = re.compile(r"public_lab/vectors/(?:finance|history)/(?:genuine\.json|pins\.json|challenge\.txt)\Z")
START = b"""QUORVANE / PUBLIC LAB 002
Financial security challenge

Extract the entire ZIP. Open public_lab/financial/index.html for the challenge
desk or public_lab/index.html for the original signed-evidence explorer.
Read public_lab/REVIEW_SCOPE.md and public_lab/financial/README.md.

From this directory, use Python 3.11+ with cryptography==50.0.0 installed:
  python -I scripts/finance_challenge.py run
  python -I scripts/public_lab.py verify

The inventory at public_lab/financial/inventory.json covers the other ZIP
members. Compare the ZIP's SHA-256 with the archive digest in a separately
obtained qualification report for the chosen Git tree. Imported reports are
reviewer-supplied observations.
"""


def checked_run():
    cmd = [sys.executable, "-I", str(ROOT / "scripts/finance_challenge.py"), "run"]
    completed = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=120)
    if completed.returncode:
        raise ValueError("challenge runner failed; run python -I scripts/finance_challenge.py run for the result")
    result = json.loads(completed.stdout)
    if not isinstance(result, dict) or result.get("outcome") != "PASS":
        raise ValueError("challenge runner did not return the expected completed result")
    return completed.stdout, result


def base_entries(raw):
    if sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise ValueError("Lab 001 ZIP differs from the exact PR #35 archive")
    with ZipFile(BytesIO(raw)) as inherited:
        return {name: inherited.read(name) for name in inherited.namelist() if name != "START-HERE.txt"}


def read_source(name):
    path = ROOT / name
    # Input names come from constants or the restricted fixture grammar.
    if any((ROOT / prefix).is_symlink() for prefix in (Path(name), *Path(name).parents)):
        raise ValueError(f"review source is a symbolic link: {name}")
    if not path.is_file():
        raise ValueError(f"review source is missing: {name}")
    return path.read_bytes()


def vector_entries(matrix, inherited):
    entries = {}
    for case in matrix["cases"]:
        name = case["fixture"]
        if BASE_INPUT.fullmatch(name):
            content = inherited[name]
        elif VECTOR_NAME.fullmatch(name):
            content = read_source(name)
            entries[name] = content
        else:
            raise ValueError(f"unexpected vector path in matrix: {name!r}")
        if sha256(content).hexdigest() != case["sha256"]:
            raise ValueError(f"vector fingerprint differs from matrix: {name}")
    return entries


def archive_bytes(entries):
    out = BytesIO()
    with ZipFile(out, "w") as archive:
        for name, data in sorted(entries.items()):
            entry = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    return out.getvalue()


def build():
    from render_financial_explorer import render

    inherited = base_entries(read_source(ORIGINAL_ZIP))
    for name, content in inherited.items():
        if read_source(name) != content:
            raise ValueError(f"checked-out verifier or evidence differs from Lab 001: {name}")
    target = {name: read_source(name) for name in TARGET_FILES}
    target_hashes = {name: sha256(data).hexdigest() for name, data in target.items()}
    fingerprint = json.dumps(target_hashes, sort_keys=True, separators=(",", ":")).encode("ascii")
    if sha256(fingerprint).hexdigest() != TARGET_SOURCES_SHA256:
        raise ValueError("synthetic target source differs from the verified PR #35 base")
    additions = {**target, **{name: read_source(name) for name in REVIEW_FILES}}
    additions.update(vector_entries(json.loads(additions[MATRIX]), inherited))
    report_bytes, report = checked_run()
    generated = {PAGE: render(report), REPORT: report_bytes}
    entries = {**inherited, **additions, **generated, "START-HERE.txt": START}
    inventory = {
        "schema": "QUORVANE_PUBLIC_LAB_002_INVENTORY_V1",
        "base": {"commit": ORIGINAL_COMMIT, "tree": ORIGINAL_TREE,
                 "archive": ORIGINAL_ZIP, "archive_sha256": ORIGINAL_SHA256},
        "algorithm": "SHA-256",
        "files": {name: sha256(content).hexdigest() for name, content in sorted(entries.items())},
    }
    generated[INVENTORY] = (json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode("utf-8")
    entries[INVENTORY] = generated[INVENTORY]
    generated[ARCHIVE] = archive_bytes(entries)
    return generated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="compare with the committed artifacts without writing")
    group.add_argument("--archive", type=Path, help="write a separate fresh ZIP to a new path")
    options = parser.parse_args()
    result = {"schema": "QUORVANE_PUBLIC_LAB_002_BUILD_V1", "outcome": "BLOCKED"}
    try:
        outputs = build()
        if options.archive:
            with options.archive.open("xb") as stream:
                stream.write(outputs[ARCHIVE])
        else:
            for name, content in outputs.items():
                if options.check:
                    if read_source(name) != content:
                        raise ValueError(f"stale build output: {name}")
                else:
                    replace_output(ROOT / name, content)
        result.update(outcome="PASS", artifacts={
            name: sha256(content).hexdigest() for name, content in outputs.items()
        })
    except (ImportError, KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        result["reason"] = str(exc)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
