"""Run the fixed Quorvane financial review cases against retained public expectations."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))

from scripts import public_lab


BASE_COMMIT = "1d6dddd654489ebdc3ddc028dc23b59d8d407281"
BASE_TREE = "20f161ffa00045d795fc7ee76740002d89c9506f"
MATRIX = "public_lab/financial/cases.json"
VECTOR_DIR = "public_lab/financial/vectors"
# The reviewed source supplies these byte pins independently of the submitted inputs.
MATRIX_SHA256 = "de3a0b1519a4ecabe6ff445a7b6584c77035819954688e5c3ac66dd89cb2b1d4"
BASE_DIGESTS = {
    "public_lab/manifest.json": "83c707ef06be9e9f2623f32605c48d4135841300dd694a9f1fe361b99f011fc8",
    "public_lab/reports/verification.json": "cf213a00dc8e3e1507a7f1f194a5df17691855e7ed145374abed33b50856e7ea",
}
LABELS = dict(public_lab._ASSURANCE)
CONTROLS = ("P01", "P02")
OUTCOMES = {"VERIFIED", "REJECTED", "INPUT_REFUSED", "NOT_ASSESSED", "UNSUPPORTED"}
MAX_BYTES = 262_144


class ReviewError(ValueError):
    """A prerequisite or a control of the financial review failed."""


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _read(root, relative, expected):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ReviewError("invalid inventory path")
    current = root
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise ReviewError(f"linked inventory input: {relative}")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(current, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ReviewError(f"expected regular file: {relative}")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or _sha(data) != expected:
        raise ReviewError(f"inventory digest differs: {relative}")
    return data


def trusted_baseline(root):
    """Return PR #35's public pins, challenges and unchanged historical results."""
    manifest = public_lab._json(_read(root, "public_lab/manifest.json",
                                     BASE_DIGESTS["public_lab/manifest.json"]), "Lab 001 manifest")
    prior = public_lab._json(_read(root, "public_lab/reports/verification.json",
                                  BASE_DIGESTS["public_lab/reports/verification.json"]), "Lab 001 report")
    canonical = {case["id"]: case["genuine"] for case in prior["cases"]}
    trusted = {}
    for experiment in manifest["experiments"]:
        profile = experiment["id"]
        directory = f"public_lab/vectors/{profile}"
        artifacts = {name: _read(root, f"{directory}/{name}", sha)
                     for name, sha in experiment["files"].items()}
        if profile in ("finance", "history"):
            pins = public_lab._json(artifacts["pins.json"], "pinned expectations")
            trusted[profile] = {
                "pins": pins, "genuine": public_lab._json(artifacts["genuine.json"], "original evidence"),
                "challenge": public_lab._challenge(profile, artifacts["challenge.txt"], pins),
                "canonical": canonical[profile],
            }
    return trusted


def _catalog(root):
    raw = _read(root, MATRIX, MATRIX_SHA256)
    document = public_lab._json(raw, "financial challenge matrix")
    if document.get("schema") != "QUORVANE_FINANCIAL_CASES_V1":
        raise ReviewError("unknown financial challenge matrix")
    rows = document["cases"]
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)) or not set(CONTROLS).issubset(ids):
        raise ReviewError("duplicate ids or missing positive controls")
    if not set("ABCDEF").issubset(row["category"] for row in rows):
        raise ReviewError("incomplete challenge categories")
    vectors = {}
    fixture_dir = root / VECTOR_DIR
    if fixture_dir.is_symlink() or not fixture_dir.is_dir():
        raise ReviewError("financial vector directory unavailable")
    for row in rows:
        path = row["fixture"]
        baseline_dir = f"public_lab/vectors/{row['profile']}/"
        if not (path.startswith(VECTOR_DIR + "/") or path.startswith(baseline_dir)):
            raise ReviewError("fixture outside documented financial profile")
        if row["expected"]["outcome"] not in OUTCOMES:
            raise ReviewError("unsupported expected outcome in catalog")
        if path not in vectors:
            vectors[path] = _read(root, path, row["sha256"])
        elif _sha(vectors[path]) != row["sha256"]:
            raise ReviewError("conflicting fixture digest")
    # All financial specimens are flat files. Stop at the first unexpected entry.
    expected = {key for key in vectors if key.startswith(VECTOR_DIR + "/")}
    for item in fixture_dir.iterdir():
        if item.relative_to(root).as_posix() not in expected:
            raise ReviewError("financial vector inventory differs")
    return rows, vectors


def _git(root, *args):
    completed = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                               timeout=15, check=False)
    if completed.returncode:
        raise ReviewError("expected revision could not be verified in Git")
    return completed.stdout.strip()


def _revision(root, commit, tree):
    if not all(isinstance(pin, str) and re.fullmatch("[0-9a-f]{40}", pin) for pin in (commit, tree)):
        raise ReviewError("supply both full lowercase commit and tree identifiers")
    if Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root.resolve():
        raise ReviewError("the qualification directory must be the Git worktree root")
    head, actual_tree, *parents = _git(root, "show", "-s", "--format=%H %T %P", "HEAD").split()
    if (head, actual_tree, parents) != (commit, tree, [BASE_COMMIT]):
        raise ReviewError("stale revision, wrong tree or different direct parent")
    if _git(root, "rev-parse", BASE_COMMIT + "^{tree}") != BASE_TREE:
        raise ReviewError("published parent tree differs")
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ReviewError("exact-tree qualification needs a clean worktree")
    return {"mode": "EXACT_GIT", "commit": head, "tree": actual_tree, "parent": parents[0]}


def _observe(row, raw, trusted):
    # Import inside the runner's operational-error boundary.
    from scripts.finance_challenge_cases import observe
    return observe(row, raw, trusted)


def _run_row(row, raw, trusted):
    record = {key: row[key] for key in ("id", "fixture", "sha256", "expected", "expected_phase")}
    try:
        observed = _observe(row, raw, trusted)
        if not isinstance(observed, dict) or observed.get("outcome") not in OUTCOMES | {"UNEXPECTED_RESULT"}:
            raise ReviewError("unsupported verification result")
        if not all(type(observed.get(key)) is str and observed[key] for key in ("reason", "phase")):
            raise ReviewError("incomplete verification observation")
        full_match = all(observed[key] == row["expected"][key] for key in ("outcome", "reason"))
        full_match = full_match and observed["phase"] == row["expected_phase"]
        if observed["outcome"] == "VERIFIED":
            details = observed.get("details", {})
            expected = trusted[row["profile"]]["canonical"]
            # JSON comparison distinguishes a number from true or false.
            full_match = (full_match and json.dumps(details.get("canonical"), sort_keys=True) ==
                          json.dumps(expected, sort_keys=True) and details.get("settlement") == "UNESTABLISHED"
                          and details.get("operational_authority") == "NOT_ISSUED")
            if row["mode"] in ("repeat", "parallel"):
                full_match = (full_match and details.get("schedule") == row["mode"] and
                              type(details.get("verifications")) is int and details["verifications"] == 2)
        result = "MATCH" if full_match else "MISMATCH"
        if full_match and observed["outcome"] in {"NOT_ASSESSED", "UNSUPPORTED"}:
            result = "UNASSESSED"
        return dict(record, observed=observed, result=result)
    except Exception as exc:
        return dict(record, result="ERROR", observed={"outcome": "ERROR", "phase": "runner",
                    "reason": str(exc) or type(exc).__name__, "error_type": type(exc).__name__})


def _summarize(report, planned):
    rows = report["cases"]
    counts = {label: sum(row["result"] == label for row in rows)
              for label in ("MATCH", "MISMATCH", "ERROR", "UNASSESSED")}
    report["summary"] = {"scheduled": len(planned), "executed": len(rows), "matched": counts["MATCH"],
                         "mismatched": counts["MISMATCH"], "errors": counts["ERROR"],
                         "unassessed": counts["UNASSESSED"]}
    if [row["id"] for row in rows] != [row["id"] for row in planned]:
        raise ReviewError("incomplete or out-of-order challenge execution")
    if any(row["result"] not in ("MATCH", "UNASSESSED") for row in rows):
        raise ReviewError("one or more challenge observations differed or could not run")
    positives = [row["id"] for row in rows if row["result"] == "MATCH"
                 and row["observed"]["outcome"] == "VERIFIED"]
    if not set(CONTROLS).issubset(positives):
        raise ReviewError("both historical positive controls must verify")


def run(case=None, *, root=ROOT, expect_commit=None, expect_tree=None):
    """Evaluate all scheduled cases; single-case runs always include both positives."""
    root = Path(root)
    exact = expect_commit is not None or expect_tree is not None
    report = {"schema": "QUORVANE_FINANCIAL_REVIEW_V1", **LABELS, "outcome": "BLOCKED",
              "selected_case": "all" if case is None else case, "matrix_sha256": MATRIX_SHA256,
              "baseline": {"commit": BASE_COMMIT, "tree": BASE_TREE},
              "provenance": {"mode": "UNVERIFIED" if exact else "PORTABLE"}, "cases": []}
    try:
        if exact:
            report["provenance"] = _revision(root, expect_commit, expect_tree)
        trusted = trusted_baseline(root)
        rows, fixtures = _catalog(root)
        if case is not None and case not in {row["id"] for row in rows}:
            raise ReviewError("unknown financial challenge id")
        planned = [row for row in rows if case is None or row["id"] in (*CONTROLS, case)]
        report["cases"] = [_run_row(row, fixtures[row["fixture"]], trusted) for row in planned]
        _summarize(report, planned)
        if exact:
            _revision(root, expect_commit, expect_tree)
        report["outcome"] = "PASS" if case is None else "SELECTED"
    except Exception as exc:
        report.update(reason=str(exc) or type(exc).__name__, error_type=type(exc).__name__)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("run", help="run the fixed offline financial review")
    command.add_argument("--case", help="select one id alongside both positive controls")
    command.add_argument("--expect-commit", help="external full commit pin, requires --expect-tree and Git")
    command.add_argument("--expect-tree", help="external full tree pin, requires --expect-commit and Git")
    args = parser.parse_args(argv)
    report = run(args.case, expect_commit=args.expect_commit, expect_tree=args.expect_tree)
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0 if report["outcome"] in ("PASS", "SELECTED") else 2


if __name__ == "__main__":
    raise SystemExit(main())
