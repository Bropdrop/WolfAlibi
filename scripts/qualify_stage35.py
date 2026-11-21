"""Emit local Stage 3.5 qualification evidence as JSON."""

import json
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

import cryptography

ROOT = Path(__file__).resolve().parents[1]


def run(*command):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    return {"command": command, "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def unit_suite(*names):
    record = run(sys.executable, "-m", "unittest", *names)
    output = record["stderr"]
    tests = re.search(r"^Ran (\d+) tests? in", output, re.MULTILINE)
    skips = re.search(r"\bskipped=(\d+)\b", output)
    record["tests"] = int(tests[1]) if tests else None
    record["skipped"] = int(skips[1]) if skips else 0
    record["outcome"] = (
        "FAIL" if record["exit_code"] or not tests else "BLOCKED" if skips else "PASS"
    )
    return record


def synthetic_trial(key):
    with tempfile.TemporaryDirectory(prefix="wolfalibi-stage35-qualification-") as state:
        record = run(sys.executable, "-m", "wolfalibi.stage35", "--state-dir", state,
                     "--run-id", "synthetic-qualification", "--challenge", secrets.token_hex(32),
                     "--key", key)
    try:
        result = json.loads(record["stdout"])
    except json.JSONDecodeError:
        result = {"outcome": "BLOCKED", "reason": "trial did not emit JSON"}
    return {"key": key, "expected": "VERIFIED with BROKER_ONLY assurance",
            "actual": result, **record}


def main():
    revision = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    if revision["exit_code"]:
        raise SystemExit(revision["stderr"])
    commit, tree = revision["stdout"].splitlines()
    bwrap = shutil.which("bwrap")
    independent_cases = unit_suite(
        "-v", "test_stage35_measurement.py", "test_stage35_policy.py", "test_stage35_verifier.py",
    )
    full = unit_suite("discover", "-v")
    mutations = run(sys.executable, "-u", "mutation_test.py")
    mutations["detected"] = len(re.findall(r"^CAUGHT\s+M\d+", mutations["stdout"], re.MULTILINE))
    trials = [synthetic_trial(key) for key in ("protected.txt", "reports/summary.txt")]
    passed = (not mutations["exit_code"] and mutations["detected"] == 8
              and independent_cases["outcome"] == full["outcome"] == "PASS"
              and all(item["exit_code"] == 0 for item in trials))
    print(json.dumps({
        "schema": "wolfalibi.stage35.local-qualification.v1",
        "commit": commit, "tree": tree,
        "working_tree_clean": run("git", "status", "--porcelain")["stdout"] == "",
        "environment": {
            "system": platform.platform(),
            "python": platform.python_version(),
            "worker_python": run("/usr/bin/python3", "--version")["stdout"].strip()
            if Path("/usr/bin/python3").is_file() else None,
            "bubblewrap": run(bwrap, "--version")["stdout"].strip() if bwrap else None,
            "cryptography": cryptography.__version__,
        },
        "stage35_tests": independent_cases, "full_suite": full,
        "mutation_suite": mutations, "trials": trials,
        "outcome": "PASS" if passed else "BLOCKED",
        "assurance": "BROKER_ONLY", "confinement": "BLOCKED",
        "qualification": "BUILDER_RUN",
    }, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
