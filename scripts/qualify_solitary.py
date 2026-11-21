"""Emit exact-tree Solitary qualification and its local evidence artifacts."""

import json
from pathlib import Path
import platform
import re
import sys
import tempfile

import cryptography

from qualify_stage35 import run, unit_suite


def cli(*args):
    record = run(sys.executable, "-m", "wolfalibi_cli", "byoa", *args)
    try:
        record["result"] = json.loads(record["stdout"])
    except ValueError:
        record["result"] = {"outcome": "BLOCKED", "reason": "missing CLI JSON"}
    return record


def main():
    revision = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    before = run("git", "status", "--porcelain")
    if revision["exit_code"]:
        raise SystemExit(revision["stderr"])
    commit, tree = revision["stdout"].splitlines()
    doctor = cli("doctor")
    pins = doctor["result"].get("declared_pins", {}).get("worker_profile", {})
    worker_python = run(pins["python"], "--version") if "python" in pins else None
    manifest = "examples/byoa_solitary_manifest.json"
    inspect = cli("inspect", "--manifest", manifest)
    focused = unit_suite("-v", "test_byoa_solitary.py")
    full = unit_suite("discover", "-v")
    mutations = run(sys.executable, "-u", "mutation_test.py")
    mutations["detected"] = len(re.findall(r"^CAUGHT\s+M\d+", mutations["stdout"], re.MULTILINE))
    with tempfile.TemporaryDirectory(prefix="wolfalibi-solitary-qualification-") as directory:
        trial = cli("test", "--manifest", manifest, "--consent", "--state-dir", directory)
        expected, evidence = Path(directory, "expected.json"), Path(directory, "evidence.json")
        checked = cli("verify", "--evidence", str(evidence), "--expect", str(expected))
        exported = {
            key: json.loads(file.read_bytes()) for key, file in
            (("expected", expected), ("evidence", evidence)) if file.is_file()
        }
    after = run("git", "status", "--porcelain")
    final = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    clean = before["exit_code"] == after["exit_code"] == 0 and before["stdout"] == after["stdout"] == ""
    unchanged = final["exit_code"] == 0 and revision["stdout"] == final["stdout"]
    passed = (
        clean and unchanged and focused["outcome"] == full["outcome"] == "PASS"
        and mutations["exit_code"] == 0 and mutations["detected"] == 8
        and doctor["result"]["outcome"] == "READY" and inspect["result"]["outcome"] == "VALID"
        and trial["result"]["outcome"] == "COMPLETED" and checked["result"]["outcome"] == "VERIFIED"
        and not any(item["exit_code"] for item in (doctor, inspect, trial, checked))
    )
    print(json.dumps({
        "schema": "wolfalibi.solitary.local-qualification.v1",
        "commit": commit, "tree": tree,
        "working_tree_clean": clean, "revision_unchanged": unchanged,
        "environment": {
            "platform": platform.platform(), "python": platform.python_version(),
            "worker_python": worker_python, "bubblewrap": pins.get("launcher_version"),
            "cryptography": cryptography.__version__,
        },
        "doctor": doctor, "inspect": inspect, "trial": trial, "offline_verification": checked,
        "exported": exported, "focused_tests": focused, "full_suite": full, "mutation_suite": mutations,
        "outcome": "PASS" if passed else "BLOCKED",
        "assurance": "BROKER_ONLY", "confinement": "BLOCKED", "qualification": "LOCAL_BUILDER_RUN",
    }, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
