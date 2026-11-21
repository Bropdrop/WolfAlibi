"""Emit exact-tree local Clearance test results and retain the demo artifacts."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tempfile

import cryptography

from qualify_stage35 import ROOT, run, unit_suite
from wolfalibi.clearance_records import verify_decision


def _cli(*args):
    entry = run(sys.executable, "-m", "wolfalibi_cli", "byoa", "clearance", *args)
    try:
        result = json.loads(entry["stdout"])
    except ValueError:
        result = None
    entry["result"] = result if type(result) is dict else {"outcome": "BLOCKED", "reason": "missing CLI JSON"}
    return entry


def _demo(directory, *, approve):
    directory.mkdir(mode=0o700)
    args = ("--approve-synthetic-read",) if approve else ()
    demo = _cli("demo", "--consent", "--state-dir", str(directory), *args)
    report, expected = directory / "report.json", directory / "expected.json"
    result = {"run": demo, "report": str(report), "expectations": str(expected), "passed": False}
    if not report.is_file() or not expected.is_file():
        return result
    checked = _cli("verify", "--report", str(report), "--expect", str(expected))
    result["verified"] = checked
    if approve:
        result["passed"] = (
            demo["exit_code"] == checked["exit_code"] == 0 and demo["result"]["outcome"] == "ALLOWED"
            and demo["result"].get("upstream_reads") == 1 and checked["result"]["outcome"] == "VERIFIED"
        )
        return result
    try:
        artifact = json.loads(report.read_bytes())
        references = json.loads(expected.read_bytes())
        decision = verify_decision(artifact["admission"], bytes.fromhex(references["gateway_pub"]))
    except (KeyError, OSError, TypeError, ValueError):
        return result
    result["signed_denial"] = decision
    result["passed"] = (
        demo["exit_code"] == checked["exit_code"] == 2
        and demo["result"]["outcome"] == artifact["outcome"] == decision["outcome"] == "DENIED"
        and decision["effect"] == "NONE" and demo["result"].get("upstream_reads") == 0
        and artifact["request"] is None and artifact["operation"] is None
        and checked["result"]["outcome"] in {"REJECTED", "BLOCKED"}
    )
    return result


def _status():
    return run("git", "status", "--porcelain=v1")


def _clean(result):
    return result["exit_code"] == 0 and result["stdout"] == ""


def _export_dir(path):
    if path is None:
        return Path(tempfile.mkdtemp(prefix="wolfalibi-clearance-qualification-"))
    path = path.resolve(strict=True)
    entry = path.stat()
    if (path == ROOT or ROOT in path.parents or entry.st_uid != os.geteuid()
            or entry.st_mode & 0o077 or any(path.iterdir())):
        raise ValueError("export directory must be empty, private and outside the checkout")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-dir", type=Path, help="existing private empty directory outside the checkout")
    args = parser.parse_args()
    revision = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    if revision["exit_code"]:
        raise SystemExit(revision["stderr"])
    commit, tree = revision["stdout"].splitlines()
    before = _status()
    result = {
        "schema": "wolfalibi.clearance.local-qualification.v1",
        "commit": commit, "tree": tree, "working_tree_clean_start": _clean(before),
        "assurance": "BROKER_ONLY", "confinement": "BLOCKED",
        "qualification": "LOCAL_BUILDER_RUN", "network_upload": False, "outcome": "BLOCKED",
    }
    if not _clean(before):
        result["reason"] = "qualification requires a clean working tree"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2
    try:
        directory = _export_dir(args.export_dir)
    except (OSError, ValueError) as exc:
        result["reason"] = str(exc)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2

    bwrap = shutil.which("bwrap")
    environment = {
        "platform": platform.platform(), "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "system_python": run("/usr/bin/python3", "--version") if Path("/usr/bin/python3").is_file() else None,
        "bubblewrap": run(bwrap, "--version") if bwrap else None,
    }
    focused = unit_suite("-v", "test_clearance.py", "test_clearance_report.py")
    full = unit_suite("discover", "-v")
    mutations = run(sys.executable, "-u", "mutation_test.py")
    mutations["detected"] = len(re.findall(r"^CAUGHT\s+M\d+", mutations["stdout"], re.MULTILINE))
    denied = _demo(directory / "denied", approve=False)
    allowed = _demo(directory / "allowed", approve=True)
    after = _status()
    final = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    unchanged = final["exit_code"] == 0 and final["stdout"] == revision["stdout"]
    passed = (
        _clean(after) and unchanged and focused["outcome"] == full["outcome"] == "PASS"
        and mutations["exit_code"] == 0 and mutations["detected"] == 8
        and denied["passed"] and allowed["passed"]
    )
    result.update(
        working_tree_clean_end=_clean(after), revision_unchanged=unchanged,
        environment=environment, focused_tests=focused, full_suite=full, mutation_suite=mutations,
        denied=denied, allowed=allowed, export_dir=str(directory), outcome="PASS" if passed else "BLOCKED",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
