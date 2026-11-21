"""Emit exact-tree local qualification for the synthetic VoidCell effect gate.

This harness runs only checked-in, local synthetic fixtures.  It retains the
signed demo artifacts outside the checkout and reports their metadata, rather
than uploading them or treating a local result as a production claim.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import stat
import sys
import tempfile

import cryptography

from qualify_stage35 import ROOT, run, unit_suite


def _cli(*args):
    entry = run(sys.executable, "-m", "wolfalibi.voidcell_demo", *args)
    try:
        result = json.loads(entry["stdout"])
    except (TypeError, ValueError):
        result = None
    entry["result"] = result if type(result) is dict else {
        "outcome": "BLOCKED", "reason": "missing VoidCell CLI JSON",
    }
    return entry


def _status():
    return run("git", "status", "--porcelain=v1")


def _clean(record):
    return record["exit_code"] == 0 and record["stdout"] == ""


def _export_dir(path):
    if path is None:
        return Path(tempfile.mkdtemp(prefix="wolfalibi-voidcell-qualification-"))
    path = path.resolve(strict=True)
    entry = path.lstat()
    if (
        path == ROOT
        or ROOT in path.parents
        or not stat.S_ISDIR(entry.st_mode)
        or entry.st_uid != os.geteuid()
        or entry.st_mode & 0o077
        or any(path.iterdir())
    ):
        raise ValueError("export directory must be empty, private and outside the checkout")
    return path


def _artifact(path):
    path = Path(path)
    result = {"path": str(path), "exists": path.is_file()}
    if not path.is_file():
        return result
    try:
        data = path.read_bytes()
        result["bytes"] = len(data)
        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["json"] = json.loads(data)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        result["error"] = str(exc)
    return result


def _external_record(value):
    """Leave signed evidence on disk; publish only its local metadata."""
    if isinstance(value, dict):
        return {
            key: _external_record(member)
            for key, member in value.items()
            if key != "json"
        }
    if isinstance(value, list):
        return [_external_record(member) for member in value]
    return value


def _named_artifact(result, key, artifact):
    value = result.get(key)
    if type(value) is not str:
        return False
    try:
        return Path(value).resolve(strict=False) == Path(artifact["path"]).resolve(strict=False)
    except (OSError, RuntimeError):
        return False


def _demo(directory):
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    demo = _cli("demo", "--consent", "--state-dir", str(directory))
    receipt = _artifact(directory / "receipt.json")
    expected = _artifact(directory / "expected.json")
    report = _artifact(directory / "report.json")
    result = {
        "run": demo,
        "receipt": receipt,
        "expectations": expected,
        "report": report,
        "passed": False,
    }
    if not (receipt["exists"] and expected["exists"] and report["exists"]):
        return result
    checked = _cli("verify", "--receipt", receipt["path"], "--expect", expected["path"])
    result["verified"] = checked

    run_result = demo["result"]
    report_result = report.get("json")
    shared = {
        "outcome": "PASS",
        "effect_count": 1,
        "direct": "DENIED",
        "observation_only": "DENIED",
        "missing_owner": "DENIED",
        "replay": "DENIED",
        "dispatch": "AMBIGUOUS",
        "reconciliation": "ACCEPTED_EVIDENCED",
        "confinement": "BLOCKED",
    }
    result["passed"] = (
        demo["exit_code"] == checked["exit_code"] == 0
        and all(run_result.get(key) == value for key, value in shared.items())
        and type(report_result) is dict
        and all(report_result.get(key) == value for key, value in shared.items())
        and type(report_result.get("credential_provisioning")) is dict
        and report_result["credential_provisioning"].get("target_or_gateway_private_keys_delivered") is False
        and report_result["credential_provisioning"].get("close_fds") is True
        and report_result.get("target_effects_after_denials") == 0
        and _named_artifact(run_result, "receipt", receipt)
        and _named_artifact(run_result, "expected", expected)
        and _named_artifact(run_result, "report", report)
        and checked["result"].get("outcome") == "VERIFIED"
        and checked["result"].get("assurance") == "RESOURCE_SIDE_EFFECT_GATE"
        and checked["result"].get("verification_scope") == "TARGET_RECEIPT_ONLY"
        and checked["result"].get("confinement") == "BLOCKED"
    )
    return result


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--export-dir", type=Path,
        help="existing empty private directory outside the checkout",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    revision = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    if revision["exit_code"]:
        raise SystemExit(revision["stderr"])
    commit, tree = revision["stdout"].splitlines()
    before = _status()
    result = {
        "schema": "wolfalibi.voidcell.local-qualification.v1",
        "commit": commit,
        "tree": tree,
        "working_tree_clean_start": _clean(before),
        "assurance": "RESOURCE_SIDE_EFFECT_GATE",
        "confinement": "BLOCKED",
        "qualification": "LOCAL_BUILDER_RUN",
        "network_upload": False,
        "outcome": "BLOCKED",
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
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "sqlite": sqlite3.sqlite_version,
        "cryptography": cryptography.__version__,
        "system_python": (
            run("/usr/bin/python3", "--version")
            if Path("/usr/bin/python3").is_file() else None
        ),
        "bubblewrap": run(bwrap, "--version") if bwrap else None,
    }
    focused = unit_suite("-v", "test_voidcell.py")
    full = unit_suite("discover", "-v")
    mutations = run(sys.executable, "-u", "mutation_test.py")
    mutations["detected"] = len(re.findall(r"^CAUGHT\s+M\d+", mutations["stdout"], re.MULTILINE))
    demo = _demo(directory / "demo")
    after = _status()
    final = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    unchanged = final["exit_code"] == 0 and final["stdout"] == revision["stdout"]
    passed = (
        _clean(after)
        and unchanged
        and focused["outcome"] == full["outcome"] == "PASS"
        and mutations["exit_code"] == 0
        and mutations["detected"] == 8
        and demo["passed"]
    )
    result.update(
        working_tree_clean_end=_clean(after),
        revision_unchanged=unchanged,
        environment=environment,
        focused_tests=focused,
        full_suite=full,
        mutation_suite=mutations,
        demo=demo,
        export_dir=str(directory),
        outcome="PASS" if passed else "BLOCKED",
    )
    print(json.dumps(_external_record(result), indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
