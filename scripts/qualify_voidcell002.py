"""Emit local VOIDCELL002 protocol evidence without claiming custody proof.

The experiment's protocol controls can be qualified locally.  Custody remains
UNSUPPORTED unless an operator has independently provisioned two ordinary,
non-root Linux principals; this harness neither creates accounts nor attempts
to impersonate one.
"""

import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import sys

import cryptography

from qualify_stage35 import ROOT, run, unit_suite


def _status():
    return run("git", "status", "--porcelain=v1")


def _clean(record):
    return record["exit_code"] == 0 and record["stdout"] == ""


def _doctor():
    record = run(sys.executable, "-m", "wolfalibi.voidcell002", "doctor")
    try:
        parsed = json.loads(record["stdout"])
    except (TypeError, ValueError):
        parsed = None
    record["result"] = parsed if type(parsed) is dict else {
        "outcome": "BLOCKED", "reason": "missing VOIDCELL002 doctor JSON",
    }
    record["expected_here"] = (
        record["exit_code"] == 2
        and record["result"].get("outcome") == "UNSUPPORTED"
        and record["result"].get("custody") == "UNSUPPORTED"
    )
    return record


def _environment():
    bwrap = shutil.which("bwrap")
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "sqlite": sqlite3.sqlite_version,
        "cryptography": cryptography.__version__,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "gid": os.getgid() if hasattr(os, "getgid") else None,
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "egid": os.getegid() if hasattr(os, "getegid") else None,
        "system_python": (
            run("/usr/bin/python3", "--version")
            if Path("/usr/bin/python3").is_file() else None
        ),
        "bubblewrap": run(bwrap, "--version") if bwrap else None,
    }


def main(argv=None):
    if argv:
        raise SystemExit("qualify_voidcell002 accepts no arguments")
    revision = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    if revision["exit_code"]:
        raise SystemExit(revision["stderr"])
    commit, tree = revision["stdout"].splitlines()
    before = _status()
    result = {
        "schema": "wolfalibi.voidcell002.local-qualification.v1",
        "commit": commit,
        "tree": tree,
        "working_tree_clean_start": _clean(before),
        "environment": _environment(),
        "custody": "UNSUPPORTED",
        "protocol_qualification": "BLOCKED",
        "network_upload": False,
        "outcome": "UNSUPPORTED",
    }
    if not _clean(before):
        result["reason"] = "protocol qualification requires a clean working tree"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2

    doctor = _doctor()
    focused = unit_suite("-v", "test_voidcell002.py")
    full = unit_suite("discover", "-v")
    mutations = run(sys.executable, "-u", "mutation_test.py")
    mutations["detected"] = len(re.findall(r"^CAUGHT\s+M\d+", mutations["stdout"], re.MULTILINE))
    after = _status()
    final = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    unchanged = final["exit_code"] == 0 and final["stdout"] == revision["stdout"]
    protocol_passed = (
        _clean(after)
        and unchanged
        and focused["outcome"] == full["outcome"] == "PASS"
        and (full["tests"] or 0) >= 214
        and mutations["exit_code"] == 0
        and mutations["detected"] == 8
    )
    result.update(
        working_tree_clean_end=_clean(after),
        revision_unchanged=unchanged,
        doctor=doctor,
        focused_tests=focused,
        full_suite=full,
        mutation_suite=mutations,
        protocol_qualification="PASS" if protocol_passed else "BLOCKED",
        custody=doctor["result"].get("custody", "BLOCKED"),
        outcome="UNSUPPORTED" if doctor["expected_here"] else "BLOCKED",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    # A local protocol pass is not a custody attestation.  The documented
    # unsupported custody outcome intentionally remains a nonzero exit.
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
