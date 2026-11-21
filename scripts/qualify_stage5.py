"""Emit exact-tree local qualification for the fixed Stage 5 agent profile.

Only checked-in synthetic fixtures are run.  The signed broker evidence,
optional local AgentProbe observation, and owner authorization are reported
as separate axes; this harness never uploads an artifact or claims confinement.
"""

import argparse
import hashlib
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

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wolfalibi.clearance_records import verify_decision


PROFILE = "solitary-python-callback"
MANIFEST = "examples/byoa_solitary_agent_manifest.json"


def _cli(*args):
    entry = run(sys.executable, "-m", "wolfalibi_cli", "byoa", *args)
    try:
        result = json.loads(entry["stdout"])
    except (TypeError, ValueError):
        result = None
    entry["result"] = result if type(result) is dict else {
        "outcome": "BLOCKED", "reason": "missing CLI JSON",
    }
    return entry


def _status():
    return run("git", "status", "--porcelain=v1")


def _clean(record):
    return record["exit_code"] == 0 and record["stdout"] == ""


def _export_dir(path):
    if path is None:
        return Path(tempfile.mkdtemp(prefix="wolfalibi-stage5-qualification-"))
    path = path.resolve(strict=True)
    entry = path.stat()
    if (path == ROOT or ROOT in path.parents or entry.st_uid != os.geteuid()
            or entry.st_mode & 0o077 or any(path.iterdir())):
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
    """Keep signed artifacts on disk; expose only their public metadata here."""
    if isinstance(value, dict):
        return {
            key: _external_record(member) for key, member in value.items()
            if key != "json"
        }
    if isinstance(value, list):
        return [_external_record(member) for member in value]
    return value


def _agent_demo(directory):
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    demo = _cli(
        "test", "--manifest", MANIFEST, "--profile", PROFILE, "--consent",
        "--state-dir", str(directory),
    )
    evidence = _artifact(directory / "evidence.json")
    expected = _artifact(directory / "expected.json")
    observation = _artifact(directory / "observation.json")
    result = {
        "run": demo, "evidence": evidence, "expectations": expected,
        "observation": observation, "passed": False,
    }
    if not (evidence["exists"] and expected["exists"] and observation["exists"]):
        return result
    checked = _cli("verify", "--evidence", evidence["path"], "--expect", expected["path"])
    result["verified"] = checked
    observed = observation.get("json")
    run_result = demo["result"]
    result["passed"] = (
        demo["exit_code"] == checked["exit_code"] == 0
        and run_result.get("outcome") == "COMPLETED"
        and run_result.get("assurance") == "BROKER_ONLY"
        and run_result.get("confinement") == "BLOCKED"
        and run_result.get("confinement_qualification") == "SYNTHETIC_CELL_CANDIDATE"
        and run_result.get("owner_authorization") == "NOT_REQUESTED"
        and type(run_result.get("observation")) is dict
        and run_result["observation"].get("outcome") == "OBSERVED"
        and run_result["observation"].get("assurance") == "OBSERVATIONAL_ONLY"
        and run_result.get("network_upload") is False
        and type(observed) is dict
        and observed.get("outcome") == "OBSERVED"
        and observed.get("assurance") == "OBSERVATIONAL_ONLY"
        and type(observed.get("summary")) is dict
        and observed["summary"].get("network_upload") is False
        and observed["summary"].get("nonaccess_proof") is False
        and checked["result"].get("outcome") == "VERIFIED"
        and checked["result"].get("assurance") == "BROKER_ONLY"
        and checked["result"].get("confinement") == "BLOCKED"
    )
    return result


def _clearance_demo(directory, *, approve):
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    args = ("--approve-synthetic-read",) if approve else ()
    demo = _cli(
        "clearance", "demo", "--profile", PROFILE, "--consent",
        "--state-dir", str(directory), *args,
    )
    report = _artifact(directory / "report.json")
    expected = _artifact(directory / "expected.json")
    result = {"run": demo, "report": report, "expectations": expected, "passed": False}
    if not report["exists"] or not expected["exists"]:
        return result
    checked = _cli("clearance", "verify", "--report", report["path"], "--expect", expected["path"])
    result["verified"] = checked
    if approve:
        result["passed"] = (
            demo["exit_code"] == checked["exit_code"] == 0
            and demo["result"].get("outcome") == "ALLOWED"
            and demo["result"].get("upstream_reads") == 1
            and checked["result"].get("outcome") == "VERIFIED"
            and checked["result"].get("broker_assurance") == "BROKER_ONLY"
            and checked["result"].get("confinement") == "BLOCKED"
            and checked["result"].get("production") == "BLOCKED"
        )
        return result
    try:
        artifact = report["json"]
        references = expected["json"]
        decision = verify_decision(artifact["admission"], bytes.fromhex(references["gateway_pub"]))
    except (KeyError, TypeError, ValueError):
        return result
    result["signed_denial"] = decision
    result["passed"] = (
        demo["exit_code"] == checked["exit_code"] == 2
        and demo["result"].get("outcome") == artifact.get("outcome") == decision.get("outcome") == "DENIED"
        and demo["result"].get("upstream_reads") == 0
        and decision.get("effect") == "NONE"
        and artifact.get("request") is None
        and artifact.get("operation") is None
        and checked["result"].get("outcome") in {"BLOCKED", "REJECTED"}
    )
    return result


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-dir", type=Path, help="existing empty private directory outside the checkout")
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    revision = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    if revision["exit_code"]:
        raise SystemExit(revision["stderr"])
    commit, tree = revision["stdout"].splitlines()
    before = _status()
    result = {
        "schema": "wolfalibi.stage5.local-qualification.v1",
        "commit": commit, "tree": tree,
        "working_tree_clean_start": _clean(before),
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
    host_capabilities = _cli("doctor")
    focused = unit_suite("-v", "test_agent_solitary.py")
    full = unit_suite("discover", "-v")
    mutations = run(sys.executable, "-u", "mutation_test.py")
    mutations["detected"] = len(re.findall(r"^CAUGHT\s+M\d+", mutations["stdout"], re.MULTILINE))
    agent = _agent_demo(directory / "agent")
    denied = _clearance_demo(directory / "denied", approve=False)
    allowed = _clearance_demo(directory / "allowed", approve=True)
    after = _status()
    final = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    unchanged = final["exit_code"] == 0 and final["stdout"] == revision["stdout"]
    passed = (
        _clean(after) and unchanged
        and host_capabilities["exit_code"] == 0 and host_capabilities["result"].get("outcome") == "READY"
        and focused["outcome"] == full["outcome"] == "PASS"
        and mutations["exit_code"] == 0 and mutations["detected"] == 8
        and agent["passed"] and denied["passed"] and allowed["passed"]
    )
    result.update(
        working_tree_clean_end=_clean(after), revision_unchanged=unchanged,
        environment=environment, linux_host_capabilities=host_capabilities,
        focused_tests=focused, full_suite=full, mutation_suite=mutations,
        agent=agent, denied=denied, allowed=allowed, export_dir=str(directory),
        outcome="PASS" if passed else "BLOCKED",
    )
    print(json.dumps(_external_record(result), indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
