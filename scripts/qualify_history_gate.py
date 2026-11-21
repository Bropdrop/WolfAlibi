"""Qualify Gate 004's synthetic historical disclosure on one clean Git tree.

The local trial authenticates a past, synthetic pending payment intent through
a separately authorized history inquiry.  It does not establish live payment
authority, real settlement, independent administration, or cross-UID custody.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import unittest

from qualify_sector_profiles import revision
from qualify_stage35 import ROOT, run, unit_suite
from qualify_voidcell002 import _clean, _environment, _status


PR33_BASE = "536b1499c7376dd9466a59da87394c1e65506082"
INHERITED_TESTS = 357
LABELS = {
    "assurance": "SIMULATED_POLICY_ONLY",
    "cross_uid_custody": "UNSUPPORTED",
    "certification": "NOT_ISSUED",
    "confinement": "BLOCKED",
    "production": "BLOCKED",
}
EXPECTED_OBSERVED = {
    "lost_response": {"outcome": "UNKNOWN", "response_read": False},
    "original_grant_expired": True,
    "historical_disclosure": "DISCLOSED",
    "challenge_replay": {"outcome": "DENIED", "reason": "CHALLENGE_USED"},
    "revocation": {"outcome": "REVOKED"},
    "revoked_new_inquiry": {"outcome": "DENIED", "reason": "HISTORY_GRANT_REVOKED"},
    "finance_snapshot_unchanged": True,
    "intent_count": 1,
    "historical_verifier": "VERIFIED",
}


def _json_command(module, *args):
    record = run(sys.executable, "-m", module, *args)
    try:
        parsed = json.loads(record["stdout"])
    except (TypeError, ValueError):
        parsed = None
    record["result"] = parsed if type(parsed) is dict else {
        "outcome": "BLOCKED", "reason": f"{module} did not emit a JSON object",
    }
    return record


def _write_new(path, data):
    """Create a qualification artifact without replacing a prior artifact."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _artifact(path):
    path = Path(path)
    record = {"path": str(path), "exists": path.is_file()}
    if not record["exists"]:
        return record
    try:
        data = path.read_bytes()
        record.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), json=json.loads(data))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        record["error"] = str(exc)
    return record


def _wrong_challenge(challenge):
    return ("0" if challenge[0] != "0" else "1") + challenge[1:]


def _loader_counts(paths):
    """Count every focused module before it is run, rejecting empty loaders."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    records = []
    for path in paths:
        source = ROOT / path
        name = Path(path).with_suffix("").as_posix().replace("/", ".")
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(name)
        records.append({
            "path": path,
            "module": name,
            "source_bytes": source.stat().st_size if source.is_file() else None,
            "tests": suite.countTestCases(),
            "loader_errors": list(getattr(loader, "errors", ())),
        })
    return records


def _history_modules():
    tracked = run("git", "ls-files", "--", "test_history*.py")
    paths = sorted(path for path in tracked["stdout"].splitlines() if path.endswith(".py"))
    return tracked, paths


def _evidence_dir(path):
    if path is None:
        return None
    path = path.resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError("place evidence outside the checkout")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    entry = path.lstat()
    if (
        not stat.S_ISDIR(entry.st_mode)
        or entry.st_uid != os.geteuid()
        or entry.st_mode & 0o077
        or any(path.iterdir())
    ):
        raise ValueError("evidence directory must be empty, private and owner-controlled")
    return path


def _matches(observed, expected):
    return all(observed.get(key) == value for key, value in expected.items())


def _demo_and_verify(directory, *, experimental=False):
    directory.mkdir(mode=0o700)
    challenge = secrets.token_hex(32)
    _write_new(directory / "challenge.txt", (challenge + "\n").encode("ascii"))
    history_pins = directory / "history-expectations.json"
    settlement_pins = directory / "settlement-expectations.json"
    evidence = directory / "history-demo.json"
    extra = ["--experimental-settlement", "--settlement-expectations-out", str(settlement_pins)] if experimental else []
    demo = _json_command("examples.quorvane_history_demo", "--challenge", challenge,
                         "--expectations-out", str(history_pins), *extra)
    _write_new(evidence, demo["stdout"].encode("utf-8"))
    trial = demo.pop("result")
    result = {"demo": demo, "challenge": challenge, "outcome": "BLOCKED"}
    if (demo["exit_code"] or trial.get("schema") != "QUORVANE_HISTORY_GATE_004_DEMO_V1"
            or trial.get("outcome") != "PASS" or trial.get("observed") != EXPECTED_OBSERVED
            or trial.get("expected") != EXPECTED_OBSERVED or not _matches(trial, LABELS)):
        return result
    paths = [history_pins, evidence] + ([settlement_pins] if experimental else [])
    result["files"] = {p.name: _artifact(p) for p in paths}
    pins = result["files"][history_pins.name].get("json", {})
    if pins.get("challenge") != challenge or not all("json" in v for v in result["files"].values()):
        return result
    for metadata in result["files"].values():
        del metadata["json"]
    history_args = ["--expectations", str(history_pins), "--evidence", str(evidence)]
    checks = [("history", "wolfalibi.history_verify", history_args,
               {"outcome": "VERIFIED", "verified": "HISTORICAL_INTENT_DISCLOSURE",
                "effect": "PENDING_EXTERNAL_SETTLEMENT", "settlement": "UNESTABLISHED"})]
    if experimental:
        if set(trial.get("experimental_evidence", {})) != {"source_record", "settlement_record"}:
            return result
        settlement_args = ["--history-expectations", str(history_pins), "--settlement-expectations",
                           str(settlement_pins), "--evidence", str(evidence)]
        checks.append(("settlement", "wolfalibi.history_settlement", settlement_args,
                       {"outcome": "SETTLEMENT_VERIFIED", "verified": "HISTORICAL_SYNTHETIC_SETTLEMENT",
                        "initiation_effect": "PENDING_EXTERNAL_SETTLEMENT", "settlement_effect": "SYNTHETIC_SETTLED"}))
    elif (trial.get("settlement") != "UNESTABLISHED" or "experimental_evidence" in trial
          or "experimental_settlement" in trial or settlement_pins.exists()):
        return result
    for name, module, args, expected in checks:
        verified = _json_command(module, *args, "--challenge", challenge)
        rejected = _json_command(module, *args, "--challenge", _wrong_challenge(challenge))
        result[name] = {"positive": verified, "wrong_challenge": rejected}
        if (verified["exit_code"] or not _matches(verified["result"], {**LABELS, **expected})
                or rejected["exit_code"] != 2 or rejected["result"].get("outcome") != "REJECTED"):
            return result
        if name == "settlement" and verified["result"] != trial.get("experimental_settlement"):
            return result
    result["outcome"] = "PASS"
    return result


def qualify(directory):
    report = {
        "schema": "quorvane.history.gate004.qualification.v1",
        "outcome": "BLOCKED",
        **LABELS,
        "independent_administration": "UNESTABLISHED",
        "network_upload": False,
        "environment": _environment(),
        "inherited_expected": {"tests": INHERITED_TESTS, "skipped": 0},
    }
    start_status = _status()
    report["working_tree_clean_start"] = _clean(start_status)
    if not _clean(start_status):
        return dict(report, reason="qualification needs a clean checkout")
    try:
        base, head = revision(PR33_BASE), revision("HEAD")
    except ValueError as exc:
        return dict(report, reason=str(exc))
    report.update(pr33_baseline=base, tested_revision=head)
    if run("git", "merge-base", "--is-ancestor", PR33_BASE, head["commit"])["exit_code"]:
        return dict(report, reason="the Gate 003 baseline is outside current ancestry")

    inherited_listing = run("git", "ls-tree", "--name-only", PR33_BASE)
    inherited = sorted(
        name for name in inherited_listing["stdout"].splitlines()
        if name.startswith("test_") and name.endswith(".py")
    )
    focused_listing, focused = _history_modules()
    if inherited_listing["exit_code"] or focused_listing["exit_code"] or not inherited or not focused:
        return dict(report, reason="inherited or focused test modules could not be enumerated")
    preserved = run(
        "git", "diff", "--exit-code", "--name-only", PR33_BASE, head["commit"],
        "--", *inherited, "alibi.py", "mutation_test.py",
    )
    report.update(
        inherited_test_modules=inherited,
        focused_test_modules=focused,
        inherited_source_check=preserved,
    )
    if preserved["exit_code"]:
        return dict(report, reason="the Gate 003 inherited tests or mutation controls differ")
    try:
        loader_counts = _loader_counts(focused)
    except (OSError, ValueError, ImportError) as exc:
        return dict(report, reason=f"focused test loader failed: {exc}")
    report["focused_loader"] = loader_counts
    if any(
        item["source_bytes"] in (None, 0) or item["tests"] <= 0 or item["loader_errors"]
        for item in loader_counts
    ):
        return dict(report, reason="every focused history test module must load at least one test")

    inherited_suite = unit_suite("-v", *inherited)
    history_suite = unit_suite("-v", *focused)
    full_suite = unit_suite("discover", "-v")
    mutations = run(sys.executable, "-u", "mutation_test.py")
    caught = sorted(re.findall(r"^CAUGHT\s+M([1-8])\b", mutations["stdout"], re.MULTILINE))
    historical = _demo_and_verify(directory / "historical")
    experiment = _demo_and_verify(directory / "experimental", experimental=True)
    final_status = _status()
    final = revision("HEAD")
    stable = _clean(final_status) and final == head
    focused_count = sum(item["tests"] for item in loader_counts)
    passed = (
        stable
        and all(suite["outcome"] == "PASS" for suite in (inherited_suite, history_suite, full_suite))
        and inherited_suite["tests"] == INHERITED_TESTS
        and inherited_suite["skipped"] == 0
        and history_suite["tests"] == focused_count
        and full_suite["tests"] == INHERITED_TESTS + focused_count
        and full_suite["skipped"] == 0
        and mutations["exit_code"] == 0
        and caught == list("12345678")
        and historical["outcome"] == experiment["outcome"] == "PASS"
    )
    return {
        **report,
        "outcome": "PASS" if passed else "BLOCKED",
        "working_tree_clean_end": _clean(final_status),
        "clean_and_same_revision_at_end": stable,
        "inherited_suite": inherited_suite,
        "history_suite": history_suite,
        "full_suite": full_suite,
        "combined_expected_tests": INHERITED_TESTS + focused_count,
        "mutations": {**mutations, "detected": caught, "target": "original eight ALIBI mutations"},
        "historical": historical,
        "experimental": experiment,
        "evidence_dir": str(directory),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, help="new empty private directory outside the checkout")
    args = parser.parse_args(argv)
    try:
        destination = _evidence_dir(args.evidence_dir)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if destination is not None:
        report = qualify(destination)
    else:
        with tempfile.TemporaryDirectory(prefix="quorvane-history-gate004-") as temporary:
            report = qualify(Path(temporary))
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
