"""Qualify the fixed offline public lab on an unchanged clean Git tree."""

import json
from pathlib import Path
import re
import sys

from qualify_history_gate import _loader_counts
from qualify_sector_profiles import revision
from qualify_stage35 import run, unit_suite
from qualify_voidcell002 import _clean, _environment, _status


PR34_BASE = "bb4d1737e481f4e0c776cb57d47c0d27f3c7f11e"
INHERITED_TESTS = 414
LABELS = {
    "assurance": "SIMULATED_POLICY_ONLY",
    "cross_uid_custody": "UNSUPPORTED",
    "confinement": "BLOCKED",
    "production": "BLOCKED",
    "certification": "NOT_ISSUED",
}
CLAIMS = {
    "education": ("HISTORICAL_SYNTHETIC_ADMISSION", None, None),
    "finance": ("HISTORICAL_SYNTHETIC_PAYMENT_INTENT", "PENDING_EXTERNAL_SETTLEMENT", None),
    "history": ("HISTORICAL_INTENT_DISCLOSURE", "PENDING_EXTERNAL_SETTLEMENT", "UNESTABLISHED"),
}
BUILD_ARTIFACTS = {
    "public_lab/index.html",
    "public_lab/reports/verification.json",
    "public_lab/quorvane-public-lab-001.zip",
}
HEX = re.compile(r"[0-9a-f]{64}\Z")


def _json_command(*command):
    record = run(sys.executable, *command)
    try:
        result = json.loads(record["stdout"])
    except (TypeError, ValueError):
        result = None
    record["result"] = result if type(result) is dict else {
        "outcome": "BLOCKED", "reason": "command did not emit a JSON object",
    }
    return record


def _public_lab():
    record = _json_command("scripts/public_lab.py", "verify")
    report = record["result"]
    cases = report.get("cases")
    valid_cases = type(cases) is list and [case.get("id") for case in cases] == list(CLAIMS)
    if valid_cases:
        for case in cases:
            claim, effect, settlement = CLAIMS[case["id"]]
            genuine, tampered = case.get("genuine", {}), case.get("tampered", {})
            valid_cases = valid_cases and (
                case.get("outcome") == "PASS"
                and case.get("integrity") == "VERIFIED"
                and genuine.get("outcome") == "VERIFIED"
                and genuine.get("verified") == claim
                and genuine.get("effect") == effect
                and genuine.get("settlement") == settlement
                and tampered.get("outcome") == "REJECTED"
                and all(genuine.get(key) == value and tampered.get(key) == value
                        for key, value in LABELS.items())
            )
    passed = (
        record["exit_code"] == 0
        and report.get("schema") == "WOLFALIBI_PUBLIC_LAB_VERIFICATION_V1"
        and report.get("outcome") == "PASS"
        and report.get("selected_case") == "all"
        and type(report.get("manifest_sha256")) is str
        and HEX.fullmatch(report["manifest_sha256"]) is not None
        and valid_cases
    )
    return {"command": record, "outcome": "PASS" if passed else "BLOCKED"}


def _build():
    record = _json_command("scripts/build_public_lab.py", "--check")
    report = record["result"]
    artifacts = report.get("artifacts")
    passed = (
        record["exit_code"] == 0
        and report.get("schema") == "QUORVANE_PUBLIC_LAB_BUILD_V1"
        and report.get("outcome") == "PASS"
        and type(artifacts) is dict
        and set(artifacts) == BUILD_ARTIFACTS
        and all(type(value) is str and HEX.fullmatch(value) is not None for value in artifacts.values())
    )
    return {"command": record, "outcome": "PASS" if passed else "BLOCKED"}


def _focused_modules():
    listing = run("git", "ls-files", "--", "test_public_lab*.py")
    return listing, sorted(path for path in listing["stdout"].splitlines() if path.endswith(".py"))


def qualify():
    report = {
        "schema": "wolfalibi.public-lab-001.qualification.v1",
        "outcome": "BLOCKED",
        **LABELS,
        "network_upload": False,
        "environment": _environment(),
        "inherited_expected": {"tests": INHERITED_TESTS, "skipped": 0},
    }
    start = _status()
    report["working_tree_clean_start"] = _clean(start)
    if not _clean(start):
        return dict(report, reason="qualification needs a clean checkout")
    try:
        base, head = revision(PR34_BASE), revision("HEAD")
    except ValueError as exc:
        return dict(report, reason=str(exc))
    report.update(pr34_baseline=base, tested_revision=head)
    if run("git", "merge-base", "--is-ancestor", PR34_BASE, head["commit"])["exit_code"]:
        return dict(report, reason="the Gate 004 baseline is outside current ancestry")

    inherited_listing = run("git", "ls-tree", "--name-only", PR34_BASE)
    inherited = sorted(name for name in inherited_listing["stdout"].splitlines()
                       if name.startswith("test_") and name.endswith(".py"))
    focused_listing, focused = _focused_modules()
    if inherited_listing["exit_code"] or focused_listing["exit_code"] or not inherited or not focused:
        return dict(report, reason="inherited or public-lab test modules could not be enumerated")
    preserved = run("git", "diff", "--exit-code", "--name-only", PR34_BASE, head["commit"],
                    "--", *inherited, "alibi.py", "mutation_test.py")
    report.update(inherited_test_modules=inherited, focused_test_modules=focused,
                  inherited_source_check=preserved)
    if preserved["exit_code"]:
        return dict(report, reason="the Gate 004 tests or original mutation controls differ")
    try:
        loader = _loader_counts(focused)
    except (ImportError, OSError, ValueError) as exc:
        return dict(report, reason=f"focused test loader failed: {exc}")
    report["focused_loader"] = loader
    if any(item["source_bytes"] in (None, 0) or item["tests"] <= 0 or item["loader_errors"]
           for item in loader):
        return dict(report, reason="every public-lab test module must load at least one test")

    inherited_suite = unit_suite("-v", *inherited)
    public_suite = unit_suite("-v", *focused)
    full_suite = unit_suite("discover", "-v")
    mutations = run(sys.executable, "-u", "mutation_test.py")
    caught = sorted(re.findall(r"^CAUGHT\s+M([1-8])\b", mutations["stdout"], re.MULTILINE))
    lab = _public_lab()
    build = _build()
    end = _status()
    final = revision("HEAD")
    stable = _clean(end) and final == head
    focused_count = sum(item["tests"] for item in loader)
    passed = (
        stable
        and all(suite["outcome"] == "PASS" for suite in (inherited_suite, public_suite, full_suite))
        and inherited_suite["tests"] == INHERITED_TESTS and inherited_suite["skipped"] == 0
        and public_suite["tests"] == focused_count and public_suite["skipped"] == 0
        and full_suite["tests"] == INHERITED_TESTS + focused_count and full_suite["skipped"] == 0
        and mutations["exit_code"] == 0 and caught == list("12345678")
        and lab["outcome"] == build["outcome"] == "PASS"
    )
    return {
        **report,
        "outcome": "PASS" if passed else "BLOCKED",
        "working_tree_clean_end": _clean(end),
        "clean_and_same_revision_at_end": stable,
        "inherited_suite": inherited_suite,
        "public_lab_suite": public_suite,
        "full_suite": full_suite,
        "combined_expected_tests": INHERITED_TESTS + focused_count,
        "mutations": {**mutations, "detected": caught, "target": "original eight ALIBI mutations"},
        "offline_public_lab": lab,
        "standalone_build": build,
    }


if __name__ == "__main__":
    result = qualify()
    print(json.dumps(result, sort_keys=True, indent=2))
    raise SystemExit(0 if result["outcome"] == "PASS" else 2)
