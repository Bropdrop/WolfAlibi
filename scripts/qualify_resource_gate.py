"""Exact-tree qualification for the local resource-side sector fixtures."""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import secrets
import sys
import tempfile

from qualify_sector_profiles import revision
from qualify_stage35 import ROOT, run, unit_suite
from qualify_voidcell002 import _clean, _doctor, _environment, _status


@dataclass(frozen=True)
class Gate:
    sector: str
    number: str
    base: str
    parent_pr: int
    inherited_count: int
    sector_count: int
    count_field: str
    verified_claim: str
    expected_effect: str | None = None


def demo_and_verifier(directory, gate):
    pins = directory / "expectations.json"
    evidence = directory / f"{gate.sector}-demo.json"
    challenge = secrets.token_hex(32)
    (directory / "challenge.txt").write_text(challenge + "\n", encoding="ascii")
    demo = run(sys.executable, "-m", f"examples.quorvane_{gate.sector}_demo",
               "--challenge", challenge, "--expectations-out", str(pins))
    evidence.write_text(demo["stdout"], encoding="utf-8")
    check = run(sys.executable, "-m", f"wolfalibi.{gate.sector}_verify",
                "--challenge", challenge, "--expectations", str(pins), "--evidence", str(evidence))
    wrong_challenge = ("0" if challenge[0] != "0" else "1") + challenge[1:]
    mismatch = run(sys.executable, "-m", f"wolfalibi.{gate.sector}_verify",
                   "--challenge", wrong_challenge, "--expectations", str(pins), "--evidence", str(evidence))
    labels = {"assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
              "certification": "NOT_ISSUED", "production": "BLOCKED", "confinement": "BLOCKED"}
    try:
        trial = json.loads(demo["stdout"])
        expectations = json.loads(pins.read_bytes())
        verified = json.loads(check["stdout"])
        rejected = json.loads(mismatch["stdout"])
        passed = (mismatch["exit_code"] == 2 and rejected["outcome"] == "REJECTED"
                  and demo["exit_code"] == check["exit_code"] == 0
                  and trial["outcome"] == "PASS" and verified["outcome"] == "VERIFIED"
                  and expectations["scope"]["challenge"] == challenge
                  and trial["observed"] == trial["expected"]
                  and trial["observed"][gate.count_field] == 1
                  and verified["verified"] == gate.verified_claim
                  and (gate.expected_effect is None or verified.get("effect") == gate.expected_effect)
                  and all(trial[k] == v and verified[k] == v for k, v in labels.items()))
    except (OSError, ValueError, KeyError, TypeError):
        expectations = None
        passed = False
    return {"demo": demo, "verifier_challenge": challenge, "expectations": expectations,
            "independent_verifier": check, "wrong_challenge": mismatch,
            "outcome": "PASS" if passed else "BLOCKED"}


def qualify(directory, gate):
    report = {
        "schema": f"quorvane.{gate.sector}.gate{gate.number}.qualification.v1", "outcome": "BLOCKED",
        "assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
        "independent_administration": "UNESTABLISHED", "confinement": "BLOCKED",
        "production": "BLOCKED", "certification": "NOT_ISSUED", "environment": _environment(),
    }
    if not _clean(_status()):
        return dict(report, reason="qualification needs a clean checkout")
    head = revision("HEAD")
    report[f"pr{gate.parent_pr}"] = revision(gate.base)
    report["tested_revision"] = head
    if run("git", "merge-base", "--is-ancestor", gate.base, head["commit"])["exit_code"]:
        return dict(report, reason=f"PR #{gate.parent_pr} is outside the current ancestry")

    parents = run("git", "ls-tree", "--name-only", gate.base)
    inherited = sorted(p for p in parents["stdout"].splitlines()
                       if p.startswith("test_") and p.endswith(".py"))
    added = run("git", "ls-files", "--", f"test_{gate.sector}*.py")
    focused = added["stdout"].splitlines()
    if parents["exit_code"] or added["exit_code"] or not inherited or not focused:
        return dict(report, reason="the required test modules could not be enumerated")
    preserved = run("git", "diff", "--exit-code", "--name-only", gate.base, head["commit"],
                    "--", *inherited, "alibi.py", "mutation_test.py")
    report["inherited_source_check"] = preserved
    if preserved["exit_code"]:
        return dict(report, reason="the original tests or mutation controls have changed")

    prior = unit_suite("-v", *inherited)
    new = unit_suite("-v", *focused)
    full = unit_suite("discover", "-v")
    mutants = run(sys.executable, "-u", "mutation_test.py")
    caught = re.findall(r"^CAUGHT\s+M([1-8])\b", mutants["stdout"], re.MULTILINE)
    trial = demo_and_verifier(directory, gate)
    stable = _clean(_status()) and revision("HEAD") == head
    passed = (stable and all(s["outcome"] == "PASS" for s in (prior, new, full))
              and prior["tests"] == gate.inherited_count and new["tests"] == gate.sector_count
              and full["tests"] == gate.inherited_count + new["tests"]
              and mutants["exit_code"] == 0 and sorted(caught) == list("12345678")
              and trial["outcome"] == "PASS")
    report[f"{gate.sector}_suite"] = new
    return dict(report, outcome="PASS" if passed else "BLOCKED",
                inherited_suite=prior, full_suite=full,
                mutations=dict(mutants, detected=caught), experiment=trial,
                custody_preflight=_doctor(), clean_and_same_revision_at_end=stable)


def main(gate, description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--evidence-dir", type=Path, help="new or empty directory outside the checkout")
    args = parser.parse_args()
    if args.evidence_dir:
        destination = args.evidence_dir.resolve()
        if destination.is_relative_to(ROOT):
            parser.error("place evidence outside the checkout")
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        if any(destination.iterdir()):
            parser.error("the evidence directory must be empty")
        result = qualify(destination, gate)
    else:
        with tempfile.TemporaryDirectory(prefix=f"quorvane-{gate.sector}-") as tmp:
            result = qualify(Path(tmp), gate)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["outcome"] == "PASS" else 2
