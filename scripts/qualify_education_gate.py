"""Run the Gate 002 qualification on a clean Git revision using only local fixtures."""

import argparse
import json
from pathlib import Path
import re
import secrets
import sys
import tempfile

from qualify_sector_profiles import revision
from qualify_stage35 import ROOT, run, unit_suite
from qualify_voidcell002 import _clean, _doctor, _environment, _status


BASE = "493629e346484a3a04c7b31fea6d18739a05346a"
INHERITED_COUNT = 291
EDUCATION_TEST_COUNT = 31


def demo_and_verifier(directory):
    pins = directory / "expectations.json"
    evidence = directory / "education-demo.json"
    challenge = secrets.token_hex(32)
    (directory / "challenge.txt").write_text(challenge + "\n", encoding="ascii")
    demo = run(sys.executable, "-m", "examples.quorvane_education_demo",
               "--challenge", challenge, "--expectations-out", str(pins))
    evidence.write_text(demo["stdout"], encoding="utf-8")
    check = run(sys.executable, "-m", "wolfalibi.education_verify",
                "--challenge", challenge, "--expectations", str(pins), "--evidence", str(evidence))
    wrong_challenge = ("0" if challenge[0] != "0" else "1") + challenge[1:]
    mismatch = run(sys.executable, "-m", "wolfalibi.education_verify",
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
                  and trial["observed"]["committed_read_count"] == 1
                  and verified["verified"] == "HISTORICAL_SYNTHETIC_ADMISSION"
                  and all(trial[k] == v and verified[k] == v for k, v in labels.items()))
    except (OSError, ValueError, KeyError, TypeError):
        expectations = None
        passed = False
    return {"demo": demo, "verifier_challenge": challenge, "expectations": expectations,
            "independent_verifier": check, "wrong_challenge": mismatch,
            "outcome": "PASS" if passed else "BLOCKED"}


def qualify(directory):
    report = {
        "schema": "quorvane.education.gate002.qualification.v1", "outcome": "BLOCKED",
        "assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
        "independent_administration": "UNESTABLISHED", "confinement": "BLOCKED",
        "production": "BLOCKED", "certification": "NOT_ISSUED", "environment": _environment(),
    }
    if not _clean(_status()):
        return dict(report, reason="qualification needs a clean checkout")
    head = revision("HEAD")
    report.update(pr31=revision(BASE), tested_revision=head)
    if run("git", "merge-base", "--is-ancestor", BASE, head["commit"])["exit_code"]:
        return dict(report, reason="PR #31 is outside the current ancestry")

    parents = run("git", "ls-tree", "--name-only", BASE)
    inherited = sorted(p for p in parents["stdout"].splitlines()
                       if p.startswith("test_") and p.endswith(".py"))
    added = run("git", "ls-files", "--", "test_education*.py")
    focused = added["stdout"].splitlines()
    if parents["exit_code"] or added["exit_code"] or not inherited or not focused:
        return dict(report, reason="the required test modules could not be enumerated")
    preserved = run("git", "diff", "--exit-code", "--name-only", BASE, head["commit"],
                    "--", *inherited, "alibi.py", "mutation_test.py")
    report["inherited_source_check"] = preserved
    if preserved["exit_code"]:
        return dict(report, reason="the original tests or mutation controls have changed")

    prior = unit_suite("-v", *inherited)
    new = unit_suite("-v", *focused)
    full = unit_suite("discover", "-v")
    mutants = run(sys.executable, "-u", "mutation_test.py")
    caught = re.findall(r"^CAUGHT\s+M([1-8])\b", mutants["stdout"], re.MULTILINE)
    trial = demo_and_verifier(directory)
    stable = _clean(_status()) and revision("HEAD") == head
    passed = (stable and all(s["outcome"] == "PASS" for s in (prior, new, full))
              and prior["tests"] == INHERITED_COUNT and new["tests"] == EDUCATION_TEST_COUNT
              and full["tests"] == INHERITED_COUNT + new["tests"]
              and mutants["exit_code"] == 0 and sorted(caught) == list("12345678")
              and trial["outcome"] == "PASS")
    return dict(report, outcome="PASS" if passed else "BLOCKED",
                inherited_suite=prior, education_suite=new, full_suite=full,
                mutations=dict(mutants, detected=caught), experiment=trial,
                custody_preflight=_doctor(), clean_and_same_revision_at_end=stable)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, help="new or empty directory outside the checkout")
    args = parser.parse_args()
    if args.evidence_dir:
        destination = args.evidence_dir.resolve()
        if destination.is_relative_to(ROOT):
            parser.error("place evidence outside the checkout")
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        if any(destination.iterdir()):
            parser.error("the evidence directory must be empty")
        result = qualify(destination)
    else:
        with tempfile.TemporaryDirectory(prefix="quorvane-education-") as tmp:
            result = qualify(Path(tmp))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
