"""Qualify the offline sector policy on the exact clean Git tree and emit JSON."""

import json
import re
import sys

from qualify_stage35 import run, unit_suite
from qualify_voidcell002 import _clean, _doctor, _environment, _status


VOIDCELL = "83dcecb9301f998a25352b2825527db7d153019a"
PR30 = "afe9b5b0bc9415a3900fc2596ee0dbbe2aa473a4"
PUBLISHED_TEST = "test_sector_profiles.py"
REVIEW_TESTS = ("test_sector_grant_scope.py", "test_sector_gate_state.py")
EXPECTED_COUNTS = {"inherited": 252, "published_sector": 24, "review": 15}
LABELS = {
    "assurance": "SIMULATED_POLICY_ONLY", "qualification": "NOT_ASSESSED",
    "confinement": "BLOCKED", "production": "BLOCKED", "certification": "NOT_ISSUED",
}
DEMO_EXPECTATIONS = {
    "tutor": ("ALLOWED_SYNTHETIC", "SYNTHETIC_RESPONSE", False),
    "student_record_without_grant": ("DENIED", "NONE", False),
    "payment_without_grant": ("DENIED", "NONE", False),
    "payment_with_owner_grant": ("ALLOWED_SYNTHETIC", "PENDING_EXTERNAL_SETTLEMENT", False),
    "payment_repeat": ("ALLOWED_SYNTHETIC", "PENDING_EXTERNAL_SETTLEMENT", True),
}


def revision(ref):
    record = run("git", "rev-parse", "--verify", ref + "^{commit}")
    if record["exit_code"]:
        raise ValueError(f"missing commit {ref}")
    commit = record["stdout"].strip()
    tree = run("git", "rev-parse", commit + "^{tree}")
    if tree["exit_code"]:
        raise ValueError(f"missing tree for {commit}")
    return {"commit": commit, "tree": tree["stdout"].strip()}


def demo_trial():
    record = run(sys.executable, "-m", "examples.quorvane_sector_profiles_demo")
    try:
        demo = json.loads(record["stdout"])
        cases = demo["cases"]
        passed = (record["exit_code"] == 0 and demo["production"] == "BLOCKED"
                  and cases.keys() == DEMO_EXPECTATIONS.keys()
                  and all((item["outcome"], item["effect"], item["repeat"]) == DEMO_EXPECTATIONS[name]
                          and all(item[k] == v for k, v in LABELS.items())
                          for name, item in cases.items()))
    except (ValueError, KeyError, TypeError, AttributeError):
        passed = False
    return dict(record, expected=DEMO_EXPECTATIONS, outcome="PASS" if passed else "FAIL")


def qualify():
    report = {
        "schema": "wolfalibi.quorvane.qualification-gate-001.v1",
        "policy_qualification": "BLOCKED", "cross_uid_custody": "UNSUPPORTED",
        "decision_labels": LABELS, "independent_administration": "UNESTABLISHED",
        "environment": _environment(),
    }
    if not _clean(_status()):
        return dict(report, reason="a clean checkout is required")
    try:
        parent, submission, head = (revision(ref) for ref in (VOIDCELL, PR30, "HEAD"))
    except ValueError as exc:
        return dict(report, reason=str(exc))
    report.update(voidcell_parent=parent, reviewed_pr30=submission, tested_revision=head)
    if any(run("git", "merge-base", "--is-ancestor", a, b)["exit_code"]
           for a, b in ((VOIDCELL, PR30), (PR30, head["commit"]))):
        return dict(report, reason="revision is outside the reviewed history")
    tracked = run("git", "ls-tree", "--name-only", VOIDCELL)
    inherited = [name for name in tracked["stdout"].splitlines()
                 if name.startswith("test_") and name.endswith(".py")]
    if tracked["exit_code"] or not inherited:
        return dict(report, reason="VOIDCELL test manifest unavailable")
    preserved = run("git", "diff", "--exit-code", "--name-only", VOIDCELL, head["commit"],
                    "--", *inherited, "mutation_test.py", "alibi.py")
    published_test = run("git", "diff", "--exit-code", "--name-only", PR30, head["commit"],
                         "--", PUBLISHED_TEST)
    report.update(inherited_sources=preserved, published_sector_test=published_test)
    if preserved["exit_code"] or published_test["exit_code"]:
        return dict(report, reason="inherited controls differ from their reviewed sources")

    previous = unit_suite("-v", *inherited)
    original = unit_suite("-v", PUBLISHED_TEST)
    extra = unit_suite("-v", *REVIEW_TESTS)
    full = unit_suite("discover", "-v")
    mutation = run(sys.executable, "-u", "mutation_test.py")
    mutations = sorted(re.findall(r"^CAUGHT\s+M([1-8])\b", mutation["stdout"], re.MULTILINE))
    demo = demo_trial()
    doctor = _doctor()
    stable = _clean(_status()) and revision("HEAD") == head
    counts = {"inherited": previous["tests"], "published_sector": original["tests"], "review": extra["tests"]}
    success = (stable and all(suite["outcome"] == "PASS" for suite in (previous, original, extra, full))
               and counts == EXPECTED_COUNTS and full["tests"] == sum(EXPECTED_COUNTS.values())
               and mutation["exit_code"] == 0 and mutations == list("12345678") and demo["outcome"] == "PASS")
    report.update(
        policy_qualification="PASS" if success else "BLOCKED", clean_and_same_revision_at_end=stable,
        expected_counts=EXPECTED_COUNTS, observed_counts=counts, inherited_suite=previous,
        full_suite=full, published_sector_suite=original, review_regressions=extra,
        mutations=dict(mutation, detected=mutations, target="inherited ALIBI controls"),
        synthetic_demo=demo, custody_preflight=doctor,
        boundaries=["In-process policy and volatile intent history only",
                    "Agent identity is a pinned label, live caller authentication is unassessed",
                    "Owner role and absolute time depend on trusted fixture configuration",
                    "External settlement, live accounts and certification issuance are outside this gate"],
    )
    return report


if __name__ == "__main__":
    result = qualify()
    print(json.dumps(result, sort_keys=True, indent=2))
    raise SystemExit(0 if result["policy_qualification"] == "PASS" else 2)
