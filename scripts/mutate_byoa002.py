"""Run fixed, local source mutation controls for the BYOA 002 qualification."""

import argparse
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
import traceback

ROOT = Path(__file__).resolve().parents[1]

# Each edit is applied once to one temporary module. The working tree and every
# public receipt remain unchanged. The original oracle must pass on this host.
CASES = {
    "002-M1": (
        "byoa002_verifier", "test_byoa002_verifier.VerifierTests.test_ack_requires_exact_retained_receipt",
        "if canon(p) != canon(_ack_payload(challenge, receipt, stamp)):",
        'if p["challenge_sha256"] != digest(challenge):',
        "The verifier links an acknowledgment to the exact target receipt."),
    "002-M2": (
        "byoa002_package", "test_byoa002_package.PackageInputTests.test_missing_evidence_keeps_settlement_and_authority_unestablished",
        '"settlement": "UNESTABLISHED"', '"settlement": "PENDING"',
        "A historical verifier supplies no settlement evidence."),
    "002-M3": (
        "byoa002_target", "test_byoa002_target.TargetAuthorityTests.test_positive_commits_one_retained_target_record",
        'payload = _verify(request, bytes.fromhex(enrollment["operator_pub"]), _REQUEST)',
        'payload = _verify(request, bytes.fromhex(enrollment["owner_pub"]), _REQUEST)',
        "Live target admission requires the enrolled operator key in its designated role."),
    "002-M4": (
        "byoa002_target", "test_byoa002_target.TargetAuthorityTests.test_duplicate_dispatch_withholds_record",
        'raise ValueError("operation already committed; use historical reconciliation")',
        'return {"outcome": "ALREADY_COMMITTED"}',
        "Submitting an already committed operation must give an explicit dispatch denial."),
    "002-M5": (
        "byoa002_target", "test_byoa002_target.TargetAuthorityTests.test_target_and_checkpoint_restore_still_need_live_pending_verifier",
        "self._pending(expected, challenge)", "None  # simulated missing precommit witness check",
        "A restored target must consult the current verifier before recording its effect."),
    "002-M6": (
        "byoa002_target", "test_byoa002_target.TargetAuthorityTests.test_owner_signature_alternative_key_is_refused",
        'payload = _verify(grant, bytes.fromhex(enrollment["owner_pub"]), _GRANT)',
        'payload = grant["payload"]',
        "An owner grant with a different signing key cannot authorize the protected read."),
}


CUSTODY_CASES = {
    "002.1-M1": ("byoa002_custody", "test_byoa002_custody.CustodyTests.test_detached_expectation",
                 '"present_authority": "NOT_ISSUED"', '"present_authority": "UNKNOWN"',
                 "The historical result must state that no present authority was issued."),
    "002.1-M2": ("byoa002_target", "test_byoa002_custody.CustodyTests.test_commit_recovery_and_restoration",
                 'return _blocked("current custody reference unavailable or inconsistent: " + str(exc))',
                 'return _blocked("unspecified error")',
                 "Restoration must report the custody disagreement explicitly."),
}
CLOSURE_CASES = {
    "002.2-M1": ("byoa002_target", "test_byoa002_closure.ClosureTests.test_publication_records_consumption",
                 'ledger.publish(previous, "consume", _digest(challenge))',
                 'ledger.publish(previous, "consume", _digest(grant))',
                 "The signed journal must irrevocably identify the consumed challenge after a lost acknowledgment."),
    "002.2-M2": ("byoa002_target", "test_byoa002_closure.ClosureTests.test_committed_target_retains_published_head",
                 'SET receipt=? WHERE id=0", (canon(head),)', 'SET receipt=? WHERE id=0", (canon(previous),)',
                 "The committed owner transaction must retain the published successor of a revocation."),
}
ALL_CASES = {**CASES, **CUSTODY_CASES, **CLOSURE_CASES}


# Match the assertion in the regression itself, independently of exception wording.
ASSERTION_LINES = {
    "002-M2": 'self.assertEqual(checked["settlement"], "UNESTABLISHED")',
    "002-M3": 'self.assertEqual(result["outcome"], "RELEASED", result)',
    "002-M4": 'self.assertEqual(second["outcome"], "DENIED")',
    "002.1-M1": 'self.assertEqual(verify_history(records, **args)["present_authority"], "NOT_ISSUED")',
    "002.1-M2": 'self.assertIn("disagrees with target", denied["reason"])',
    "002.2-M1": 'self.assertEqual((record["payload"]["action"], record["payload"]["subject"]),',
    "002.2-M2": 'self.assertEqual(head["digest"], target_digest(self.history()[-1]))',
}


class TestRecord(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.assertions = []

    def addFailure(self, test, err):
        sites = [frame.line for frame in traceback.extract_tb(err[2])
                 if frame.name == test._testMethodName and Path(frame.filename).stem == type(test).__module__]
        self.assertions.append({"source_lines": sites, "test": test.id(), "type": err[0].__name__, "message": str(err[1])[:1500]})
        super().addFailure(test, err)


def oracle(case_id, overlay):
    name, test_id, _, _, _ = ALL_CASES[case_id]
    sys.path.insert(0, str(ROOT))
    import wolfalibi
    if overlay is not None:
        wolfalibi.__path__.insert(0, str(overlay))
    module = importlib.import_module("wolfalibi." + name)
    path = (overlay or ROOT / "wolfalibi") / (name + ".py")
    if Path(module.__file__).resolve() != path.resolve():
        raise ValueError("source under observation differs from selected module")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(test_id)
    result = TestRecord()
    suite.run(result)
    return {"tests": result.testsRun, "assertions": result.assertions, "failures": len(result.failures),
            "errors": [text[-1500:] for _, text in result.errors], "skips": [reason for _, reason in result.skipped],
            "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
            "loader_errors": loader.errors, "module_sha256": sha256(path.read_bytes())}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run_oracle(case_id, *, mutated=False):
    args = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--oracle", case_id]
    if mutated:
        args.append("--mutated")
    proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=120)
    if proc.returncode:
        raise ValueError(f"{case_id}: oracle process failed: {proc.stderr[-1500:]}")
    return json.loads(proc.stdout)


def completed(result, expected_hash):
    return (result["tests"] == 1 and result["module_sha256"] == expected_hash
            and not any(result[key] for key in ("errors", "skips", "expected_failures", "unexpected_successes", "loader_errors")))


def caught(original, altered, before, after, test_id):
    return (completed(original, before) and original["failures"] == 0 and not original["assertions"]
            and completed(altered, after) and altered["failures"] == 1 and len(altered["assertions"]) == 1
            and altered["assertions"][0]["test"] == test_id and altered["assertions"][0]["type"] == "AssertionError")


def exercise(case_id):
    name, test_id, old, new, purpose = ALL_CASES[case_id]
    path = ROOT / "wolfalibi" / (name + ".py")
    source = path.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise ValueError(f"{case_id}: source no longer matches the fixed mutation site")
    before = sha256(path.read_bytes())
    baseline = run_oracle(case_id)
    after = sha256(source.replace(old, new).encode("utf-8"))
    mutant = run_oracle(case_id, mutated=True)
    expected = ASSERTION_LINES.get(case_id)
    matched = any(expected in item["source_lines"] for item in mutant["assertions"])
    return {"expected_assertion": expected, "id": case_id, "purpose": purpose, "test": test_id, "source": str(path.relative_to(ROOT)),
            "original_sha256": before, "mutant_sha256": after, "control": baseline, "mutant": mutant,
            "detected": (expected is None or matched) and before != after and caught(baseline, mutant, before, after, test_id)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", choices=ALL_CASES, help=argparse.SUPPRESS)
    parser.add_argument("--mutated", action="store_true", help=argparse.SUPPRESS)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--custody", action="store_true")
    group.add_argument("--closure", action="store_true")
    args = parser.parse_args()
    if args.oracle:
        with TemporaryDirectory(prefix="qv-mutation-") as work:
            directory = None
            if args.mutated:
                name, _, old, new, _ = ALL_CASES[args.oracle]
                source = (ROOT / "wolfalibi" / (name + ".py")).read_text(encoding="utf-8")
                if source.count(old) != 1:
                    raise ValueError("fixed mutation site missing")
                directory = Path(work)
                (directory / (name + ".py")).write_text(source.replace(old, new), encoding="utf-8")
            print(json.dumps(oracle(args.oracle, directory)))
        return 0
    if args.mutated:
        parser.error("--mutated requires a fixed oracle")
    report = {"schema": "quorvane.byoa002.mutation-results.v1", "outcome": "BLOCKED", "cases": [],
              "detected": 0, "command": [sys.executable, "-I", "scripts/mutate_byoa002.py"]}
    cases = CUSTODY_CASES if args.custody else CASES
    if args.custody:
        report["command"].append("--custody")
    if args.closure:
        cases = CLOSURE_CASES
        report["command"].append("--closure")
    for case in cases:
        try:
            report["cases"].append(exercise(case))
        except (KeyError, ValueError, OSError, subprocess.SubprocessError) as exc:
            report["cases"].append({"id": case, "detected": False, "reason": str(exc)})
    report["detected"] = sum(item["detected"] for item in report["cases"])
    if report["detected"] == len(cases):
        report["outcome"] = "PASS"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
