"""Measure fixed pending-intent controls in an ephemeral local Linux target."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
from tempfile import TemporaryDirectory
import time


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "public_lab/financial/controls/target.json"
FIXTURE_HASH = "fd5ab902e66258cde25a058c70868ffd850a2d895e16e80d25c534d2830cb70d"
HISTORY_FILES = {
    "genuine.json": "2db01e42507f29137e559aebf8d02b46702c5854b05f19c4febb9989d33d3789",
    "pins.json": "4ea815b30bcf9d47421935771068fd4642d24cf6d3df0826aca1ceb333397237",
    "challenge.txt": "92a6c9405f3f2755e179b9e7936425d6e9a53b0f3874f5189cecd627a8425ad1",
}
LABELS = {
    "assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
    "production": "BLOCKED", "confinement": "BLOCKED", "certification": "NOT_ISSUED",
}


def _fixed(path, expected):
    raw = (ROOT / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"fixed input differs from the published digest: {path}")
    return raw


def _count(resource):
    resource.stop_target()
    status = resource.offline_status()
    if status["outcome"] != "READY" or type(status.get("intent_count")) is not int:
        raise RuntimeError("target could not authenticate its intent count")
    return status["intent_count"]


def _concurrent(resource):
    frame = resource.invoke("parallel")
    pair = frame["results"]
    retry = resource.invoke()["result"]
    payload = resource.verify(frame["packet"], retry["receipt"])
    return {
        "initial_pair": sorted(item["outcome"] for item in pair), "live_retry": retry["outcome"],
        "same_receipts": all(item.get("receipt") == retry["receipt"] for item in pair),
        "intent_count": _count(resource), "effect": payload["outcome"],
    }


def _conflict(resource):
    first = resource.invoke()
    altered = dict(resource.scope, amount_minor=4501)
    conflict = resource.invoke(scope=altered, grant=resource.make_grant(scope=altered))["result"]
    receipt = first["result"]["receipt"]
    observed = resource.invoke("reconcile", packet=first["packet"])["result"]
    return {
        "conflict": conflict, "original_reconciled": observed == {"outcome": "RECONCILED", "receipt": receipt},
        "intent_count": _count(resource), "effect": resource.verify(first["packet"], receipt)["outcome"],
    }


def _lost_reply(resource):
    packet = resource.invoke("sign")["packet"]
    previous = resource.retained_anchor()
    delivery = resource.invoke("lost-reply", packet=packet)["result"]
    resource.wait_for_checkpoint_change(previous)
    advanced = resource.retained_anchor() != previous
    resource.stop_target()
    # Capture the original receipt before either reconciliation RPC.
    ledger = (resource.target_state / "ledger.sqlite").as_uri() + "?mode=ro"
    with closing(sqlite3.connect(ledger, uri=True)) as db:
        (entry,), = db.execute("SELECT receipt FROM decisions").fetchall()
    archived = json.loads(entry)["receipt"]
    effect = resource.verify(packet, archived)["outcome"]
    resource.start_target()
    replies = [resource.invoke("reconcile", packet=packet)["result"] for _ in range(2)]
    return {
        "delivery": delivery, "checkpoint_advanced": advanced, "replies": [r["outcome"] for r in replies],
        "same_archived_receipt": all(r.get("receipt") == archived for r in replies),
        "intent_count": _count(resource), "effect": effect,
    }


def _historical_reads(resource):
    from wolfalibi.finance_verify import verify_admission

    frame = resource.invoke()
    evidence = {"packet": frame["packet"], "receipt": frame["result"]["receipt"]}
    count_before = _count(resource)
    ledger = resource.target_state / "ledger.sqlite"
    before = ledger.read_bytes()
    checkpoint = resource.retained_anchor()
    with ThreadPoolExecutor(max_workers=2) as pool:
        reports = list(pool.map(verify_admission, (resource.expectations,) * 2, (evidence,) * 2))
    return {
        "claims": [r["verified"] for r in reports], "effects": [r["effect"] for r in reports],
        "same_receipt_digest": all(r["receipt_sha256"] == resource.records.digest(evidence["receipt"])
                                   for r in reports),
        "ledger_unchanged": ledger.read_bytes() == before,
        "checkpoint_unchanged": resource.retained_anchor() == checkpoint,
        "count_before": count_before, "count_after": _count(resource),
    }


def _positive_after_control(resource):
    count = _count(resource)
    resource.start_target()
    result = resource.invoke()
    resource.verify(result["packet"], result["result"]["receipt"])
    return count, result["result"]["outcome"], _count(resource)


def _expired(resource):
    now = int(time.time())
    expired = resource.make_grant(start=now - 60, end=now - 1)
    result = resource.invoke(grant=expired)["result"]
    before, positive, after = _positive_after_control(resource)
    return {"expired": result, "count_after_expired": before, "positive": positive, "count_after_positive": after}


def _revoked(resource):
    from wolfalibi.finance_verify import verify_admission

    frame = resource.invoke()
    resource.stop_target()
    revocation = resource.revoke()
    evidence = {"packet": frame["packet"], "receipt": frame["result"]["receipt"]}
    historic = verify_admission(resource.expectations, evidence)
    resource.start_target()
    return {
        "revocation": revocation["outcome"], "history": historic["verified"], "live": resource.invoke()["result"],
        "effect": historic["effect"], "intent_count": _count(resource),
    }


def _auditor(resource):
    from wolfalibi.history_verify import verify_history

    raw = {name: _fixed("public_lab/vectors/history/" + name, sha) for name, sha in HISTORY_FILES.items()}
    evidence = json.loads(raw["genuine.json"])["evidence"]
    historical = verify_history(json.loads(raw["pins.json"]), evidence, challenge=raw["challenge.txt"].decode().strip())
    result = resource.invoke(grant=evidence["request"]["grant"])["result"]
    before, positive, after = _positive_after_control(resource)
    return {
        "history": historical["verified"], "historical_settlement": historical["settlement"],
        "live": result, "count_after_auditor": before, "positive": positive, "count_after_positive": after,
    }


def _old_ledger(resource):
    from wolfalibi.finance_target import FinanceTarget, FinanceTargetError
    from wolfalibi.voidcell002_anchor import LedgerDivergence

    resource.stop_target()
    ledger = resource.target_state / "ledger.sqlite"
    empty = ledger.read_bytes()
    resource.start_target()
    accepted = resource.invoke()
    resource.verify(accepted["packet"], accepted["result"]["receipt"])
    clean_reopen = _count(resource)
    current = ledger.read_bytes()
    checkpoint = resource.retained_anchor()
    outcome = "OPENED_OLDER_LEDGER"
    try:
        ledger.write_bytes(empty)
        try:
            with FinanceTarget(resource.target_state, resource.anchor):
                pass
        except FinanceTargetError as exc:
            # Only an authenticated checkpoint mismatch counts for this case.
            if not isinstance(exc.__cause__, LedgerDivergence):
                raise
            outcome = "REJECTED_LEDGER_DIVERGENCE"
    finally:
        ledger.write_bytes(current)
    return {
        "clean_reopen": clean_reopen, "old_ledger": outcome,
        "checkpoint_preserved": resource.retained_anchor() == checkpoint, "restored_reopen": _count(resource),
    }


CONTROLS = {
    "B-T01": _concurrent, "B-T02": _conflict, "B-T03": _lost_reply, "B-T04": _historical_reads,
    "C-T01": _expired, "C-T02": _revoked, "C-T03": _auditor, "F-T01": _old_ledger,
}


def _linux_controls():
    required = ("AF_UNIX", "SOCK_SEQPACKET", "SO_PEERCRED", "SO_PASSCRED", "SCM_CREDENTIALS", "MSG_CMSG_CLOEXEC")
    return (sys.platform.startswith("linux") and hasattr(os, "pidfd_open") and Path("/proc/self/stat").is_file()
            and all(hasattr(socket, name) for name in required))


def _run_case(case, scenario, assumptions, limits):
    from examples.quorvane_finance_demo import fixture

    report = {
        **scenario, "assumptions": assumptions, "limitations": limits, "fixture": FIXTURE,
        "fixture_sha256": FIXTURE_HASH, "command": f"python scripts/financial_effect_controls.py --case {case}",
        "outcome": "BLOCKED", "observed": None,
    }
    try:
        with TemporaryDirectory(prefix="qv-intent-") as root, fixture(root, challenge="c4" * 32) as resource:
            observed = CONTROLS[case](resource)
        # Preserve JSON type distinctions, including one versus true.
        report["observed"] = observed
        matched = json.dumps(observed, sort_keys=True) == json.dumps(scenario["expected"], sort_keys=True)
        report["outcome"] = "PASS" if matched else "FAIL"
    except Exception as exc:
        report.update(reason="local control did not complete", error_type=type(exc).__name__)
    return report


def run(selected=None):
    report = {
        "schema": "QUORVANE_FINANCIAL_EFFECT_CONTROLS_V1", **LABELS, "outcome": "BLOCKED",
        "selected_case": selected or "all", "controls": [], "fixture_sha256": FIXTURE_HASH,
    }
    try:
        spec = json.loads(_fixed(FIXTURE, FIXTURE_HASH))
        if [item["id"] for item in spec["controls"]] != list(CONTROLS):
            raise ValueError("control inventory differs from expected")
        if selected is not None and selected not in CONTROLS:
            raise ValueError("unknown control ID")
        if not _linux_controls():
            return dict(report, outcome="UNSUPPORTED", reason="Linux Unix peer credentials, procfs and pidfds required")
        for scenario in spec["controls"]:
            if selected is None or selected == scenario["id"]:
                report["controls"].append(_run_case(scenario["id"], scenario, spec["assumptions"], spec["limits"]))
    except Exception as exc:
        return dict(report, reason="fixture or runtime unavailable", error_type=type(exc).__name__)
    outcomes = {row["outcome"] for row in report["controls"]}
    report["outcome"] = "PASS" if outcomes == {"PASS"} else ("FAIL" if "FAIL" in outcomes else "BLOCKED")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=CONTROLS, help="run only the named fixed control")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    result = run(args.case)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["outcome"] == "PASS" else 2)
