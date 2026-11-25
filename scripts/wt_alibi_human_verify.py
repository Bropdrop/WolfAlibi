#!/usr/bin/env python3
"""Independently verify a historical counter effect from public records."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.wt_alibi_human_handoff import (
    HandoffError, READY_LIMIT, pinned_inputs, read_pins, read_public, strict_read, verified_bundle,
)
from scripts.wt_alibi_human_oracle import LIMIT as LEDGER_LIMIT, SCHEMA as OBSERVATION_SCHEMA
from shirudo_adapter.action_gate import (
    CLOCK_SKEW_MS, MAX_ACTION_REQUEST_BYTES, MAX_CHALLENGE_BYTES, MAX_INTEGER,
    _grant_payload, make_grant_payload, verify_effect_receipt,
)
from shirudo_adapter.model import (
    AdapterError, MAX_EVIDENCE_BYTES, bounded_int, canonical_json, check_evidence,
    digest, exact_keys, require_hex,
)
from shirudo_adapter.owner import MAX_BUNDLE_BYTES, MAX_INTENT_BYTES, MAX_PROFILE_BYTES
from shirudo_adapter.receipt import verify_record

AUDIT_PINS_SCHEMA = "wolfalibi.shirudo.effect-review-pins.v1"
MAX_OBSERVATION_BYTES = 1_048_576


def checked_observation(observation, profile, expected_sha):
    require_hex(expected_sha, 64, "independent journal observation digest")
    if digest(observation) != expected_sha:
        raise HandoffError("ORACLE_DIGEST", "Journal observation differs from independent custody")
    exact_keys(observation, {"schema", "gate_instance_id", "policy_sha256", "public_key",
                             "observed_at_ms", "counter", "committed_operations", "ledger"},
               "journal observation")
    if (observation["schema"] != OBSERVATION_SCHEMA
            or observation["gate_instance_id"] != profile["gate_instance_id"]
            or observation["policy_sha256"] != digest(profile["policy"])
            or observation["public_key"] != profile["gate_public_key"]):
        raise HandoffError("ORACLE_IDENTITY", "Journal observation belongs to another gate")
    counter = bounded_int(observation["counter"], 0, LEDGER_LIMIT, "observed counter")
    count = bounded_int(observation["committed_operations"], 0, LEDGER_LIMIT, "committed rows")
    bounded_int(observation["observed_at_ms"], 1, MAX_INTEGER, "observation time")
    ledger = observation["ledger"]
    if type(ledger) is not list or len(ledger) != count or count != counter:
        raise HandoffError("ORACLE_COUNTER", "Counter and complete committed journal disagree")
    operation_ids = set()
    for index, row in enumerate(ledger):
        exact_keys(row, {"operation_id", "request_sha256", "grant_id", "grant_sha256",
                         "assessment_sha256", "counter_before", "counter_after", "receipt"},
                   "committed journal row")
        operation_id = require_hex(row["operation_id"], 32, "observed operation")
        require_hex(row["grant_id"], 32, "observed grant")
        for field in ("request_sha256", "grant_sha256", "assessment_sha256"):
            require_hex(row[field], 64, field)
        bounded_int(row["counter_before"], 0, LEDGER_LIMIT - 1, "row counter before")
        bounded_int(row["counter_after"], 1, LEDGER_LIMIT, "row counter after")
        if operation_id in operation_ids or (row["counter_before"], row["counter_after"]) != (index, index + 1):
            raise HandoffError("ORACLE_LEDGER", "Journal has duplicate or nonconsecutive effects")
        # Every retained row must describe a signed effect under the pinned
        # gate and its row bindings, including rows preceding this request.
        verify_effect_receipt(
            row["receipt"], profile["gate_public_key"], expected_target=profile["target_id"],
            expected_gate_instance_id=profile["gate_instance_id"], expected_operation_id=operation_id,
            expected_grant_id=row["grant_id"], expected_grant_sha256=row["grant_sha256"],
            expected_assessment_sha256=row["assessment_sha256"],
        )
        payload = row["receipt"]["payload"]
        if (payload["policy_sha256"] != observation["policy_sha256"]
                or payload["policy_generation"] != profile["policy_generation"]
                or (payload["counter_before"], payload["counter_after"]) != (index, index + 1)
                or payload["committed_at_ms"] > observation["observed_at_ms"]):
            raise HandoffError("ORACLE_LEDGER", "Signed effect differs from its recorded journal position")
        operation_ids.add(operation_id)
    return ledger


def verify_effect(pins, audit_pins, intent, profile, ready, bundle, raw_evidence,
                  request, receipt, before, after):
    pins, intent, profile = pinned_inputs(pins, intent, profile)
    exact_keys(audit_pins, {"schema", "request_id", "operation_id", "bundle_sha256", "ready_sha256",
                           "before_sha256", "after_sha256"}, "independent review pins")
    if audit_pins["schema"] != AUDIT_PINS_SCHEMA or audit_pins["request_id"] != pins["request_id"]:
        raise HandoffError("AUDIT_REQUEST", "Independent review is for a different request")
    operation_id = require_hex(audit_pins["operation_id"], 32, "original operation ID")
    require_hex(audit_pins["ready_sha256"], 64, "observed owner READY digest")
    if digest(ready) != audit_pins["ready_sha256"]:
        raise HandoffError("AUDIT_READY", "READY differs from the independent owner observation")
    require_hex(audit_pins["bundle_sha256"], 64, "owner-reviewed bundle digest")
    if digest(bundle) != audit_pins["bundle_sha256"]:
        raise HandoffError("AUDIT_BUNDLE", "Bundle differs from the independently frozen owner review")

    exact_keys(request, {"operation_id", "grant", "assessment"}, "retained execution request")
    if request["operation_id"] != operation_id:
        raise HandoffError("AUDIT_OPERATION", "Execution request names a different operation")
    grant = _grant_payload(verify_record(request["grant"], profile["owner_public_key"]))
    review = verified_bundle(intent, profile, bundle, ready, pins=pins, at_ms=grant["issued_at_ms"])
    if review["operation_id"] != operation_id or request["assessment"] != bundle["assessment"]:
        raise HandoffError("AUDIT_OPERATION", "Execution request differs from the owner-reviewed operation")
    if grant != make_grant_payload(bundle["action_challenge"], bundle["assessment"],
                                   grant_id=grant["grant_id"], issued_at_ms=grant["issued_at_ms"],
                                   expires_at_ms=review["expires_at_ms"]):
        raise HandoffError("GRANT_MISMATCH", "Signed grant differs from the original reviewed authority")
    assessment = bundle["assessment"]["payload"]
    check_evidence(raw_evidence, profile["policy"], assessment["nonce"])
    if hashlib.sha256(raw_evidence).hexdigest() != assessment["evidence_sha256"]:
        raise HandoffError("EVIDENCE_DIGEST", "Retained raw evidence differs from the signed assessment")

    result = verify_effect_receipt(
        receipt, profile["gate_public_key"], expected_target=profile["target_id"],
        expected_gate_instance_id=profile["gate_instance_id"], expected_operation_id=operation_id,
        expected_grant_id=grant["grant_id"], expected_grant_sha256=digest(request["grant"]),
        expected_assessment_sha256=digest(request["assessment"]),
        expected_action_challenge=bundle["action_challenge"],
    )
    committed = receipt["payload"]["committed_at_ms"]
    if (committed >= grant["expires_at_ms"]
            or max(grant["issued_at_ms"], assessment["completed_at_ms"]) > committed + CLOCK_SKEW_MS):
        raise HandoffError("EFFECT_TIME", "Effect fell outside the mutually valid authority interval")
    previous = checked_observation(before, profile, audit_pins["before_sha256"])
    current = checked_observation(after, profile, audit_pins["after_sha256"])
    if not before["observed_at_ms"] <= committed <= after["observed_at_ms"]:
        raise HandoffError("ORACLE_TIME", "Independent observations do not bracket the recorded effect")
    if len(current) != len(previous) + 1 or current[:-1] != previous:
        raise HandoffError("ORACLE_DELTA", "Journal interval contains a missing, extra or rewritten effect")
    expected = {
        "operation_id": operation_id, "request_sha256": digest(request),
        "grant_id": grant["grant_id"], "grant_sha256": digest(request["grant"]),
        "assessment_sha256": digest(request["assessment"]), "receipt": receipt,
        "counter_before": result["counter_before"], "counter_after": result["counter_after"],
    }
    if current[-1] != expected:
        raise HandoffError("ORACLE_BINDING", "The newly committed row does not match the signed exact request")
    return {"status": "HISTORICAL_EFFECT_VERIFIED", "request_id": pins["request_id"],
            "operation_id": operation_id, "receipt_id": result["receipt_id"],
            "request_sha256": digest(request), "counter_before": result["counter_before"],
            "counter_after": result["counter_after"], "authorization": "NONE",
            "actual_human_approval": "NOT_RUN"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("pins", "pins-sha256", "audit-pins", "audit-pins-sha256", "intent", "profile",
                 "ready", "bundle", "evidence", "request", "receipt", "before", "after"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_effect(
            read_pins(args.pins, args.pins_sha256), read_pins(args.audit_pins, args.audit_pins_sha256),
            strict_read(args.intent, MAX_INTENT_BYTES), strict_read(args.profile, MAX_PROFILE_BYTES),
            strict_read(args.ready, READY_LIMIT), strict_read(args.bundle, MAX_BUNDLE_BYTES),
            read_public(args.evidence, MAX_EVIDENCE_BYTES), strict_read(args.request, MAX_ACTION_REQUEST_BYTES),
            strict_read(args.receipt, MAX_CHALLENGE_BYTES), strict_read(args.before, MAX_OBSERVATION_BYTES),
            strict_read(args.after, MAX_OBSERVATION_BYTES),
        )
        code = 0
    except (AdapterError, OSError) as exc:
        result = {"status": "BLOCKED", "reason": exc.code if isinstance(exc, AdapterError) else "LOCAL_IO",
                  "actual_human_approval": "NOT_RUN", "authorization": "NONE"}
        code = 2
    print(canonical_json(result).decode("ascii"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
