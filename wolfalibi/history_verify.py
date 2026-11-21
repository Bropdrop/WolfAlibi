"""Verify a historical disclosure using independently retained public expectations."""

import argparse
import json

from .clearance_records import _document, _fields, _time
from .education_records import _verify, digest
from .finance_records import PENDING
from .finance_verify import verify_admission
from .history_records import check_inquiry, inquiry_scope
from .solitary_cli import _read
from .stage3_evidence import _hex


DISCLOSURE_DOMAIN = b"quorvane/finance/history/disclosure/v1"
LIMITS = {
    "assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
    "certification": "NOT_ISSUED", "production": "BLOCKED", "confinement": "BLOCKED",
}


def separate_keys(finance, history_pub, auditor_pub=None):
    keys = [finance[k] for k in ("owner_pub", "target_pub", "supervisor_pub", "witness_pub")]
    keys.extend([finance["scope"]["caller_pub"], history_pub])
    if auditor_pub is not None:
        keys.append(auditor_pub)
    for key in keys:
        _hex(key, 32, "financial role key")
    if len(set(keys)) != len(keys):
        raise ValueError("financial, inquiry and disclosure roles require distinct keys")


def disclosure_payload(finance, anchor_sha256, request, original, checked_at):
    _time(checked_at, "historical disclosure time")
    if checked_at < original["receipt"]["payload"]["authorized_at"]:
        raise ValueError("historical disclosure predates the signed original")
    return {
        "type": "QUORVANE_HISTORICAL_INTENT_DISCLOSURE_V1", "disposition": PENDING,
        "authorized_at": checked_at, "challenge": request["challenge"],
        "inquiry_sha256": digest(request), "original_receipt_sha256": digest(original["receipt"]),
        "finance_expectations_sha256": digest(finance), "anchor_sha256": anchor_sha256,
    }


def verify_history(expected, evidence, *, challenge):
    """Authenticate both signatures and scopes at their respective historical times."""
    expected = _document(expected, "external history pins")
    _fields(expected, {"finance", "history_pub", "anchor_sha256", "auditor_pub", "challenge"}, "history pins")
    _hex(challenge, 32, "verifier inquiry challenge")
    _hex(expected["anchor_sha256"], 32, "retained archive anchor")
    if challenge != expected["challenge"]:
        raise ValueError("inquiry challenge differs from the verifier's expectations")
    evidence = _document(evidence, "historical disclosure evidence", max_bytes=65_536)
    _fields(evidence, {"original", "request", "attestation"}, "history evidence")
    finance = expected["finance"]
    original = evidence["original"]
    payment = verify_admission(finance, original)
    if finance["scope"]["challenge"] == challenge:
        raise ValueError("the historical inquiry requires its own challenge")
    separate_keys(finance, expected["history_pub"], expected["auditor_pub"])
    signed = _verify(evidence["attestation"], bytes.fromhex(expected["history_pub"]), DISCLOSURE_DOMAIN)
    request = _document(evidence["request"], "historical inquiry")
    checked_at = signed.get("authorized_at")
    grant_id = check_inquiry(request, scope=inquiry_scope(finance["scope"]),
                             owner_pub=bytes.fromhex(finance["owner_pub"]), challenge=challenge, now=checked_at)
    if request["grant"]["payload"]["auditor_pub"] != expected["auditor_pub"]:
        raise ValueError("unexpected auditor credential")
    if signed != disclosure_payload(finance, expected["anchor_sha256"], request, original, checked_at):
        raise ValueError("historical disclosure differs from external pins or original evidence")
    return {**LIMITS, "outcome": "VERIFIED", "verified": "HISTORICAL_INTENT_DISCLOSURE",
            "effect": payment["effect"], "settlement": "UNESTABLISHED", "grant_id": grant_id,
            "receipt_sha256": payment["receipt_sha256"], "anchor_sha256": expected["anchor_sha256"],
            "request_id": payment["request_id"], "authorized_at": checked_at}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--challenge", required=True)
    args = parser.parse_args()
    try:
        artifact = _read(args.evidence, 262_144)
        result = verify_history(_read(args.expectations, 32_768), artifact["evidence"], challenge=args.challenge)
    except (OSError, KeyError, ValueError, TypeError, RecursionError) as exc:
        result = {**LIMITS, "outcome": "REJECTED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
