"""Verify a historical synthetic payment intent using external public pins."""

import argparse
import json

from .clearance_records import _document, _fields
from .finance_records import PENDING, check_packet, digest, validate_scope, verify_receipt
from .solitary_cli import _read
from .stage3_evidence import _hex


_EXPECTED = {"scope", "target_pub", "owner_pub", "supervisor_pub", "witness_pub", "peer", "witness_head"}
_LIMITATIONS = {
    "assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
    "confinement": "BLOCKED", "production": "BLOCKED", "certification": "NOT_ISSUED",
}


def verify_admission(expected, evidence):
    """Authenticate the exact historical grant, qualification, dispatch and pending receipt."""
    expected = _document(expected, "finance verifier expectations")
    evidence = _document(evidence, "finance evidence", max_bytes=32_768)
    _fields(expected, _EXPECTED, "finance verifier expectations")
    _fields(evidence, {"packet", "receipt"}, "finance evidence")
    scope = validate_scope(expected["scope"])
    target_pub = _hex(expected["target_pub"], 32, "expected finance target key")
    packet = evidence["packet"]
    signed = evidence["receipt"]
    payload = verify_receipt(signed, target_pub=target_pub, scope=scope, packet=packet)
    grant_id = check_packet(
        packet, expected_scope=scope, owner_pub=_hex(expected["owner_pub"], 32, "finance owner key"),
        supervisor_pub=_hex(expected["supervisor_pub"], 32, "finance supervisor key"),
        witness_pub=_hex(expected["witness_pub"], 32, "finance witness key"), peer=expected["peer"],
        witness_head=expected["witness_head"], now=payload["authorized_at"],
    )
    return {
        **_LIMITATIONS, "outcome": "VERIFIED", "verified": "HISTORICAL_SYNTHETIC_PAYMENT_INTENT",
        "effect": PENDING, "run_id": scope["run_id"], "request_id": scope["request_id"],
        "grant_id": grant_id, "authorized_at": payload["authorized_at"],
        "receipt_sha256": digest(signed), "business_sha256": payload["business_sha256"],
        "idempotency_key": payload["idempotency_key"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations", required=True, help="independently retained public pins")
    parser.add_argument("--evidence", required=True, help="JSON output of the local finance demo")
    parser.add_argument("--challenge", required=True, help="independently chosen 32-byte lowercase hex challenge")
    args = parser.parse_args()
    try:
        _hex(args.challenge, 32, "verifier challenge")
        expected = _read(args.expectations, 16_384)
        if expected["scope"]["challenge"] != args.challenge:
            raise ValueError("externally supplied run challenge differs from expectations")
        artifact = _read(args.evidence, 262_144)
        result = verify_admission(expected, artifact["evidence"])
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        result = {**_LIMITATIONS, "outcome": "REJECTED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
