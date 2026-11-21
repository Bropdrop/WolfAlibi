"""Verify a historical synthetic admission against separately supplied public inputs."""

import argparse
import json

from .clearance_records import _fields
from .education_records import check_packet, digest, validate_scope, verify_receipt
from .solitary_cli import _read
from .stage3_evidence import _hex


_EXPECTED = {"scope", "owner_pub", "supervisor_pub", "witness_pub", "target_pub",
             "peer", "witness_head", "response_sha256"}
_LIMITATIONS = {
    "assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
    "confinement": "BLOCKED", "production": "BLOCKED", "certification": "NOT_ISSUED",
}


def verify_admission(expected, evidence):
    """Check the target signature, both authorities, caller proof and response binding."""
    _fields(expected, _EXPECTED, "verifier expectations")
    _fields(evidence, {"packet", "response", "receipt"}, "education evidence")
    scope = validate_scope(expected["scope"])
    target_pub = _hex(expected["target_pub"], 32, "expected target key")
    if scope["target_pub"] != expected["target_pub"]:
        raise ValueError("scope differs from the independently provisioned target")
    response_digest = digest(evidence["response"])
    if response_digest != expected["response_sha256"]:
        raise ValueError("response differs from the expected fictional record")
    receipt = verify_receipt(evidence["receipt"], target_pub=target_pub, scope=scope,
                             packet=evidence["packet"], response=evidence["response"])
    grant_id = check_packet(evidence["packet"], expected_scope=scope,
                            owner_pub=_hex(expected["owner_pub"], 32, "owner key"),
                            supervisor_pub=_hex(expected["supervisor_pub"], 32, "supervisor key"),
                            witness_pub=_hex(expected["witness_pub"], 32, "witness key"),
                            peer=expected["peer"], witness_head=expected["witness_head"],
                            now=receipt["authorized_at"])
    return {**_LIMITATIONS, "outcome": "VERIFIED", "verified": "HISTORICAL_SYNTHETIC_ADMISSION",
            "run_id": scope["run_id"], "request_id": scope["request_id"], "grant_id": grant_id,
            "authorized_at": receipt["authorized_at"], "receipt_sha256": digest(evidence["receipt"]),
            "response_sha256": response_digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations", required=True, help="public expectations retained before dispatch")
    parser.add_argument("--evidence", required=True, help="JSON output of the education demo")
    parser.add_argument("--challenge", help="optional challenge independently chosen for this run")
    args = parser.parse_args()
    try:
        expected = _read(args.expectations, 16384)
        if args.challenge is not None:
            _hex(args.challenge, 32, "verifier challenge")
            if expected["scope"]["challenge"] != args.challenge:
                raise ValueError("externally supplied run challenge differs from expectations")
        demo = _read(args.evidence, 262144)
        result = verify_admission(expected, demo["evidence"])
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        result = {**_LIMITATIONS, "outcome": "REJECTED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
