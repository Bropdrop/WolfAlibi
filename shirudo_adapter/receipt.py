"""Signed local records, verified using an externally supplied Ed25519 key."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .model import (AdapterError, MAX_RECORD_BYTES, UPSTREAM_COMMIT, bounded_int,
                    canonical_json, digest, exact_keys, fail, identifier,
                    require_hex, strict_json)
from .runner import validate_recorded_report


def sign_record(private_key, payload: dict) -> dict:
    return {"schema": "wolfalibi.signed-record.v1", "payload": payload,
            "signature": private_key.sign(canonical_json(payload)).hex()}


def verify_record(envelope: dict, public_key_hex: str) -> dict:
    exact_keys(envelope, {"schema", "payload", "signature"}, "signed record")
    if envelope["schema"] != "wolfalibi.signed-record.v1" or type(envelope["payload"]) is not dict:
        fail("INVALID_RECORD", "Unsupported signed record")
    require_hex(public_key_hex, 64, "externally supplied public key")
    require_hex(envelope["signature"], 128, "signature")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(envelope["signature"]), canonical_json(envelope["payload"]))
    except (ValueError, InvalidSignature) as exc:
        raise AdapterError("INVALID_SIGNATURE", "Record signature does not match the trusted key") from exc
    return envelope["payload"]


def _validate_upstream(upstream: dict, assurance: str, accepted: bool) -> None:
    exact_keys(upstream, {"source_commit", "expected_binary_sha256", "expected_version_id",
                         "observed_binary_sha256", "observed_version_id", "execution_profile",
                         "exit_code", "report", "report_sha256", "required_checks"},
               "receipt upstream record")
    if upstream["source_commit"] != UPSTREAM_COMMIT:
        fail("INVALID_RECEIPT", "Receipt names an unsupported upstream revision")
    for key in ("expected_binary_sha256", "expected_version_id"):
        require_hex(upstream[key], 64, key)
    profile = upstream["execution_profile"]
    if profile == "NO_VERIFIED_RESULT":
        if (accepted or any(upstream[key] is not None for key in
                            ("observed_binary_sha256", "observed_version_id", "exit_code",
                             "report", "report_sha256")) or upstream["required_checks"] != []):
            fail("INVALID_RECEIPT", "Receipt without a verifier result contains inconsistent claims")
        return
    expected_profile = "SYNTHETIC" if assurance == "SYNTHETIC" else "UPSTREAM_CLI"
    if profile != expected_profile:
        fail("INVALID_RECEIPT", "Execution profile disagrees with assurance")
    for key in ("observed_binary_sha256", "observed_version_id", "report_sha256"):
        require_hex(upstream[key], 64, key)
    if (upstream["observed_binary_sha256"] != upstream["expected_binary_sha256"] or
            upstream["observed_version_id"] != upstream["expected_version_id"]):
        fail("INVALID_RECEIPT", "Recorded execution does not match the approved executable pins")
    if digest(upstream["report"]) != upstream["report_sha256"]:
        fail("INVALID_RECEIPT", "Recorded verifier report digest mismatch")
    verified = validate_recorded_report(upstream["report"], upstream["exit_code"],
                                        upstream["required_checks"])
    if accepted and not verified:
        fail("INVALID_RECEIPT", "Accepted receipt contains a rejected verifier report")


def verify_receipt(envelope: dict, public_key_hex: str, *, expected_target: str,
                   expected_policy_sha256: str, expected_challenge_id: str) -> dict:
    envelope = strict_json(canonical_json(envelope), MAX_RECORD_BYTES)
    identifier(expected_target, "expected target")
    require_hex(expected_policy_sha256, 64, "expected policy")
    require_hex(expected_challenge_id, 32, "expected challenge")
    payload = verify_record(envelope, public_key_hex)
    required = {"schema", "receipt_id", "instance_id", "challenge_id", "nonce", "target_id",
                "policy_sha256", "enrollment_record_sha256", "evidence_sha256", "assurance",
                "outcome", "reason_code", "issued_at_ms", "expires_at_ms", "started_at_ms",
                "completed_at_ms", "upstream", "scope", "authorization", "limitations"}
    exact_keys(payload, required, "receipt")
    if payload["schema"] != "wolfalibi.shirudo.receipt.v1":
        fail("INVALID_RECEIPT", "Unsupported receipt schema")
    if (payload["target_id"] != expected_target or
            payload["policy_sha256"] != expected_policy_sha256 or
            payload["challenge_id"] != expected_challenge_id):
        fail("RECEIPT_SCOPE_MISMATCH", "Receipt does not match independently supplied expectations")
    for key in ("receipt_id", "instance_id", "challenge_id"):
        require_hex(payload[key], 32, key)
    for key in ("nonce", "policy_sha256", "enrollment_record_sha256"):
        require_hex(payload[key], 64, key)
    for key in ("issued_at_ms", "expires_at_ms", "started_at_ms", "completed_at_ms"):
        bounded_int(payload[key], 0, 2 ** 63 - 1, key)
    if not 0 < payload["expires_at_ms"] - payload["issued_at_ms"] <= 300_000:
        fail("INVALID_RECEIPT", "Invalid recorded challenge lifetime")
    identifier(payload["reason_code"], "receipt reason code")
    limits = payload["limitations"]
    if (type(limits) is not list or not 1 <= len(limits) <= 16 or
            any(type(item) is not str or not 1 <= len(item) <= 1024 or
                any(ord(char) < 32 for char in item) for item in limits)):
        fail("INVALID_RECEIPT", "Invalid recorded limitations")
    if payload["authorization"] != "NONE" or payload["scope"] != "HISTORICAL_EVIDENCE_ONLY":
        fail("INVALID_RECEIPT", "Receipt claims unsupported authority")
    outcome = payload["outcome"]
    if outcome not in ("EVIDENCE_ACCEPTED", "SIMULATED_POLICY_ONLY", "REJECTED", "BLOCKED"):
        fail("INVALID_RECEIPT", "Unknown receipt outcome")
    if payload["evidence_sha256"] is not None:
        require_hex(payload["evidence_sha256"], 64, "evidence digest")
    elif outcome in ("EVIDENCE_ACCEPTED", "SIMULATED_POLICY_ONLY"):
        fail("INVALID_RECEIPT", "Accepted evidence needs its digest")
    if payload["assurance"] not in ("SYNTHETIC", "LAB_VTPM", "HARDWARE_TPM"):
        fail("INVALID_RECEIPT", "Unknown assurance")
    if outcome == "EVIDENCE_ACCEPTED" and payload["assurance"] == "SYNTHETIC":
        fail("INVALID_RECEIPT", "Synthetic evidence cannot earn upstream acceptance")
    if outcome == "SIMULATED_POLICY_ONLY" and payload["assurance"] != "SYNTHETIC":
        fail("INVALID_RECEIPT", "Simulation label disagrees with assurance")
    accepted = outcome in ("EVIDENCE_ACCEPTED", "SIMULATED_POLICY_ONLY")
    if accepted:
        if not payload["issued_at_ms"] <= payload["started_at_ms"] <= payload["completed_at_ms"] < payload["expires_at_ms"]:
            fail("INVALID_RECEIPT", "Accepted receipt falls outside the challenge interval")
        if payload["reason_code"] != "REQUIRED_CHECKS_PASSED":
            fail("INVALID_RECEIPT", "Accepted receipt has an inconsistent reason")
    _validate_upstream(payload["upstream"], payload["assurance"], accepted)
    return {"signature_valid": True, "historical_outcome": outcome,
            "current_authorization": False, "current_target_state": "NOT_ESTABLISHED",
            "assurance": payload["assurance"], "receipt_id": payload["receipt_id"],
            "scope": payload["scope"]}
