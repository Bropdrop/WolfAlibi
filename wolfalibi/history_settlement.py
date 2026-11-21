"""Offline verification of a separate, explicitly synthetic settlement phase."""

import argparse
import json

from .clearance_records import _document, _fields, _id, _key, _time
from .education_records import _sign, _verify
from .finance_records import PENDING, business_digest, digest, validate_scope
from .finance_verify import verify_admission
from .history_verify import LIMITS, verify_history
from .solitary_cli import _read
from .stage3_evidence import _hex


SYNTHETIC_SETTLED = "SYNTHETIC_SETTLED"
_SOURCE_TYPE = "QUORVANE_SYNTHETIC_SETTLEMENT_SOURCE_V1"
_SETTLEMENT_TYPE = "QUORVANE_SYNTHETIC_SETTLEMENT_AUTHORITY_V1"
_SOURCE_DOMAIN = b"quorvane/history/synthetic-settlement-source/v1"
_SETTLEMENT_DOMAIN = b"quorvane/history/synthetic-settlement-authority/v1"
_SOURCE_FIELDS = {"type", "outcome", "reference", "settled_at", "initiation_sha256", "business_sha256"}
_SETTLEMENT_PINS = {"source_pub", "authority_pub", "expected_reference", "expected_source_sha256"}
_SETTLEMENT_EVIDENCE = {"source_record", "settlement_record"}


def _source_payload(payload):
    _fields(payload, _SOURCE_FIELDS, "synthetic settlement source")
    if (payload["type"], payload["outcome"]) != (_SOURCE_TYPE, SYNTHETIC_SETTLED):
        raise ValueError("source did not attest a synthetic settlement")
    _id(payload["reference"], "external settlement reference")
    _time(payload["settled_at"], "synthetic settlement time")
    _hex(payload["initiation_sha256"], 32, "original finance receipt digest")
    _hex(payload["business_sha256"], 32, "payment business digest")
    return payload


def sign_source(source, *, finance_receipt, scope, reference, settled_at, observed_outcome):
    """Sign the supplied synthetic source observation in its own signature domain.

    The input is an explicit observation asserted by this fixture source. The
    verifier independently authenticates the original Gate003 evidence.
    """
    scope = validate_scope(scope)
    public = _key(source.pub, "synthetic settlement source key")
    if public in (scope["target_pub"], scope["caller_pub"]):
        raise ValueError("the settlement source key must be distinct from finance keys")
    finance_receipt = _document(finance_receipt, "original finance receipt", max_bytes=4096)
    _fields(finance_receipt, {"payload", "signature"}, "original finance receipt")
    return _sign(source, _SOURCE_DOMAIN, _source_payload({
        "type": _SOURCE_TYPE, "outcome": observed_outcome, "reference": reference,
        "settled_at": settled_at, "initiation_sha256": digest(finance_receipt),
        "business_sha256": business_digest(scope),
    }))


def _approval(source_sha256):
    return {"type": _SETTLEMENT_TYPE, "outcome": SYNTHETIC_SETTLED, "source_sha256": source_sha256}


def sign_settlement(authority, *, source_record, source_pub):
    """Approve the exact record of a separately signed synthetic observation."""
    if _key(authority.pub, "synthetic settlement authority key") == _key(source_pub, "settlement source key"):
        raise ValueError("settlement source and authority require distinct keys")
    source_record = _document(source_record, "synthetic settlement source record", max_bytes=4096)
    _source_payload(_verify(source_record, source_pub, _SOURCE_DOMAIN))
    return _sign(authority, _SETTLEMENT_DOMAIN, _approval(digest(source_record)))


def verify_settlement(source_record, settlement_record, *, finance_pins, finance_evidence,
                      history_pub, auditor_pub, source_pub, authority_pub, expected_reference,
                      expected_source_sha256):
    """Authenticate the two records using external keys and an exact source pin.

    This proves what the pinned synthetic source and authority signed. The
    original Gate003 receipt remains pending and this function performs no effect.
    """
    _id(expected_reference, "expected settlement reference")
    _hex(expected_source_sha256, 32, "expected settlement source digest")
    history_key = _key(history_pub, "expected history target key")
    auditor_key = _key(auditor_pub, "expected history auditor key")
    source_key = _key(source_pub, "expected settlement source key")
    authority_key = _key(authority_pub, "expected settlement authority key")
    finance_pins = _document(finance_pins, "original finance expectations")
    original = verify_admission(finance_pins, finance_evidence)
    role_keys = (
        finance_pins["owner_pub"], finance_pins["target_pub"], finance_pins["supervisor_pub"],
        finance_pins["witness_pub"], finance_pins["scope"]["caller_pub"],
        history_key, auditor_key, source_key, authority_key,
    )
    if len(set(role_keys)) != len(role_keys):
        raise ValueError("settlement, inquiry and finance roles require distinct keys")

    source_record = _document(source_record, "synthetic settlement source record", max_bytes=4096)
    source_sha256 = digest(source_record)
    if source_sha256 != expected_source_sha256:
        raise ValueError("source record differs from the independently pinned digest")
    observed = _source_payload(_verify(source_record, source_pub, _SOURCE_DOMAIN))
    if observed["reference"] != expected_reference:
        raise ValueError("source record differs from the independently pinned reference")
    if (observed["initiation_sha256"] != original["receipt_sha256"]
            or observed["business_sha256"] != original["business_sha256"]):
        raise ValueError("settlement differs from the verified original payment intent")
    if observed["settled_at"] <= original["authorized_at"]:
        raise ValueError("settlement must occur after the original payment intent")

    settlement_record = _document(settlement_record, "synthetic settlement authority record", max_bytes=4096)
    approved = _verify(settlement_record, authority_pub, _SETTLEMENT_DOMAIN)
    if approved != _approval(source_sha256):
        raise ValueError("authority did not approve the exact verified synthetic source record")
    return {
        **LIMITS,
        "outcome": "SETTLEMENT_VERIFIED", "verified": "HISTORICAL_SYNTHETIC_SETTLEMENT",
        "initiation_effect": PENDING, "settlement_effect": SYNTHETIC_SETTLED,
        "initiation_sha256": original["receipt_sha256"], "business_sha256": original["business_sha256"],
        "reference": observed["reference"], "settled_at": observed["settled_at"],
        "source_sha256": source_sha256, "settlement_sha256": digest(settlement_record),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history-expectations", required=True)
    parser.add_argument("--settlement-expectations", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--challenge", required=True, help="independently pinned history challenge")
    args = parser.parse_args(argv)
    try:
        history_pins = _read(args.history_expectations, 32_768)
        artifact = _read(args.evidence, 262_144)
        history = artifact["evidence"]
        verify_history(history_pins, history, challenge=args.challenge)
        pins = _read(args.settlement_expectations, 16_384)
        _fields(pins, _SETTLEMENT_PINS, "external settlement pins")
        evidence = artifact["experimental_evidence"]
        _fields(evidence, _SETTLEMENT_EVIDENCE, "synthetic settlement evidence")
        result = verify_settlement(
            evidence["source_record"], evidence["settlement_record"],
            finance_pins=history_pins["finance"], finance_evidence=history["original"],
            history_pub=_hex(history_pins["history_pub"], 32, "expected history target key"),
            auditor_pub=_hex(history_pins["auditor_pub"], 32, "expected history auditor key"),
            source_pub=_hex(pins["source_pub"], 32, "expected settlement source key"),
            authority_pub=_hex(pins["authority_pub"], 32, "expected settlement authority key"),
            expected_reference=pins["expected_reference"], expected_source_sha256=pins["expected_source_sha256"],
        )
    except (OSError, KeyError, ValueError, TypeError, RecursionError) as exc:
        result = {**LIMITS, "outcome": "REJECTED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] == "SETTLEMENT_VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
