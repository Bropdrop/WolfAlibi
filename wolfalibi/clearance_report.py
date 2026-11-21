"""Offline verification of a historical synthetic Clearance decision chain.

The verifier uses the signed gateway times to check the historical windows.
It does not query live revocation, witness availability or process identity.
The effect observation is the gateway's signed account of the local fixture
operation. Existing broker-only assurance and the production block apply.
"""

import json

from alibi import H, canon
from .clearance_records import (
    CAPABILITY_TTL, QUALIFICATION_TTL, check_grant, check_request_digest, make_scope,
    verify_decision,
)
from .solitary_evidence import verify_solitary
from .stage3_evidence import _hex


REPORT_TYPE = "WOLFALIBI_CLEARANCE_REPORT_V1"
_REPORT_FIELDS = {"type", "prepare", "qualification", "grant", "admission", "request", "operation", "outcome"}
_ISSUER_FIELDS = ("broker_pub", "witness_pub", "supervisor_pub")
_KEY_FIELDS = (*_ISSUER_FIELDS, "owner_pub", "gateway_pub", "agent_pub")
_EXPECTED_FIELDS = {"contract", "expected_witness_state_digest", *_KEY_FIELDS}
_MAX_REPORT_BYTES = 256 * 1024


class _IncompleteReport(ValueError):
    """A mandatory part of the positive chain is unavailable."""


def _snapshot(report):
    if report is None:
        raise _IncompleteReport("Clearance report is missing")
    if type(report) is not dict or report.keys() - _REPORT_FIELDS:
        raise ValueError("invalid Clearance report fields")
    if _REPORT_FIELDS - report.keys():
        raise _IncompleteReport("Clearance report lacks required records")
    encoded = canon(report)
    if len(encoded) > _MAX_REPORT_BYTES:
        raise ValueError("Clearance report exceeds size limit")
    report = json.loads(encoded)
    if report["type"] != REPORT_TYPE:
        raise ValueError("unsupported Clearance report type")
    if report["outcome"] in ("BLOCKED", "INCOMPLETE"):
        raise _IncompleteReport("Clearance report has no confirmed effect")
    if report["outcome"] != "ALLOWED":
        raise ValueError("Clearance report has no allowed effect")
    if any(report[key] is None for key in _REPORT_FIELDS - {"type", "outcome"}):
        raise _IncompleteReport("Clearance report lacks required records")
    return report


def _checked_at(payload):
    value = payload.get("checked_at")
    if type(value) is not int or not 0 <= value < 2**63 - QUALIFICATION_TTL:
        raise ValueError("invalid signed gateway time")
    return value


def _same(actual, expected, label):
    if canon(actual) != canon(expected):
        raise ValueError(f"{label} differs from the expected Clearance chain")


def verify_report(report, expected):
    """Verify an allowed synthetic report against externally supplied pins.

    The exact expected fields are the Solitary contract, six distinct signing
    keys, and the retained pre-run witness digest. Keys and digest use lowercase
    hexadecimal strings. Use verify_decision for an isolated gateway decision.
    """
    try:
        if type(expected) is not dict or expected.keys() != _EXPECTED_FIELDS:
            raise ValueError("missing or invalid independent references")
        keys = {field: _hex(expected[field], 32, field) for field in _KEY_FIELDS}
        if len(set(keys.values())) != len(keys):
            raise ValueError("Clearance roles require distinct signing keys")
        initial = _hex(expected["expected_witness_state_digest"], 32, "retained witness digest")
        contract = json.loads(canon(expected["contract"]))
        scope = make_scope(contract, agent_pub=keys["agent_pub"], gateway_pub=keys["gateway_pub"],
                           expected_witness_state_digest=initial)
    except (ValueError, TypeError, KeyError, RuntimeError):
        return {"outcome": "BLOCKED", "reason": "missing or invalid independent references"}

    try:
        return _verify_positive(_snapshot(report), contract, scope, keys, initial)
    except _IncompleteReport as exc:
        return {"outcome": "BLOCKED", "reason": str(exc)}
    except ValueError as exc:
        return {"outcome": "REJECTED", "reason": str(exc)}
    except (TypeError, KeyError, RuntimeError):
        return {"outcome": "REJECTED", "reason": "invalid Clearance report encoding"}


def _verify_positive(report, contract, scope, keys, initial):
    prepared = verify_decision(report["prepare"], keys["gateway_pub"])
    admitted = verify_decision(report["admission"], keys["gateway_pub"])
    operation = verify_decision(report["operation"], keys["gateway_pub"])
    prepared_at, admitted_at, operated_at = map(_checked_at, (prepared, admitted, operation))
    deadline = contract["expires_at"]
    if deadline != prepared_at + QUALIFICATION_TTL or not (prepared_at <= admitted_at <= operated_at < deadline):
        raise ValueError("gateway records disagree on the qualification window")
    issuers = {field: keys[field].hex() for field in _ISSUER_FIELDS}
    common = {
        "type": "WOLFALIBI_CLEARANCE_DECISION_V1", "scope": scope, "observation": "SYNTHETIC_GATEWAY",
        "broker_assurance": "BROKER_ONLY", "production": "BLOCKED",
        "qualification_issuers": issuers, "owner_pub": keys["owner_pub"].hex(),
    }
    _same(prepared, {
        **common, "phase": "PREPARE", "outcome": "ISSUED", "reason": "CHALLENGE_ISSUED",
        "checked_at": prepared_at, "grant_id": None, "qualification": "UNCHECKED",
        "owner_authorization": "UNCHECKED", "effect": "NONE", "expires_at": deadline,
    }, "prepare decision")

    owner = check_grant(report["grant"], owner_pub=keys["owner_pub"], scope=scope, now=admitted_at)
    expiry = min(deadline, owner["expires_at"], admitted_at + CAPABILITY_TTL)
    if not admitted_at <= operated_at < expiry:
        raise ValueError("operation falls outside the admitted capability window")
    capability_digest = admitted.get("capability_sha256")
    _hex(capability_digest, 32, "admitted capability digest")
    request = check_request_digest(report["request"], agent_pub=keys["agent_pub"],
                                   capability_sha256=capability_digest)

    qualification = verify_solitary(
        report["qualification"], contract=contract, now=admitted_at,
        expected_witness_state_digest=initial, **{field: keys[field] for field in _ISSUER_FIELDS},
    )
    if qualification["outcome"] == "BLOCKED":
        raise _IncompleteReport("required Solitary qualification is unavailable")
    if qualification["outcome"] != "VERIFIED" or qualification.get("assurance") != "BROKER_ONLY":
        raise ValueError("Solitary qualification could not be verified")
    common.update(
        grant_id=owner["grant_id"], grant_sha256=H(canon(report["grant"])).hex(),
        qualification="SYNTHETIC_CURRENT", owner_authorization="CURRENT",
        qualification_sha256=H(canon(report["qualification"])).hex(),
        witness_head=qualification["witness_state_digest"],
    )
    _same(admitted, {
        **common, "phase": "ADMISSION", "outcome": "ADMITTED", "reason": "BOTH_PREDICATES_CURRENT",
        "checked_at": admitted_at, "effect": "NONE", "expires_at": expiry, "budget": 1,
        "capability_sha256": capability_digest,
    }, "admission decision")
    response_digest = operation.get("response_sha256")
    _hex(response_digest, 32, "reported response digest")
    _same(operation, {
        **common, "phase": "OPERATION", "outcome": "ALLOWED", "reason": "PROTECTED_READ_COMPLETED",
        "checked_at": operated_at, "effect": "OBSERVED", "response_sha256": response_digest,
        "admission_sha256": H(canon(report["admission"])).hex(),
        "request_id": request["request_id"], "request_sha256": H(canon(report["request"])).hex(),
    }, "operation decision")
    return {
        "outcome": "VERIFIED", "scope": scope, "checked_at": operated_at, "historical": True,
        "qualification": "SYNTHETIC_VERIFIED_AT_ADMISSION",
        "owner_authorization": "SIGNED_GRANT_IN_WINDOW_AT_OPERATION",
        "effect": "OBSERVED", "effect_source": "GATEWAY_SIGNATURE", "response_sha256": response_digest,
        "broker_assurance": "BROKER_ONLY", "confinement": "BLOCKED", "production": "BLOCKED",
        "grant_id": owner["grant_id"], "request_id": request["request_id"],
    }
