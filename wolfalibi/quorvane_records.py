"""Canonical, role-specific signatures for the synthetic Quorvane protocol."""

from alibi import H, canon, verify_sig
from .clearance_records import _document, _fields, _id, _key, _period, _time
from .stage3_evidence import _hex


AUDIENCE = "wolfalibi.quorvane.v1"
PROFILES = frozenset({"education", "finance"})

_RUN_FIELDS = {"run_id", "challenge", "profile", "tenant", "policy_epoch", "expires_at", "audience"}
_REQUEST_FIELDS = {"run_id", "challenge", "tenant", "policy_epoch", "operation", "request_id", "parameters"}
_QUALIFICATION_TYPE = "WOLFALIBI_QUORVANE_QUALIFICATION_V1"
_WITNESS_TYPE = "WOLFALIBI_QUORVANE_WITNESS_V1"
_GRANT_TYPE = "WOLFALIBI_QUORVANE_GRANT_V1"
_REVOCATION_TYPE = "WOLFALIBI_QUORVANE_REVOCATION_V1"
_SETTLEMENT_TYPE = "WOLFALIBI_QUORVANE_SETTLEMENT_V1"
_QUALIFICATION_DOMAIN = b"wolfalibi/quorvane/qualification/v1"
_WITNESS_DOMAIN = b"wolfalibi/quorvane/witness/v1"
_GRANT_DOMAIN = b"wolfalibi/quorvane/owner-grant/v1"
_REVOCATION_DOMAIN = b"wolfalibi/quorvane/owner-revocation/v1"
_SETTLEMENT_DOMAIN = b"wolfalibi/quorvane/settlement/v1"
_RECEIPT_DOMAIN = b"wolfalibi/quorvane/target-receipt/v1"


def _digest(value):
    return H(canon(value)).hex()


def _epoch(value):
    if type(value) is not int or not 1 <= value < (1 << 63):
        raise ValueError("invalid policy epoch")


def validate_run(run):
    """Return a bounded snapshot of the expected synthetic run."""
    run = _document(run, "Quorvane run", max_bytes=4096)
    _fields(run, _RUN_FIELDS, "Quorvane run")
    if (type(run["profile"]) is not str or run["profile"] not in PROFILES
            or run["audience"] != AUDIENCE):
        raise ValueError("invalid Quorvane profile or audience")
    _id(run["run_id"], "run ID")
    _id(run["tenant"], "tenant")
    _epoch(run["policy_epoch"])
    _hex(run["challenge"], 32, "run challenge")
    _time(run["expires_at"], "run expiration")
    if run["expires_at"] == 0:
        raise ValueError("invalid run expiration")
    return run


def _request_digest(request):
    request = _document(request, "Quorvane request", max_bytes=8192, decision=True)
    _fields(request, _REQUEST_FIELDS, "Quorvane request")
    for field in ("run_id", "tenant", "operation", "request_id"):
        _id(request[field], field)
    _hex(request["challenge"], 32, "request challenge")
    _epoch(request["policy_epoch"])
    if type(request["parameters"]) is not dict:
        raise ValueError("invalid request parameters")
    return _digest(request)


def _sign(signer, domain, payload):
    _key(signer.pub, "signing key")
    return {"payload": payload, "signature": signer.sign(domain, canon(payload)).hex()}


def _verify(record, public_key, domain, *, receipt=False):
    record = _document(record, "signed Quorvane record", decision=receipt)
    _fields(record, {"payload", "signature"}, "signed Quorvane record")
    _key(public_key, "expected signing key")
    signature = _hex(record["signature"], 64, "signature")
    payload = record["payload"]
    if type(payload) is not dict or not verify_sig(public_key, domain, canon(payload), signature):
        raise ValueError("invalid Quorvane record signature or payload")
    return payload


def _qualification_core(run, identity, previous_head):
    identity = _document(identity, "live workload identity", max_bytes=4096)
    if not identity:
        raise ValueError("live workload identity is missing")
    return {
        "run": validate_run(run), "identity": identity,
        "previous_head": _key(previous_head, "prior witness head"),
    }


def issue_qualification(qualifier, witness, *, run, identity, previous_head):
    """Sign the qualification and a separate witness link to its exact bytes."""
    if qualifier.pub == witness.pub:
        raise ValueError("qualifier and witness keys must be distinct")
    core = _qualification_core(run, identity, previous_head)
    qualified = _sign(qualifier, _QUALIFICATION_DOMAIN, {"type": _QUALIFICATION_TYPE, **core})
    witnessed = _sign(witness, _WITNESS_DOMAIN, {
        "type": _WITNESS_TYPE, **core, "qualifier_record_sha256": _digest(qualified),
    })
    return {"qualification": qualified, "witness": witnessed}


def check_qualification(record, *, qualifier_pub, witness_pub, run, identity, previous_head):
    """Verify both roles and return the exact digest for retained-head checks."""
    record = _document(record, "Quorvane qualification", max_bytes=16_384)
    _fields(record, {"qualification", "witness"}, "Quorvane qualification")
    if qualifier_pub == witness_pub:
        raise ValueError("qualifier and witness keys must be distinct")
    core = _qualification_core(run, identity, previous_head)
    qualified = _verify(record["qualification"], qualifier_pub, _QUALIFICATION_DOMAIN)
    witnessed = _verify(record["witness"], witness_pub, _WITNESS_DOMAIN)
    if canon(qualified) != canon({"type": _QUALIFICATION_TYPE, **core}):
        raise ValueError("qualification run, live identity or prior witness head mismatch")
    if canon(witnessed) != canon({
        "type": _WITNESS_TYPE, **core,
        "qualifier_record_sha256": _digest(record["qualification"]),
    }):
        raise ValueError("witness link does not match the exact qualification")
    return _digest(record)


def grant(owner, *, run, request, grant_id, not_before, expires_at):
    """Sign approval of exactly one canonical request for a bounded interval."""
    _id(grant_id, "owner grant ID")
    _period(not_before, expires_at)
    return _sign(owner, _GRANT_DOMAIN, {
        "type": _GRANT_TYPE, "run": validate_run(run), "request_sha256": _request_digest(request),
        "grant_id": grant_id, "not_before": not_before, "expires_at": expires_at, "budget": 1,
    })


def check_grant(record, *, owner_pub, run, request, now):
    payload = _verify(record, owner_pub, _GRANT_DOMAIN)
    _fields(payload, {"type", "run", "request_sha256", "grant_id", "not_before", "expires_at", "budget"},
            "owner grant")
    if (payload["type"] != _GRANT_TYPE or type(payload["budget"]) is not int
            or payload["budget"] != 1):
        raise ValueError("invalid Quorvane grant type or use budget")
    _id(payload["grant_id"], "owner grant ID")
    _period(payload["not_before"], payload["expires_at"])
    _time(now, "grant check time")
    if not payload["not_before"] <= now < payload["expires_at"]:
        raise ValueError("owner grant is outside its validity window")
    if (validate_run(payload["run"]) != validate_run(run)
            or payload["request_sha256"] != _request_digest(request)):
        raise ValueError("owner grant run or request mismatch")
    return payload


def revoke(owner, *, run, grant_id):
    _id(grant_id, "owner grant ID")
    return _sign(owner, _REVOCATION_DOMAIN, {
        "type": _REVOCATION_TYPE, "run": validate_run(run), "grant_id": grant_id,
    })


def check_revocation(record, *, owner_pub, run):
    payload = _verify(record, owner_pub, _REVOCATION_DOMAIN)
    _fields(payload, {"type", "run", "grant_id"}, "owner revocation")
    if payload["type"] != _REVOCATION_TYPE or validate_run(payload["run"]) != validate_run(run):
        raise ValueError("owner revocation run mismatch")
    _id(payload["grant_id"], "owner grant ID")
    return payload["grant_id"]


def settlement(settler, *, tenant, payment_id, initiation_sha256):
    """Authorize settlement of one exact synthetic payment initiation."""
    _id(tenant, "tenant")
    _id(payment_id, "payment ID")
    _hex(initiation_sha256, 32, "payment initiation digest")
    return _sign(settler, _SETTLEMENT_DOMAIN, {
        "type": _SETTLEMENT_TYPE, "tenant": tenant, "payment_id": payment_id,
        "initiation_sha256": initiation_sha256,
    })


def check_settlement(record, *, settler_pub):
    payload = _verify(record, settler_pub, _SETTLEMENT_DOMAIN)
    _fields(payload, {"type", "tenant", "payment_id", "initiation_sha256"}, "payment settlement")
    if payload["type"] != _SETTLEMENT_TYPE:
        raise ValueError("invalid settlement record type")
    _id(payload["tenant"], "tenant")
    _id(payload["payment_id"], "payment ID")
    _hex(payload["initiation_sha256"], 32, "payment initiation digest")
    return payload


def sign_receipt(target, payload):
    """Sign a bounded target receipt in its own protocol domain."""
    payload = _document(payload, "target receipt", decision=True)
    return _sign(target, _RECEIPT_DOMAIN, payload)


def verify_receipt(record, target_pub):
    """Return the validated target payload without conferring authorization."""
    return _verify(record, target_pub, _RECEIPT_DOMAIN, receipt=True)
