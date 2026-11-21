"""Signed records for one synthetic finance payment-intent profile."""

import re

from alibi import canon
from .clearance_records import _document, _fields, _id, _key, _time
from .education_records import (
    MAX_GRANT_SECONDS, MAX_QUALIFICATION_SECONDS, _GRANT_FIELDS, _PACKET_FIELDS,
    _QUALIFICATION_FIELDS, _current, _current_attachments, _distinct, _period,
    _sign, _verify, _verify_signature, digest, validate_identifier, validate_peer,
)
from .stage3_evidence import _hex


TENANT = "fictional-bank"
ACCOUNT = "fictional-checking"
CURRENCY = "CAD"
OPERATION = "fin.payment.initiate"
PENDING = "PENDING_EXTERNAL_SETTLEMENT"
MAX_AMOUNT_MINOR = 1_000_000

_RUN_FIELDS = {
    "tenant", "account", "currency", "operation", "target_pub", "policy_epoch",
    "run_id", "challenge", "caller_pub",
}
_PAYMENT_FIELDS = {"payee", "amount_minor", "request_id"}
_SCOPE_FIELDS = _RUN_FIELDS | _PAYMENT_FIELDS
_IDEMPOTENCY_FIELDS = {"target_pub", "tenant", "operation", "request_id"}
_BUSINESS_FIELDS = _IDEMPOTENCY_FIELDS | {"account", "payee", "amount_minor", "currency"}
_PAYEE = re.compile(r"fictional-[a-z0-9][a-z0-9-]{0,53}\Z")
_GRANT_TYPE = "QUORVANE_FINANCE_OWNER_GRANT_V1"
_QUALIFICATION_TYPE = "QUORVANE_FINANCE_LIVE_QUALIFICATION_V1"
_CALLER_TYPE = "QUORVANE_FINANCE_CALLER_DISPATCH_V1"
_RECEIPT_TYPE = "QUORVANE_FINANCE_TARGET_RECEIPT_V1"
_GRANT_DOMAIN = b"quorvane/finance/owner-grant/v1"
_SUPERVISOR_DOMAIN = b"quorvane/finance/supervisor/v1"
_WITNESS_DOMAIN = b"quorvane/finance/witness/v1"
_CALLER_DOMAIN = b"quorvane/finance/caller-dispatch/v1"
_TARGET_DOMAIN = b"quorvane/finance/target-receipt/v1"


def _project(scope, fields):
    return {field: scope[field] for field in fields}


def _validate_run_values(scope):
    if (scope["tenant"], scope["account"], scope["currency"], scope["operation"]) != (
        TENANT, ACCOUNT, CURRENCY, OPERATION,
    ):
        raise ValueError("scope differs from the fixed synthetic payment profile")
    _time(scope["policy_epoch"], "finance policy epoch")
    if scope["policy_epoch"] == 0:
        raise ValueError("finance policy epoch must be positive")
    _id(scope["run_id"], "finance run ID")
    for field in ("target_pub", "challenge", "caller_pub"):
        _hex(scope[field], 32, field)
    _distinct(scope)


def validate_run_scope(scope):
    """Detach the exact enrollment shared by potentially many payment intents."""
    scope = _document(scope, "finance run scope", max_bytes=4096)
    _fields(scope, _RUN_FIELDS, "finance run scope")
    _validate_run_values(scope)
    return scope


def validate_scope(scope):
    """Detach and validate the fixed synthetic profile and one payment request."""
    scope = _document(scope, "finance payment scope", max_bytes=4096)
    _fields(scope, _SCOPE_FIELDS, "finance payment scope")
    _validate_run_values(scope)
    _id(scope["request_id"], "finance request ID")
    if type(scope["payee"]) is not str or not _PAYEE.fullmatch(scope["payee"]):
        raise ValueError("invalid synthetic payee")
    amount = scope["amount_minor"]
    if type(amount) is not int or not 1 <= amount <= MAX_AMOUNT_MINOR:
        raise ValueError("invalid synthetic payment amount")
    return scope


def run_scope(scope):
    """Project a payment onto the independently enrolled run fields."""
    return _project(validate_scope(scope), _RUN_FIELDS)


def idempotency_key(scope):
    """Name one durable target, tenant, operation and request ID slot."""
    return digest(_project(validate_scope(scope), _IDEMPOTENCY_FIELDS))


def business_digest(scope):
    """Hash the immutable business request independently of authorization renewal."""
    return digest(_project(validate_scope(scope), _BUSINESS_FIELDS))


def owner_grant(owner, scope, grant_id, start, end):
    """Sign owner authority for the exact payment and execution scope."""
    scope = validate_scope(scope)
    _distinct(scope, owner=owner.pub)
    _id(grant_id, "finance grant ID")
    _period(start, end, MAX_GRANT_SECONDS)
    return _sign(owner, _GRANT_DOMAIN, {
        "type": _GRANT_TYPE, "scope_sha256": digest(scope), "grant_id": grant_id,
        "not_before": start, "expires_at": end,
    })


def qualify(supervisor, witness, scope, peer, start, end):
    """Bind the peer measurement to the run and witness the exact attestation."""
    scope = run_scope(scope) if type(scope) is dict and scope.keys() == _SCOPE_FIELDS else validate_run_scope(scope)
    _distinct(scope, supervisor=supervisor.pub, witness=witness.pub)
    _period(start, end, MAX_QUALIFICATION_SECONDS)
    payload = {
        "type": _QUALIFICATION_TYPE, "scope_sha256": digest(scope), "peer": validate_peer(peer),
        "not_before": start, "expires_at": end,
    }
    signed = _sign(supervisor, _SUPERVISOR_DOMAIN, payload)
    attestation = {"payload": payload, "supervisor_signature": signed["signature"]}
    return {**attestation, "witness_signature": witness.sign(_WITNESS_DOMAIN, canon(attestation)).hex()}


def _caller_payload(packet):
    return {"type": _CALLER_TYPE, "scope_sha256": digest(packet["scope"]),
            "grant_sha256": digest(packet["grant"]), "qualification_sha256": digest(packet["qualification"])}


def dispatch(caller, scope, grant, qualification):
    """Sign the exact business request and the supplied authorization attachments."""
    packet = {
        "scope": validate_scope(scope),
        "grant": None if grant is None else _document(grant, "finance grant"),
        "qualification": None if qualification is None else _document(qualification, "finance qualification"),
    }
    if _key(caller.pub, "finance caller key") != packet["scope"]["caller_pub"]:
        raise ValueError("signer differs from the scoped finance caller")
    return {**packet, "caller_proof": _sign(caller, _CALLER_DOMAIN, _caller_payload(packet))}


def snapshot_packet(packet):
    """Take an exact detached snapshot of the bounded finance carrier."""
    packet = _document(packet, "finance dispatch")
    _fields(packet, _PACKET_FIELDS, "finance dispatch")
    packet["scope"] = validate_scope(packet["scope"])
    return packet


def _expect_scope(scope, expected):
    if type(expected) is dict and expected.keys() == _SCOPE_FIELDS:
        if scope != validate_scope(expected):
            raise ValueError("dispatch differs from the expected payment scope")
    elif _project(scope, _RUN_FIELDS) != validate_run_scope(expected):
        raise ValueError("dispatch differs from the enrolled finance run")


def _check_grant(grant, scope, owner_pub, now):
    payload = _verify(grant, owner_pub, _GRANT_DOMAIN)
    _fields(payload, _GRANT_FIELDS, "finance grant payload")
    if payload["type"] != _GRANT_TYPE or payload["scope_sha256"] != digest(scope):
        raise ValueError("owner grant differs from the exact payment scope")
    _id(payload["grant_id"], "finance grant ID")
    _current(payload, now, MAX_GRANT_SECONDS)
    return payload["grant_id"]


def _check_qualification(record, scope, supervisor_pub, witness_pub, peer, now, retained):
    _fields(record, {"payload", "supervisor_signature", "witness_signature"}, "finance qualification")
    payload = record["payload"]
    _fields(payload, _QUALIFICATION_FIELDS, "finance qualification payload")
    if (payload["type"] != _QUALIFICATION_TYPE
            or payload["scope_sha256"] != digest(_project(scope, _RUN_FIELDS))
            or validate_peer(payload["peer"]) != peer):
        raise ValueError("qualification differs from the enrolled finance run or measured peer")
    _current(payload, now, MAX_QUALIFICATION_SECONDS)
    if digest(record) != retained:
        raise ValueError("finance qualification differs from the retained witness digest")
    supervisor_signature = record["supervisor_signature"]
    _verify_signature(supervisor_pub, _SUPERVISOR_DOMAIN, payload, supervisor_signature)
    attestation = {"payload": payload, "supervisor_signature": supervisor_signature}
    _verify_signature(witness_pub, _WITNESS_DOMAIN, attestation, record["witness_signature"])


def check_packet(packet, *, expected_scope, owner_pub, supervisor_pub, witness_pub, peer, now, witness_head):
    """Return the exact grant ID after authenticating the scoped run and payment."""
    packet = snapshot_packet(packet)
    scope = packet["scope"]
    _expect_scope(scope, expected_scope)
    _distinct(scope, owner=owner_pub, supervisor=supervisor_pub, witness=witness_pub)
    peer = validate_peer(peer)
    _time(now, "trusted finance admission time")
    if type(witness_head) is bytes:
        witness_head = _key(witness_head, "retained finance witness digest")
    else:
        _hex(witness_head, 32, "retained finance witness digest")

    proof = _verify(packet["caller_proof"], bytes.fromhex(scope["caller_pub"]), _CALLER_DOMAIN)
    if canon(proof) != canon(_caller_payload(packet)):
        raise ValueError("caller proof differs from the payment or its attachments")
    grant_id = _check_grant(packet["grant"], scope, owner_pub, now)
    _check_qualification(packet["qualification"], scope, supervisor_pub, witness_pub, peer, now, witness_head)
    return grant_id


def check_admission_time(packet, now):
    """Recheck validity windows after authentication and return their earliest expiry."""
    return _current_attachments(snapshot_packet(packet), now)


def _receipt_payload(scope, packet, now):
    packet = snapshot_packet(packet)
    if packet["scope"] != scope:
        raise ValueError("receipt differs from the exact payment scope")
    _current_attachments(packet, now)
    return {
        "type": _RECEIPT_TYPE, "outcome": PENDING, "authorized_at": now,
        "target_pub": scope["target_pub"], "request_id": scope["request_id"],
        "scope_sha256": digest(scope), "packet_sha256": digest(packet),
        "grant_sha256": digest(packet["grant"]), "qualification_sha256": digest(packet["qualification"]),
        "caller_proof_sha256": digest(packet["caller_proof"]),
        "business_sha256": digest(_project(scope, _BUSINESS_FIELDS)),
        "idempotency_key": digest(_project(scope, _IDEMPOTENCY_FIELDS)),
    }


def receipt(target, scope, packet, now):
    """Sign the pending synthetic intent committed by the local target."""
    scope = validate_scope(scope)
    if _key(target.pub, "finance target key") != scope["target_pub"]:
        raise ValueError("receipt signer differs from the scoped finance target")
    return _sign(target, _TARGET_DOMAIN, _receipt_payload(scope, packet, now))


def verify_receipt(record, *, target_pub, scope, packet):
    """Check the signed historical pending-intent receipt against exact public inputs."""
    scope = validate_scope(scope)
    if _key(target_pub, "finance target key") != scope["target_pub"]:
        raise ValueError("target key differs from the expected finance scope")
    payload = _verify(record, target_pub, _TARGET_DOMAIN)
    expected = _receipt_payload(scope, packet, payload.get("authorized_at"))
    if canon(payload) != canon(expected):
        raise ValueError("finance receipt differs from the exact pending intent")
    return payload
