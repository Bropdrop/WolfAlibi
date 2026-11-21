"""Distinct read-only authority to inquire about one synthetic payment intent."""

from alibi import canon
from .clearance_records import _document, _fields, _id, _key, _time
from .education_records import _current, _period, _sign, _verify, digest
from .finance_records import ACCOUNT, OPERATION, TENANT, validate_scope as validate_finance_scope
from .stage3_evidence import _hex


PURPOSE = "fin.payment.history.inquire"
MAX_GRANT_SECONDS = 300

_INTENT_FIELDS = ("tenant", "account", "operation", "request_id", "target_pub")
_SCOPE_FIELDS = {*_INTENT_FIELDS, "purpose"}
_GRANT_FIELDS = {"type", "scope_sha256", "auditor_pub", "grant_id", "not_before", "expires_at"}
_REQUEST_FIELDS = {"scope", "grant", "challenge", "auditor_proof"}
_GRANT_TYPE = "QUORVANE_HISTORY_OWNER_GRANT_V1"
_PROOF_TYPE = "QUORVANE_HISTORY_AUDITOR_INQUIRY_V1"
_GRANT_DOMAIN = b"quorvane/history/owner-grant/v1"
_PROOF_DOMAIN = b"quorvane/history/auditor-inquiry/v1"


def validate_scope(scope):
    """Detach and validate the exact read-only inquiry scope."""
    scope = _document(scope, "history inquiry scope", max_bytes=4096)
    _fields(scope, _SCOPE_FIELDS, "history inquiry scope")
    if (scope["tenant"], scope["account"], scope["operation"], scope["purpose"]) != (
        TENANT, ACCOUNT, OPERATION, PURPOSE,
    ):
        raise ValueError("unsupported synthetic history inquiry scope")
    _id(scope["request_id"], "history request ID")
    _hex(scope["target_pub"], 32, "history target key")
    return scope


def inquiry_scope(finance_scope):
    """Name the exact historical intent without carrying its execution authority."""
    finance_scope = validate_finance_scope(finance_scope)
    return {**{field: finance_scope[field] for field in _INTENT_FIELDS}, "purpose": PURPOSE}


def _check_roles(scope, owner_pub, auditor_pub):
    roles = {scope["target_pub"], _key(owner_pub, "history owner key"), _key(auditor_pub, "history auditor key")}
    if len(roles) != 3:
        raise ValueError("history target, owner and auditor signing keys must be distinct")


def issue_grant(owner, scope, auditor_pub, grant_id, start, end):
    """Issue a bounded read-only grant to a distinct auditor credential."""
    scope = validate_scope(scope)
    _check_roles(scope, owner.pub, auditor_pub)
    _id(grant_id, "history grant ID")
    _period(start, end, MAX_GRANT_SECONDS)
    return _sign(owner, _GRANT_DOMAIN, {
        "type": _GRANT_TYPE, "scope_sha256": digest(scope), "auditor_pub": auditor_pub.hex(),
        "grant_id": grant_id, "not_before": start, "expires_at": end,
    })


def _grant_auditor(payload, scope):
    _fields(payload, _GRANT_FIELDS, "history grant payload")
    if payload["type"] != _GRANT_TYPE or payload["scope_sha256"] != digest(scope):
        raise ValueError("grant differs from the exact read-only history inquiry scope")
    _id(payload["grant_id"], "history grant ID")
    _period(payload["not_before"], payload["expires_at"], MAX_GRANT_SECONDS)
    return _hex(payload["auditor_pub"], 32, "history auditor key")


def _proof_payload(scope, grant, challenge):
    return {
        "type": _PROOF_TYPE, "scope_sha256": digest(scope),
        "grant_sha256": digest(grant), "challenge": challenge,
    }


def sign_inquiry(auditor, scope, grant, challenge):
    """Prove possession of the named auditor key for the exact inquiry challenge."""
    scope = validate_scope(scope)
    _hex(challenge, 32, "history inquiry challenge")
    grant = _document(grant, "history inquiry grant")
    _fields(grant, {"payload", "signature"}, "history inquiry grant")
    _hex(grant["signature"], 64, "history grant signature")
    auditor_pub = _grant_auditor(grant["payload"], scope)
    if _key(auditor.pub, "history auditor signer") != auditor_pub.hex() or auditor_pub.hex() == scope["target_pub"]:
        raise ValueError("signer differs from the scoped history auditor")
    proof = _sign(auditor, _PROOF_DOMAIN, _proof_payload(scope, grant, challenge))
    return {"scope": scope, "grant": grant, "challenge": challenge, "auditor_proof": proof}


def check_inquiry(request, *, scope, owner_pub, challenge, now):
    """Authenticate one inquiry against the expected scope, owner, challenge and time."""
    scope = validate_scope(scope)
    _hex(challenge, 32, "expected history inquiry challenge")
    _time(now, "trusted history inquiry time")
    request = _document(request, "history inquiry")
    _fields(request, _REQUEST_FIELDS, "history inquiry")
    if validate_scope(request["scope"]) != scope or request["challenge"] != challenge:
        raise ValueError("history inquiry differs from the expected scope or challenge")
    grant = request["grant"]
    payload = _verify(grant, owner_pub, _GRANT_DOMAIN)
    auditor_pub = _grant_auditor(payload, scope)
    _check_roles(scope, owner_pub, auditor_pub)
    _current(payload, now, MAX_GRANT_SECONDS)
    proof = _verify(request["auditor_proof"], auditor_pub, _PROOF_DOMAIN)
    if canon(proof) != canon(_proof_payload(scope, grant, challenge)):
        raise ValueError("auditor proof differs from the exact inquiry grant or challenge")
    return payload["grant_id"]
