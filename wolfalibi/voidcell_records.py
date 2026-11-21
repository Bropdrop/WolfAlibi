"""Signed records for VoidCell's fixed synthetic counter operation."""

from alibi import H, canon, verify_sig
from .clearance_records import _document, _fields, _id, _key, _period, _time
from .solitary_evidence import _policy
from .stage3_evidence import _hex


AUDIENCE = "wolfalibi.voidcell.001"
TENANT = "synthetic-owner"
RESOURCE = "synthetic-counter"
OPERATION = "increment"

_TARGET = {"audience": AUDIENCE, "tenant": TENANT, "resource": RESOURCE, "operation": OPERATION}
_SCOPE_DIGESTS = {
    "challenge", "contract_sha256", "profile_sha256", "gateway_pub", "target_pub",
    "expected_witness_state_digest",
}
_SCOPE_FIELDS = set(_TARGET) | _SCOPE_DIGESTS | {"run_id", "operation_id"}
_DISPATCH_FIELDS = {"route", "qualification", "grant"}
_GRANT_TYPE = "WOLFALIBI_VOIDCELL_GRANT_V1"
_DISPATCH_TYPE = "WOLFALIBI_VOIDCELL_DISPATCH_V1"
_RECONCILE_TYPE = "WOLFALIBI_VOIDCELL_RECONCILE_V1"
_REVOCATION_TYPE = "WOLFALIBI_VOIDCELL_REVOCATION_V1"
_RECEIPT_TYPE = "WOLFALIBI_VOIDCELL_TARGET_RECEIPT_V1"
_GRANT_DOMAIN = b"wolfalibi/voidcell/grant/v1"
_DISPATCH_DOMAIN = b"wolfalibi/voidcell/dispatch/v1"
_RECONCILE_DOMAIN = b"wolfalibi/voidcell/reconcile/v1"
_REVOCATION_DOMAIN = b"wolfalibi/voidcell/revocation/v1"
_RECEIPT_DOMAIN = b"wolfalibi/voidcell/target-receipt/v1"
_RECEIPT_OUTCOMES = ("ACCEPTED_EVIDENCED", "DENIED", "FENCED")
_MAX_DISPATCH_BYTES = 262_144


def _digest(value):
    return H(canon(value)).hex()


def make_scope(contract, *, gateway_pub, target_pub, operation_id, expected_witness_state_digest):
    """Bind the target, gateway and one operation to the expected trial contract."""
    contract = _document(contract, "run contract", max_bytes=49_152)
    _policy(contract)
    if "agent_adapter" not in contract["profile"]:
        raise ValueError("VOIDCELL requires the fixed Stage 5 callback profile")
    return _scope({
        **_TARGET, "run_id": contract["run_id"], "challenge": contract["challenge"],
        "contract_sha256": _digest(contract), "profile_sha256": _digest(contract["profile"]),
        "gateway_pub": _key(gateway_pub, "gateway key"), "target_pub": _key(target_pub, "target key"),
        "expected_witness_state_digest": _key(expected_witness_state_digest, "witness head"),
        "operation_id": operation_id,
    })


def _scope(value):
    scope = _document(value, "VoidCell scope")
    _fields(scope, _SCOPE_FIELDS, "VoidCell scope")
    if any(scope[key] != expected for key, expected in _TARGET.items()):
        raise ValueError("scope differs from the synthetic counter operation")
    run_id = scope["run_id"]
    if type(run_id) is not str or not 1 <= len(run_id) <= 256:
        raise ValueError("invalid run ID")
    _id(scope["operation_id"], "operation ID")
    for field in _SCOPE_DIGESTS:
        _hex(scope[field], 32, field)
    return scope


def _role(scope, public_key, field):
    if scope[field] != _key(public_key, field):
        raise ValueError("signing key does not match the scoped role")


def _sign(signer, domain, payload):
    return {"payload": payload, "signature": signer.sign(domain, canon(payload)).hex()}


def _verify(record, public_key, domain):
    record = _document(record, "signed VoidCell record")
    _fields(record, {"payload", "signature"}, "signed VoidCell record")
    _key(public_key, "expected signing key")
    signature = _hex(record["signature"], 64, "signature")
    payload = record["payload"]
    if type(payload) is not dict or not verify_sig(public_key, domain, canon(payload), signature):
        raise ValueError("invalid VoidCell record signature or payload")
    return payload


def _one(value):
    return type(value) is int and value == 1


def grant(owner, *, scope, grant_id, not_before, expires_at):
    """Sign one owner-authorized use with a bounded validity window."""
    _id(grant_id, "grant ID")
    _period(not_before, expires_at)
    return _sign(owner, _GRANT_DOMAIN, {
        "type": _GRANT_TYPE, "scope": _scope(scope), "grant_id": grant_id,
        "not_before": not_before, "expires_at": expires_at, "seq": 1, "budget": 1,
    })


def check_grant(record, *, owner_pub, scope, now):
    payload = _verify(record, owner_pub, _GRANT_DOMAIN)
    _fields(payload, {"type", "scope", "grant_id", "not_before", "expires_at", "seq", "budget"},
            "owner grant")
    if payload["type"] != _GRANT_TYPE or not _one(payload["seq"]) or not _one(payload["budget"]):
        raise ValueError("invalid grant type, sequence or budget")
    _id(payload["grant_id"], "grant ID")
    _period(payload["not_before"], payload["expires_at"])
    _time(now, "grant evaluation time")
    if not payload["not_before"] <= now < payload["expires_at"]:
        raise ValueError("owner grant is outside its validity window")
    if _scope(payload["scope"]) != _scope(scope):
        raise ValueError("owner grant scope mismatch")
    return payload


def _snapshot_carrier(value):
    """Copy attached synthetic evidence with bounds that cover an exact WAL."""
    nodes = 16_384
    characters = _MAX_DISPATCH_BYTES

    def text(value):
        nonlocal characters
        characters -= len(value)
        if characters < 0 or (value and not value.isprintable()):
            raise ValueError("invalid or oversized dispatch text")
        return value

    def walk(item, depth):
        nonlocal nodes
        nodes -= 1
        if nodes < 0 or depth > 16:
            raise ValueError("dispatch carrier exceeds structural bounds")
        if type(item) is dict and len(item) <= nodes:
            copied = {}
            for key, member in tuple(item.items()):
                if type(key) is not str or not 1 <= len(key) <= 128:
                    raise ValueError("invalid dispatch field name")
                copied[text(key)] = walk(member, depth + 1)
            return copied
        if type(item) is list and len(item) <= nodes:
            return [walk(member, depth + 1) for member in tuple(item)]
        if type(item) is str:
            return text(item)
        if item is None or type(item) is bool:
            return item
        # Snapshot device and inode identities may occupy unsigned 64 bits.
        if type(item) is int and -(1 << 63) <= item < (1 << 64):
            return item
        raise ValueError("invalid or oversized dispatch value")

    snapshot = walk(value, 0)
    if len(canon(snapshot)) > _MAX_DISPATCH_BYTES:
        raise ValueError("dispatch carrier exceeds byte bound")
    return snapshot


def _attachment(value):
    if value is not None and type(value) is not dict:
        raise ValueError("dispatch attachments must be objects or null")


def snapshot_dispatch(packet):
    """Freeze the carrier once at target ingress before checking its attachments."""
    _fields(packet, _DISPATCH_FIELDS, "dispatch carrier")
    copied = _snapshot_carrier(packet)
    _fields(copied, _DISPATCH_FIELDS, "dispatch carrier")
    _fields(copied["route"], {"payload", "signature"}, "signed dispatch route")
    _attachment(copied["qualification"])
    _attachment(copied["grant"])
    return copied


def dispatch_digest(packet):
    return _digest(snapshot_dispatch(packet))


def _route(scope, qualification, owner_grant):
    return {
        "type": _DISPATCH_TYPE, "scope": scope, "seq": 1,
        "qualification_sha256": _digest(qualification), "grant_sha256": _digest(owner_grant),
    }


def sign_dispatch(gateway, *, scope, qualification, owner_grant):
    """Sign routing and attachment hashes; the target evaluates both attachments."""
    scope = _scope(scope)
    _role(scope, gateway.pub, "gateway_pub")
    _attachment(qualification)
    _attachment(owner_grant)
    packet = _snapshot_carrier({"qualification": qualification, "grant": owner_grant})
    packet["route"] = _sign(gateway, _DISPATCH_DOMAIN, _route(
        scope, packet["qualification"], packet["grant"],
    ))
    return snapshot_dispatch(packet)


def check_dispatch(packet, *, gateway_pub, scope):
    packet = snapshot_dispatch(packet)
    scope = _scope(scope)
    _role(scope, gateway_pub, "gateway_pub")
    payload = _verify(packet["route"], gateway_pub, _DISPATCH_DOMAIN)
    expected = _route(scope, packet["qualification"], packet["grant"])
    if canon(payload) != canon(expected):
        raise ValueError("dispatch scope, sequence or attachment digest mismatch")
    return payload


def sign_reconcile(gateway, *, scope, dispatch_sha256):
    scope = _scope(scope)
    _role(scope, gateway.pub, "gateway_pub")
    _hex(dispatch_sha256, 32, "dispatch digest")
    return _sign(gateway, _RECONCILE_DOMAIN, {
        "type": _RECONCILE_TYPE, "scope": scope, "dispatch_sha256": dispatch_sha256,
    })


def check_reconcile(record, *, gateway_pub, scope):
    scope = _scope(scope)
    _role(scope, gateway_pub, "gateway_pub")
    payload = _verify(record, gateway_pub, _RECONCILE_DOMAIN)
    _fields(payload, {"type", "scope", "dispatch_sha256"}, "reconciliation request")
    if payload["type"] != _RECONCILE_TYPE or _scope(payload["scope"]) != scope:
        raise ValueError("reconciliation request scope mismatch")
    _hex(payload["dispatch_sha256"], 32, "dispatch digest")
    return payload["dispatch_sha256"]


def revoke(owner, *, scope, grant_id):
    _id(grant_id, "grant ID")
    return _sign(owner, _REVOCATION_DOMAIN, {
        "type": _REVOCATION_TYPE, "scope": _scope(scope), "grant_id": grant_id,
    })


def check_revocation(record, *, owner_pub, scope):
    payload = _verify(record, owner_pub, _REVOCATION_DOMAIN)
    _fields(payload, {"type", "scope", "grant_id"}, "owner revocation")
    if payload["type"] != _REVOCATION_TYPE or _scope(payload["scope"]) != _scope(scope):
        raise ValueError("owner revocation scope mismatch")
    _id(payload["grant_id"], "grant ID")
    return payload["grant_id"]


def _receipt(scope, dispatch_sha256, checked_at, outcome, reason):
    _hex(dispatch_sha256, 32, "dispatch digest")
    _time(checked_at, "target evaluation time")
    if type(outcome) is not str or outcome not in _RECEIPT_OUTCOMES:
        raise ValueError("invalid target outcome")
    _id(reason, "target reason code")
    return {
        "type": _RECEIPT_TYPE, "scope": scope, "dispatch_sha256": dispatch_sha256,
        "checked_at": checked_at, "outcome": outcome, "reason": reason,
    }


def sign_receipt(target, *, scope, dispatch_sha256, checked_at, outcome, reason):
    scope = _scope(scope)
    _role(scope, target.pub, "target_pub")
    return _sign(target, _RECEIPT_DOMAIN, _receipt(scope, dispatch_sha256, checked_at, outcome, reason))


def verify_receipt(record, *, target_pub, scope, dispatch_sha256):
    scope = _scope(scope)
    _role(scope, target_pub, "target_pub")
    payload = _verify(record, target_pub, _RECEIPT_DOMAIN)
    _fields(payload, {"type", "scope", "dispatch_sha256", "checked_at", "outcome", "reason"},
            "target receipt")
    expected = _receipt(scope, dispatch_sha256, payload["checked_at"], payload["outcome"], payload["reason"])
    if canon(payload) != canon(expected):
        raise ValueError("target receipt scope or dispatch digest mismatch")
    return payload
