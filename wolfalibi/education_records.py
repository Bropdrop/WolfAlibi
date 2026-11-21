"""Signed records for one fixed synthetic Education read.

Admission uses externally pinned keys, a live transport observation and a
retained witness digest. Offline receipt verification authenticates a signed
historical target record against supplied artifacts. The receipt alone
provides no live authorization or process assurance.
"""

import re

from alibi import H, canon, verify_sig
from .clearance_records import _document, _fields, _id, _key, _time
from .stage3_evidence import _hex


PURPOSE = "approved-support"
OPERATION = "edu.student_record.read"
POLICY_VERSION = "edu-gate-002.v1"
MAX_GRANT_SECONDS = 300
MAX_QUALIFICATION_SECONDS = 120

_SCOPE_FIELDS = {
    "tenant", "student", "purpose", "operation", "target_pub", "policy_version",
    "run_id", "challenge", "caller_pub", "request_id",
}
_PEER_DIGESTS = {"exe_sha256", "argv_sha256", "source_sha256"}
_PEER_FIELDS = {"pid", "uid", "gid", "start_ticks", "boot_id", *_PEER_DIGESTS}
_PACKET_FIELDS = {"scope", "grant", "qualification", "caller_proof"}
_GRANT_FIELDS = {"type", "scope_sha256", "grant_id", "not_before", "expires_at"}
_QUALIFICATION_FIELDS = {"type", "scope_sha256", "peer", "not_before", "expires_at"}
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_SYNTHETIC_TENANT = "fictional-school"
_SYNTHETIC_STUDENT = "fictional-aster"
_SYNTHETIC_RESPONSE = {"student_ref": _SYNTHETIC_STUDENT, "support_level": "scheduled-check-in"}
_GRANT_TYPE = "QUORVANE_EDUCATION_OWNER_GRANT_V1"
_QUALIFICATION_TYPE = "QUORVANE_EDUCATION_LIVE_QUALIFICATION_V1"
_CALLER_TYPE = "QUORVANE_EDUCATION_CALLER_DISPATCH_V1"
_RECEIPT_TYPE = "QUORVANE_EDUCATION_TARGET_RECEIPT_V1"
_GRANT_DOMAIN = b"quorvane/education/owner-grant/v1"
_SUPERVISOR_DOMAIN = b"quorvane/education/supervisor/v1"
_WITNESS_DOMAIN = b"quorvane/education/witness/v1"
_CALLER_DOMAIN = b"quorvane/education/caller-dispatch/v1"
_TARGET_DOMAIN = b"quorvane/education/target-receipt/v1"


def digest(value):
    """Return the SHA-256 of an exact canonical record as lowercase hex."""
    return H(canon(value)).hex()


def validate_identifier(value, label="identifier"):
    """Validate a bounded synthetic identifier."""
    _id(value, label)
    return value


def validate_scope(scope):
    """Snapshot and check the exact protected Education read scope."""
    scope = _document(scope, "education scope", max_bytes=4096)
    _fields(scope, _SCOPE_FIELDS, "education scope")
    for field in ("tenant", "student", "run_id", "request_id"):
        _id(scope[field], field)
    for field in ("target_pub", "caller_pub", "challenge"):
        _hex(scope[field], 32, field)
    if (scope["purpose"], scope["operation"], scope["policy_version"]) != (PURPOSE, OPERATION, POLICY_VERSION):
        raise ValueError("unsupported education purpose, operation or policy version")
    if scope["target_pub"] == scope["caller_pub"]:
        raise ValueError("target and caller require distinct signing keys")
    return scope


def validate_peer(peer):
    """Snapshot the fixed Linux observation grammar before signing or checking."""
    peer = _document(peer, "measured education peer", max_bytes=4096)
    _fields(peer, _PEER_FIELDS, "measured education peer")
    for field in ("pid", "uid", "gid"):
        if type(peer[field]) is not int or not 0 < peer[field] < (1 << 31):
            raise ValueError("invalid measured education peer identity")
    _time(peer["start_ticks"], "peer process start ticks")
    if peer["start_ticks"] == 0:
        raise ValueError("peer process start ticks unavailable")
    if type(peer["boot_id"]) is not str or not _BOOT_ID.fullmatch(peer["boot_id"]):
        raise ValueError("invalid measured peer boot ID")
    for field in _PEER_DIGESTS:
        _hex(peer[field], 32, f"measured peer {field}")
    return peer


def _distinct(scope, **roles):
    keys = (scope["target_pub"], scope["caller_pub"], *(_key(pub, role) for role, pub in roles.items()))
    if len(set(keys)) != len(keys):
        raise ValueError("education signing roles must be distinct")


def _period(start, end, maximum):
    _time(start, "authorization start")
    _time(end, "authorization expiry")
    if not 1 <= end - start <= maximum:
        raise ValueError("invalid education validity interval")


def _current(payload, now, maximum):
    _period(payload["not_before"], payload["expires_at"], maximum)
    if not payload["not_before"] <= now < payload["expires_at"]:
        raise ValueError("education authorization is outside its validity window")


def _sign(signer, domain, payload):
    return {"payload": payload, "signature": signer.sign(domain, canon(payload)).hex()}


def _verify_signature(public_key, domain, payload, signature):
    _key(public_key, "expected signing key")
    if not verify_sig(public_key, domain, canon(payload), _hex(signature, 64, "record signature")):
        raise ValueError("invalid education record signature")


def _verify(record, public_key, domain):
    record = _document(record, "signed education record")
    _fields(record, {"payload", "signature"}, "signed education record")
    payload = record["payload"]
    if type(payload) is not dict:
        raise ValueError("invalid education record payload")
    _verify_signature(public_key, domain, payload, record["signature"])
    return payload


def owner_grant(owner, scope, grant_id, start, end):
    """Sign test-only owner authority for the exact request scope."""
    scope = validate_scope(scope)
    _distinct(scope, owner=owner.pub)
    _id(grant_id, "grant ID")
    _period(start, end, MAX_GRANT_SECONDS)
    return _sign(owner, _GRANT_DOMAIN, {
        "type": _GRANT_TYPE, "scope_sha256": digest(scope), "grant_id": grant_id,
        "not_before": start, "expires_at": end,
    })


def qualify(supervisor, witness, scope, peer, start, end):
    """Bind a measured process to one run and countersign the exact observation."""
    scope = validate_scope(scope)
    _distinct(scope, supervisor=supervisor.pub, witness=witness.pub)
    peer = validate_peer(peer)
    _period(start, end, MAX_QUALIFICATION_SECONDS)
    payload = {
        "type": _QUALIFICATION_TYPE, "scope_sha256": digest(scope), "peer": peer,
        "not_before": start, "expires_at": end,
    }
    record = {"payload": payload, "supervisor_signature": supervisor.sign(_SUPERVISOR_DOMAIN, canon(payload)).hex()}
    return {**record, "witness_signature": witness.sign(_WITNESS_DOMAIN, canon(record)).hex()}


def _caller_payload(packet):
    return {"type": _CALLER_TYPE, "scope_sha256": digest(packet["scope"]),
            "grant_sha256": digest(packet["grant"]), "qualification_sha256": digest(packet["qualification"])}


def dispatch(caller, scope, grant, qualification):
    """Sign the exact scope and supplied attachments with the scoped caller key."""
    packet = {
        "scope": validate_scope(scope),
        "grant": _document(grant, "education grant") if grant is not None else None,
        "qualification": _document(qualification, "education qualification") if qualification is not None else None,
    }
    if _key(caller.pub, "caller key") != packet["scope"]["caller_pub"]:
        raise ValueError("caller signer differs from the scoped caller")
    return {**packet, "caller_proof": _sign(caller, _CALLER_DOMAIN, _caller_payload(packet))}


def snapshot_packet(packet):
    """Take a bounded, detached snapshot of a dispatch before checking it."""
    packet = _document(packet, "education dispatch")
    _fields(packet, _PACKET_FIELDS, "education dispatch")
    packet["scope"] = validate_scope(packet["scope"])
    return packet


def _scoped_packet(packet, expected_scope):
    packet = snapshot_packet(packet)
    if packet["scope"] != expected_scope:
        raise ValueError("dispatch differs from the expected scope")
    return packet


def _check_grant(grant, scope, owner_pub, now):
    payload = _verify(grant, owner_pub, _GRANT_DOMAIN)
    _fields(payload, _GRANT_FIELDS, "owner grant")
    if payload["type"] != _GRANT_TYPE or payload["scope_sha256"] != digest(scope):
        raise ValueError("owner grant differs from the scoped read")
    _id(payload["grant_id"], "grant ID")
    _current(payload, now, MAX_GRANT_SECONDS)
    return payload["grant_id"]


def _check_qualification(qualification, scope, supervisor_pub, witness_pub, peer, now, retained):
    _fields(qualification, {"payload", "supervisor_signature", "witness_signature"}, "education qualification")
    payload = qualification["payload"]
    _fields(payload, _QUALIFICATION_FIELDS, "education qualification payload")
    if (payload["type"] != _QUALIFICATION_TYPE or payload["scope_sha256"] != digest(scope)
            or validate_peer(payload["peer"]) != peer):
        raise ValueError("qualification differs from the scoped read or measured peer")
    _current(payload, now, MAX_QUALIFICATION_SECONDS)
    if digest(qualification) != retained:
        raise ValueError("qualification differs from the retained witness digest")
    supervisor_signature = qualification["supervisor_signature"]
    _verify_signature(supervisor_pub, _SUPERVISOR_DOMAIN, payload, supervisor_signature)
    witnessed = {"payload": payload, "supervisor_signature": supervisor_signature}
    _verify_signature(witness_pub, _WITNESS_DOMAIN, witnessed, qualification["witness_signature"])


def check_packet(packet, *, expected_scope, owner_pub, supervisor_pub, witness_pub, peer, now, witness_head):
    """Return the grant ID only after both independent predicates are current."""
    scope = validate_scope(expected_scope)
    _distinct(scope, owner=owner_pub, supervisor=supervisor_pub, witness=witness_pub)
    peer = validate_peer(peer)
    _time(now, "trusted admission time")
    if type(witness_head) is bytes:
        witness_head = _key(witness_head, "retained witness digest")
    else:
        _hex(witness_head, 32, "retained witness digest")
    packet = _scoped_packet(packet, scope)
    proof = _verify(packet["caller_proof"], bytes.fromhex(scope["caller_pub"]), _CALLER_DOMAIN)
    if canon(proof) != canon(_caller_payload(packet)):
        raise ValueError("caller proof differs from the scope or authorization attachments")
    grant_id = _check_grant(packet["grant"], scope, owner_pub, now)
    _check_qualification(packet["qualification"], scope, supervisor_pub, witness_pub, peer, now, witness_head)
    return grant_id


def _current_attachments(packet, now):
    _time(now, "target authorization time")
    expiries = []
    for field, payload_fields, maximum in (
            ("grant", _GRANT_FIELDS, MAX_GRANT_SECONDS),
            ("qualification", _QUALIFICATION_FIELDS, MAX_QUALIFICATION_SECONDS)):
        record = packet[field]
        if type(record) is not dict:
            raise ValueError("education authorization requires both signed attachments")
        body = record.get("payload")
        _fields(body, payload_fields, field)
        _current(body, now, maximum)
        expiries.append(body["expires_at"])
    return min(expiries)


def check_admission_time(packet, now):
    """Recheck both windows of an already authenticated packet and return the deadline."""
    return _current_attachments(snapshot_packet(packet), now)


def _receipt_payload(scope, packet, response, now):
    if (scope["tenant"], scope["student"]) != (_SYNTHETIC_TENANT, _SYNTHETIC_STUDENT):
        raise ValueError("scope differs from the fixed synthetic Education fixture")
    if response != _SYNTHETIC_RESPONSE:
        raise ValueError("response differs from the fixed synthetic Education record")
    # These are historical claims within the packet. The target signs only
    # after the live gate authenticates the corresponding records.
    _current_attachments(packet, now)
    return {
        "type": _RECEIPT_TYPE, "authorized_at": now, "target_pub": scope["target_pub"],
        "request_id": scope["request_id"], "scope_sha256": digest(scope), "packet_sha256": digest(packet),
        "grant_sha256": digest(packet["grant"]), "qualification_sha256": digest(packet["qualification"]),
        "caller_proof_sha256": digest(packet["caller_proof"]), "response_sha256": digest(response),
    }


def receipt(target, scope, packet, response, now):
    """Sign the completed synthetic response for one exact, previously admitted packet."""
    scope = validate_scope(scope)
    if _key(target.pub, "target key") != scope["target_pub"]:
        raise ValueError("receipt signer differs from the scoped target")
    return _sign(target, _TARGET_DOMAIN, _receipt_payload(
        scope, _scoped_packet(packet, scope), _document(response, "education response"), now,
    ))


def verify_receipt(record, *, target_pub, scope, packet, response):
    """Verify a historical target receipt against the independently pinned inputs."""
    scope = validate_scope(scope)
    if _key(target_pub, "target key") != scope["target_pub"]:
        raise ValueError("target key differs from the expected scope")
    payload = _verify(record, target_pub, _TARGET_DOMAIN)
    expected = _receipt_payload(
        scope, _scoped_packet(packet, scope), _document(response, "education response"), payload.get("authorized_at"),
    )
    if canon(payload) != canon(expected):
        raise ValueError("target receipt differs from the supplied scope, packet or response")
    return payload
