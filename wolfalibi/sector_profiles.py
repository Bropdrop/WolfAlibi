"""Offline synthetic education/finance admission profile reference tests.

Not a certificate, live agent qualification, regulatory determination, or
production enforcement mechanism. This module has no network or file effects.
"""
from __future__ import annotations

import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCHEMA = "quorvane.sector_lab.v1"
GRANT_DOMAIN = b"quorvane/sector-lab/owner-grant/v1\x00"
AUDIENCE = "quorvane.synthetic-sector-lab"
PROFILES = {
    "EDU_STUDENT_DATA_READ_V0": ("edu.tutor.respond", "edu.student_record.read"),
    "FIN_PAYMENT_INITIATION_V0": ("fin.balance.read", "fin.payment.initiate"),
}
_ROLES = {"edu.student_record.read": "school_officer",
          "fin.balance.read": "account_owner", "fin.payment.initiate": "account_owner"}
_REQ_FIELDS = {"profile", "action", "tenant", "resource", "agent_pub", "request_id", "args"}
_GRANT_FIELDS = {"type", "audience", "grant_id", "scope_sha256", "role", "not_before", "expires_at"}
_TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_MAX_GRANT_SECONDS = 300


class ProfileError(ValueError):
    """Invalid synthetic profile or signed authorization."""


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _hash(value):
    return hashlib.sha256(_canon(value)).hexdigest()


def _str(value, label):
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ProfileError("invalid " + label)
    return value


def _key(hex_value):
    if type(hex_value) is not str or len(hex_value) != 64 or hex_value.lower() != hex_value:
        raise ProfileError("invalid public key")
    try:
        value = bytes.fromhex(hex_value)
    except ValueError as exc:
        raise ProfileError("invalid public key") from exc
    if len(value) != 32:
        raise ProfileError("invalid public key")
    return value


def _args(request):
    action, args = request["action"], request["args"]
    if type(args) is not dict:
        raise ProfileError("invalid action arguments")
    if action == "edu.tutor.respond":
        if args.keys() != {"lesson"} or args["lesson"] not in ("math", "reading"):
            raise ProfileError("tutor accepts only synthetic lesson categories")
        if request["resource"] != "synthetic-lessons":
            raise ProfileError("tutor route cannot access student records")
    elif action == "edu.student_record.read":
        if args.keys() != {"student_ref", "purpose"} or args["purpose"] != "approved-support":
            raise ProfileError("invalid synthetic school record request")
        _str(args["student_ref"], "student reference")
        if request["resource"] != "synthetic-student-records":
            raise ProfileError("record read uses exact protected resource")
    elif action == "fin.balance.read":
        if args.keys() != {"account_ref"} or request["resource"] != "synthetic-balances":
            raise ProfileError("invalid synthetic balance scope")
        _str(args["account_ref"], "account reference")
    elif action == "fin.payment.initiate":
        if args.keys() != {"account_ref", "payee_ref", "amount_minor", "currency"}:
            raise ProfileError("invalid synthetic payment parameters")
        _str(args["account_ref"], "account reference")
        _str(args["payee_ref"], "payee reference")
        if (type(args["amount_minor"]) is not int or not 1 <= args["amount_minor"] <= 1_000_000
                or args["currency"] != "CAD" or request["resource"] != "synthetic-payment-intents"):
            raise ProfileError("invalid payment amount, currency or resource")
    else:
        raise ProfileError("unknown action")


def validate_request(request):
    """Validate the exact closed synthetic route grammar."""
    if type(request) is not dict or request.keys() != _REQ_FIELDS:
        raise ProfileError("invalid request fields")
    if (type(request["profile"]) is not str or request["profile"] not in PROFILES
            or type(request["action"]) is not str
            or request["action"] not in PROFILES[request["profile"]]):
        raise ProfileError("action is outside the declared sector profile")
    for field in ("tenant", "resource", "request_id"):
        _str(request[field], field)
    _key(request["agent_pub"])
    _args(request)
    if len(_canon(request)) > 4096:
        raise ProfileError("request exceeds synthetic bound")
    return json.loads(_canon(request))


def make_grant(owner: Ed25519PrivateKey, request: dict, *, grant_id: str,
               role: str, not_before: int, expires_at: int):
    """Issue a test-only owner grant for one exact request (never a certificate)."""
    request = validate_request(request)
    _str(grant_id, "grant ID")
    if role != _ROLES.get(request["action"]):
        raise ProfileError("invalid role for protected operation")
    if (type(not_before) is not int or type(expires_at) is not int
            or not 0 < expires_at - not_before <= _MAX_GRANT_SECONDS):
        raise ProfileError("invalid grant interval")
    payload = {"type": "QUORVANE_SECTOR_LAB_GRANT_V1", "audience": AUDIENCE,
               "grant_id": grant_id, "scope_sha256": _hash(request), "role": role,
               "not_before": not_before, "expires_at": expires_at}
    return {"payload": payload, "signature": owner.sign(GRANT_DOMAIN + _canon(payload)).hex()}


def verify_grant(grant, request, *, expected_owner_pub: bytes, now: int):
    if (type(grant) is not dict or grant.keys() != {"payload", "signature"}
            or type(grant["payload"]) is not dict or grant["payload"].keys() != _GRANT_FIELDS):
        raise ProfileError("missing or malformed owner grant")
    if type(expected_owner_pub) is not bytes or len(expected_owner_pub) != 32:
        raise ProfileError("missing independent owner key")
    payload = grant["payload"]
    _str(payload["grant_id"], "grant ID")
    if (payload["type"] != "QUORVANE_SECTOR_LAB_GRANT_V1" or payload["audience"] != AUDIENCE
            or payload["role"] != _ROLES.get(request["action"])
            or payload["scope_sha256"] != _hash(request)):
        raise ProfileError("grant differs from exact protected request")
    if (type(now) is not int or type(payload["not_before"]) is not int
            or type(payload["expires_at"]) is not int
            or not 0 < payload["expires_at"] - payload["not_before"] <= _MAX_GRANT_SECONDS
            or not payload["not_before"] <= now < payload["expires_at"]):
        raise ProfileError("grant expired or invalid")
    try:
        raw = bytes.fromhex(grant["signature"])
        if len(raw) != 64 or raw.hex() != grant["signature"]:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(expected_owner_pub).verify(raw, GRANT_DOMAIN + _canon(payload))
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise ProfileError("owner signature invalid") from exc
    return payload["grant_id"]


class SyntheticSectorGate:
    """Reference target policy with no real upstream effect or certificate issuance.

    The gate has an in-memory single-use synthetic intent ledger. It is not
    durable, independently administered or suitable for live transactions.
    """

    def __init__(self, *, owner_pub: bytes, agent_pub: bytes, tenant: str):
        if (type(owner_pub) is not bytes or len(owner_pub) != 32
                or type(agent_pub) is not bytes or len(agent_pub) != 32 or owner_pub == agent_pub):
            raise ProfileError("distinct pinned synthetic identities required")
        self.owner_pub = owner_pub
        self.agent_pub = agent_pub.hex()
        self.tenant = _str(tenant, "tenant")
        self.intents = {}
        self.revoked_grants = set()

    def revoke(self, grant_id: str) -> None:
        # Synthetic owner-controlled fixture operation. Not a live revoke protocol.
        self.revoked_grants.add(_str(grant_id, "grant ID"))

    def evaluate(self, request, *, grant=None, now: int):
        """Return a fixed, minimally identifying lab report; never perform I/O."""
        def decision(outcome, reason, effect="NONE", repeat=False):
            return {"schema": SCHEMA, "outcome": outcome, "reason": reason, "effect": effect,
                    "repeat": repeat, "assurance": "SIMULATED_POLICY_ONLY",
                    "qualification": "NOT_ASSESSED", "confinement": "BLOCKED",
                    "certification": "NOT_ISSUED", "production": "BLOCKED"}
        if type(now) is not int or not 0 <= now < 2**63:
            return decision("BLOCKED", "TRUSTED_TIME_REQUIRED")
        try:
            request = validate_request(request)
        except (ProfileError, TypeError, ValueError, RecursionError):
            return decision("DENIED", "INVALID_OR_OUT_OF_SCOPE_REQUEST")
        if request["agent_pub"] != self.agent_pub or request["tenant"] != self.tenant:
            return decision("DENIED", "TENANT_OR_AGENT_MISMATCH")
        # Non-sensitive tutoring is a separate synthetic capability.
        if request["action"] == "edu.tutor.respond":
            return decision("ALLOWED_SYNTHETIC", "TUTORING_ONLY", "SYNTHETIC_RESPONSE")
        try:
            grant_id = verify_grant(grant, request, expected_owner_pub=self.owner_pub, now=now)
        except (ProfileError, TypeError, ValueError, RecursionError):
            return decision("DENIED", "OWNER_AUTHORIZATION_MISSING_OR_INVALID")
        if grant_id in self.revoked_grants:
            return decision("DENIED", "OWNER_GRANT_REVOKED")
        if request["action"] != "fin.payment.initiate":
            return decision("ALLOWED_SYNTHETIC", "SIGNED_SCOPE_CURRENT", "SYNTHETIC_READ")
        digest = _hash(request)
        row = self.intents.get(request["request_id"])
        if row:
            if row[0] != digest:
                return decision("DENIED", "IDEMPOTENCY_KEY_CONFLICT")
            return decision("ALLOWED_SYNTHETIC", "HISTORICAL_INTENT_ONLY",
                            "PENDING_EXTERNAL_SETTLEMENT", repeat=True)
        self.intents[request["request_id"]] = (digest, grant_id)
        return decision("ALLOWED_SYNTHETIC", "SIGNED_SCOPE_CURRENT",
                        "PENDING_EXTERNAL_SETTLEMENT")


def public_key(owner: Ed25519PrivateKey) -> bytes:
    return owner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def fake_owner():
    """Ephemeral test key only; never use this with a protected live service."""
    return Ed25519PrivateKey.generate()
