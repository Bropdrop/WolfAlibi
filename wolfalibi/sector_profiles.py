"""Offline synthetic education/finance admission profile reference tests.

Not a certificate, live agent qualification, regulatory determination, or
production enforcement mechanism. This module has no network or file effects.
"""
from __future__ import annotations

import hashlib
import json
import re
from types import MappingProxyType
from threading import Lock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCHEMA = "quorvane.sector_lab.v1"
GRANT_DOMAIN = b"quorvane/sector-lab/owner-grant/v1\x00"
AUDIENCE = "quorvane.synthetic-sector-lab"
_PROFILE_ACTIONS = MappingProxyType({
    "EDU_STUDENT_DATA_READ_V0": ("edu.tutor.respond", "edu.student_record.read"),
    "FIN_PAYMENT_INITIATION_V0": ("fin.balance.read", "fin.payment.initiate"),
})
# Preserve the public description as a plain dict without using it as policy.
PROFILES = dict(_PROFILE_ACTIONS)
_ROLES = MappingProxyType({
    "edu.student_record.read": "school_officer",
    "fin.balance.read": "account_owner", "fin.payment.initiate": "account_owner",
})
_REQ_FIELDS = frozenset({"profile", "action", "tenant", "resource", "agent_pub", "request_id", "args"})
_ARG_FIELDS = MappingProxyType({
    "edu.tutor.respond": frozenset({"lesson"}),
    "edu.student_record.read": frozenset({"student_ref", "purpose"}),
    "fin.balance.read": frozenset({"account_ref"}),
    "fin.payment.initiate": frozenset({"account_ref", "payee_ref", "amount_minor", "currency"}),
})
_GRANT_FIELDS = frozenset({"type", "audience", "grant_id", "scope_sha256", "role", "not_before", "expires_at"})
_GRANT_TYPE = "QUORVANE_SECTOR_LAB_GRANT_V1"
_TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_MAX_GRANT_SECONDS = 300
_MAX_TIME = (1 << 63) - 1


class ProfileError(ValueError):
    """Invalid synthetic profile or signed authorization."""


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _hash(value):
    return hashlib.sha256(_canon(value)).hexdigest()


def _snapshot(document, fields, label):
    """Detach a fixed object without invoking caller-defined mapping hooks."""
    if type(document) is not dict or len(document) != len(fields):
        raise ProfileError("invalid " + label + " fields")
    snapshot = document.copy()
    if any(type(key) is not str for key in snapshot) or snapshot.keys() != fields:
        raise ProfileError("invalid " + label + " fields")
    return snapshot


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
    if action == "edu.tutor.respond":
        if type(args["lesson"]) is not str or args["lesson"] not in ("math", "reading"):
            raise ProfileError("tutor accepts only synthetic lesson categories")
        if request["resource"] != "synthetic-lessons":
            raise ProfileError("tutor route cannot access student records")
    elif action == "edu.student_record.read":
        if type(args["purpose"]) is not str or args["purpose"] != "approved-support":
            raise ProfileError("invalid synthetic school record request")
        _str(args["student_ref"], "student reference")
        if request["resource"] != "synthetic-student-records":
            raise ProfileError("record read uses exact protected resource")
    elif action == "fin.balance.read":
        if request["resource"] != "synthetic-balances":
            raise ProfileError("invalid synthetic balance scope")
        _str(args["account_ref"], "account reference")
    elif action == "fin.payment.initiate":
        _str(args["account_ref"], "account reference")
        _str(args["payee_ref"], "payee reference")
        if (type(args["amount_minor"]) is not int or not 1 <= args["amount_minor"] <= 1_000_000
                or type(args["currency"]) is not str or args["currency"] != "CAD"
                or request["resource"] != "synthetic-payment-intents"):
            raise ProfileError("invalid payment amount, currency or resource")
    else:
        raise ProfileError("unknown action")


def validate_request(request):
    """Validate and return a detached copy of the closed synthetic route."""
    request = _snapshot(request, _REQ_FIELDS, "request")
    if (type(request["profile"]) is not str or request["profile"] not in _PROFILE_ACTIONS
            or type(request["action"]) is not str
            or request["action"] not in _PROFILE_ACTIONS[request["profile"]]):
        raise ProfileError("action is outside the declared sector profile")
    request["args"] = _snapshot(request["args"], _ARG_FIELDS[request["action"]], "action arguments")
    for field in ("tenant", "resource", "request_id"):
        _str(request[field], field)
    _key(request["agent_pub"])
    _args(request)
    if len(_canon(request)) > 4096:
        raise ProfileError("request exceeds synthetic bound")
    return request


def _require_grant_role(request, role):
    expected = _ROLES.get(request["action"])
    if expected is None:
        raise ProfileError("action does not accept an owner grant")
    if type(role) is not str or role != expected:
        raise ProfileError("invalid role for protected operation")


def _valid_time(value):
    return type(value) is int and 0 <= value <= _MAX_TIME


def _grant_interval(not_before, expires_at):
    if (not _valid_time(not_before) or not _valid_time(expires_at)
            or not 1 <= expires_at - not_before <= _MAX_GRANT_SECONDS):
        raise ProfileError("invalid grant interval")


def make_grant(owner: Ed25519PrivateKey, request: dict, *, grant_id: str,
               role: str, not_before: int, expires_at: int):
    """Issue a test-only owner grant for one exact request (never a certificate)."""
    request = validate_request(request)
    _str(grant_id, "grant ID")
    _require_grant_role(request, role)
    _grant_interval(not_before, expires_at)
    payload = {"type": _GRANT_TYPE, "audience": AUDIENCE,
               "grant_id": grant_id, "scope_sha256": _hash(request), "role": role,
               "not_before": not_before, "expires_at": expires_at}
    return {"payload": payload, "signature": owner.sign(GRANT_DOMAIN + _canon(payload)).hex()}


def verify_grant(grant, request, *, expected_owner_pub: bytes, now: int):
    """Return the grant ID authenticated for a detached, exact request."""
    if type(expected_owner_pub) is not bytes or len(expected_owner_pub) != 32:
        raise ProfileError("missing independent owner key")
    grant = _snapshot(grant, {"payload", "signature"}, "owner grant")
    payload = _snapshot(grant["payload"], _GRANT_FIELDS, "owner grant payload")
    request = validate_request(request)
    _str(payload["grant_id"], "grant ID")
    _require_grant_role(request, payload["role"])
    if (type(payload["type"]) is not str or payload["type"] != _GRANT_TYPE
            or type(payload["audience"]) is not str or payload["audience"] != AUDIENCE
            or type(payload["scope_sha256"]) is not str or payload["scope_sha256"] != _hash(request)):
        raise ProfileError("grant differs from exact protected request")
    _grant_interval(payload["not_before"], payload["expires_at"])
    if not _valid_time(now) or not payload["not_before"] <= now < payload["expires_at"]:
        raise ProfileError("grant expired or invalid")
    signature = grant["signature"]
    if type(signature) is not str or len(signature) != 128:
        raise ProfileError("owner signature invalid")
    try:
        raw = bytes.fromhex(signature)
        if raw.hex() != signature:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(expected_owner_pub).verify(raw, GRANT_DOMAIN + _canon(payload))
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise ProfileError("owner signature invalid") from exc
    return payload["grant_id"]


class SyntheticSectorGate:
    """Process-local reference target policy for synthetic requests.

    Each instance owns an in-memory intent ledger and revocation set. The
    fixture operator supplies trusted time and invokes revocations. A newer
    time sample may block an older concurrent evaluation at admission.
    """

    def __init__(self, *, owner_pub: bytes, agent_pub: bytes, tenant: str):
        if (type(owner_pub) is not bytes or len(owner_pub) != 32
                or type(agent_pub) is not bytes or len(agent_pub) != 32 or owner_pub == agent_pub):
            raise ProfileError("distinct pinned synthetic identities required")
        self._owner_pub = owner_pub
        self._agent_pub = agent_pub.hex()
        self._tenant = _str(tenant, "tenant")
        self._lock = Lock()
        self._latest_now = 0
        self._intents: dict[str, tuple[str, str]] = {}
        self._revoked_grants: set[str] = set()

    @property
    def owner_pub(self) -> bytes:
        return self._owner_pub

    @property
    def agent_pub(self) -> str:
        return self._agent_pub

    @property
    def tenant(self) -> str:
        return self._tenant

    @property
    def intents(self) -> dict[str, tuple[str, str]]:
        """Return a snapshot of the in-memory intent ledger."""
        with self._lock:
            return self._intents.copy()

    @property
    def revoked_grants(self) -> frozenset[str]:
        """Return a snapshot of revoked synthetic grant IDs."""
        with self._lock:
            return frozenset(self._revoked_grants)

    def revoke(self, grant_id: str) -> None:
        # Synthetic owner-controlled fixture operation. Not a live revoke protocol.
        grant_id = _str(grant_id, "grant ID")
        with self._lock:
            self._revoked_grants.add(grant_id)

    def evaluate(self, request, *, grant=None, now: int):
        """Return a fixed, minimally identifying lab report; never perform I/O."""
        def decision(outcome, reason, effect="NONE", repeat=False):
            return {"schema": SCHEMA, "outcome": outcome, "reason": reason, "effect": effect,
                    "repeat": repeat, "assurance": "SIMULATED_POLICY_ONLY",
                    "qualification": "NOT_ASSESSED", "confinement": "BLOCKED",
                    "certification": "NOT_ISSUED", "production": "BLOCKED"}
        if not _valid_time(now):
            return decision("BLOCKED", "TRUSTED_TIME_REQUIRED")
        with self._lock:
            if now < self._latest_now:
                return decision("BLOCKED", "TRUSTED_TIME_REGRESSION")
            self._latest_now = now
        try:
            request = validate_request(request)
        except (ProfileError, TypeError, ValueError, RecursionError):
            return decision("DENIED", "INVALID_OR_OUT_OF_SCOPE_REQUEST")
        if request["agent_pub"] != self.agent_pub or request["tenant"] != self.tenant:
            return decision("DENIED", "TENANT_OR_AGENT_MISMATCH")
        is_tutor = request["action"] == "edu.tutor.respond"
        grant_id = None
        if not is_tutor:
            try:
                grant_id = verify_grant(grant, request, expected_owner_pub=self.owner_pub, now=now)
            except (ProfileError, TypeError, ValueError, RecursionError):
                return decision("DENIED", "OWNER_AUTHORIZATION_MISSING_OR_INVALID")
        # Serialize freshness and revocation checks with admission and mutation.
        with self._lock:
            if now < self._latest_now:
                return decision("BLOCKED", "TRUSTED_TIME_REGRESSION")
            if is_tutor:
                return decision("ALLOWED_SYNTHETIC", "TUTORING_ONLY", "SYNTHETIC_RESPONSE")
            if grant_id in self._revoked_grants:
                return decision("DENIED", "OWNER_GRANT_REVOKED")
            if request["action"] != "fin.payment.initiate":
                return decision("ALLOWED_SYNTHETIC", "SIGNED_SCOPE_CURRENT", "SYNTHETIC_READ")
            digest = _hash(request)
            request_id = request["request_id"]
            row = self._intents.get(request_id)
            if row is not None:
                if row[0] != digest:
                    return decision("DENIED", "IDEMPOTENCY_KEY_CONFLICT")
                return decision("ALLOWED_SYNTHETIC", "HISTORICAL_INTENT_ONLY",
                                "PENDING_EXTERNAL_SETTLEMENT", repeat=True)
            self._intents[request_id] = (digest, grant_id)
            return decision("ALLOWED_SYNTHETIC", "SIGNED_SCOPE_CURRENT",
                            "PENDING_EXTERNAL_SETTLEMENT")


def public_key(owner: Ed25519PrivateKey) -> bytes:
    return owner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def fake_owner():
    """Ephemeral test key only; never use this with a protected live service."""
    return Ed25519PrivateKey.generate()
