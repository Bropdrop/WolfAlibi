"""Signed records for the fixed synthetic Alibi Clearance protocol."""

import re

from alibi import H, canon, verify_sig
from .agent_solitary_worker import AGENT_PROFILE
from .solitary_evidence import SOLITARY_POLICY_VERSION, _policy
from .stage3 import FIXTURE_BYTES, FIXTURE_KEY
from .stage3_evidence import _hex


AUDIENCE = "wolfalibi.clearance.synthetic.v1"
RESOURCE = "synthetic-records"
OPERATION = "read"
PROFILE = "solitary-synthetic"
MAX_GRANT_SECONDS = 300
QUALIFICATION_TTL = 120
CAPABILITY_TTL = 30

_GRANT_TYPE = "WOLFALIBI_CLEARANCE_GRANT_V1"
_REVOCATION_TYPE = "WOLFALIBI_CLEARANCE_REVOCATION_V1"
_REQUEST_TYPE = "WOLFALIBI_CLEARANCE_REQUEST_V1"
_GRANT_DOMAIN = b"wolfalibi/clearance/grant/v1"
_REVOCATION_DOMAIN = b"wolfalibi/clearance/revoke/v1"
_REQUEST_DOMAIN = b"wolfalibi/clearance/request/v1"
_DECISION_DOMAIN = b"wolfalibi/clearance/decision/v1"
_FIXTURE_SHA256 = H(FIXTURE_BYTES).hex()
_TARGET = {"audience": AUDIENCE, "resource": RESOURCE, "operation": OPERATION}
_IDENTITIES = {"python_sha256", "worker_sha256", "profile_sha256", "policy_sha256"}
_SCOPE_FIELDS = set(_TARGET) | _IDENTITIES | {
    "profile", "run_id", "challenge", "key", "fixture_sha256", "contract_sha256",
    "agent_pub", "gateway_pub", "expected_witness_state_digest",
}
_MAX_UNIX_SECONDS = (1 << 63) - 1
_ID = re.compile(r"[a-zA-Z0-9_.-]{1,128}\Z")
_SECRET_DECISION_FIELDS = {
    "api_key", "authorization", "capability", "capability_token", "credential",
    "credentials", "password", "private_key", "secret", "token",
}


def _fields(value, expected, label):
    if type(value) is not dict or value.keys() != expected:
        raise ValueError(f"invalid {label} fields")


def _id(value, label):
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError(f"invalid {label}")


def _key(value, label):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(f"invalid {label}")
    return value.hex()


def _time(value, label):
    if type(value) is not int or not 0 <= value <= _MAX_UNIX_SECONDS:
        raise ValueError(f"invalid {label}")


def _document(value, label, *, max_bytes=16_384, decision=False):
    """Take a bounded JSON snapshot without accepting coerced key/value types."""
    if type(value) is not dict:
        raise ValueError(f"invalid {label}")
    remaining = 2048

    def walk(item, level):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or level > 8:
            raise ValueError(f"{label} exceeds structural bounds")
        if type(item) is dict:
            if len(item) > remaining:
                raise ValueError(f"{label} exceeds structural bounds")
            result = {}
            for name, member in tuple(item.items()):
                if type(name) is not str or not 1 <= len(name) <= 128 or not name.isprintable():
                    raise ValueError(f"invalid {label} key")
                if decision and name.lower().replace("-", "_") in _SECRET_DECISION_FIELDS:
                    raise ValueError("decisions cannot include credential or capability fields")
                result[name] = walk(member, level + 1)
            return result
        if type(item) is list:
            if len(item) > remaining:
                raise ValueError(f"{label} exceeds structural bounds")
            return [walk(member, level + 1) for member in tuple(item)]
        if type(item) is str and len(item) <= 2048 and (not item or item.isprintable()):
            return item
        if type(item) is int and -_MAX_UNIX_SECONDS <= item <= _MAX_UNIX_SECONDS:
            return item
        if item is None or type(item) is bool:
            return item
        raise ValueError(f"invalid {label} value")

    snapshot = walk(value, 0)
    if len(canon(snapshot)) > max_bytes:
        raise ValueError(f"{label} exceeds size bound")
    return snapshot


def identity_pins(profile):
    """Return hashes of the executable, worker source and declared policies.

    The full profile digest binds the launcher and the declared runtime
    configuration. It makes no claim to hash every runtime file.
    """
    profile = _document(profile, "worker profile", max_bytes=32_768)
    executable = profile.get("python_sha256")
    worker = profile.get("worker_sha256")
    _hex(executable, 32, "worker executable digest")
    _hex(worker, 32, "worker source digest")
    policy = profile.get("solitary")
    if type(policy) is not dict or policy.get("policy_version") != SOLITARY_POLICY_VERSION:
        raise ValueError("unsupported Solitary worker policy")
    return {
        "python_sha256": executable, "worker_sha256": worker,
        "profile_sha256": H(canon(profile)).hex(), "policy_sha256": H(canon(policy)).hex(),
    }


def make_scope(contract, *, agent_pub, gateway_pub, expected_witness_state_digest):
    """Bind a fixed read scope to an independently supplied Solitary contract."""
    contract = _document(contract, "run contract", max_bytes=49_152)
    _policy(contract)
    return {
        **_TARGET, **identity_pins(contract["profile"]),
        "profile": AGENT_PROFILE if "agent_adapter" in contract["profile"] else PROFILE,
        "run_id": contract["run_id"], "challenge": contract["challenge"], "key": contract["key"],
        "fixture_sha256": contract["fixture_sha256"], "contract_sha256": H(canon(contract)).hex(),
        "agent_pub": _key(agent_pub, "agent key"), "gateway_pub": _key(gateway_pub, "gateway key"),
        "expected_witness_state_digest": _key(expected_witness_state_digest, "witness state digest"),
    }


def _scope(value):
    scope = _document(value, "grant scope")
    _fields(scope, _SCOPE_FIELDS, "grant scope")
    if (any(scope[key] != value for key, value in _TARGET.items())
            or scope["profile"] not in (PROFILE, AGENT_PROFILE) or scope["key"] != FIXTURE_KEY
            or scope["fixture_sha256"] != _FIXTURE_SHA256):
        raise ValueError("scope does not match the fixed synthetic read")
    rid = scope["run_id"]
    if type(rid) is not str or not 1 <= len(rid) <= 256:
        raise ValueError("invalid scope run ID")
    for field in _IDENTITIES | {
            "challenge", "contract_sha256", "agent_pub", "gateway_pub",
            "expected_witness_state_digest",
    }:
        _hex(scope[field], 32, field)
    return scope


def _sign(signer, domain, payload):
    return {"payload": payload, "signature": signer.sign(domain, canon(payload)).hex()}


def _verify(record, public_key, domain, *, decision=False):
    _fields(record, {"payload", "signature"}, "signed clearance record")
    _key(public_key, "expected signing key")
    payload = _document(record["payload"], "signed payload", decision=decision)
    signature = _hex(record["signature"], 64, "signature")
    if not verify_sig(public_key, domain, canon(payload), signature):
        raise ValueError("invalid clearance record signature")
    return payload


def _period(not_before, expires_at):
    _time(not_before, "grant start")
    _time(expires_at, "grant expiration")
    if not 0 < expires_at - not_before <= MAX_GRANT_SECONDS:
        raise ValueError("grant validity must span between 1 and 300 seconds")


def grant(owner, *, scope, not_before, expires_at, grant_id):
    """Owner-approve exactly one use of the declared synthetic scope."""
    _period(not_before, expires_at)
    _id(grant_id, "grant ID")
    return _sign(owner, _GRANT_DOMAIN, {
        "type": _GRANT_TYPE, "scope": _scope(scope), "not_before": not_before,
        "expires_at": expires_at, "grant_id": grant_id, "budget": 1,
    })


def check_grant(record, *, owner_pub, scope, now):
    payload = _verify(record, owner_pub, _GRANT_DOMAIN)
    _fields(payload, {"type", "scope", "grant_id", "not_before", "expires_at", "budget"}, "grant")
    if payload["type"] != _GRANT_TYPE or type(payload["budget"]) is not int or payload["budget"] != 1:
        raise ValueError("invalid grant type or use budget")
    _id(payload["grant_id"], "grant ID")
    _period(payload["not_before"], payload["expires_at"])
    _time(now, "verifier time")
    if not payload["not_before"] <= now < payload["expires_at"]:
        raise ValueError("grant is outside its validity window")
    if canon(_scope(payload["scope"])) != canon(_scope(scope)):
        raise ValueError("grant scope does not match expected scope")
    return payload


def revoke(owner, *, grant_id, gateway_pub):
    """Sign an explicit owner revocation for one gateway."""
    _id(grant_id, "grant ID")
    return _sign(owner, _REVOCATION_DOMAIN, {
        "type": _REVOCATION_TYPE, "audience": AUDIENCE, "grant_id": grant_id,
        "gateway_pub": _key(gateway_pub, "gateway key"),
    })


def check_revocation(record, *, owner_pub, gateway_pub):
    payload = _verify(record, owner_pub, _REVOCATION_DOMAIN)
    _fields(payload, {"type", "audience", "grant_id", "gateway_pub"}, "revocation")
    if (payload["type"] != _REVOCATION_TYPE or payload["audience"] != AUDIENCE
            or payload["gateway_pub"] != _key(gateway_pub, "gateway key")):
        raise ValueError("revocation does not match the expected gateway")
    _id(payload["grant_id"], "grant ID")
    return payload["grant_id"]


def capability_digest(capability):
    """Hash the canonical lowercase token text for use in records and storage."""
    _hex(capability, 32, "capability token")
    return H(capability.encode("ascii")).hex()


def _request(capability_sha256, request_id):
    _id(request_id, "request ID")
    _hex(capability_sha256, 32, "capability digest")
    return {
        **_TARGET, "type": _REQUEST_TYPE, "request_id": request_id,
        "capability_sha256": capability_sha256,
    }


def sign_request(agent, *, capability, request_id):
    """Prove possession of the agent key for this capability and request ID."""
    return _sign(agent, _REQUEST_DOMAIN, _request(capability_digest(capability), request_id))


def check_request(record, *, agent_pub, capability):
    return check_request_digest(record, agent_pub=agent_pub, capability_sha256=capability_digest(capability))


def check_request_digest(record, *, agent_pub, capability_sha256):
    """Check a signed request against an externally pinned token digest."""
    payload = _verify(record, agent_pub, _REQUEST_DOMAIN)
    _fields(payload, set(_TARGET) | {"type", "request_id", "capability_sha256"}, "request")
    if canon(payload) != canon(_request(capability_sha256, payload["request_id"])):
        raise ValueError("request scope or capability digest mismatch")
    return payload


def sign_decision(gateway, payload):
    """Sign a bounded, redacted gateway decision in its separate protocol domain."""
    payload = _document(payload, "decision", decision=True)
    return _sign(gateway, _DECISION_DOMAIN, payload)


def verify_decision(record, gateway_pub):
    return _verify(record, gateway_pub, _DECISION_DOMAIN, decision=True)
