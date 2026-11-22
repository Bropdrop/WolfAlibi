"""Verify one historical BYOA trial against public inputs selected before execution."""

import json

from alibi import H, canon, verify_sig
from .agent_solitary_observation import parse_observation
from .byoa_bundle import validate_identity
from .byoa_effect_gate import financial_boundary, verify_read_admission
from .solitary_evidence import verify_solitary
from .stage3_evidence import _hex, validate_contract


EXPECTATIONS = "quorvane.byoa.expectations.v1"
REPORT = "quorvane.byoa.trial.v1"
_DOMAIN = b"quorvane/byoa/trial/v1"
_ROLES = ("broker_pub", "witness_pub", "supervisor_pub", "owner_pub", "target_pub")
_ASSURANCE = {
    "observation": "OBSERVATIONAL_ONLY", "broker": "BROKER_ONLY",
    "confinement": "BLOCKED", "cross_uid_custody": "UNSUPPORTED",
    "independent_witness_custody": "NOT_ASSESSED", "production": "BLOCKED",
    "certification": "NOT_ISSUED", "scope": "SIMULATED_POLICY_ONLY",
}


class _Incomplete(ValueError):
    pass


def _fields(obj, names, label):
    if obj is None or (type(obj) is dict and set(names) - obj.keys()):
        raise _Incomplete(f"incomplete {label}")
    if type(obj) is not dict or obj.keys() != set(names):
        raise ValueError(f"unexpected {label} fields")


def _snapshot(obj):
    # The CLI reads bounded JSON. Detach a stable, strict JSON copy for library callers too.
    data = json.dumps(obj, sort_keys=True, allow_nan=False, separators=(",", ":"))
    if len(data) > 262144:
        raise ValueError("trial document exceeds size bound")
    return json.loads(data)


def _checked_inputs(expected):
    pins = _snapshot(expected)
    _fields(pins, {"schema", "contract", "expected_witness_state_digest", "now", *_ROLES},
            "external expectations")
    if pins["schema"] != EXPECTATIONS:
        raise ValueError("unsupported expectations schema")
    contract = pins["contract"]
    validate_contract(contract)
    profile = contract["profile"]
    validate_identity(profile.get("byoa"))
    adapter = profile.get("agent_adapter")
    dependency = profile["byoa"]["dependencies"][0]
    if (type(adapter) is not dict or adapter.get("probe_sha256") != dependency["sha256"]
            or adapter.get("name") != "python-callbacks"):
        raise ValueError("expected adapter differs from the approved dependency")
    keys = {name: _hex(pins[name], 32, name) for name in _ROLES}
    if len(set(keys.values())) != len(keys):
        raise ValueError("BYOA requires five distinct expected signing keys")
    prior = _hex(pins["expected_witness_state_digest"], 32, "retained witness digest")
    if type(pins["now"]) is not int or not 0 <= pins["now"] < contract["expires_at"]:
        raise ValueError("historical reference time outside the challenge interval")
    return pins, keys, prior


def make_expectations(contract, *, broker_pub, witness_pub, supervisor_pub, owner_pub, target_pub,
                      expected_witness_state_digest, now):
    """Encode the public contract, independently chosen reference time, keys and retained head."""
    values = (broker_pub, witness_pub, supervisor_pub, owner_pub, target_pub)
    if any(type(value) is not bytes or len(value) != 32 for value in (*values, expected_witness_state_digest)):
        raise ValueError("external keys and witness digest must be 32 bytes")
    pins = {"schema": EXPECTATIONS, "contract": contract, "now": now,
            "expected_witness_state_digest": expected_witness_state_digest.hex(),
            **{name: key.hex() for name, key in zip(_ROLES, values, strict=True)}}
    return _checked_inputs(pins)[0]


def _historical_read(contract):
    return {"claim": "HISTORICAL_BROKER_READ", "actor": "TRUSTED_CELL_BOOTSTRAP",
            "operation": "read", "resource": contract["key"], "response_sha256": contract["fixture_sha256"]}


def _validate(payload, pins, keys, prior):
    _fields(payload, {"schema", "expectations_sha256", "observation", "execution", "authorization",
                      "effect", "assurance"}, "signed trial")
    if payload["schema"] != REPORT or payload["expectations_sha256"] != H(canon(pins)).hex():
        raise ValueError("trial differs from the external expectations")
    if canon(payload["assurance"]) != canon(_ASSURANCE):
        raise ValueError("unsupported assurance claims")
    financial = financial_boundary()
    authorization = payload["authorization"]
    _fields(authorization, {"owner_grant", "target_admission", "financial"}, "authorization")
    if canon(authorization["financial"]) != canon(financial["authorization"]):
        raise ValueError("unsupported financial authorization claim")
    contract = pins["contract"]
    effect = {"broker_read": _historical_read(contract), "financial": financial["effect"]}
    if canon(payload["effect"]) != canon(effect):
        raise ValueError("unsupported effect claim")
    measured = verify_solitary(payload["execution"], contract=contract, broker_pub=keys["broker_pub"],
                              witness_pub=keys["witness_pub"], supervisor_pub=keys["supervisor_pub"],
                              expected_witness_state_digest=prior, now=pins["now"])
    if measured["outcome"] == "BLOCKED":
        raise _Incomplete(measured["reason"])
    if measured["outcome"] != "VERIFIED":
        raise ValueError(measured["reason"])

    observation = payload["observation"]
    _fields(observation, {"outcome", "assurance", "summary"}, "callback observation")
    checked = parse_observation(canon({"type": "agent-observation", "summary": observation["summary"]}))
    if checked["outcome"] != "OBSERVED" or canon(checked) != canon(observation):
        raise ValueError("unsupported callback observation")
    snapshot = payload["execution"]["supervisor_record"]["payload"]["snapshot"]
    grant, admission = authorization["owner_grant"], authorization["target_admission"]
    if grant is None or admission is None:
        raise _Incomplete("missing owner grant or target admission")
    read = verify_read_admission(pins, grant, admission, snapshot)
    if (read.get("outcome") != "VERIFIED_HISTORICAL_READ_ADMISSION"
            or canon(admission["witness_state"]) != canon(payload["execution"]["evidence"]["witness_state_chain"][0])):
        raise ValueError("target admission is outside the witnessed broker execution")
    return {"outcome": "VERIFIED", "claim": "HISTORICAL_AUTHORIZED_SYNTHETIC_TRIAL",
            "run_id": contract["run_id"], "challenge": contract["challenge"],
            "observation": checked,
            "execution": {"measurement": measured["measurement"], "scope": "PRE_RELEASE_SNAPSHOT_AND_EXIT",
                          "identity": snapshot["identity"], "bundle": contract["profile"]["byoa"],
                          "limits": measured["observed_limits"], "closure": measured["closure"],
                          "retained_witness_sha256": measured["witness_state_digest"]},
            "authorization": {"read": read, "financial": financial["authorization"],
                              "present_authority": "NOT_ISSUED"},
            "effect": effect, "assurance": dict(_ASSURANCE)}


def sign_trial(expected, envelope, observation, supervisor, *, grant, admission):
    """Sign after verifying the closed cell transcript, wrapped observation and read admission."""
    pins, keys, prior = _checked_inputs(expected)
    if supervisor.pub != keys["supervisor_pub"]:
        raise ValueError("unexpected trial supervisor")
    financial = financial_boundary()
    payload = _snapshot({"schema": REPORT, "expectations_sha256": H(canon(pins)).hex(),
                         "observation": observation, "execution": envelope,
                         "authorization": {"owner_grant": grant, "target_admission": admission,
                                           "financial": financial["authorization"]},
                         "effect": {"broker_read": _historical_read(pins["contract"]),
                                    "financial": financial["effect"]},
                         "assurance": _ASSURANCE})
    _validate(payload, pins, keys, prior)
    return {"payload": payload, "signature": supervisor.sign(_DOMAIN, canon(payload)).hex()}


def verify_trial(report, expected):
    """Historical verification is repeatable and does not consult or mutate a live authority."""
    try:
        pins, keys, prior = _checked_inputs(expected)
    except (TypeError, ValueError, KeyError, IndexError, RecursionError) as exc:
        return {"outcome": "BLOCKED", "reason": str(exc), "assurance": dict(_ASSURANCE)}
    try:
        record = _snapshot(report)
        _fields(record, {"payload", "signature"}, "signed trial envelope")
        sig = _hex(record["signature"], 64, "trial supervisor signature")
        payload = record["payload"]
        if not verify_sig(keys["supervisor_pub"], _DOMAIN, canon(payload), sig):
            raise ValueError("invalid trial supervisor signature")
        return _validate(payload, pins, keys, prior)
    except _Incomplete as exc:
        return {"outcome": "BLOCKED", "reason": str(exc), "assurance": dict(_ASSURANCE)}
    except (TypeError, ValueError, KeyError, IndexError, RecursionError) as exc:
        return {"outcome": "REJECTED", "reason": str(exc), "assurance": dict(_ASSURANCE)}
