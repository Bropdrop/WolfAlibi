"""Offline verification of the Solitary supervisor envelope.

The broker transcript retains broker-only assurance. The supervisor signs
separate fields for its snapshot, worker-reported checks, observed resource
limits and lifecycle observations.
"""

from errno import EPERM
import json

from alibi import H, canon, verify_sig
from .solitary_worker import (
    CONTROL_RESULTS, LIMITS, POLICY_VERSION as SOLITARY_POLICY_VERSION,
    _ALLOW_FD0_SYSCALLS, _ALLOW_SYSCALLS,
)
from .stage3 import FIXTURE_BYTES, FIXTURE_KEY
from .stage3_evidence import ASSURANCE, _hex, validate_contract, verify_execution
from .stage35_measure import MeasurementBlocked, verify_measurement_record


SOLITARY_TYPE = "WOLFALIBI_SOLITARY_EVIDENCE_V1"
_DOMAIN = b"wolfalibi/solitary/supervisor/v1"
_FIXTURE_SHA256 = H(FIXTURE_BYTES).hex()
_CONTROL_FIELDS = frozenset(CONTROL_RESULTS)
_LIMIT_FIELDS = frozenset(LIMITS)
_EXPECTED_CONTROLS = canon(CONTROL_RESULTS)
_EXPECTED_LIMITS = canon(LIMITS)
_SECCOMP_RULES = {
    "default_errno": EPERM, "allow": list(_ALLOW_SYSCALLS),
    "allow_fd0": list(_ALLOW_FD0_SYSCALLS),
}
_CLOSURE_FIELDS = frozenset({
    "launcher_reaped", "worker_pidfd_exited", "peer_hangup", "broker_drained",
})
_PAYLOAD_FIELDS = frozenset({
    "type", "assurance", "contract_sha256", "evidence_sha256", "snapshot",
    "worker_self_report", "observed_limits", "closure",
})


class _IncompleteEvidence(ValueError):
    """The envelope is missing an observation required by the profile."""


def _fields(value, fields, name):
    if value is None:
        raise _IncompleteEvidence(f"{name} is missing")
    if type(value) is not dict:
        raise ValueError(f"invalid {name}")
    if fields - value.keys():
        raise _IncompleteEvidence(f"{name} lacks required fields")
    if value.keys() != fields:
        raise ValueError(f"unexpected fields in {name}")


def _key(value):
    return isinstance(value, bytes) and len(value) == 32


def _policy(contract):
    validate_contract(contract)
    if contract["key"] != FIXTURE_KEY or contract["fixture_sha256"] != _FIXTURE_SHA256:
        raise ValueError("Solitary contract requires the fixed synthetic fixture")
    solitary = contract["profile"].get("solitary")
    _fields(solitary, {"policy_version", "limits", "control_results", "seccomp"},
            "Solitary contract policy")
    if solitary["policy_version"] != SOLITARY_POLICY_VERSION:
        raise ValueError("unsupported Solitary policy version")
    seccomp = solitary["seccomp"]
    _fields(seccomp, {"library_sha256", *_SECCOMP_RULES}, "declared Solitary seccomp policy")
    _hex(seccomp["library_sha256"], 32, "seccomp library digest")
    if canon(seccomp) != canon({**_SECCOMP_RULES, "library_sha256": seccomp["library_sha256"]}):
        raise ValueError("declared seccomp rules differ from the Solitary policy")
    limits = solitary["limits"]
    _fields(limits, _LIMIT_FIELDS, "pinned resource limits")
    if canon(limits) != _EXPECTED_LIMITS:
        raise ValueError("declared resource limits differ from the Solitary policy")
    controls = solitary["control_results"]
    _fields(controls, _CONTROL_FIELDS, "pinned worker controls")
    if canon(controls) != _EXPECTED_CONTROLS:
        raise ValueError("declared worker controls differ from the Solitary policy")
    return solitary


def _check_observations(payload, contract, policy):
    controls = payload["worker_self_report"]
    _fields(controls, _CONTROL_FIELDS, "worker self-report")
    if canon(controls) != canon(policy["control_results"]):
        raise ValueError("worker self-report differs from the pinned control expectations")
    limits = payload["observed_limits"]
    _fields(limits, _LIMIT_FIELDS, "observed resource limits")
    if canon(limits) != canon(policy["limits"]):
        raise ValueError("observed resource limits differ from the pinned limits")
    closure = payload["closure"]
    _fields(closure, _CLOSURE_FIELDS, "run closure")
    if any(value is not True for value in closure.values()):
        raise ValueError("run closure observations do not support completion")

    snapshot = payload["snapshot"]
    if snapshot is None:
        raise _IncompleteEvidence("supervisor snapshot is missing")
    if type(snapshot) is not dict:
        raise ValueError("invalid supervisor snapshot")
    standard_snapshot = dict(snapshot)
    kernel = standard_snapshot.pop("solitary_kernel", None)
    _fields(kernel, {"launcher_seccomp_filters", "worker_seccomp_filters", "environment_keys"},
            "Solitary kernel observation")
    if kernel["environment_keys"] != ["PWD"]:
        raise ValueError("worker environment keys differ from the pinned profile")
    launcher_filters, worker_filters = kernel["launcher_seccomp_filters"], kernel["worker_seccomp_filters"]
    if (type(launcher_filters) is not int or type(worker_filters) is not int
            or not 0 <= launcher_filters < worker_filters):
        raise ValueError("worker filter count does not exceed the launcher count")
    verify_measurement_record(standard_snapshot, contract)
    if standard_snapshot["credentials"]["seccomp_mode"] != 2:
        raise ValueError("worker snapshot does not report seccomp filter mode")


def sign_envelope(base_evidence, snapshot, controls, limits, closure, supervisor):
    """Sign a completed observation record and bind the exact broker transcript."""
    # Freeze both artifacts before deriving digests and returning the result.
    envelope = json.loads(canon({
        "evidence": base_evidence,
        "supervisor_record": {"payload": {
            "type": SOLITARY_TYPE, "assurance": ASSURANCE, "snapshot": snapshot,
            "worker_self_report": controls, "observed_limits": limits, "closure": closure,
        }},
    }))
    evidence = envelope["evidence"]
    payload = envelope["supervisor_record"]["payload"]
    try:
        broker_payload = evidence["payload"]
        contract = broker_payload["contract"]
        policy = _policy(contract)
        if supervisor.pub.hex() in (broker_payload["broker"], broker_payload["witness"]):
            raise ValueError("expected distinct supervisor, broker and witness keys")
        payload["contract_sha256"] = H(canon(contract)).hex()
        payload["evidence_sha256"] = H(canon(evidence)).hex()
        _check_observations(payload, contract, policy)
    except (KeyError, TypeError, MeasurementBlocked) as exc:
        raise ValueError("cannot sign an invalid Solitary evidence envelope") from exc
    envelope["supervisor_record"]["signature"] = supervisor.sign(_DOMAIN, canon(payload)).hex()
    return envelope


def verify_solitary(envelope, *, contract, broker_pub, witness_pub, supervisor_pub,
                    expected_witness_state_digest, now):
    """Verify separately pinned Solitary references and their signed observations."""
    try:
        contract = json.loads(canon(contract))
        policy = _policy(contract)
        if any(not _key(key) for key in (broker_pub, witness_pub, supervisor_pub)):
            raise ValueError("missing or invalid expected signing key")
        if not _key(expected_witness_state_digest) or type(now) is not int or now < 0:
            raise ValueError("missing or invalid expected witness head or verifier time")
    except (ValueError, TypeError, RuntimeError) as exc:
        return {"outcome": "BLOCKED", "reason": str(exc)}
    if len({broker_pub, witness_pub, supervisor_pub}) != 3:
        return {"outcome": "REJECTED", "reason": "expected distinct supervisor, broker and witness keys"}

    try:
        envelope = json.loads(canon(envelope))
        _fields(envelope, {"evidence", "supervisor_record"}, "Solitary evidence envelope")
        record = envelope["supervisor_record"]
        _fields(record, {"payload", "signature"}, "supervisor record")
        payload = record["payload"]
        signature = _hex(record["signature"], 64, "supervisor signature")
        if not verify_sig(supervisor_pub, _DOMAIN, canon(payload), signature):
            raise ValueError("invalid Solitary supervisor signature")
        _fields(payload, _PAYLOAD_FIELDS, "supervisor record payload")
        if payload["type"] != SOLITARY_TYPE or payload["assurance"] != ASSURANCE:
            raise ValueError("unsupported Solitary evidence type or assurance")
        if payload["contract_sha256"] != H(canon(contract)).hex():
            raise ValueError("supervisor record contract digest mismatch")
        evidence = envelope["evidence"]
        if evidence is None:
            raise _IncompleteEvidence("broker transcript is missing")
        if payload["evidence_sha256"] != H(canon(evidence)).hex():
            raise ValueError("supervisor record broker transcript digest mismatch")
        _check_observations(payload, contract, policy)
    except _IncompleteEvidence as exc:
        return {"outcome": "BLOCKED", "reason": str(exc)}
    except (ValueError, TypeError, RuntimeError) as exc:
        return {"outcome": "REJECTED", "reason": str(exc)}

    verified = verify_execution(
        evidence, contract=contract, broker_pub=broker_pub, witness_pub=witness_pub,
        expected_witness_state_digest=expected_witness_state_digest, now=now,
    )
    if verified["outcome"] != "VERIFIED":
        return verified
    return {
        **verified, "measurement": "SIGNED_SUPERVISOR_SNAPSHOT",
        "worker_self_report": payload["worker_self_report"],
        "observed_limits": payload["observed_limits"], "closure": payload["closure"],
    }
