"""Supervisor measurement and verifier acceptance for fixed synthetic trials."""

from __future__ import annotations

import argparse
import json
import stat
import time
from pathlib import Path

from alibi import DurableWitness, H, Signer, canon, verify_sig
from . import stage3
from .stage3_evidence import validate_contract, verify_execution
from .stage3_worker import UnsupportedWorker
from .stage35_measure import MeasurementBlocked, measure_worker, verify_measurement_record
from .stage35_verifier import VerifierStore, VerifierStoreError


_FIXTURES = {
    stage3.FIXTURE_KEY: stage3.FIXTURE_BYTES,
    "reports/summary.txt": b"WolfAlibi Stage 3.5 synthetic nested report\n",
}
_DOM = b"alibi/stage35/supervisor-measurement/v1"
_TYPE = "WOLFALIBI_STAGE35_SUPERVISOR_SNAPSHOT_V1"


def measured_contract(run_id, challenge, expires_at, *, key=stage3.FIXTURE_KEY):
    """Select a fixture from the fixed synthetic catalog."""
    if key not in _FIXTURES:
        raise ValueError("unknown synthetic resource key")
    contract = stage3.trial_contract(run_id, challenge, expires_at)
    contract.update(key=key, fixture_sha256=H(_FIXTURES[key]).hex())
    return contract


def _expected_layout(key):
    fixture = _FIXTURES[key]
    parts = key.split("/")
    return {
        "directories": ["."] + ["/".join(parts[:i]) for i in range(1, len(parts))],
        "directory_mode": 0o700, "key": key, "mode": 0o400, "links": 1,
        "size": len(fixture), "sha256": H(fixture).hex(),
    }


def inspect_layout(root, key):
    """Check the whole small, trusted synthetic tree just before broker access."""
    expected = _expected_layout(key)
    root = Path(root)
    root_stat = root.lstat()
    current = root
    for name in key.split("/"):
        mode = current.lstat().st_mode
        if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != expected["directory_mode"]:
            raise stage3.TrialBlocked("fixture directory permissions or type differ from the contract")
        if {entry.name for entry in current.iterdir()} != {name}:
            raise stage3.TrialBlocked("unexpected path or alias in the synthetic fixture tree")
        current = current / name
        if current.lstat().st_dev != root_stat.st_dev:
            raise stage3.TrialBlocked("fixture tree spans filesystems")
    file_stat = current.lstat()
    if (not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != expected["links"] or
            stat.S_IMODE(file_stat.st_mode) != expected["mode"] or
            file_stat.st_size != expected["size"] or H(current.read_bytes()).hex() != expected["sha256"]):
        raise stage3.TrialBlocked("fixture identity, content or permissions differ from the contract")
    return expected


def run_measured_trial(state_dir, *, contract, signer, witness, supervisor,
                       expected_witness_state_digest, timeout=10.0):
    """Require a supervisor snapshot at the response gate and sign it separately."""
    try:
        validate_contract(contract)
        contract = json.loads(canon(contract))
        key = contract["key"]
        if key not in _FIXTURES or H(_FIXTURES[key]).hex() != contract["fixture_sha256"]:
            raise ValueError("fixture differs from the measured trial catalog")
        if supervisor.pub in (signer.pub, witness.signer.pub):
            raise ValueError("supervisor, broker and witness require distinct keys")
    except ValueError as exc:
        return {"outcome": "BLOCKED", "reason": str(exc)}

    observed = {}

    def observe(proc, endpoint_inode, root, canary_fd, deadline):
        observed["resource_layout"] = inspect_layout(root, key)
        try:
            observed["worker"] = measure_worker(proc, contract, endpoint_inode, root,
                                                canary_fd=canary_fd, deadline=deadline)
        except (MeasurementBlocked, ValueError) as exc:
            raise stage3.TrialBlocked(f"supervisor measurement unavailable: {exc}") from exc

    result = stage3.run_trial(
        state_dir, contract=contract, signer=signer, witness=witness,
        expected_witness_state_digest=expected_witness_state_digest, timeout=timeout,
        _fixture=(key, _FIXTURES[key]), _before_release=observe,
    )
    if result["outcome"] != "COMPLETED":
        return result
    payload = {
        "type": _TYPE, "phase": "BEFORE_BROKER_READ", "assurance": "BROKER_ONLY",
        "contract_sha256": H(canon(contract)).hex(),
        "transcript_sha256": H(canon(result["evidence"])).hex(),
        "resource_layout": observed["resource_layout"], "worker": observed["worker"],
    }
    result["supervisor_record"] = {
        "payload": payload, "signature": supervisor.sign(_DOM, canon(payload)).hex(),
    }
    return result


def verify_measured_trial(evidence, record, *, supervisor_pub, contract, **references):
    """Verify the transcript and a pinned supervisor's point-in-time observations."""
    result = verify_execution(evidence, contract=contract, **references)
    if result["outcome"] != "VERIFIED":
        return result
    if record is None or not isinstance(supervisor_pub, bytes) or len(supervisor_pub) != 32:
        return {"outcome": "BLOCKED", "reason": "missing supervisor record or expected key"}
    try:
        if supervisor_pub in (references["broker_pub"], references["witness_pub"]):
            raise ValueError("supervisor key must differ from broker and witness keys")
        payload = record["payload"]
        if not verify_sig(supervisor_pub, _DOM, canon(payload), bytes.fromhex(record["signature"])):
            raise ValueError("invalid supervisor signature")
        expected = {
            "type": _TYPE, "phase": "BEFORE_BROKER_READ", "assurance": "BROKER_ONLY",
            "contract_sha256": H(canon(contract)).hex(),
            "transcript_sha256": H(canon(evidence)).hex(),
            "resource_layout": _expected_layout(contract["key"]), "worker": payload["worker"],
        }
        if canon(payload) != canon(expected):
            raise ValueError("supervisor record does not match the transcript and scope")
        verify_measurement_record(payload["worker"], contract)
    except (KeyError, TypeError, ValueError, MeasurementBlocked, RecursionError) as exc:
        return {"outcome": "REJECTED", "reason": str(exc)}
    return {**result, "measurement": "SIGNED_SUPERVISOR_SNAPSHOT",
            "scope": payload["resource_layout"]}


def _demo(args):
    contract = measured_contract(args.run_id, bytes.fromhex(args.challenge),
                                 int(time.time()) + 120, key=args.key)
    broker, supervisor = Signer(), Signer()
    with DurableWitness(args.state_dir / "witness.json", Signer()) as witness:
        witness_pub, initial = witness.signer.pub, witness.state_digest
        with VerifierStore(args.state_dir / "verifier.db", bootstrap_heads={witness_pub: initial}) as store:
            issued = store.issue(contract=contract, broker_pub=broker.pub, witness_pub=witness_pub,
                                 supervisor_pub=supervisor.pub)
            if issued["outcome"] != "ISSUED":
                return issued
            result = run_measured_trial(
                args.state_dir, contract=contract, signer=broker, witness=witness,
                supervisor=supervisor, expected_witness_state_digest=initial,
            )
            if result["outcome"] != "COMPLETED":
                return result
            checked_at = int(time.time())
            result["demo_references"] = {
                "supervisor_pub": supervisor.pub.hex(), "contract": contract,
                "broker_pub": broker.pub.hex(), "witness_pub": witness_pub.hex(),
                "expected_witness_state_digest": initial.hex(), "now": checked_at,
            }
            result["measurement_verification"] = verify_measured_trial(
                result["evidence"], result["supervisor_record"], supervisor_pub=supervisor.pub,
                contract=contract, now=checked_at, broker_pub=broker.pub,
                witness_pub=witness_pub, expected_witness_state_digest=initial,
            )
            if result["measurement_verification"]["outcome"] == "VERIFIED":
                result["fresh_acceptance"] = store.accept(
                    result["evidence"], challenge=contract["challenge"],
                    supervisor_record=result["supervisor_record"],
                )
            return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--key", choices=sorted(_FIXTURES), default=stage3.FIXTURE_KEY)
    args = parser.parse_args()
    try:
        result = _demo(args)
    except UnsupportedWorker as exc:
        result = {"outcome": "UNSUPPORTED", "reason": str(exc)}
    except (ValueError, OSError, VerifierStoreError) as exc:
        result = {"outcome": "BLOCKED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("fresh_acceptance", {}).get("outcome") == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
