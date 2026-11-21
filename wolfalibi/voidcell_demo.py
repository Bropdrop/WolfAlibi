"""Run or verify the offline synthetic VOIDCELL Experiment 001."""

import argparse
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time

from alibi import DurableWitness, Signer, canon
from .agent_solitary import agent_solitary_contract, run_agent_solitary
from .solitary_cli import _read, _write_new
from .stage3_evidence import _hex
from .stage3_worker import UnsupportedWorker
from .voidcell_gateway import EffectGateway
from .voidcell_records import dispatch_digest, grant, make_scope, sign_dispatch, verify_receipt
from .voidcell_service import VaultProcess


_HOSTILE_FIXTURE = """
import hashlib, json, os, sys
scope = json.loads(sys.stdin.buffer.read())
observation = {"assurance": "OBSERVATIONAL_ONLY", "outcome": "PASS",
               "claims_qualification": True, "claims_effect": "ACCEPTED_EVIDENCED"}
encoded = json.dumps(observation, sort_keys=True, separators=(",", ":")).encode()
route = {"type": "WOLFALIBI_VOIDCELL_DISPATCH_V1", "scope": scope, "seq": 1,
         "qualification_sha256": hashlib.sha256(encoded).hexdigest(),
         "grant_sha256": hashlib.sha256(b"null").hexdigest()}
print(json.dumps({"environment_keys": sorted(os.environ),
                  "request": {"route": {"payload": route, "signature": "00" * 64},
                              "qualification": observation, "grant": None}}))
"""


def _hostile_request(scope, cwd):
    # Only public scope is provided. This process runs a fixed local fixture.
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", _HOSTILE_FIXTURE],
        input=canon(scope), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"LC_ALL": "C"}, cwd=cwd, close_fds=True, timeout=5, check=True,
    )
    return json.loads(result.stdout)


def _run_demo(state):
    target_seed = secrets.token_bytes(32)
    target_pub = Signer(target_seed).pub
    owner, gateway, broker, supervisor = (Signer() for _ in range(4))
    qualification_keys = {"broker_pub": broker.pub, "supervisor_pub": supervisor.pub}
    now = int(time.time())
    contract = agent_solitary_contract("voidcell-experiment-001", secrets.token_bytes(32), now + 120)
    operation_id = "voidcell-counter-increment-001"
    head_path = state / "retained-witness.json"
    with DurableWitness(state / "witness.json", Signer()) as witness:
        qualification_keys["witness_pub"] = witness.signer.pub
        initial = witness.state_digest
        scope = make_scope(contract, gateway_pub=gateway.pub, target_pub=target_pub,
                           operation_id=operation_id, expected_witness_state_digest=initial)
        _write_new(state / "qualification-expected.json", {
            **{key: value.hex() for key, value in qualification_keys.items()},
            "contract": contract, "expected_witness_state_digest": initial.hex(), "now": now,
        })
        trial = run_agent_solitary(state, contract=contract, signer=broker, witness=witness,
                                  supervisor=supervisor, expected_witness_state_digest=initial)
        if trial["outcome"] != "COMPLETED":
            return {**trial, "confinement": "BLOCKED"}
        _write_new(head_path, {"head": witness.state_digest.hex()})
    envelope = trial["envelope"]
    _write_new(state / "qualification.json", envelope)
    approved = grant(owner, scope=scope, grant_id="demo-owner-increment", not_before=now,
                     expires_at=contract["expires_at"])
    _write_new(state / "owner-expected.json", {"owner_pub": owner.pub.hex()})
    intended = sign_dispatch(gateway, scope=scope, qualification=envelope, owner_grant=approved)
    _write_new(state / "dispatch.json", intended)
    expected = {"target_pub": target_pub.hex(), "scope": scope, "dispatch_sha256": dispatch_digest(intended)}
    _write_new(state / "expected.json", expected)
    agent_dir = state / "agent"
    agent_dir.mkdir(mode=0o700)
    hostile = _hostile_request(scope, agent_dir)
    with VaultProcess(
        state / "target.sqlite", target_seed=target_seed, owner_pub=owner.pub, gateway_pub=gateway.pub,
        contract=contract, operation_id=operation_id, expected_witness_state_digest=initial,
        witness_head_path=head_path, **qualification_keys,
    ) as vault:
        return _exercise(state, vault, gateway, scope, envelope, approved, intended, hostile)


def _exercise(state, vault, gateway, scope, envelope, approved, intended, hostile):
    direct = vault.call("dispatch", hostile["request"])
    observation_only = vault.call("dispatch", sign_dispatch(
        gateway, scope=scope, qualification=hostile["request"]["qualification"], owner_grant=approved,
    ))
    missing_owner = vault.call("dispatch", sign_dispatch(
        gateway, scope=scope, qualification=envelope, owner_grant=None,
    ))
    denied_count = vault.call("count")
    denied = {"direct": direct, "observation_only": observation_only, "missing_owner": missing_owner}
    if hostile["environment_keys"] != ["LC_ALL"] or denied_count != 0 or any(
            result["outcome"] != "DENIED" for result in denied.values()):
        return {"outcome": "BLOCKED", "reason": "synthetic pre-effect controls did not qualify",
                "confinement": "BLOCKED", "effect_count": denied_count}

    def lose_reply(action, packet):
        vault.call(action, packet)
        raise TimeoutError("synthetic loss of target acknowledgement")

    journal = state / "gateway.sqlite"
    gateway_config = dict(signer=gateway, scope=scope, target_pub=bytes.fromhex(scope["target_pub"]))
    with EffectGateway(journal, **gateway_config, transport=lose_reply) as dispatching:
        dispatched = dispatching.dispatch(qualification=envelope, owner_grant=approved)
    with EffectGateway(journal, **gateway_config, transport=vault.call) as recovering:
        reconciled = recovering.reconcile()
    replayed = vault.call("dispatch", intended)
    effects = vault.call("count")

    passed = (
        dispatched["outcome"] == "AMBIGUOUS" and reconciled["outcome"] == "ACCEPTED_EVIDENCED"
        and replayed["outcome"] == "DENIED" and type(effects) is int and effects == 1
    )
    result = {
        "outcome": "PASS" if passed else "BLOCKED", "effect_count": effects, "confinement": "BLOCKED",
        "assurance": "RESOURCE_SIDE_EFFECT_GATE", "broker_assurance": "BROKER_ONLY",
        "direct": direct["outcome"], "observation_only": observation_only["outcome"],
        "missing_owner": missing_owner["outcome"], "dispatch": dispatched["outcome"],
        "reconciliation": reconciled["outcome"], "replay": replayed["outcome"],
        "credential_provisioning": {
            "bootstrap_fields": sorted(scope), "target_or_gateway_private_keys_delivered": False,
            "configured_environment": ["LC_ALL"], "fixture_reported_environment": hostile["environment_keys"],
            "close_fds": True,
        },
        "report": str(state / "report.json"), "expected": str(state / "expected.json"),
        "receipt": str(state / "receipt.json") if passed else None,
    }
    _write_new(state / "report.json", {
        **result, "target_denials": denied, "dispatch_result": dispatched,
        "reconciliation_result": reconciled, "replay_result": replayed,
        "target_effects_after_denials": denied_count, "network_upload": False,
    })
    if passed:
        _write_new(state / "receipt.json", reconciled["receipt"])
    return result


def _demo(args):
    if not args.consent:
        return {"outcome": "BLOCKED", "reason": "explicit consent required for the fixed local fixture"}
    state = Path(args.state_dir).absolute()
    mode = state.lstat()
    if (not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.geteuid() or mode.st_mode & 0o077
            or any(state.iterdir())):
        raise ValueError("use a new private operator-owned state directory")
    return _run_demo(state)


def _verify(args):
    expected = _read(args.expect, 16384)
    if type(expected) is not dict or expected.keys() != {"target_pub", "scope", "dispatch_sha256"}:
        raise ValueError("separate target expectations required")
    expected["target_pub"] = _hex(expected["target_pub"], 32, "target key")
    receipt = verify_receipt(_read(args.receipt, 16384), **expected)
    if receipt["outcome"] != "ACCEPTED_EVIDENCED":
        return {"outcome": "REJECTED", "reason": "receipt does not record an accepted effect"}
    return {
        "outcome": "VERIFIED", "historical": True, "receipt": receipt,
        "verification_scope": "TARGET_RECEIPT_ONLY",
        "assurance": "RESOURCE_SIDE_EFFECT_GATE", "confinement": "BLOCKED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--state-dir", required=True)
    demo.add_argument("--consent", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--expect", required=True)
    args = parser.parse_args(argv)
    try:
        result = _demo(args) if args.command == "demo" else _verify(args)
    except UnsupportedWorker as exc:
        result = {"outcome": "UNSUPPORTED", "reason": str(exc), "confinement": "BLOCKED"}
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError):
        result = {"outcome": "BLOCKED", "reason": "VOIDCELL local state, transport or references unavailable",
                  "confinement": "BLOCKED"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in {"PASS", "VERIFIED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
