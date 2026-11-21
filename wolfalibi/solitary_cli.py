"""Local fixed-profile qualification, with external verification inputs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import stat
import time

from alibi import DurableWitness, Signer
from .agent_solitary import agent_solitary_contract, run_agent_solitary
from .agent_solitary_worker import AGENT_PROFILE
from .solitary import run_solitary, solitary_contract
from .solitary_evidence import verify_solitary
from .solitary_preflight import preflight
from .stage3_worker import UnsupportedWorker
from .stage35_verifier import VerifierStore, VerifierStoreError


_MANIFEST = {
    "schema": "wolfalibi.byoa.solitary.manifest.v1",
    "profile": "solitary-synthetic",
    "fixture": "protected.txt",
}
_AGENT_MANIFEST = {**_MANIFEST, "profile": AGENT_PROFILE}
_REFERENCE_KEYS = ("broker_pub", "witness_pub", "supervisor_pub", "expected_witness_state_digest")


def _unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON field")
    return result


def _read(path, bound):
    with open(path, "rb") as stream:
        data = stream.read(bound + 1)
    if len(data) > bound:
        raise ValueError("input exceeds the profile size limit")
    return json.loads(data, object_pairs_hook=_unique_object)


def _write_new(path, value):
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def inspect_manifest(path):
    manifest = _read(path, 4096)
    if manifest not in (_MANIFEST, _AGENT_MANIFEST):
        raise ValueError("Solitary accepts only the fixed synthetic manifests")
    result = {"outcome": "VALID", "profile": manifest["profile"],
            "worker": "FIXED_SYNTHETIC", "resources": [{"key": manifest["fixture"], "operation": "read"}],
            "agent_imports": False, "network_upload": False}
    if manifest == _AGENT_MANIFEST:
        result["adapter"] = {"name": "python-callbacks", "version": "1"}
    return result


def _test(args):
    profile = inspect_manifest(args.manifest)["profile"]
    if args.profile is not None and args.profile != profile:
        raise ValueError("requested profile does not match the fixed manifest")
    agent_profile = profile == AGENT_PROFILE
    if not args.consent:
        return {"outcome": "BLOCKED", "reason": "explicit consent is required for the local trial"}
    readiness = preflight()
    if readiness["outcome"] != "READY":
        return readiness
    state = Path(args.state_dir)
    state.mkdir(mode=0o700, exist_ok=True)
    entry = state.lstat()
    if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or entry.st_mode & 0o077:
        raise ValueError("state directory must be private and owner-controlled")
    expected_path, evidence_path = state / "expected.json", state / "evidence.json"
    if any(os.path.lexists(state / name) for name in
           ("expected.json", "evidence.json", "observation.json", "witness.json", "verifier.db")):
        raise ValueError("use a new state directory for each one-run trial")
    challenge = bytes.fromhex(args.challenge) if args.challenge else secrets.token_bytes(32)
    now = int(time.time())
    contract_for, trial_runner = (
        (agent_solitary_contract, run_agent_solitary) if agent_profile else (solitary_contract, run_solitary)
    )
    contract = contract_for(args.run_id, challenge, now + 120)
    broker, supervisor = Signer(), Signer()
    with DurableWitness(state / "witness.json", Signer()) as witness:
        pins = {"broker_pub": broker.pub, "witness_pub": witness.signer.pub,
                "supervisor_pub": supervisor.pub}
        prior = witness.state_digest
        with VerifierStore(state / "verifier.db", bootstrap_heads={witness.signer.pub: prior}) as store:
            issued = store.issue(contract=contract, **pins, now=now)
            if issued["outcome"] != "ISSUED":
                return issued
            _write_new(expected_path, {
                **{name: value.hex() for name, value in pins.items()},
                "contract": contract, "expected_witness_state_digest": prior.hex(),
                "now": now,
            })
            trial = trial_runner(state, contract=contract, signer=broker, witness=witness,
                                 supervisor=supervisor, expected_witness_state_digest=prior)
            if trial["outcome"] != "COMPLETED":
                return trial
            envelope = trial["envelope"]
            # Keep the signed envelope even if the verifier's acceptance
            # transaction is interrupted. Export alone cannot consume a nonce.
            _write_new(evidence_path, envelope)
            verification = store.accept(envelope["evidence"], challenge=contract["challenge"],
                                        supervisor_record=envelope["supervisor_record"])
            if verification["outcome"] != "VERIFIED":
                return verification
    result = {"outcome": "COMPLETED", "assurance": "BROKER_ONLY", "confinement": "BLOCKED",
            "expected": str(expected_path), "evidence": str(evidence_path),
            "fresh_acceptance": verification, "network_upload": False}
    if agent_profile:
        observation = trial["observation"]
        observation_path = state / "observation.json"
        _write_new(observation_path, observation)
        result.update(
            profile=AGENT_PROFILE, confinement_qualification="SYNTHETIC_CELL_CANDIDATE",
            owner_authorization="NOT_REQUESTED",
            observation={"assurance": observation["assurance"], "outcome": observation["outcome"],
                         "path": str(observation_path)},
        )
    return result


def _verify(args):
    expected = _read(args.expect, 65536)
    if not isinstance(expected, dict) or expected.keys() != set(_REFERENCE_KEYS) | {"contract", "now"}:
        raise ValueError("an independent expectation file is required")
    for field in _REFERENCE_KEYS:
        expected[field] = bytes.fromhex(expected[field])
    verified = verify_solitary(_read(args.evidence, 262144), **expected)
    return {**verified, "freshness": "HISTORICAL_VERIFICATION_ONLY"}


def command(args):
    try:
        if args.byoa_command == "doctor":
            result = preflight()
        elif args.byoa_command == "inspect":
            result = inspect_manifest(args.manifest)
        elif args.byoa_command == "test":
            result = _test(args)
        else:
            result = _verify(args)
    except UnsupportedWorker as exc:
        result = {"outcome": "UNSUPPORTED", "reason": str(exc)}
    except (ValueError, OSError, TypeError, VerifierStoreError, RecursionError) as exc:
        result = {"outcome": "BLOCKED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in {"READY", "VALID", "COMPLETED", "VERIFIED"} else 2


def add_byoa_parser(subcommands):
    from .clearance_cli import add_clearance_parser

    parser = subcommands.add_parser("byoa", help="run fixed synthetic Solitary profiles")
    commands = parser.add_subparsers(dest="byoa_command", required=True)
    commands.add_parser("doctor", help="exercise local prerequisites")
    inspect = commands.add_parser("inspect", help="inspect the fixed manifest without executing code")
    inspect.add_argument("--manifest", required=True)
    test = commands.add_parser("test", help="run one consented fixed synthetic trial")
    test.add_argument("--manifest", required=True)
    test.add_argument("--profile", choices=[_MANIFEST["profile"], AGENT_PROFILE])
    test.add_argument("--state-dir", required=True)
    test.add_argument("--consent", action="store_true")
    test.add_argument("--challenge", help="verifier-issued 32-byte hex challenge")
    test.add_argument("--run-id", default="solitary-synthetic")
    verify = commands.add_parser("verify", help="verify a transcript with separate expectations")
    verify.add_argument("--evidence", required=True)
    verify.add_argument("--expect", required=True)
    add_clearance_parser(commands)
    parser.set_defaults(handler=command)
