#!/usr/bin/env python3
"""Local CLI for synthetic WolfAlibi receipts and explicit verification.

This command intentionally has no network, cloud, or credential integration.
Its demo subcommand uses only the synthetic fixture supplied by alibi.py.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import tempfile

from alibi import Broker, DurableWitness, Signer, _sandbox, subtree
from wolfalibi.isolation import isolation_status
from wolfalibi.receipts import (EvidenceRun, sha256_file,
                                verify_negative_access_receipt)


def _json_dump(path: str | Path, value) -> None:
    Path(path).write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _json_load(path: str | Path):
    return json.loads(Path(path).read_bytes())


def _hex(value: str, label: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as ex:
        raise argparse.ArgumentTypeError(f"{label} must be hexadecimal") from ex


def cmd_demo_receipt(args) -> int:
    state_dir = Path(args.state_dir).resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    policy = _json_load(args.policy) if args.policy else {
        "actor": "synthetic-cli-agent",
        "resource_model": "brokered-filesystem-v1",
        "effect": "negative-access-receipt",
    }
    challenge = _hex(args.challenge, "challenge") if args.challenge else secrets.token_bytes(32)
    code_digest = sha256_file(args.code) if args.code else __import__("hashlib").sha256(
        b"wolfalibi-synthetic-cli-artifact-v1").digest()
    with tempfile.TemporaryDirectory(prefix="wolfalibi-cli-") as root:
        _sandbox(root)
        witness = DurableWitness(state_dir / "witness-state.json", Signer())
        broker = Broker(root, Signer(), witness, journal=os.path.join(root, "events.wal"))
        try:
            run = EvidenceRun(broker, run_id=args.run_id, challenge=challenge,
                              policy=policy, code_digest=code_digest)
            run.begin()
            broker.read("docs/notes.txt")
            receipt = run.finish_negative(*subtree(args.protected_prefix))
            _json_dump(args.output, receipt)
            inputs = {
                "broker_pub": broker.signer.pub.hex(),
                "witness_pub": witness.signer.pub.hex(),
                "challenge": challenge.hex(),
                "policy": policy,
                "lo": subtree(args.protected_prefix)[0].hex(),
                "hi": subtree(args.protected_prefix)[1].hex(),
                "run_id": args.run_id,
                "code_digest": code_digest.hex(),
                "epochs": [1, 1],
            }
            _json_dump(args.inputs, inputs)
        finally:
            broker.close()
            witness.close()
    print(json.dumps({"outcome": "GENERATED", "receipt": str(args.output),
                      "verification_inputs": str(args.inputs),
                      "assurance": "BROKER_ONLY"}, sort_keys=True))
    return 0


def cmd_verify(args) -> int:
    receipt, policy = _json_load(args.receipt), _json_load(args.policy)
    result = verify_negative_access_receipt(
        receipt,
        broker_pub=_hex(args.broker_pub, "broker public key"),
        witness_pub=_hex(args.witness_pub, "witness public key"),
        challenge=_hex(args.challenge, "challenge"),
        policy=policy,
        lo=_hex(args.lo, "lower range bound"),
        hi=_hex(args.hi, "upper range bound"),
        run_id=args.run_id,
        code_digest=_hex(args.code_digest, "code digest"),
        epochs=(args.epoch_from, args.epoch_to),
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] == "VERIFIED" else 2


def cmd_isolation_status(_args) -> int:
    print(json.dumps(isolation_status(), sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo-receipt", help="create a synthetic broker-only receipt")
    demo.add_argument("--output", required=True, help="receipt JSON output path")
    demo.add_argument("--inputs", required=True, help="external verification inputs JSON path")
    demo.add_argument("--state-dir", required=True, help="durable witness state directory")
    demo.add_argument("--run-id", default="synthetic-cli-run-001")
    demo.add_argument("--protected-prefix", default="finance")
    demo.add_argument("--challenge", help="fresh verifier challenge as hex; generated if omitted")
    demo.add_argument("--policy", help="expected policy JSON path")
    demo.add_argument("--code", help="local code artifact to hash (declared, not attested)")
    demo.set_defaults(handler=cmd_demo_receipt)

    verify = sub.add_parser("verify", help="verify using independently supplied references")
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--broker-pub", required=True)
    verify.add_argument("--witness-pub", required=True)
    verify.add_argument("--challenge", required=True)
    verify.add_argument("--policy", required=True)
    verify.add_argument("--lo", required=True, help="expected lower range bound as hex")
    verify.add_argument("--hi", required=True, help="expected upper range bound as hex")
    verify.add_argument("--run-id", required=True)
    verify.add_argument("--code-digest", required=True)
    verify.add_argument("--epoch-from", required=True, type=int)
    verify.add_argument("--epoch-to", required=True, type=int)
    verify.set_defaults(handler=cmd_verify)

    status = sub.add_parser("isolation-status", help="report optional Linux isolation support")
    status.set_defaults(handler=cmd_isolation_status)
    return result


if __name__ == "__main__":
    arguments = parser().parse_args()
    raise SystemExit(arguments.handler(arguments))
