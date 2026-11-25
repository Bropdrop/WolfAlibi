"""JSON CLI. Only the local verifier state is changed."""

from __future__ import annotations

import argparse
from base64 import b64encode
import sys

from .model import (AdapterError, MAX_POLICY_BYTES,
                    MAX_RECORD_BYTES, canonical_json, read_bounded_file, strict_json)
from .receipt import verify_receipt
from .service import Service


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("init", "register-policy", "challenge", "verify", "receipt", "revoke-policy"):
        p = commands.add_parser(name)
        p.add_argument("--state", required=True)
        if name == "register-policy":
            p.add_argument("--policy", required=True)
        if name in ("challenge", "revoke-policy"):
            p.add_argument("--policy-sha256", required=True)
        if name in ("verify", "receipt"):
            p.add_argument("--challenge-id", required=True)
        if name == "verify":
            p.add_argument("--evidence", required=True)
            p.add_argument("--verifier", required=True)
            p.add_argument("--include-upstream-report", action="store_true")
    p = commands.add_parser("verify-receipt")
    p.add_argument("--receipt", required=True)
    p.add_argument("--public-key", required=True)
    p.add_argument("--expected-target", required=True)
    p.add_argument("--expected-policy-sha256", required=True)
    p.add_argument("--expected-challenge-id", required=True)
    return root


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    reports = []
    try:
        if args.command == "init":
            service = Service.initialize(args.state)
            result = {"status": "INITIALIZED", "instance_id": service.instance_id,
                      "public_key": service.public_key_hex()}
        elif args.command == "verify-receipt":
            result = verify_receipt(strict_json(read_bounded_file(args.receipt, MAX_RECORD_BYTES)),
                                    args.public_key, expected_target=args.expected_target,
                                    expected_policy_sha256=args.expected_policy_sha256,
                                    expected_challenge_id=args.expected_challenge_id)
        else:
            service = Service(args.state)
            if args.command == "register-policy":
                policy = strict_json(read_bounded_file(args.policy, MAX_POLICY_BYTES), MAX_POLICY_BYTES)
                result = {"policy_sha256": service.register_policy(policy)}
            elif args.command == "challenge":
                result = service.issue_challenge(args.policy_sha256)
            elif args.command == "revoke-policy":
                service.revoke_policy(args.policy_sha256)
                result = {"status": "REVOKED", "policy_sha256": args.policy_sha256}
            elif args.command == "receipt":
                result = service.get_receipt(args.challenge_id)
            elif args.include_upstream_report:
                result = service.assess_file(args.challenge_id, args.evidence, args.verifier,
                                             report_sink=reports.append)
            else:
                result = service.assess_file(args.challenge_id, args.evidence, args.verifier)
        outcome = result.get("payload", {}).get("outcome")
        if args.command == "verify" and args.include_upstream_report:
            report = result["payload"]["upstream"]["report"]
            raw = b64encode(reports[0]).decode("ascii") if reports and report is not None else None
            result = {"receipt": result, "upstream_report_base64": raw}
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        return 1 if outcome in ("REJECTED", "BLOCKED") else 0
    except AdapterError as exc:
        sys.stdout.buffer.write(canonical_json({"status": "BLOCKED", "code": exc.code,
                                              "message": exc.message}) + b"\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
