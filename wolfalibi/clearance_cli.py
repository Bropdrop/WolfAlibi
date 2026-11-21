"""Run and inspect the offline Alibi Clearance synthetic demonstration."""

import hmac
import json
import os
from pathlib import Path
import secrets
import stat

from alibi import DurableWitness, Signer
from .agent_solitary import run_agent_solitary
from .agent_solitary_worker import AGENT_PROFILE, agent_worker_profile
from .clearance import ClearanceError, ClearanceGateway
from .clearance_records import PROFILE, grant, identity_pins, sign_request
from .clearance_report import REPORT_TYPE, verify_report
from .solitary import run_solitary
from .solitary_cli import _read, _write_new
from .solitary_preflight import preflight
from .solitary_worker import worker_profile


def _demo(args):
    if not args.consent:
        return {"outcome": "BLOCKED", "reason": "explicit consent required for the local trial"}
    ready = preflight()
    if ready["outcome"] != "READY":
        return ready
    state = Path(args.state_dir)
    entry = state.lstat()
    if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or entry.st_mode & 0o077
            or any(state.iterdir())):
        raise ClearanceError("use an empty private directory owned by the operator")
    db = state / "gateway"
    db.mkdir(mode=0o700)
    gateway_key, owner, agent, broker, supervisor = (Signer() for _ in range(5))
    credential = secrets.token_bytes(32)
    reads = 0
    trial_runner, profile_reader = (
        (run_agent_solitary, agent_worker_profile) if args.profile == AGENT_PROFILE
        else (run_solitary, worker_profile)
    )

    def service(secret):
        nonlocal reads
        if not hmac.compare_digest(secret, credential):
            raise PermissionError("synthetic gateway credential required")
        reads += 1
        return b"wolfalibi synthetic service record"

    expected_path, report_path = state / "expected.json", state / "report.json"
    with DurableWitness(state / "witness.json", Signer()) as witness:
        genesis = witness.state_digest
        keys = dict(owner_pub=owner.pub, broker_pub=broker.pub, witness_pub=witness.signer.pub,
                    supervisor_pub=supervisor.pub)
        with ClearanceGateway(
            db, signer=gateway_key, **keys, expected_witness_state_digest=genesis,
            observe_witness_head=lambda: witness.state_digest,
            observe_identity=lambda _agent_pub: identity_pins(profile_reader()),
            upstream=service, upstream_credential=credential,
        ) as gateway:
            prepared = gateway.prepare("clearance-synthetic-demo", agent_pub=agent.pub, profile=args.profile)
            if prepared["outcome"] != "ISSUED":
                return prepared
            contract = prepared["contract"]
            expected = {
                **{name: key.hex() for name, key in keys.items()},
                "gateway_pub": gateway_key.pub.hex(), "agent_pub": agent.pub.hex(),
                "contract": contract, "expected_witness_state_digest": genesis.hex(),
            }
            _write_new(expected_path, expected)
            approved = None
            if args.approve_synthetic_read:
                issued_at = prepared["decision"]["payload"]["checked_at"]
                approved = grant(owner, scope=prepared["scope"], not_before=issued_at,
                                 expires_at=contract["expires_at"], grant_id="synthetic-owner-read")
            trial = trial_runner(
                state, contract=contract, signer=broker, witness=witness, supervisor=supervisor,
                expected_witness_state_digest=genesis,
            )
            envelope = trial.get("envelope")
            admitted = gateway.admit(challenge=contract["challenge"], envelope=envelope, grant=approved)
            request, operation = None, None
            outcome = admitted["outcome"]
            if outcome == "ADMITTED":
                token = admitted["capability"]
                request = sign_request(agent, capability=token, request_id="synthetic-protected-read")
                result = gateway.perform(capability=token, request=request)
                operation, outcome = result["decision"], result["outcome"]
            report = {
                "type": REPORT_TYPE, "outcome": outcome, "prepare": prepared["decision"],
                "qualification": envelope, "grant": approved, "admission": admitted["decision"],
                "request": request, "operation": operation,
            }
            _write_new(report_path, report)
    return {
        "outcome": outcome, "upstream_reads": reads, "report": str(report_path),
        "expected": str(expected_path), "broker_assurance": "BROKER_ONLY", "production": "BLOCKED",
    }


def command(args):
    try:
        if args.clearance_command == "demo":
            result = _demo(args)
        else:
            result = verify_report(_read(args.report, 512_000), _read(args.expect, 64_000))
    except (OSError, TypeError, ValueError, RuntimeError):
        result = {"outcome": "BLOCKED", "reason": "local Clearance prerequisites or inputs unavailable"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in {"ALLOWED", "VERIFIED"} else 2


def add_clearance_parser(commands):
    clearance = commands.add_parser("clearance", help="exercise the local synthetic authorization gateway")
    sub = clearance.add_subparsers(dest="clearance_command", required=True)
    demo = sub.add_parser("demo", help="qualify and optionally authorize one synthetic read")
    demo.add_argument("--state-dir", required=True)
    demo.add_argument("--profile", choices=[PROFILE, AGENT_PROFILE], default=PROFILE)
    demo.add_argument("--consent", action="store_true", help="consent to the fixed local Solitary execution")
    demo.add_argument("--approve-synthetic-read", action="store_true", help="sign the synthetic owner's grant")
    verify = sub.add_parser("verify", help="verify a positive report against external expectations")
    verify.add_argument("--report", required=True)
    verify.add_argument("--expect", required=True)
    clearance.set_defaults(handler=command)
