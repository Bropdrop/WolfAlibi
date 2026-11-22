"""Operator, verifier and owner entry points for the one-run local BYOA profile."""

import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

from alibi import DurableWitness, Signer, canon
from .clearance_records import MAX_GRANT_SECONDS
from .solitary_cli import _unique_object, _write_new
from .stage35_verifier import VerifierStore


TRIAL_ROLES = ("broker", "witness", "supervisor", "target")


def _read(path, limit):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("expected a regular JSON document")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("JSON document exceeds profile size limit")
    obj = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    if type(obj) is not dict:
        raise ValueError("expected a JSON object")
    return obj


def _sync_dir(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_dir(path, *, create=False):
    path = Path(path).absolute()
    if path != path.resolve(strict=False):
        raise ValueError("role and output directories require direct paths")
    if create:
        path.mkdir(mode=0o700)
        _sync_dir(path.parent)
    entry = path.lstat()
    if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or entry.st_mode & 0o077:
        raise ValueError("role and output directories must be private and owner-controlled")
    return path


def _open_key(directory, role):
    fd = os.open(directory / (role + ".seed"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size != 32):
            raise ValueError("invalid private role key file")
        seed = stream.read(33)
    if len(seed) != 32:
        raise ValueError("incomplete role key")
    return Signer(seed)


def _new_key(directory, role):
    seed = secrets.token_bytes(32)
    fd = os.open(directory / (role + ".seed"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(seed)
        stream.flush()
        os.fsync(stream.fileno())
    return Signer(seed)


def provision(args):
    from .byoa_effect_gate import initialize_read_target

    directory = _private_dir(args.output, create=True)
    roles = TRIAL_ROLES if args.role == "trial" else ("owner",)
    keys = {role: _new_key(directory, role) for role in roles}
    public = {role + "_pub": key.pub.hex() for role, key in keys.items()}
    if args.role == "trial":
        with DurableWitness(directory / "witness.json", keys["witness"]) as witness:
            public["expected_witness_state_digest"] = witness.state_digest.hex()
        target = _private_dir(directory / "target", create=True)
        initialize_read_target(target, keys["target"])
    _write_new(directory / "public.json", public)
    return {"outcome": "PROVISIONED", "role": args.role, "public": str(directory / "public.json")}


def enroll_owner(args):
    from .byoa_effect_gate import enroll_read_authorities

    if not args.approve_owner:
        raise ValueError("explicit target administrator enrollment is required")
    state = _private_dir(args.trial)
    owner = _read(args.owner_pin, 4096)
    if owner.keys() != {"owner_pub"}:
        raise ValueError("expected a resource-owner public key document")
    return enroll_read_authorities(
        state / "target", owner_pub=owner["owner_pub"], target_signer=_open_key(state, "target"),
        **{role + "_pub": _open_key(state, role).pub.hex() for role in ("broker", "witness", "supervisor")},
    )


def prepare(args):
    from .byoa_attestation import make_expectations
    from .byoa_bundle import load_bundle
    from .byoa_cell import cell_contract

    bundle = load_bundle(args.manifest)
    trial = _read(args.trial_pins, 4096)
    owner = _read(args.owner_pin, 4096)
    if (trial.keys() != {*(r + "_pub" for r in TRIAL_ROLES), "expected_witness_state_digest"}
            or owner.keys() != {"owner_pub"}):
        raise ValueError("expected trial and owner public pin documents")
    now = int(time.time())
    if not 1 <= args.ttl <= MAX_GRANT_SECONDS:
        raise ValueError(f"challenge lifetime must be between 1 and {MAX_GRANT_SECONDS} seconds")
    nonce = secrets.token_bytes(32) if args.challenge is None else bytes.fromhex(args.challenge)
    if len(nonce) != 32 or (args.challenge is not None and nonce.hex() != args.challenge):
        raise ValueError("invalid verifier challenge")
    contract = cell_contract(bundle, args.run_id or secrets.token_hex(16), nonce, now + args.ttl)
    keys = {name: bytes.fromhex(value) for name, value in {**owner, **trial}.items()}
    expected = make_expectations(contract, now=now, **keys)
    review = _private_dir(args.output, create=True)
    heads = {keys["witness_pub"]: keys["expected_witness_state_digest"]}
    with VerifierStore(review / "verifier.db", bootstrap_heads=heads) as store:
        issued = store.issue(contract=contract, **{name: keys[name] for name in
                             ("broker_pub", "witness_pub", "supervisor_pub")}, now=now)
        if issued["outcome"] != "ISSUED":
            raise ValueError(issued["reason"])
    _write_new(review / "expected.json", expected)
    # Separately anchor all five roles in verifier state. The inherited store pins three.
    checksum = hashlib.sha256(canon(expected)).hexdigest()
    _write_new(review / "issued.json", {"expected_sha256": checksum})
    return {"outcome": "PREPARED", "expected_sha256": checksum, "run_id": contract["run_id"],
            "challenge": nonce.hex(), "expires_at": contract["expires_at"], "bundle": bundle.identity()}


def grant_read(args):
    from .byoa_effect_gate import issue_read_grant

    if not args.approve_read:
        raise ValueError("the resource owner must explicitly approve the scoped fixture read")
    expected = _read(args.expect, 65536)
    signer = _open_key(_private_dir(args.owner), "owner")
    grant = issue_read_grant(expected, signer)
    _write_new(Path(args.output), grant)
    return {"outcome": "GRANTED", "operation": "read", "resource": expected["contract"]["key"]}


def _target_action(args):
    from .byoa_effect_gate import recover_read_admission, revoke_read_grant

    trial = _private_dir(args.trial)
    expected, grant = _read(args.expect, 65536), _read(args.grant, 32768)
    signer = _open_key(trial, "target")
    if args.byoa_command == "revoke-read":
        revoke_read_grant(trial / "target", expected, grant, signer)
        return {"outcome": "REVOKED"}
    decision = recover_read_admission(trial / "target", expected, grant, signer)
    if decision is None:
        raise ValueError("the read target has no recorded admission for this grant")
    return {"outcome": "RECONCILED", "target_admission": decision,
            "delivery": "NOT_ESTABLISHED_BY_ADMISSION", "redispatched": False}


def _publish_report(path, report):
    # Only link a complete, fsynced document into its final name. Never replace an earlier report.
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".pending-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(canon(report))
            stream.flush()
            os.fsync(stream.fileno())
            os.link(temporary, path)
            _sync_dir(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def qualify(args):
    from .byoa_attestation import sign_trial, verify_trial
    from .byoa_bundle import load_bundle
    from .byoa_cell import cell_contract, run_cell
    from .byoa_effect_gate import ReadGate
    from .solitary_preflight import preflight

    if not args.consent:
        raise ValueError("explicit consent for this reviewed local entrypoint is required")
    review, trial = _private_dir(args.review), _private_dir(args.trial)
    expected = _read(review / "expected.json", 65536)
    checksum = hashlib.sha256(canon(expected)).hexdigest()
    if _read(review / "issued.json", 1024) != {"expected_sha256": checksum}:
        raise ValueError("the expectations differ from the verifier's retained issuance")
    contract = expected["contract"]
    bundle = load_bundle(args.manifest)
    actual = cell_contract(bundle, contract["run_id"], bytes.fromhex(contract["challenge"]), contract["expires_at"])
    if canon(actual) != canon(contract):
        raise ValueError("agent source, policy or execution profile differs from approval")
    if not expected["now"] <= int(time.time()) < contract["expires_at"]:
        raise ValueError("challenge expired or the clock moved backwards")
    grant = _read(args.grant, 32768)
    keys = {role: _open_key(trial, role) for role in TRIAL_ROLES}
    if any(key.pub.hex() != expected[role + "_pub"] for role, key in keys.items()):
        raise ValueError("local role keys do not match the verifier's pins")
    readiness = preflight()
    if readiness["outcome"] != "READY":
        return {"outcome": readiness["outcome"], "preflight": readiness, "agent_started": False}
    prior = bytes.fromhex(expected["expected_witness_state_digest"])
    output = _private_dir(args.output, create=True)
    # Reserve in BOTH one-run trust directories. Each create is durable before launch.
    # Failure between reservations burns the attempt and cannot dispatch a read.
    with DurableWitness(trial / "witness.json", keys["witness"], expected_state_digest=prior) as witness:
        with VerifierStore(review / "verifier.db", expected_heads={keys["witness"].pub: prior}) as store:
            with ReadGate(trial / "target", expected, grant, keys["target"],
                          witness_state=witness.state_anchor) as gate:
                attempt = {"run_id": contract["run_id"], "expected_sha256": checksum}
                for directory in (review, trial):
                    _write_new(directory / "attempt.json", attempt)
                result = run_cell(output, bundle=bundle, contract=contract, signer=keys["broker"],
                                  witness=witness, supervisor=keys["supervisor"],
                                  expected_witness_state_digest=prior, read_gate=gate, consent=args.consent)
                if result["outcome"] != "COMPLETED":
                    return result
                envelope = result["envelope"]
                report = sign_trial(expected, envelope, result["observation"], keys["supervisor"],
                                    grant=grant, admission=gate.decision)
                checked = verify_trial(report, expected)
                if checked["outcome"] != "VERIFIED":
                    return checked
                accepted = store.accept(envelope["evidence"], challenge=contract["challenge"],
                                        supervisor_record=envelope["supervisor_record"])
                if accepted["outcome"] != "VERIFIED":
                    return accepted
                _publish_report(output / "report.json", report)
    return {"outcome": "COMPLETED", "report": str(output / "report.json"),
            "fresh_acceptance": accepted, "historical": checked}


def dispatch(args):
    try:
        if not sys.platform.startswith("linux"):
            result = {"outcome": "UNSUPPORTED", "reason": "qualification 001 requires the supported Linux profile"}
        elif getattr(args, "framework", None) == "langchain":
            from .byoa_langchain import run_linked
            result = run_linked(args)
        else:
            result = args.byoa_action(args)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, ImportError, sqlite3.Error, subprocess.SubprocessError, RecursionError) as exc:
        result = {"outcome": "BLOCKED", "reason": str(exc) or type(exc).__name__}
    if args.byoa_command == "qualify" and result["outcome"] != "COMPLETED":
        result["diagnostic"] = {
            "schema": "quorvane.byoa.incomplete.v1", "signature": "UNSIGNED",
            "observation": "NOT_VERIFIED", "execution": "NOT_VERIFIED",
            "authorization": "CHECK_ORIGINAL_GRANT_AND_TARGET_ADMISSION",
            "effect": "UNKNOWN_FROM_THIS_DIAGNOSTIC", "settlement": "UNESTABLISHED",
            "confinement": "BLOCKED", "production": "BLOCKED", "certification": "NOT_ISSUED",
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in {"PROVISIONED", "ENROLLED", "PREPARED", "GRANTED", "COMPLETED",
                                     "VERIFIED", "RECONCILED", "REVOKED"} else 2


def verify(args):
    from .byoa_attestation import verify_trial
    return verify_trial(_read(args.report, 262144), _read(args.expect, 65536))


def add_commands(commands):
    def command(name, handler, help_text, fields):
        parser = commands.add_parser(name, help=help_text)
        for field in fields:
            parser.add_argument("--" + field, required=True)
        parser.set_defaults(handler=dispatch, byoa_action=handler)
        return parser

    provisioner = command("provision", provision, "create one-run synthetic role credentials", ["output"])
    provisioner.add_argument("--role", choices=["owner", "trial"], required=True)
    admin = command("enroll-owner", enroll_owner, "pin the target administrator's chosen owner", ["trial", "owner-pin"])
    admin.add_argument("--approve-owner", action="store_true")
    verifier = command("prepare", prepare, "pin the source and issue verifier expectations",
                       ["manifest", "trial-pins", "owner-pin", "output"])
    verifier.add_argument("--run-id")
    verifier.add_argument("--challenge")
    verifier.add_argument("--ttl", type=int, default=180)
    owner = command("grant-read", grant_read, "approve one read of the synthetic fixture", ["owner", "expect", "output"])
    owner.add_argument("--approve-read", action="store_true")
    runner = command("qualify", qualify, "run one reviewed agent under the approved cell profile",
                     ["manifest", "trial", "review", "grant", "output"])
    runner.add_argument("--framework", choices=["langchain"], help="drive this trial with a local scripted LangChain agent")
    runner.add_argument("--consent", action="store_true", help="authorize this execution of reviewed local source")
    command("verify-qualification", verify, "authenticate historical evidence with external pins", ["report", "expect"])
    command("recover-read", _target_action, "inspect the durable admission without redispatch", ["trial", "expect", "grant"])
    command("revoke-read", _target_action, "record revocation at the synthetic read target", ["trial", "expect", "grant"])
