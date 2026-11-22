"""Local role commands for the BYOA 002 owner, operator and verifier."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from wolfalibi.byoa002_enrollment import FIXED, TRIAL_ROLES, digest, validate_enrollment
from wolfalibi.byoa002_exchange import WitnessConnection, serve_witness
from wolfalibi.byoa002_transport import make_inventory, measure_gateway, serve
from wolfalibi.byoa002_verifier import VerifierPrincipal, initialize_verifier
from wolfalibi.byoa_bundle import load_bundle
from wolfalibi.byoa_cell import cell_contract
from wolfalibi.byoa_qualification_cli import _new_key, _open_key, _private_dir, _read
from wolfalibi.solitary_cli import _write_new
from wolfalibi.voidcell003_revision import source_revision


def read(path):
    return _read(path, 512 * 1024)


def provision(role, directory):
    path = _private_dir(directory, create=True)
    roles = ("owner", "target") if role == "owner" else (role,)
    public = {name + "_pub": _new_key(path, name).pub.hex() for name in roles}
    _write_new(path / "public.json", public)
    return public


def enroll(*, manifest, trial_public, bootstrap_owner, operator_public, owner_public, verifier_public,
           revision, gateway, owner_uid, epoch):
    profile = cell_contract(load_bundle(manifest), "0" * 32, bytes(32), 1)["profile"]
    if (operator_public.keys() != {"operator_pub"} or owner_public.keys() != {"owner_pub", "target_pub"}
            or verifier_public.keys() != {"verifier_pub"} or bootstrap_owner.keys() != {"owner_pub"}
            or trial_public.keys() != (set(TRIAL_ROLES) - {"owner_pub"} | {"expected_witness_state_digest"})):
        raise ValueError("invalid public role handoff")
    return validate_enrollment({**FIXED, **operator_public, **owner_public, **verifier_public,
        "trial_pins": {k: (bootstrap_owner if k == "owner_pub" else trial_public)[k] for k in TRIAL_ROLES},
        "gateway": gateway, "owner_uid": owner_uid, "policy_epoch": epoch, "revision": revision,
        "trial_witness_sha256": trial_public["expected_witness_state_digest"],
        "profile_sha256": digest(profile), "manifest_sha256": profile["byoa"]["manifest_sha256"]})


def _stopping():
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    return stopped


def announce(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def command(a):
    from wolfalibi.byoa002_target import Target, initialize_target, issue_owner_grant, sign_request
    if a.cmd == "provision":
        return provision(a.role, a.keys)
    if a.cmd == "enroll":
        result = enroll(manifest=a.manifest, trial_public=read(a.trial_pins), bootstrap_owner=read(a.bootstrap_owner),
            operator_public=read(a.operator_pin), owner_public=read(a.owner_pins), verifier_public=read(a.verifier_pin),
            revision=source_revision(), gateway=measure_gateway(a.gateway_pid, a.socket),
            owner_uid=os.geteuid(), epoch=a.epoch)
        _write_new(a.output, result)
        return {"outcome": "ENROLLED", "sha256": digest(result)}
    enrollment = validate_enrollment(read(a.enrollment))
    if enrollment["owner_uid"] != enrollment["gateway"]["uid"] and source_revision() != enrollment["revision"]:
        raise ValueError("independent-principal checkout differs from enrollment")
    keys = _private_dir(a.keys)
    if a.cmd in {"approve", "serve-verifier", "head", "init-verifier", "fresh"}:
        signer = _open_key(keys, "verifier")
        if signer.pub.hex() != enrollment["verifier_pub"]:
            raise ValueError("verifier pin differs")
        if a.cmd == "init-verifier":
            initialize_verifier(_private_dir(a.state, create=True), enrollment=enrollment)
            return {"outcome": "INITIALIZED"}
        head = read(a.expect_head) if getattr(a, "expect_head", None) else None
        with VerifierPrincipal(a.state, signer, enrollment, expected_head=head) as verifier:
            if a.cmd == "fresh":
                _write_new(a.output, verifier.fresh())
                return {"outcome": "RESERVED"}
            if a.cmd == "approve":
                q = verifier.issue(read(a.expected))
                _write_new(a.output, q)
                return {"outcome": "ISSUED", "challenge_sha256": digest(q)}
            if a.cmd == "head":
                _write_new(a.output, verifier.head())
                return {"outcome": "EXPORTED"}
            serve_witness(a.socket, verifier, enrollment, signer,
                          lambda: announce({"outcome": "READY", "pid": os.getpid()}), _stopping())
            return {"outcome": "STOPPED"}
    if a.cmd == "request":
        expected, challenge, grant, report = (read(path) for path in (a.expected, a.challenge, a.grant, a.report))
        extra = {"recovery_peer": read(a.recovery_peer)} if a.recovery_peer else {}
        request = sign_request(a.action, expected, enrollment, challenge, grant, report,
                               _open_key(keys, "operator"), **extra)
        _write_new(a.output, {"expected": expected, "challenge": challenge, "grant": grant,
                              "report": report, "request": request})
        return {"outcome": "SIGNED_REQUEST"}
    if os.geteuid() != enrollment["owner_uid"]:
        raise ValueError("current UID differs from enrolled owner")
    if a.cmd == "grant":
        q = issue_owner_grant(read(a.expected), enrollment, read(a.challenge), _open_key(keys, "owner"))
        _write_new(a.output, q)
        return {"outcome": "GRANTED"}
    signer = _open_key(keys, "target")
    journal = None
    if getattr(a, "custody_journal", None):
        from wolfalibi.byoa002_custody import Journal
        journal = Journal(a.custody_journal, signer, enrollment)
        if a.cmd == "init-target":
            journal.initialize()
    if a.cmd == "init-target":
        initialize_target(_private_dir(a.state, create=True), signer, enrollment, journal=journal)
        return {"outcome": "INITIALIZED"}
    witness = WitnessConnection(a.witness_socket, enrollment, signer)
    with Target(a.state, signer, enrollment, check_pending=witness.check_pending, retain=witness.retain,
                reconcile_head=witness.reconcile, journal=journal) as target:
        if a.cmd == "revoke":
            return target.revoke(read(a.grant), read(a.expected), read(a.challenge))
        if enrollment["gateway"]["uid"] == os.geteuid() and not a.single_account_control:
            return {"outcome": "UNSUPPORTED", "reason": "separately provisioned owner and gateway required"}
        def ready():
            inventory = make_inventory(keys / "target.seed", Path(a.state) / "ledger" / "ledger.sqlite",
                                       signer, enrollment["gateway"])
            announce({"outcome": "READY", "pid": os.getpid(), "uid": os.geteuid(), "inventory": inventory})
        serve(target, a.socket, gateway_peer=enrollment["gateway"], on_ready=ready, stop_event=_stopping())
        return {"outcome": "STOPPED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="cmd", required=True)
    p = cmds.add_parser("provision")
    p.add_argument("--role", choices=("owner", "verifier", "operator"), required=True)
    p.add_argument("--keys", required=True)
    p = cmds.add_parser("enroll")
    for name in ("manifest", "trial-pins", "bootstrap-owner", "operator-pin", "owner-pins", "verifier-pin",
                 "socket", "output"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--gateway-pid", required=True, type=int)
    p.add_argument("--epoch", required=True, type=int)
    p.add_argument("--approve-pins", required=True, action="store_true")
    for name, flags in {
        "init-verifier": ["state"], "head": ["state", "output"], "fresh": ["state", "output"],
        "approve": ["state", "expected", "output"], "serve-verifier": ["state", "socket"],
        "grant": ["expected", "challenge", "output"], "init-target": ["state"],
        "serve-target": ["state", "socket", "witness-socket"], "request": ["expected", "challenge", "grant", "report", "output"],
        "revoke": ["state", "witness-socket", "expected", "challenge", "grant"]}.items():
        p = cmds.add_parser(name)
        for flag in ["enrollment", "keys", *flags]:
            p.add_argument("--" + flag, required=True)
        if name in {"fresh", "approve", "serve-verifier"}:
            p.add_argument("--expect-head", required=True, help="latest separately retained public head")
        if name in {"grant", "approve"}:
            p.add_argument("--consent", required=True, action="store_true")
        if name in {"init-target", "serve-target", "revoke"}:
            p.add_argument("--custody-journal")
        if name == "serve-target":
            p.add_argument("--single-account-control", action="store_true")
        if name == "request":
            p.add_argument("--action", choices=("dispatch", "reconcile"), required=True)
            p.add_argument("--recovery-peer", help="new gateway peer object for signed historical inquiry")
    args = parser.parse_args()
    try:
        result = command(args)
    except PermissionError as exc:
        result = {"outcome": "UNSUPPORTED", "reason": str(exc)}
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        result = {"outcome": "BLOCKED", "reason": str(exc)}
    announce(result)
    return 2 if result.get("outcome") in {"BLOCKED", "DENIED", "UNSUPPORTED"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
