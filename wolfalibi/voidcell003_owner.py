"""Owner-side observations and a one-shot crash fixture for VOIDCELL's synthetic counter."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3

from alibi import H
from .solitary_cli import _read
from .stage3_evidence import _hex
from .voidcell002 import TargetAuthority, _file_id, _private_directory, _read_private
from .voidcell002_anchor import LedgerDivergence
from .voidcell002_probe import _ordinary, _status
from .voidcell002_transport import request, serve
from .voidcell003_revision import source_revision
from .voidcell_records import dispatch_digest


def observe(socket_path, target_pid, packet=None):
    """Observe the live owner endpoint and attempt the gateway role from the owner UID."""
    peer = dict(expected_target_uid=os.geteuid(), expected_target_pid=target_pid)
    before = request(socket_path, "status", **peer)
    digest = dispatch_digest(packet) if packet is not None else None
    denied = request(socket_path, "dispatch", packet, **peer)
    after = request(socket_path, "status", **peer)
    matched = (
        before.get("outcome") == after.get("outcome") == "READY"
        and before.get("pid") == after.get("pid") == target_pid
        and before.get("target_uid") == os.geteuid()
        and before.get("gateway_uid") != os.geteuid()
        and isinstance(before.get("inventory_v2"), dict)
        and before["inventory_v2"] == after.get("inventory_v2")
        and before.get("anchor") == after.get("anchor")
        and before.get("effect_count") == after.get("effect_count")
        and denied == {"outcome": "BLOCKED", "reason": "VOIDCELL002_TRANSPORT_REJECTED"}
    )
    return {
        "schema": "wolfalibi.voidcell003.owner-observation.v1",
        "outcome": "OBSERVED" if matched else "BLOCKED",
        "caller_uid": os.geteuid(), "peer_pid": target_pid,
        "attempted_dispatch_sha256": digest,
        "owner_status_before": before, "owner_role_dispatch": denied, "owner_status_after": after,
    }


def _arm_crash_trial(target):
    status = target.status()
    if (status.get("effect_count") != 0 or status["anchor"]["generation"] != 0
            or target.scope["resource"] != "synthetic-counter"):
        raise ValueError("crash trial requires a fresh synthetic counter")
    # Keep the failpoint on this disposable target instance, outside the normal service.
    advance = target._anchor.advance

    def after_sql_commit(vault):
        if vault.effect_count() == 1:
            os._exit(73)
        return advance(vault)

    target._anchor.advance = after_sql_commit


def serve_trial(state_dir, anchor_dir, socket_path, *, crash_after_commit, revision):
    """Serve the existing authority and identify the target checkout in its readiness record."""
    with TargetAuthority(state_dir, anchor_dir) as target:
        if crash_after_commit:
            _arm_crash_trial(target)
        serve(target, gateway_uid=target.gateway_uid, socket_path=socket_path,
              on_ready=lambda: print(json.dumps(dict(target.status(), source_revision=revision),
                                                sort_keys=True), flush=True))


def inspect_crash(state_dir, anchor_dir, prior_anchor_sha256, operation_id):
    """Compare a stopped fixture to the retained pre-trial digest and test ordinary reopen."""
    _hex(prior_anchor_sha256, 32, "pre-trial owner checkpoint digest")
    state, _ = _private_directory(state_dir)
    retained, _ = _private_directory(anchor_dir)
    current = H(_read_private(retained / "ledger-anchor.json", 16384)).hex()
    if current != prior_anchor_sha256:
        raise ValueError("retained checkpoint differs from pre-trial reference")
    ledger = state / "ledger.sqlite"
    _file_id(ledger)
    with closing(sqlite3.connect(ledger.as_uri() + "?mode=ro", uri=True)) as db:
        rows = db.execute("SELECT operation_id, outcome, dispatch_digest FROM effects LIMIT 2").fetchall()
    if len(rows) != 1 or rows[0][:2] != (operation_id, "ACCEPTED_EVIDENCED"):
        raise ValueError("expected exactly one committed effect for the external operation ID")
    divergence = False
    try:
        with TargetAuthority(state, retained):
            pass
    except LedgerDivergence:
        divergence = True
    return {
        "schema": "wolfalibi.voidcell003.crash-inspection.v1",
        "outcome": "FAIL_STOP_OBSERVED" if divergence else "BLOCKED",
        "target_uid": os.geteuid(), "operation_id": operation_id, "unanchored_sql_rows": 1,
        "dispatch_sha256": rows[0][2], "retained_anchor_sha256": current,
        "ordinary_reopen_detected_divergence": divergence, "recovery": "OWNER_REVIEW_REQUIRED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    live = commands.add_parser("observe")
    live.add_argument("--socket", required=True, type=Path)
    live.add_argument("--target-pid", required=True, type=int)
    live.add_argument("--packet", type=Path, help="gateway-prepared public synthetic packet")
    crash = commands.add_parser("serve-crash-trial", help="disposable synthetic fixture only")
    normal = commands.add_parser("serve", help="ordinary synthetic trial")
    for server in (crash, normal):
        server.add_argument("--socket", required=True, type=Path)
    inspect = commands.add_parser("inspect-crash")
    inspect.add_argument("--prior-anchor-sha256", required=True)
    inspect.add_argument("--operation-id", required=True)
    for command in (normal, crash, inspect):
        command.add_argument("--state-dir", required=True, type=Path)
        command.add_argument("--anchor-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if not _ordinary(_status("self")):
            print(json.dumps({"outcome": "UNSUPPORTED", "reason": "ordinary non-root owner required"}))
            return 2
        revision = source_revision()
        if args.action == "observe":
            packet = _read(args.packet, 65536) if args.packet else None
            result = observe(args.socket, args.target_pid, packet)
        elif args.action == "inspect-crash":
            result = inspect_crash(args.state_dir, args.anchor_dir, args.prior_anchor_sha256,
                                   args.operation_id)
        else:
            crash_trial = args.action == "serve-crash-trial"
            serve_trial(args.state_dir, args.anchor_dir, args.socket, revision=revision,
                        crash_after_commit=crash_trial)
            return 2 if crash_trial else 0
        result["source_revision"] = revision
    except (OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
        result = {"outcome": "BLOCKED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 2 if result["outcome"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
