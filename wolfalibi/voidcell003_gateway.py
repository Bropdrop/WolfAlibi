"""Measure one provisioned VOIDCELL gateway trial across an owner-led restart."""

import argparse
from contextlib import closing
from dataclasses import dataclass
import json
import os
from pathlib import Path
import select
import sqlite3
import stat
import sys

from alibi import H, Signer, canon
from .solitary_cli import _unique_object, _write_new
from .stage3_evidence import _hex
from .stage35_measure import _process_fields
from .voidcell002_probe import _check_inventory, _INVENTORY_V2_TYPE, probe
from .voidcell002_transport import _encode_request, request
from .voidcell003_revision import source_revision
from .voidcell_gateway import EffectGateway
from .voidcell_records import dispatch_digest, sign_dispatch, verify_receipt


_TRIAL = "wolfalibi.voidcell003.gateway-trial.v1"
_CAPTURE = "wolfalibi.voidcell003.observed-lost-reply.v1"
_JOURNAL = "gateway.sqlite"
_LOST = "lost-reply.json"
_READY_FIELDS = {
    "outcome", "effect_count", "target_pub", "target_uid", "pid", "gateway_uid",
    "anchor", "inventory", "inventory_v2", "source_revision",
}
_FILE_IDENTITY = ("key_device", "key_inode", "ledger_device", "ledger_inode")


class _Blocked(ValueError):
    """A required provisioned reference or observed control is unavailable."""


@dataclass(frozen=True)
class _Plan:
    directory: Path
    signer: Signer
    payload: dict
    handoff_sha256: str
    target_pub: bytes

    @property
    def journal(self):
        return self.directory / _JOURNAL

    @property
    def capture(self):
        return self.directory / _LOST

    @property
    def scope(self):
        return self.payload["scope"]

    @property
    def attachments(self):
        return {"qualification": self.payload["qualification"], "owner_grant": self.payload["owner_grant"]}


def _result(outcome, phase, **fields):
    return {"schema": _TRIAL, "outcome": outcome, "phase": phase, "network_upload": False, **fields}


def _read(path, bound, *, private=False):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        entry = os.fstat(stream.fileno())
        if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or entry.st_mode & 0o022
                or not 0 < entry.st_size <= bound
                or (private and (entry.st_uid != os.geteuid() or stat.S_IMODE(entry.st_mode) != 0o600))):
            raise _Blocked("invalid provisioned artifact")
        contents = stream.read(bound + 1)
        if len(contents) != entry.st_size:
            raise _Blocked("provisioned artifact changed during read")
    return contents


def _json(path, bound, *, private=False):
    return json.loads(_read(path, bound, private=private), object_pairs_hook=_unique_object)


def _plan(gateway_state, handoff, owner_pub):
    from .voidcell003_fixture import (
        _read_canonical_public, load_gateway_signer, verify_owner_handoff,
    )

    directory = Path(os.path.abspath(os.fspath(gateway_state)))
    record = _read_canonical_public(handoff, "owner handoff")
    payload = verify_owner_handoff(record, owner_pub=owner_pub)
    signer = load_gateway_signer(directory)
    if signer.pub.hex() != payload["gateway_pub"]:
        raise _Blocked("local gateway key differs from the provisioned scope")
    if (os.getuid() != os.geteuid() or os.getgid() != os.getegid()
            or (os.geteuid(), os.getegid()) != (payload["gateway_uid"], payload["gateway_gid"])
            or payload["target_uid"] == os.geteuid()
            or min(payload["target_uid"], payload["target_gid"], payload["gateway_gid"]) <= 0):
        raise _Blocked("distinct ordinary gateway and target identities differ from the handoff")
    target_pub = _hex(payload["target_pub"], 32, "target key")
    return _Plan(directory, signer, payload, H(canon(record)).hex(), target_pub)


def _proc_identity(pid):
    state, _, ticks = _process_fields(Path(f"/proc/{pid}/stat").read_text())
    return state, ticks


def _ready(plan, *, target_pid, target_start_ticks, target_state, inventory, effect_count):
    ready = _json(inventory, 16384)
    pins = plan.payload
    if (type(target_pid) is not int or not 0 < target_pid < (1 << 31)
            or type(ready) is not dict or ready.keys() != _READY_FIELDS
            or type(ready["effect_count"]) is not int or ready["effect_count"] != effect_count
            or ready["outcome"] != "READY" or ready["pid"] != target_pid
            or ready["target_uid"] != pins["target_uid"] or ready["gateway_uid"] != pins["gateway_uid"]
            or ready["target_pub"] != pins["target_pub"]
            or ready["source_revision"] != pins["source_revision"]):
        raise _Blocked("owner ready record differs from the pinned trial phase")
    owner_state = Path(target_state).absolute()
    entry = owner_state.lstat()
    visible = {
        "state_device": str(entry.st_dev), "state_inode": str(entry.st_ino),
        "state_mode": stat.S_IMODE(entry.st_mode),
    }
    declared = pins["target_state"]
    if (not stat.S_ISDIR(entry.st_mode)
            or entry.st_uid != pins["target_uid"]
            or canon({field: declared[field] for field in visible}) != canon(visible)):
        raise _Blocked("target state directory differs from the provisioned identity")
    signed = _check_inventory(ready["inventory_v2"], plan.target_pub, {
        "target_pid": target_pid, "target_uid": pins["target_uid"], "uid": pins["gateway_uid"],
        "target_start_ticks": str(target_start_ticks),
    }, entry)
    if signed["type"] != _INVENTORY_V2_TYPE:
        raise _Blocked("current signed target inventory V2 is required")
    if any(signed[field] != declared[field] for field in ("key_mode", "ledger_mode")):
        raise _Blocked("signed target file modes differ from the handoff")
    return ready, owner_state, entry


def _ordinary_gateway():
    return (sys.platform.startswith("linux") and hasattr(os, "pidfd_open")
            and hasattr(os, "geteuid") and os.geteuid() > 0)


def _require_live(pid, ticks, poller):
    state, current = _proc_identity(pid)
    if poller.poll(0) or state in {"Z", "X", "x"} or current != ticks:
        raise _Blocked("pinned target process changed during the trial")


def _journal_phase(path):
    EffectGateway._check_private(path.lstat(), directory=False)
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        packet, digest, state, outcome, receipt = db.execute("""
            SELECT packet, dispatch_sha256, state, outcome, receipt FROM intent WHERE slot = 1
        """).fetchone()
    if (H(packet).hex() != digest or state not in {"PENDING", "TERMINAL"}
            or (state == "PENDING" and (outcome is not None or receipt is not None))
            or (state == "TERMINAL" and (outcome != "ACCEPTED_EVIDENCED" or type(receipt) is not bytes))):
        raise _Blocked("gateway intent journal does not match the trial")
    return {
        "state": state, "dispatch_sha256": digest, "outcome": outcome,
        "receipt_sha256": H(receipt).hex() if receipt is not None else None,
    }


def _accepted(plan, response, digest):
    if (type(response) is not dict or response.keys() != {"outcome", "receipt"}
            or response["outcome"] != "ACCEPTED_EVIDENCED"):
        raise _Blocked("target returned no accepted signed receipt")
    payload = verify_receipt(response["receipt"], target_pub=plan.target_pub, scope=plan.scope,
                             dispatch_sha256=digest)
    if payload["outcome"] != response["outcome"]:
        raise _Blocked("target response differs from its signed receipt")
    return response["receipt"]


def _gateway(plan, transport):
    return EffectGateway(plan.journal, signer=plan.signer, scope=plan.scope,
                         target_pub=plan.target_pub, transport=transport)


def _prepared_packet(plan):
    packet = sign_dispatch(plan.signer, scope=plan.scope, **plan.attachments)
    _encode_request("dispatch", packet)
    return packet


def _dispatch(plan, *, pid, ticks, target_inventory, transport, custody):
    if os.path.lexists(plan.journal) or os.path.lexists(plan.capture):
        raise _Blocked("dispatch requires a new gateway journal and capture")
    calls = []
    observed = None

    def lose_reply(action, packet):
        nonlocal observed
        if calls or action != "dispatch":
            raise _Blocked("unexpected gateway transport action")
        calls.append(action)
        digest = dispatch_digest(packet)
        journal = _journal_phase(plan.journal)
        if journal["state"] != "PENDING" or journal["dispatch_sha256"] != digest:
            raise _Blocked("gateway did not persist the exact dispatch before transport")
        receipt = _accepted(plan, transport(action, packet), digest)
        _write_new(plan.capture, {
            "schema": _CAPTURE, "handoff_sha256": plan.handoff_sha256, "target_pid": pid,
            "target_start_ticks": ticks, "dispatch_sha256": digest, "receipt": receipt,
            "source_revision": plan.payload["source_revision"], "target_inventory": target_inventory,
        })
        observed = receipt
        raise TimeoutError("synthetic withholding of an observed reply")

    with _gateway(plan, lose_reply) as gateway:
        first = gateway.dispatch(**plan.attachments)
        replay = gateway.dispatch(**plan.attachments)
    journal = _journal_phase(plan.journal)
    if (first.get("outcome") != "AMBIGUOUS" or replay.get("outcome") != "AMBIGUOUS"
            or journal["state"] != "PENDING" or calls != ["dispatch"]):
        raise _Blocked("gateway did not retain the pending intent without redispatch")
    if observed is None:
        return _result("BLOCKED", "dispatch", custody=custody, rpc_actions=calls, journal=journal,
                       reason="dispatch remains pending without an independently observed signed reply")
    return _result("AMBIGUOUS", "dispatch", custody=custody, rpc_actions=calls, journal=journal,
                   target_pid=pid, reply_withheld=True, replay_without_transport=True,
                   original_receipt_sha256=H(canon(observed)).hex())


def _original(plan, target_pid, target_state_entry, target_inventory):
    record = _json(plan.capture, 65536, private=True)
    if (type(record) is not dict or record.keys() != {
            "schema", "handoff_sha256", "target_pid", "target_start_ticks", "dispatch_sha256", "receipt",
            "source_revision", "target_inventory",
            } or record["schema"] != _CAPTURE or record["handoff_sha256"] != plan.handoff_sha256
            or record["source_revision"] != plan.payload["source_revision"]):
        raise _Blocked("observer record differs from the provisioned handoff")
    old_pid, old_ticks = record["target_pid"], record["target_start_ticks"]
    if (type(old_pid) is not int or not 0 < old_pid < (1 << 31) or old_pid == target_pid
            or type(old_ticks) is not int or old_ticks <= 0):
        raise _Blocked("reconciliation requires a different target process")
    previous = _check_inventory(record["target_inventory"], plan.target_pub, {
        "target_pid": old_pid, "target_uid": plan.payload["target_uid"],
        "uid": plan.payload["gateway_uid"], "target_start_ticks": str(old_ticks),
    }, target_state_entry)
    if (previous["type"] != _INVENTORY_V2_TYPE or any(
            previous[key] != target_inventory["payload"][key] for key in _FILE_IDENTITY)):
        raise _Blocked("target key or ledger identity differs after restart")
    try:
        state, ticks = _proc_identity(old_pid)
    except FileNotFoundError:
        pass
    else:
        if ticks == old_ticks and state not in {"Z", "X", "x"}:
            raise _Blocked("original target process is still running")
    _accepted(plan, {"outcome": "ACCEPTED_EVIDENCED", "receipt": record["receipt"]},
              record["dispatch_sha256"])
    return record


def _reconcile(plan, *, pid, target_state_entry, target_inventory, transport, custody):
    original = _original(plan, pid, target_state_entry, target_inventory)
    digest = original["dispatch_sha256"]
    if _journal_phase(plan.journal)["dispatch_sha256"] != digest:
        raise _Blocked("pending intent differs from the observed dispatch")
    calls = []

    def reconcile_only(action, packet):
        if calls or action != "reconcile":
            raise _Blocked("unexpected gateway transport action")
        calls.append(action)
        response = transport(action, packet)
        if canon(_accepted(plan, response, digest)) != canon(original["receipt"]):
            raise _Blocked("restarted target did not return the exact original receipt")
        return response

    with _gateway(plan, reconcile_only) as gateway:
        before = gateway.dispatch(**plan.attachments)
        if before.get("outcome") != "AMBIGUOUS" or calls:
            raise _Blocked("existing intent did not stay pending before reconciliation")
        recovered = gateway.reconcile()
        repeated = gateway.reconcile()
        replay = gateway.dispatch(**plan.attachments)
    confirmed = {
        "outcome": "ACCEPTED_EVIDENCED", "receipt": original["receipt"], "dispatch_sha256": digest,
    }
    journal = _journal_phase(plan.journal)
    if (calls != ["reconcile"] or any(canon(value) != canon(confirmed)
                                      for value in (recovered, repeated, replay))
            or journal["state"] != "TERMINAL"
            or journal["receipt_sha256"] != H(canon(original["receipt"])).hex()):
        raise _Blocked("gateway did not retain and replay the exact original receipt")
    return _result("CONDITIONAL", "reconcile", custody=custody, rpc_actions=calls, journal=journal,
                   original_target_pid=original["target_pid"], target_pid=pid,
                   original_receipt_matched=True, replay_without_transport=True,
                   same_target_file_identity=True, original_target_inventory=original["target_inventory"],
                   receipt=original["receipt"])


def run_trial(action, *, handoff, gateway_state, owner_pub, target_pid=None,
              target_state=None, inventory=None):
    """Run the named phase using only operator-supplied provisioned references."""
    if not _ordinary_gateway():
        return _result("UNSUPPORTED", action, custody="UNSUPPORTED", reason="ordinary Linux gateway required")
    custody = "BLOCKED"
    try:
        plan = _plan(gateway_state, handoff, owner_pub)
        if action == "prepare":
            return _prepared_packet(plan)
        if action not in {"dispatch", "reconcile"}:
            raise _Blocked("unknown gateway trial phase")
        _prepared_packet(plan)
        revision = source_revision()
        if revision != plan.payload["source_revision"]:
            raise _Blocked("gateway checkout differs from the signed handoff revision")
        if type(target_pid) is not int or not 0 < target_pid < (1 << 31):
            raise _Blocked("external target PID is required")
        with closing(_LiveTarget(target_pid)) as live:
            ready, owner_state, target_entry = _ready(
                plan, target_pid=target_pid, target_start_ticks=live.ticks, target_state=target_state,
                inventory=inventory, effect_count=int(action == "reconcile"),
            )
            observation = probe(
                plan.payload["target_uid"], target_pid=target_pid, state_dir=owner_state,
                socket_path=plan.payload["socket_path"], inventory=ready["inventory_v2"],
                target_pub=plan.target_pub,
            )
            custody = observation.get("custody", "BLOCKED")
            if observation.get("outcome") != "MEASURED_CANDIDATE" or custody != "MEASURED_CANDIDATE":
                return _result("UNSUPPORTED" if custody == "UNSUPPORTED" else "BLOCKED", action,
                               custody="UNSUPPORTED" if custody == "UNSUPPORTED" else "BLOCKED",
                               custody_probe=observation, reason="candidate custody probe did not qualify")
            if (observation.get("target_gid") != plan.payload["target_gid"]
                    or observation.get("gid") != plan.payload["gateway_gid"]
                    or observation.get("target_uid") != plan.payload["target_uid"]
                    or observation.get("target_pid") != target_pid
                    or observation.get("target_start_ticks") != str(live.ticks)
                    or observation.get("uid") != plan.payload["gateway_uid"]):
                raise _Blocked("measured principal identities differ from the handoff")
            live.require()

            def transport(rpc, packet):
                live.require()
                reply = request(plan.payload["socket_path"], rpc, packet,
                                expected_target_uid=plan.payload["target_uid"], expected_target_pid=target_pid)
                live.require()
                return reply

            if action == "dispatch":
                result = _dispatch(plan, pid=target_pid, ticks=live.ticks, target_inventory=ready["inventory_v2"],
                                   transport=transport, custody=custody)
            else:
                result = _reconcile(plan, pid=target_pid, target_state_entry=target_entry,
                                    target_inventory=ready["inventory_v2"], transport=transport, custody=custody)
            return {**result, "source_revision": revision, "custody_probe": observation,
                    "target_inventory": ready["inventory_v2"],
                    "owner_ready_effect_count": ready["effect_count"],
                    "owner_ready_basis": "OPERATOR_SUPPLIED_OWNER_READY_STATUS"}
    except _Blocked as exc:
        return _result("BLOCKED", action, custody=custody, reason=str(exc))
    except (ImportError, OSError, NotImplementedError, TypeError, ValueError, RuntimeError, KeyError, sqlite3.Error):
        return _result("BLOCKED", action, custody=custody, reason="required gateway trial reference is unavailable")


class _LiveTarget:
    """Tie the peer PID pin to one kernel process lifetime during the phase."""

    def __init__(self, pid):
        self.pid = pid
        self.fd = os.pidfd_open(pid)
        try:
            self.poller = select.poll()
            self.poller.register(self.fd, select.POLLIN)
            _, self.ticks = _proc_identity(pid)
            self.require()
        except BaseException:
            self.close()
            raise

    def require(self):
        _require_live(self.pid, self.ticks, self.poller)

    def close(self):
        os.close(self.fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("prepare", "dispatch", "reconcile"):
        command = commands.add_parser(action)
        command.add_argument("--handoff", type=Path, required=True)
        command.add_argument("--gateway-state", type=Path, required=True)
        command.add_argument("--owner-pub", required=True)
        if action != "prepare":
            command.add_argument("--target-pid", type=int, required=True)
            command.add_argument("--target-state", type=Path, required=True)
            command.add_argument("--inventory", type=Path, required=True)
    arguments = vars(parser.parse_args(argv))
    action = arguments.pop("action")
    try:
        arguments["owner_pub"] = _hex(arguments["owner_pub"], 32, "external owner key")
        result = run_trial(action, **arguments)
    except (TypeError, ValueError):
        result = _result("BLOCKED", action, custody="BLOCKED", reason="invalid external owner key")
    print(json.dumps(result, sort_keys=True))
    if action == "prepare" and result.keys() == {"route", "qualification", "grant"}:
        return 0
    return 0 if result.get("outcome") in {"AMBIGUOUS", "CONDITIONAL"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
