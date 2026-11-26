"""Private lab role entry points and single-host control-plane processes."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import time
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shirudo_adapter.model import AdapterError, digest
from shirudo_adapter.receipt import sign_record, verify_record
from shirudo_adapter.action_gate_cli import serve, _denied, _dispatch
from research.blackout import reader
from research.wt_swarm.roles import emit
from research.schism.storage import (
    demand,
    administer,
    attach,
    FencedGate,
    guard,
    PERMIT,
    TRANSITION,
    STAMP,
)


def barrier():
    emit({"phase": "writer_held", "ns": time.monotonic_ns()})
    if input() != "release":
        raise RuntimeError("controller disconnected")


def key_for(path):
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def main():
    role = sys.argv[1]
    if role == "issuer":
        key = Ed25519PrivateKey.generate()
        emit(key.public_key().public_bytes_raw().hex())
        for command in sys.stdin:
            payload = json.loads(command)
            if payload["schema"] not in (PERMIT, TRANSITION):
                raise ValueError("issuer role")
            emit(sign_record(key, payload))
        return
    args = json.loads(Path(sys.argv[2]).read_bytes())
    paths = {k: Path(v) for k, v in args["paths"].items()}
    pins = args["pins"]
    if role == "reader":
        paths["target"] = Path("/journal/journal.sqlite3")

        class RecoveryConnection(sqlite3.Connection):
            verified_versions = None
            verified_operations = None

        def connect(path):
            con = reader.database(path, RecoveryConnection)
            try:
                attach(con, paths, pins, "ro", "ro")
            except (OSError, sqlite3.Error, AdapterError):
                # guard rechecks the snapshot before any definitive outcome.
                pass
            return con

        def check(con, b):
            con.execute("SELECT hash FROM main.schism_tag").fetchone()
            versions = tuple(
                con.execute(f"PRAGMA {db}.data_version").fetchone()[0]
                for db in ("main", "control", "witness")
            )
            guard(con, paths, pins, full=con.verified_versions != versions)
            if con.verified_versions != versions:
                con.verified_operations = set()
            con.verified_versions = versions
            if b["operation_id"] in con.verified_operations:
                return
            effect = con.execute(
                "SELECT record FROM witness.events WHERE operation=?",
                (b["operation_id"],),
            ).fetchone()
            row = con.execute(
                "SELECT status,receipt FROM main.operations WHERE id=?",
                (b["operation_id"],),
            ).fetchone()
            if row and row[0] == "COMMITTED":
                demand(effect is not None, "MISSING_ENDORSEMENT")
                record = json.loads(effect[0])
                epoch = record["payload"]["epoch"]
                transition = con.execute(
                    "SELECT record FROM control.transitions WHERE epoch=?", (epoch,)
                ).fetchone()
                permit = con.execute(
                    "SELECT record FROM control.permits WHERE op=?",
                    (b["operation_id"],),
                ).fetchone()
                demand(transition and permit, "EFFECT_AUTHORITY")
                transition = json.loads(transition[0])
                permit = json.loads(permit[0])
                holder = verify_record(transition, pins["issuer"])["executor"]
                signed = verify_record(record, holder)
                expected = dict(
                    schema=PERMIT,
                    epoch=epoch,
                    head=digest(transition),
                    executor=holder,
                    op=b["operation_id"],
                    gate=pins["gate"],
                    target=pins["target"],
                    request=b["request_sha256"],
                    grant=b["grant_sha256"],
                )
                demand(
                    holder in pins["executors"]
                    and verify_record(permit, pins["issuer"]) == expected
                    and signed
                    == dict(
                        expected,
                        schema=STAMP,
                        permit=digest(permit),
                        receipt=digest(json.loads(row[1])),
                    ),
                    "EFFECT_AUTHORITY",
                )
            else:
                demand(effect is None, "MISSING_EFFECT")
            con.verified_operations.add(b["operation_id"])

        return reader.main(connect, check)
    try:
        if role in ("transition", "register"):
            record = json.loads(input())
            emit({"phase": "attempt", "ns": time.monotonic_ns()})
            trace = (
                (lambda: emit({"phase": "begin_immediate", "ns": time.monotonic_ns()}))
                if "trace" in sys.argv[3:]
                else None
            )
            result = administer(
                paths, pins, record, barrier if "pause" in sys.argv[3:] else None, trace
            )
            emit(result)
        elif role == "inspect":
            with closing(
                sqlite3.connect(
                    paths["target"].as_uri() + "?mode=rw",
                    uri=True,
                    isolation_level=None,
                )
            ) as c:
                attach(c, paths, pins, "rw")
                c.execute("BEGIN IMMEDIATE")
                epoch, head, executor = guard(c, paths, pins)
                emit({"epoch": epoch, "head": head, "executor": executor})
        else:
            state = Path(sys.argv[3])
            gate = FencedGate(state, paths, pins, key_for(Path(sys.argv[4])))
            if role == "serve":
                if "pause" in sys.argv[6:]:
                    gate._before_commit = barrier
                if "trace" in sys.argv[6:]:
                    log = open(
                        Path(sys.argv[5]).parent / "decisions.jsonl", "x", buffering=1
                    )
                    mon = sys.monitoring
                    mon.use_tool_id(mon.PROFILER_ID, "Schism admission")
                    log_lock = threading.Lock()

                    def observed(code, offset, value):
                        label = value.get("reason") or value.get("result")
                        if isinstance(label, str):
                            with log_lock:
                                log.write(
                                    json.dumps([time.monotonic_ns(), label]) + "\n"
                                )

                    mon.register_callback(
                        mon.PROFILER_ID, mon.events.PY_RETURN, observed
                    )
                    for func in (_denied, _dispatch):
                        mon.set_local_events(
                            mon.PROFILER_ID, func.__code__, mon.events.PY_RETURN
                        )
                serve(gate, Path(sys.argv[5]), replace_stale=True)
            elif role == "revoke":
                gate.revoke_grant(sys.argv[5])
                emit({"status": "REVOKED"})
            elif role == "probe":
                emit(gate.execute(json.loads(input())))
            else:
                raise ValueError("unknown role")
    except AdapterError as exc:
        emit({"status": "DENIED", "reason": exc.code})


if __name__ == "__main__":
    main()
