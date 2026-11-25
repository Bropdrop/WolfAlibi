"""Keyless clients for a single namespace-local disposable gate socket."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time

from shirudo_adapter.action_gate_cli import (
    MAX_RESPONSE_BYTES, _read_frame, _validate_response, _write_frame, request,
)
from shirudo_adapter.model import AdapterError, canonical_json, digest

SOCKET = Path("/endpoint/gate.sock")


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def send_once(body, *, hold=False, opened=None):
    row = {"start_ns": time.monotonic_ns(), "connected_ns": None, "sent_ns": None}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        if opened is not None:
            opened()
        try:
            # Use the kernel's bounded listen queue. The parent imposes a
            # process deadline including time spent waiting in connect().
            peer.connect(str(SOCKET))
            row["connected_ns"] = time.monotonic_ns()
            deadline = time.monotonic() + 10
            try:
                _write_frame(peer, body, deadline)
                row["sent_ns"] = time.monotonic_ns()
                peer.shutdown(socket.SHUT_WR)
            except BrokenPipeError:
                # A full native busy frame may already be waiting. The usual
                # framing and EOF checks still apply to any claimed denial.
                if hold:
                    raise
            if hold:
                emit({"phase": "sent_before_read", "time_ns": row["sent_ns"]})
                input()  # independent supervisor interrupts this disposable client
            response = _read_frame(peer, MAX_RESPONSE_BYTES, deadline)
            _validate_response(response)
        except (OSError, AdapterError) as exc:
            row["transport_error"] = type(exc).__name__
            response = {"status": "AMBIGUOUS", "reason": "TRANSPORT_LOST"}
    row.update(end_ns=time.monotonic_ns(), outcome=response.get("result", response.get("status")),
               reason=response.get("reason"))
    if "receipt" in response:
        row["receipt_sha256"] = digest(response["receipt"])
    return row


def batch(kind, documents):
    workers, rounds = {"contention": (1000, 1), "duplicates": (2, 1), "overload": (64, 156)}[kind]
    release = {}
    def open_barrier():
        release["ns"] = time.monotonic_ns()
    barrier = threading.Barrier(workers, action=open_barrier, timeout=40)
    bodies = [canonical_json({"op": "execute", "request": doc}) for doc in documents]
    threading.stack_size(512 * 1024)

    started = 0
    started_lock = threading.Lock()
    def socket_opened():
        nonlocal started
        with started_lock:
            started += 1
            if started == workers:
                emit({"phase": "all_sockets_open", "count": started, "ns": time.monotonic_ns()})

    def worker(index):
        tid = threading.get_native_id()
        ready = time.monotonic_ns()
        barrier.wait()
        rows = []
        count = rounds + int(kind == "overload" and index < 16)
        for iteration in range(count):
            slot = (index + iteration) % len(bodies)
            row = send_once(bodies[slot], opened=socket_opened if kind == "contention" else None)
            row.update(worker=index, tid=tid, ready_ns=ready, iteration=iteration, slot=slot)
            rows.append(row)
        return rows

    with ThreadPoolExecutor(max_workers=workers) as pool:
        groups = list(pool.map(worker, range(workers)))
    emit({"release_ns": release["ns"], "workers": workers, "request_ids":
          [r["operation_id"] for r in documents], "rows": [r for group in groups for r in group]})


if __name__ == "__main__":
    mode = sys.argv[1]
    data = json.loads(input())
    if mode in ("contention", "duplicates", "overload"):
        batch(mode, data)
    elif mode == "hold":
        send_once(canonical_json(data), hold=True)
    elif mode == "rpc":
        emit(request(SOCKET, data)[0])
    elif mode == "custody":
        emit({"owner_state_visible": Path("/tmp/lab-owner").exists(),
              "host_gate_state_visible": Path(data["state"]).exists(),
              "fixture_verifier_file_visible": Path("/tmp/fixture").exists(),
              "socket_mount_read_only": bool(os.statvfs("/endpoint").f_flag & os.ST_RDONLY),
              "pid_namespace": os.readlink("/proc/self/ns/pid"),
              "mount_namespace": os.readlink("/proc/self/ns/mnt")})
    elif mode == "votes":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from shirudo_adapter.receipt import sign_record
        # Independent opinions about one operation, with no owner signature.
        votes = []
        for _ in range(3):
            key = Ed25519PrivateKey.generate()
            vote = sign_record(key, {"operation_id": data["operation_id"], "approve": True})
            votes.append({"public_key": key.public_key().public_bytes_raw().hex(), "vote": vote})
        doc = {"op": "execute", "request": dict(data, grant={"votes": votes})}
        emit({"votes": votes, "reply": request(SOCKET, doc)[0]})
    else:
        raise ValueError("unknown lab client")
