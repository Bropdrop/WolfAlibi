"""Recovery-only role. Each TLS connection uses the role's own disposable certificate."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import socket
import sys
import threading
import time

from shirudo_adapter.action_gate import verify_effect_receipt
from shirudo_adapter.model import canonical_json, digest, strict_json, AdapterError
from shirudo_adapter.receipt import verify_record
from research.blackout.credentials import context
from research.blackout.reader import DENIAL, MAX_FRAME, UNKNOWN, locator


def validate(reply, query, binding, pins):
    if reply == DENIAL:
        return "UNRESOLVED"
    if set(reply) != {"proof", "receipt"}:
        raise ValueError("unexpected recovery response")
    payload = verify_record(reply["proof"], pins["proof_key"])
    if (
        binding is None
        or query != locator(binding)
        or any(payload.get(k) != v for k, v in query.items())
        or payload["grant_id"] != binding["grant_id"]
        or payload["schema"] != "wolfalibi.blackout.reconciliation.v1"
        or payload["authority"] != "READ_ONLY"
    ):
        raise ValueError("recovery proof binding")
    state = payload["outcome"]
    if state == "NOT_COMMITTED":
        if type(payload["revoked_at_ms"]) is not int or payload["revoked_at_ms"] <= 0:
            raise ValueError("missing durable revocation")
    elif payload["revoked_at_ms"] is not None:
        raise ValueError("unexpected revocation proof")
    receipt = reply["receipt"]
    if state == "COMMITTED":
        if (
            payload["reason"] != "ORIGINAL_RECEIPT"
            or digest(receipt) != payload["receipt_sha256"]
        ):
            raise ValueError("recovery receipt digest")
        verify_effect_receipt(
            receipt,
            pins["gate_public_key"],
            expected_target=binding["target_id"],
            expected_gate_instance_id=binding["gate_instance_id"],
            expected_operation_id=binding["operation_id"],
            expected_grant_id=binding["grant_id"],
            expected_grant_sha256=binding["grant_sha256"],
            expected_assessment_sha256=binding["assessment_sha256"],
        )
    elif (
        receipt is not None
        or payload["receipt_sha256"] is not None
        or (state, payload["reason"])
        not in {
            ("NOT_COMMITTED", "DURABLE_GRANT_REVOCATION"),
            *(
                ("UNRESOLVED", r)
                for r in (
                    "NO_ROW",
                    "JOURNAL_BINDING",
                    "JOURNAL_IDENTITY",
                    "NO_TERMINAL_EVIDENCE",
                    "JOURNAL_UNAVAILABLE",
                )
            ),
        }
    ):
        raise ValueError("unsupported settlement")
    return state


@contextmanager
def session(tls, pin):
    with socket.socket(socket.AF_UNIX) as raw:
        raw.settimeout(6)
        raw.connect("/endpoint/recover.sock")
        with (
            tls.wrap_socket(raw, server_hostname="reader") as peer,
            peer.makefile("rb") as stream,
        ):
            if hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() != pin:
                raise ValueError("TLS reader pin")
            if stream.readline(32) != b"RECOVERY-READY\n":
                raise ConnectionError("recovery handshake did not complete")

            def query(data):
                peer.sendall(data)
                return strict_json(stream.readline(MAX_FRAME + 1), MAX_FRAME)

            yield query


def main():
    args = json.loads(input())
    tls = context(False)
    pins = args["pins"]
    queries = args["queries"]
    wires = [canonical_json(q) + b"\n" for q in queries]
    workers, rounds = (4, 7500) if sys.argv[1] == "storm" else (1, 1)
    barrier = threading.Barrier(workers, timeout=10)

    def worker(idx):
        rows, proofs, seen = [], {}, set()
        barrier.wait()
        i = 0
        while i < rounds:
            start = time.monotonic_ns()
            try:
                with session(tls, pins["reader"]) as exchange:
                    for _ in range(min(256, rounds - i)):
                        slot = (idx + i) % len(queries)
                        reply = exchange(wires[slot])
                        ref = digest(reply)
                        if (slot, ref) not in seen:
                            proofs[ref] = reply
                            try:
                                if (
                                    reply != DENIAL
                                    and queries[slot].get("principal")
                                    != pins[args["role"]]
                                ):
                                    raise ValueError("cross-principal reply")
                                validate(
                                    reply,
                                    queries[slot],
                                    args["bindings"].get(
                                        queries[slot].get("request_sha256")
                                    ),
                                    pins,
                                )
                            except (AdapterError, KeyError, TypeError, ValueError):
                                # Preserve even an invalid wire reply for independent disclosure review.
                                rows.append(
                                    [
                                        start,
                                        time.monotonic_ns(),
                                        slot,
                                        ref,
                                        "INVALID_REPLY",
                                    ]
                                )
                                i += 1
                                start = time.monotonic_ns()
                                continue
                            seen.add((slot, ref))
                        end = time.monotonic_ns()
                        rows.append([start, end, slot, ref])
                        i += 1
                        start = time.monotonic_ns()
            except (OSError, ValueError, AdapterError) as exc:
                ref = digest(UNKNOWN)
                proofs[ref] = UNKNOWN
                rows.append(
                    [
                        start,
                        time.monotonic_ns(),
                        (idx + i) % len(queries),
                        ref,
                        type(exc).__name__,
                        getattr(exc, "reason", None),
                    ]
                )
                i += 1
        return {"thread": threading.get_native_id(), "rows": rows, "proofs": proofs}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        groups = list(pool.map(worker, range(workers)))
    print(
        json.dumps(
            {
                "groups": groups,
                "native_socket_visible": Path("/endpoint/gate.sock").exists(),
                "journal_visible": Path("/journal/journal.sqlite3").exists(),
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
