"""Trusted administrator fixtures for measuring the two SQLite writer orders."""
import json
from pathlib import Path
import select
import sys
import time

from shirudo_adapter.action_gate import Gate
from shirudo_adapter.action_gate_cli import serve


def event(name):
    print(json.dumps({"phase": name, "time_ns": time.monotonic_ns()}), flush=True)


def rendezvous():
    event("writer_held")
    if not select.select([sys.stdin], [], [], 3)[0] or input() != "release":
        raise RuntimeError("trusted controller did not release the writer")


class TracedGate(Gate):
    def _begin(self, connection):
        # Observe SQLite's actual transaction attempt, including a blocked writer.
        def trace(statement):
            if statement == "BEGIN IMMEDIATE":
                event("begin_immediate")
        connection.set_trace_callback(trace)
        return super()._begin(connection)


class HeldRevocation(TracedGate):
    def _begin(self, connection):
        now = super()._begin(connection)
        rendezvous()
        return now


if __name__ == "__main__":
    role, state, arg = sys.argv[1:]
    if role in ("gate", "held-gate"):
        gate = TracedGate(state)
        if role == "held-gate":
            gate._before_commit = rendezvous
        serve(gate, Path(arg), replace_stale=True)
    else:
        gate = (HeldRevocation if role == "held-revoker" else TracedGate)(state)
        event("armed")
        if input() != "start":
            raise ValueError("expected start")
        gate.revoke_grant(arg)
        event("revoked")
