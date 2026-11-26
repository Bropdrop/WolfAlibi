"""Keyless lab coordinator retaining its local claim and one frozen request."""

import json
import os
from pathlib import Path
import sys
import time
from research.wt_swarm.client import SOCKET, emit
from shirudo_adapter.action_gate_cli import request
from shirudo_adapter.model import digest


def main():
    state = Path("/queue/pending.json")
    if not state.exists():
        state.write_text(json.dumps(json.loads(input()), sort_keys=True))
    pending = json.loads(state.read_bytes())
    emit(
        dict(
            claim="LEADER",
            coordinator=pending["name"],
            claimed_epoch=pending["epoch"],
            request=digest(pending["request"]),
            ready_ns=time.monotonic_ns(),
            mount=os.readlink("/proc/self/ns/mnt"),
            pidns=os.readlink("/proc/self/ns/pid"),
            socket_readonly=bool(os.statvfs(SOCKET.parent).f_flag & os.ST_RDONLY),
        )
    )
    for command in sys.stdin:
        if command.strip() != "submit":
            return
        emit(request(SOCKET, dict(op="execute", request=pending["request"]))[0])


if __name__ == "__main__":
    main()
