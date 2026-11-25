"""Record native Python function returns without replacing gate code (Python 3.12+)."""
import json
from pathlib import Path
import sys
import threading
import time

from shirudo_adapter.action_gate import Gate
from shirudo_adapter.action_gate_cli import _denied, _dispatch, serve


def main():
    state, sock, trace = map(Path, sys.argv[1:])
    lock = threading.Lock()
    monitor = sys.monitoring
    tool = monitor.PROFILER_ID
    monitor.use_tool_id(tool, "WT-SWARM-001")
    with trace.open("x", buffering=1) as stream:
        def returned(code, offset, value):
            if value.get("status") == "STATUS":
                return
            row = {"ns": time.monotonic_ns(), "thread": threading.get_native_id(),
                   "at": code.co_name, "decision": value.get("result") or value.get("reason")}
            with lock:
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        monitor.register_callback(tool, monitor.events.PY_RETURN, returned)
        for function in (_denied, _dispatch):
            monitor.set_local_events(tool, function.__code__, monitor.events.PY_RETURN)
        try:
            serve(Gate(state), sock, replace_stale=True)
        finally:
            monitor.free_tool_id(tool)


if __name__ == "__main__":
    main()
