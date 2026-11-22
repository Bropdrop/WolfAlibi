"""Long-lived, local BYOA 002 gateway. Read one operator command per stdin JSON line."""

import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wolfalibi.byoa002_transport import custody, measure_gateway, request
from wolfalibi.solitary_cli import _unique_object


def send(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def main():
    if len(sys.argv) != 2:
        raise ValueError("supply one absolute local socket path")
    path = sys.argv[1]
    try:
        peer = measure_gateway(os.getpid(), path)
    except (OSError, RuntimeError, ValueError):
        send({"outcome": "UNSUPPORTED", "reason": "ordinary Linux process measurements unavailable"})
        return 2
    send({"outcome": "READY", "peer": peer, "socket_path": path})
    while True:
        raw = sys.stdin.buffer.readline(150_001)
        if not raw:
            return 0
        if len(raw) > 150_000 or not raw.endswith(b"\n"):
            send({"outcome": "BLOCKED", "reason": "invalid gateway command framing"})
            return 2
        try:
            fields = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
            action = fields.pop("action")
            if action == "quit" and not fields:
                return 0
            pins = {"expected_target_uid", "expected_target_pid"}
            if action == "custody" and fields.keys() == pins | {"inventory", "target_pub"}:
                result = custody(path, **fields)
            elif action in {"lose-reply", "dispatch", "reconcile"} and fields.keys() == pins | {"packet"}:
                result = request(path, action, **fields)
            else:
                raise ValueError("unsupported gateway command")
        except PermissionError:
            result = {"outcome": "UNSUPPORTED", "reason": "required kernel measurement unavailable"}
        except (KeyError, AttributeError, OSError, TypeError, ValueError, RuntimeError):
            result = {"outcome": "BLOCKED", "reason": "invalid input or unavailable local evidence"}
        send(result)


if __name__ == "__main__":
    raise SystemExit(main())
