"""One-operation partition fixture. The supervisor alone controls release."""

from pathlib import Path
import socket
import sys
import time

from research.wt_swarm.roles import emit
from shirudo_adapter.action_gate_cli import _read_frame, request, MAX_REQUEST_BYTES
from shirudo_adapter.model import digest


def main():
    path, native, mode, expected = sys.argv[1:]
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        listener.listen(1)
        emit("ready")
        client, _ = listener.accept()
        with client:
            doc = _read_frame(client, MAX_REQUEST_BYTES, time.monotonic() + 10)
            if doc["op"] != "execute" or digest(doc["request"]) != expected:
                raise ValueError("partition fixture scope")
            if mode == "delay":
                client.close()
                emit(
                    {
                        "phase": "buffered_disconnected",
                        "ns": time.monotonic_ns(),
                        "digest": expected,
                    }
                )
                if input() != "deliver":
                    raise ValueError("expected delivery")
            result = request(Path(native), doc)[0]
            emit({"phase": "delivered", "ns": time.monotonic_ns(), "reply": result})
            if mode == "drop_after" and input() != "disconnect":
                raise ValueError("expected disconnect")


if __name__ == "__main__":
    main()
