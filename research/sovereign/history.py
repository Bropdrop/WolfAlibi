"""Separate, read-only historical endpoint for a trusted observer's frozen evidence."""

import hashlib
import json
import socket
import ssl
import sys
import tempfile
import time
from pathlib import Path

from research.sovereign.cluster import tls
from research.sovereign.review import inspect
from research.sovereign.wire import Session
from research.wt_swarm.run import line, send, stop
from shirudo_adapter.model import canonical_json

FILES = ("enrollment", "oracle", "quorum-audit", "materials")


def historical_trial(lab):
    from research.sovereign.trial import box, save

    # Observer captures bytes from its own directory and its independent target
    # SQL snapshot. Transport these bytes over a private pipe, with no database mount.
    captured = {n: (lab.out / (n + ".json")).read_bytes() for n in FILES}
    pins = {n: hashlib.sha256(b).hexdigest() for n, b in captured.items()}
    assert pins == json.loads((lab.out / "observer-pins.json").read_bytes())
    process = lab.spawn(
        box("history", [("--ro-bind", lab.base / "history", "/identity")], True)
        + [json.dumps(pins)]
    )
    send(process, {k: v.decode() for k, v in captured.items()})
    port = line(process)["port"]
    stop(lab.proc)
    observed = {}
    for role, name in (
        ("alice", "lost"),
        ("bob", "lost"),
        ("alice", "pending"),
        ("alice", "revoked"),
    ):
        ctx = tls(lab.base / role)
        ctx.endpoint = lab.cert["history"]
        with Session(port, ctx) as session:
            observed[f"{role}/{name}"] = session.call(lab.ops[name]["binding"])
    assert observed["alice/lost"] == dict(
        state="COMMITTED", receipt=lab.replies["retry"]["receipt"]
    )
    assert observed["bob/lost"] == dict(state="UNRESOLVED")
    assert observed["alice/pending"] == dict(state="UNRESOLVED")
    assert observed["alice/revoked"] == dict(state="NOT_COMMITTED")
    save(lab.out / "historical.json", observed)


def serve():
    from research.wt_swarm.review import require

    pins = json.loads(sys.argv[1])
    data = json.loads(sys.stdin.readline())
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for name in FILES:
            value = data[name].encode()
            require(hashlib.sha256(value).hexdigest() == pins[name], "OBSERVER_PIN")
            (root / (name + ".json")).write_bytes(value)
        _, expected, receipts = inspect(root, pins["enrollment"])
        materials = json.loads(data["materials"])
    bindings = {canonical_json(m["binding"]): name for name, m in materials.items()}
    ctx = tls(Path("/identity"), True)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        print(json.dumps(dict(port=listener.getsockname()[1])), flush=True)
        while True:
            raw, _ = listener.accept()
            try:
                raw.settimeout(5)
                with (
                    raw,
                    ctx.wrap_socket(raw, server_side=True) as peer,
                    peer.makefile("rb") as stream,
                ):
                    who = hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()
                    request = stream.readline(65537)
                    if len(request) > 65536 or not request.endswith(b"\n"):
                        continue
                    binding = json.loads(request)
                    name = bindings.get(canonical_json(binding))
                    reply = dict(state="UNRESOLVED")
                    if (
                        name
                        and binding["payload"]["principal"] == who
                        and time.time()
                        < ssl.cert_time_to_seconds(peer.getpeercert()["notAfter"])
                    ):
                        reply = dict(state=expected[name])
                        if name in receipts:
                            reply["receipt"] = receipts[name]
                    peer.sendall(canonical_json(reply) + b"\n")
            except (OSError, ValueError, KeyError):
                continue


if __name__ == "__main__":
    serve()
