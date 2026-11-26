"""Independently enrolled loopback signers for the disposable counter trial."""

import hashlib
import json
import socket
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.sovereign.cluster import tls
from research.wt_swarm.roles import emit
from shirudo_adapter.model import canonical_json
from shirudo_adapter.receipt import sign_record
from tests.test_action_gate import GateFixture


def serve(identity, handle, controller):
    context = tls(Path("/identity"), True)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        emit(dict(port=listener.getsockname()[1], identity=identity))
        while True:
            raw, _ = listener.accept()
            try:
                with (
                    raw,
                    context.wrap_socket(raw, server_side=True) as peer,
                    peer.makefile("rb") as stream,
                ):
                    peer.settimeout(5)
                    if (
                        hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()
                        != controller
                    ):
                        continue
                    request = stream.readline(65537)
                    if len(request) > 65536 or not request.endswith(b"\n"):
                        continue
                    peer.sendall(canonical_json(handle(json.loads(request))) + b"\n")
            except (OSError, ValueError, KeyError):
                continue


def main():
    role, controller = sys.argv[1:]
    if role == "verifier":
        with tempfile.TemporaryDirectory() as temp:
            fixture = GateFixture(Path(temp) / "v")
            identity = dict(
                policy=fixture.policy,
                key=fixture.trust["verifier_public_key"],
                instance=fixture.verifier_instance_id,
            )

            def assess(command):
                if command == "collect":
                    fixture.now = time.time_ns() // 1000000
                    return fixture.challenge()
                return fixture.assessment(command)

            serve(identity, assess, controller)
        return
    k = Ed25519PrivateKey.generate()
    allowed = {
        "owner": {
            "wolfalibi.sovereign.order.v1",
            "wolfalibi.resurrection.activation.v1",
            "wolfalibi.sovereign.permit.v1",
            "wolfalibi.sovereign.recover.v1",
            "wolfalibi.shirudo.action-grant.v1",
        },
        "executor": {"wolfalibi.sovereign.submit.v1"},
    }[role]

    def endorse(doc):
        if doc["schema"] not in allowed:
            raise ValueError("signing domain")
        return sign_record(k, doc)

    serve(k.public_key().public_bytes_raw().hex(), endorse, controller)


if __name__ == "__main__":
    main()
