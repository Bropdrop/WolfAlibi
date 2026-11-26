from concurrent.futures import ThreadPoolExecutor
import json
import ssl
import socket
from contextlib import closing
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.blackout.reader import database, locator, DENIAL
from research.schism.storage import attach
from research.continuity.recovery import FrozenRecovery
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import verify_record


def probe(directory, paths, pins, roots, package, acl, requests):
    key = Ed25519PrivateKey.generate()
    reader = FrozenRecovery(roots, package, key)

    def context(role):
        d = directory / role
        ctx = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER if role == "reader" else ssl.PROTOCOL_TLS_CLIENT
        )
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=d / "ca.pem")
        ctx.load_cert_chain(d / "cert.pem", d / "key.pem")
        return ctx

    out = []
    for role, req, expected in (
        ("alice", requests[0], "COMMITTED"),
        ("alice", requests[1], "UNRESOLVED"),
        ("alice", requests[2], "NOT_COMMITTED"),
        ("bob", requests[0], "DENIED"),
    ):
        a, b = socket.socketpair()
        query = locator(acl[digest(req)])

        def serve():
            with (
                context("reader").wrap_socket(a, server_side=True) as peer,
                peer.makefile("rb") as stream,
                closing(database(paths["target"])) as con,
            ):
                attach(con, paths, pins, "ro", "ro")
                result = reader.response(
                    peer, json.loads(stream.readline(16384)), con, paths, pins
                )
                peer.sendall(json.dumps(result).encode() + b"\n")

        with ThreadPoolExecutor(max_workers=1) as pool:
            task = pool.submit(serve)
            with (
                context(role).wrap_socket(b, server_hostname="reader") as client,
                client.makefile("rb") as stream,
            ):
                client.sendall(json.dumps(query).encode() + b"\n")
                result = json.loads(stream.readline())
            task.result()
        if expected == "DENIED":
            assert result == DENIAL
        else:
            payload = verify_record(
                result["proof"], key.public_key().public_bytes_raw().hex()
            )
            assert payload["outcome"] == expected
            if expected == "COMMITTED":
                assert result["receipt"] == json.loads(
                    reader.history[req["operation_id"]]["receipt"]
                )
            else:
                assert result["receipt"] is None
        out.append(dict(role=role, expected=expected, result=result))
    return dict(proof_key=key.public_key().public_bytes_raw().hex(), observations=out)
