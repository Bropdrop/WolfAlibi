"""Four-session read-only TLS fixture. The server is scoped to the local lab socket."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json, socket
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.blackout.credentials import context
from research.blackout.reader import database
from research.continuity.recovery import FrozenRecovery
from research.schism.storage import attach


def main():
    cfg = json.loads(Path("/config.json").read_bytes())
    paths = {k: Path(v) for k, v in cfg["paths"].items()}
    pins = cfg["pins"]
    key = Ed25519PrivateKey.generate()
    reader = FrozenRecovery(cfg["roots"], cfg["package"], key)
    tls = context(True)

    def handle(raw):
        with (
            raw,
            tls.wrap_socket(raw, server_side=True) as peer,
            peer.makefile("rb") as stream,
            closing(database(paths["target"])) as con,
        ):
            attach(con, paths, pins, "ro", "ro")
            for _ in range(25000):
                query = json.loads(stream.readline(16384))
                reply = reader.response(peer, query, con, paths, pins)
                peer.sendall(json.dumps(reply, separators=(",", ":")).encode() + b"\n")

    with (
        socket.socket(socket.AF_UNIX) as sock,
        ThreadPoolExecutor(max_workers=4) as pool,
    ):
        sock.bind("/endpoint/recover.sock")
        sock.listen(4)
        print(
            json.dumps(dict(proof_key=key.public_key().public_bytes_raw().hex())),
            flush=True,
        )
        jobs = [pool.submit(handle, sock.accept()[0]) for _ in range(4)]
        for job in jobs:
            job.result()
        input()


if __name__ == "__main__":
    main()
