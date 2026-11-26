"""mTLS loopback interface for the stationary lab target."""

from concurrent.futures import ThreadPoolExecutor
import hashlib, json, socket, ssl, sys, threading, time
from pathlib import Path
from research.sovereign.cluster import tls
from research.sovereign.target import Stationary
from shirudo_adapter.model import AdapterError, canonical_json


class Session:
    def __init__(self, port, ctx, raw=None):
        if raw is None:
            raw = socket.create_connection(("127.0.0.1", port), timeout=6)
        self.peer = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        if (
            hashlib.sha256(self.peer.getpeercert(binary_form=True)).hexdigest()
            != ctx.endpoint
        ):
            self.peer.close()
            raise ValueError("target TLS identity")
        self.stream = self.peer.makefile("rb")

    def call(self, body):
        self.peer.sendall(canonical_json(body) + b"\n")
        response = self.stream.readline(131072)
        if not response:
            raise ConnectionError("No acknowledgement")
        return json.loads(response)

    def close(self):
        self.stream.close()
        self.peer.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def serve(factory=Stationary):
    config = json.loads(Path("/public.json").read_bytes())
    context = tls(Path("/identity"))
    context.member_pins = config["member_pins"]
    context.token = Path("/token").read_text()
    gate = factory(Path("/state"), config, context)
    release = threading.Event()

    def held():
        gate._before_commit = None
        print(
            json.dumps(dict(event="native_writer_held", ns=time.monotonic_ns())),
            flush=True,
        )
        if not release.wait(12):
            raise RuntimeError("test barrier expired")

    def control():
        for cmd in sys.stdin:
            if cmd.strip() == "arm":
                release.clear()
                gate._before_commit = held
                print(json.dumps(dict(event="armed")), flush=True)
            elif cmd.strip() == "arm-reservation" and hasattr(gate, "activate"):
                release.clear()
                gate.reservation_hook = held
                print(json.dumps(dict(event="reservation-armed")), flush=True)
            elif cmd.startswith("{") and hasattr(gate, "activate"):
                try:
                    reply = gate.activate(json.loads(cmd))
                except (
                    AdapterError,
                    ValueError,
                    KeyError,
                    OSError,
                    RuntimeError,
                ) as exc:
                    reply = dict(
                        state="RECOVERY_UNRESOLVED",
                        reason=getattr(exc, "code", type(exc).__name__),
                    )
                print(json.dumps(reply), flush=True)
            elif cmd.strip() == "release":
                release.set()

    threading.Thread(target=control, daemon=True).start()
    server = tls(Path("/identity"), True)
    limit = threading.BoundedSemaphore(4)

    def handle(raw):
        try:
            raw.settimeout(10)
            with (
                raw,
                server.wrap_socket(raw, server_side=True) as peer,
                peer.makefile("rb") as stream,
            ):
                who = hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()
                expires = ssl.cert_time_to_seconds(peer.getpeercert()["notAfter"])
                for _ in range(30000):
                    data = stream.readline(65537)
                    if (
                        not data
                        or len(data) > 65536
                        or not data.endswith(b"\n")
                        or time.time() >= expires
                    ):
                        return
                    body = json.loads(data)
                    try:
                        op = body["op"]
                        if op == "execute":
                            result = gate.submit(body["frame"], who)
                        elif op == "recover":
                            result = gate.recover(body["binding"], who)
                        elif op == "enroll" and who == config["preparer"]:
                            result = gate.enroll(body["frame"], body["binding"])
                        elif op == "sync":
                            result = gate.synchronize()
                        elif op == "prepare" and who == config["preparer"]:
                            result = gate.prepare(body["challenge"])
                        else:
                            result = {"state": "DENIED", "reason": "ROLE"}
                    except AdapterError as exc:
                        result = {
                            "state": "DENIED" if op != "recover" else "UNRESOLVED",
                            "reason": exc.code,
                        }
                    peer.sendall(canonical_json(result) + b"\n")
        except (ValueError, OSError, KeyError, ConnectionError):
            pass
        finally:
            limit.release()

    with socket.socket() as s, ThreadPoolExecutor(max_workers=4) as pool:
        s.bind(("127.0.0.1", 0))
        s.listen(256)
        print(json.dumps(dict(port=s.getsockname()[1], boot=gate.boot)), flush=True)
        while True:
            raw, _ = s.accept()
            if limit.acquire(False):
                pool.submit(handle, raw)
            else:
                raw.close()


if __name__ == "__main__":
    try:
        serve()
    except AdapterError as exc:
        print(json.dumps({"startup": "DENIED", "reason": exc.code}), file=sys.stderr)
        sys.exit(1)
