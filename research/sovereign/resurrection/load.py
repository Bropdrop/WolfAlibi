"""Bounded client waves against the recovering and the newly active native service."""

import gzip, json, os, select, signal, socket, threading, time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from research.sovereign.trial import save, sample
from research.blackout.experiment import reader_pid
from research.sovereign.wire import Session
from shirudo_adapter.model import digest

LIMIT = json.loads(Path(__file__).with_name("budgets.json").read_bytes())


def measure(lab):
    def size(directory):
        return sum(f.stat().st_size for f in directory.rglob("*") if f.is_file())

    return dict(
        ns=time.monotonic_ns(),
        target=sample(lab.pid),
        witness=sample(reader_pid(lab.witness)),
        members=[sample(lab.c.pids[i]) for i in range(3)],
        target_bytes=size(lab.state),
        witness_bytes=size(lab.store),
        member_bytes=[size(lab.base / f"m{i}" / "data") for i in range(3)],
    )


def overlap(lab):
    n = LIMIT["attempts"]
    barrier = threading.Barrier(n + 1, timeout=45)
    threading.stack_size(512 * 1024)

    def attempt(i):
        with socket.socket() as raw:
            start = time.monotonic_ns()
            tid = threading.get_native_id()
            raw.setblocking(False)
            raw.connect_ex(("127.0.0.1", lab.port))
            barrier.wait()
            try:
                if not select.select([], [raw], [], 6)[1]:
                    raise TimeoutError("connection")
                raw.settimeout(6)
                with Session(lab.port, lab.ctx["a"], raw) as client:
                    reply = client.call(
                        dict(op="execute", frame=lab.ops["pending"]["frame"])
                    )
                result = reply.get("reason", reply.get("result"))
            except OSError:
                result = "NO_ACK"
            return [tid, start, time.monotonic_ns(), result]

    before = measure(lab)
    with ThreadPoolExecutor(n) as pool:
        os.kill(lab.pid, signal.SIGSTOP)
        try:
            jobs = [pool.submit(attempt, i) for i in range(n)]
            barrier.wait()
        finally:
            os.kill(lab.pid, signal.SIGCONT)
        rows = [f.result() for f in jobs]
    after = measure(lab)
    tally = Counter(r[3] for r in rows)
    assert len({r[0] for r in rows}) == n and max(r[1] for r in rows) <= min(
        r[2] for r in rows
    )
    assert tally["RECOVERY_CLOSED"] > 0 and set(tally) <= {"RECOVERY_CLOSED", "NO_ACK"}
    save(
        lab.out / "overlap.json",
        dict(rows=rows, resources=[before, after], outcomes=tally),
    )


def storm(lab):
    n = LIMIT["sessions"]
    barrier = threading.Barrier(n, timeout=10)
    names = ("new-lost", "revoked", "crash")

    def lane(i):
        docs = {}
        rows = []
        with Session(lab.port, lab.ctx["alice"]) as client:
            barrier.wait()
            for j in range(LIMIT["queries_per_session"]):
                name = names[(i + j) % len(names)]
                start = time.monotonic_ns()
                reply = client.call(
                    dict(op="recover", binding=lab.ops[name]["binding"])
                )
                end = time.monotonic_ns()
                h = digest(reply)
                docs[h] = reply
                rows.append([start, end, name, h])
        with gzip.open(lab.out / f"lane-{i}.json.gz", "wt") as f:
            json.dump(rows, f, separators=(",", ":"))
        save(lab.out / f"proofs-{i}.json", docs)

    before = measure(lab)
    with ThreadPoolExecutor(n) as pool:
        list(pool.map(lane, range(n)))
    after = measure(lab)
    save(lab.out / "storm.json", dict(resources=[before, after]))
