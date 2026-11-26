"""Fixed local workloads. Raw durations use monotonic nanoseconds."""

import gzip
import json
import os
import signal
import select
from pathlib import Path
import socket
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import sqlite3
from research.sovereign.cluster import read
from research.sovereign.target import seal
from research.sovereign.trial import sample, save
from research.sovereign.wire import Session
from shirudo_adapter.model import digest


def stress(lab):
    budget = json.loads(Path(__file__).with_name("budgets.json").read_bytes())
    n = budget["overlap_workers"]
    lab.material("mass", "b")
    gate = threading.Barrier(n + 1, timeout=45)

    def attempt(i):
        begin = time.monotonic_ns()
        tid = threading.get_native_id()
        answered = None
        with socket.socket() as raw:
            raw.setblocking(False)
            raw.connect_ex(("127.0.0.1", lab.port))
            gate.wait()
            try:
                if not select.select([], [raw], [], 6)[1]:
                    raise TimeoutError("admission")
                raw.settimeout(6)
                with Session(lab.port, lab.ctx["b"], raw) as session:
                    sent = time.monotonic_ns()
                    reply = session.call(
                        dict(op="execute", frame=lab.ops["mass"]["frame"])
                    )
                    answered = time.monotonic_ns() - sent
                result = reply.get("result", reply.get("reason"))
            except (OSError, ValueError):
                result = "NO_ACK"
        return [tid, begin, time.monotonic_ns(), result, answered]

    def snapshot():
        return {
            k: sample(pid)
            for k, pid in dict(
                target=lab.pid,
                **lab.service_pids,
                **{f"member{i}": p for i, p in lab.c.pids.items()},
            ).items()
        }

    def storage():
        return {
            k: sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
            for k, d in dict(
                target=lab.state,
                **{f"member{i}": lab.base / f"m{i}" / "data" for i in range(3)},
            ).items()
        }

    before = snapshot()
    initial = storage()
    start = time.monotonic()
    threading.stack_size(512 * 1024)
    with ThreadPoolExecutor(n) as pool:
        os.kill(lab.pid, signal.SIGSTOP)
        try:
            jobs = [pool.submit(attempt, i) for i in range(n)]
            gate.wait()
        finally:
            os.kill(lab.pid, signal.SIGCONT)
        rows = [j.result() for j in jobs]
    overlap = max(x[1] for x in rows) <= min(x[2] for x in rows)
    save(lab.out / "attempts.json", rows)
    after = snapshot()
    first = time.monotonic() - start
    assert overlap and len(set(x[0] for x in rows)) == n
    assert sum(x[3] == "COMMITTED" for x in rows) == 1, Counter(x[3] for x in rows)
    lab.replies["mass-retry"] = lab.execute("mass", "b")
    assert lab.replies["mass-retry"].get("result") in (
        "COMMITTED",
        "ALREADY_COMMITTED",
    ), lab.replies["mass-retry"]
    names = ["lost", "revoked", "pending"]
    fence = threading.Barrier(4)

    def recover(i):
        docs = {}
        raw = []
        with Session(lab.port, lab.ctx["alice"]) as s:
            fence.wait()
            for j in range(budget["recovery_queries_per_worker"]):
                name = names[(j + i) % 3]
                begin = time.monotonic_ns()
                reply = s.call(dict(op="recover", binding=lab.ops[name]["binding"]))
                end = time.monotonic_ns()
                h = digest(reply)
                docs[h] = reply
                raw.append([begin, end, name, h])
        with gzip.open(lab.out / f"recover-{i}.json.gz", "wt") as f:
            json.dump(raw, f, separators=(",", ":"))
        save(lab.out / f"proof-{i}.json", docs)
        return raw

    begin = time.monotonic()
    with ThreadPoolExecutor(4) as pool:
        waves = list(pool.map(recover, range(4)))
    second = time.monotonic() - begin
    end = snapshot()
    final = storage()
    delays = sorted(r[1] - r[0] for wave in waves for r in wave)

    def pct(values):
        return {f"p{p}_ns": values[(len(values) - 1) * p // 100] for p in (50, 95, 99)}

    profile = []
    with closing(
        sqlite3.connect((lab.state / "journal.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as c:
        for _ in range(100):
            t = time.monotonic_ns()
            read(lab.c.clients[0], lab.c.auditor, lab.idx)
            mid = time.monotonic_ns()
            seal(c)
            profile.append([mid - t, time.monotonic_ns() - mid])
    violated = []
    for label, pre, post, wall in (
        ("attempt", before, after, first),
        ("recover", after, end, second),
    ):
        if wall > budget["max_wall_seconds_per_wave"]:
            violated.append(label + " wall")
        for k in post:
            if (
                post[k]["cpu"] - pre[k]["cpu"]
                > budget["max_cpu_seconds_per_service_per_wave"]
            ):
                violated.append(label + " cpu " + k)
            if post[k]["rss_kib"] > budget["max_rss_mib_per_service"] * 1024:
                violated.append(label + " rss " + k)
    for k, v in final.items():
        if (
            v
            > budget[
                "max_target_bytes" if k == "target" else "max_etcd_member_storage_bytes"
            ]
        ):
            violated.append("disk " + k)
    save(
        lab.out / "performance.json",
        dict(
            attempts=n,
            overlap=overlap,
            attempt_seconds=first,
            attempt_outcomes=dict(Counter(x[3] for x in rows)),
            attempt_latency=pct(sorted(x[2] - x[1] for x in rows)),
            recoveries=len(delays),
            seconds=second,
            recovery_rps=len(delays) / second,
            recovery_latency=pct(delays),
            samples=[before, after, end],
            storage=[initial, final],
            floor_profile_ns=profile,
            exceeded=violated,
        ),
    )
