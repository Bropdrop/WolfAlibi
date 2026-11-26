"""Fixed local contention and recovery workloads for the disposable trial."""

from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
import gzip, json, os, signal, socket, ssl, subprocess, time
from research.schism.experiment import box, buffered
from research.wt_swarm.run import sandbox, stop, line, send, gate_limits
from research.blackout.experiment import reader_pid, usage
from research.blackout.review import timing
from research.blackout.reader import locator
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import verify_record


def save(path, data):
    path.write_text(json.dumps(data, sort_keys=True) + "\n")


def spawn(stack, args, limited=False):
    p = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        bufsize=0,
        preexec_fn=gate_limits if limited else None,
    )
    stack.callback(stop, p)
    return p


def contention(lab, req, retire, out):
    endpoint = lab.root / "endpoint"
    endpoint.mkdir()
    cfg = lab.root / "pins.json"
    save(cfg, dict(pins=lab.pins, paths={k: str(v) for k, v in lab.paths.items()}))
    key = lab.root / "holder"
    key.write_bytes(lab.keys[0].private_bytes_raw())
    mounts = [
        ("--ro-bind", cfg, cfg),
        ("--ro-bind", key, key),
        ("--bind", lab.f.state, lab.f.state),
        ("--ro-bind", lab.paths["control"].parent, lab.paths["control"].parent),
        ("--bind", lab.paths["witness"].parent, lab.paths["witness"].parent),
        ("--bind", endpoint, endpoint),
    ]
    with ExitStack() as stack:
        gate = spawn(
            stack,
            box("role", mounts)
            + [
                "serve",
                str(cfg),
                str(lab.f.state),
                str(key),
                str(endpoint / "gate.sock"),
                "normal",
            ],
            True,
        )
        assert line(gate)["status"] == "READY"
        pid = reader_pid(gate)
        start = usage(pid, lab.paths["target"])
        os.kill(pid, signal.SIGSTOP)
        try:
            clients = spawn(stack, sandbox("client", endpoint) + ["contention"])
            send(clients, [req])
            opened = line(clients, 45)
            assert opened["count"] == 1000
            begin = time.monotonic_ns()
            retire()
            end = time.monotonic_ns()
        finally:
            os.kill(pid, signal.SIGCONT)
        batch = buffered(clients)
        after = usage(pid, lab.paths["target"])
        rows = batch["rows"]
        assert len({r["tid"] for r in rows}) == len(rows) == 1000 and max(
            r["start_ns"] for r in rows
        ) <= begin < end <= min(r["end_ns"] for r in rows)
        assert all(r["outcome"] in ("DENIED", "AMBIGUOUS") for r in rows)
        save(
            out / "contention.json",
            dict(
                batch=batch,
                opened=opened,
                begin=begin,
                end=end,
                usage=[start, after],
                latency=timing([(r["start_ns"], r["end_ns"]) for r in rows]),
            ),
        )


def recovery_load(private, paths, pins, roots, package, acl, requests, out):
    endpoint = private / "recover-socket"
    endpoint.mkdir()
    conf = private / "reader-config.json"
    save(
        conf,
        dict(
            paths={k: str(v) for k, v in paths.items()},
            pins=pins,
            roots=roots,
            package=package,
        ),
    )
    # Only the three public SQLite database files and public transfer are visible.
    mounts = [
        ("--ro-bind", conf, "/config.json"),
        ("--ro-bind", private / "reader", "/identity"),
        ("--bind", endpoint, "/endpoint"),
    ]
    for p in paths.values():
        mounts.append(("--ro-bind", p, p))
    args = box("role", mounts)
    pos = args.index("--chdir")
    args[pos:pos] = [
        "--ro-bind",
        str(Path(__file__).resolve().parent),
        "/src/research/continuity",
    ]
    args[-1] = "research.continuity.service"
    with ExitStack() as stack:
        server = spawn(stack, args, True)
        key = line(server)["proof_key"]
        pid = reader_pid(server)
        first = usage(pid, paths["target"])
        barrier = Barrier(4)

        def work(worker):
            ctx = ssl.create_default_context(cafile=private / "alice" / "ca.pem")
            ctx.load_cert_chain(
                private / "alice" / "cert.pem", private / "alice" / "key.pem"
            )
            seen = {}
            rows = []
            wires = [
                json.dumps(locator(acl[digest(r)])).encode() + b"\n" for r in requests
            ]
            with socket.socket(socket.AF_UNIX) as raw:
                raw.connect(str(endpoint / "recover.sock"))
                raw.settimeout(15)
                with (
                    ctx.wrap_socket(raw, server_hostname="reader") as peer,
                    peer.makefile("rb") as stream,
                ):
                    barrier.wait(10)
                    for i in range(25000):
                        idx = (i + worker) % 3
                        begin = time.monotonic_ns()
                        peer.sendall(wires[idx])
                        result = stream.readline(16384)
                        end = time.monotonic_ns()
                        if (idx, result) not in seen:
                            reply = json.loads(result)
                            proof = verify_record(reply["proof"], key)
                            assert proof["outcome"] == (
                                "COMMITTED",
                                "UNRESOLVED",
                                "NOT_COMMITTED",
                            )[idx] and proof["request_sha256"] == digest(requests[idx])
                            seen[idx, result] = digest(reply)
                        rows.append([begin, end, idx, seen[idx, result]])
            return dict(
                rows=rows, replies={v: json.loads(r) for (_, r), v in seen.items()}
            )

        with ThreadPoolExecutor(max_workers=4) as pool:
            groups = list(pool.map(work, range(4)))
        last = usage(pid, paths["target"])
    stats = timing([(r[0], r[1]) for g in groups for r in g["rows"]])
    assert (
        stats["count"] == 100000
        and stats["seconds"] <= 300
        and last["peak_rss_kib"] <= 160 * 1024
        and last["db_bytes"] == first["db_bytes"] <= 8388608
        and (last["cpu_ticks"] - first["cpu_ticks"]) / last["clock_ticks"] <= 400
    )
    save(out / "storm-metrics.json", dict(timing=stats, usage=[first, last], key=key))
    with gzip.open(out / "storm.json.gz", "wt") as f:
        json.dump(groups, f, separators=(",", ":"))
