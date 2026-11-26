"""Run Schism only on newly provisioned disposable local storage."""

from contextlib import ExitStack, closing
from pathlib import Path
from types import SimpleNamespace
import argparse
import json
import cryptography
import resource
import os
import platform
import select
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.blackout.experiment import (
    Experiment as Blackout,
    ROOT,
    read,
    reader_pid,
    usage,
)
from research.wt_swarm.run import (
    Run,
    sandbox,
    save,
    line,
    send,
    stop,
    command,
    gate_limits,
)
from research.schism.storage import PERMIT, TRANSITION, ZERO, provision
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import sign_record

BASE = "c9dbeef48fbb5e60a4edf89bcfbc444fbd995539"
BUDGET = Path(__file__).with_name("budgets.json")


def backup(source, dest):
    with (
        closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src,
        closing(sqlite3.connect(dest)) as dst,
    ):
        src.backup(dst)


def box(module, mounts):
    args = sandbox("client")
    args = args[: args.index("--chdir")]
    for pkg in ("blackout", "schism"):
        path = "research/" + pkg
        args += ["--ro-bind", str(ROOT / path), "/src/" + path]
    for mode, src, dst in mounts:
        args += [mode, str(src), str(dst)]
    return args + [
        "--chdir",
        "/src",
        sys.executable,
        "-B",
        "-m",
        "research.schism." + module,
    ]


def buffered(p):
    with os.fdopen(os.dup(p.stdout.fileno()), "rb") as stream:
        result = json.load(stream)
    if p.wait(5):
        raise RuntimeError("lab worker failed")
    return result


class Experiment(Blackout):
    def __init__(self, private, out, stack):
        super().__init__(private, out, stack)
        self.faces = {}
        self.head = (0, ZERO)
        self.actions = {}
        self.bound_epochs = {}
        self.checkpoints = {}

    def snapshot(self, name):
        Run.snapshot(self, name)
        if hasattr(self, "paths"):
            values = {}
            for db, table, columns in (
                ("control", "transitions", "epoch,record"),
                ("witness", "anchor", "id,hash"),
            ):
                try:
                    with closing(
                        sqlite3.connect(self.paths[db].as_uri() + "?mode=ro", uri=True)
                    ) as con:
                        values[db] = con.execute(
                            f"SELECT {columns} FROM {table} ORDER BY 1 DESC LIMIT 1"
                        ).fetchone()
                except sqlite3.Error:
                    values[db] = None
            with closing(
                sqlite3.connect(self.journal.as_uri() + "?mode=ro", uri=True)
            ) as con:
                values["local"] = con.execute(
                    "SELECT epoch,head,hash FROM schism_head,schism_tag"
                ).fetchone()
            values["bytes"] = {
                k: path.stat().st_size
                for k, path in self.paths.items()
                if path.exists()
            }
            self.checkpoints[name] = values

    def bootstrap(self):
        Run.setup(self)
        stop(self.gate)
        self.profile = read(self.out / "profile.json")
        self.issuer = self.spawn(box("role", []) + ["issuer"])
        issuer = line(self.issuer)
        self.dirs = {n: self.private / ("socket-" + n) for n in ("a", "b")}
        self.keys = {}
        self.public = {}
        for n, dir in self.dirs.items():
            dir.mkdir()
            key = Ed25519PrivateKey.generate()
            self.keys[n] = self.private / ("executor-" + n)
            self.keys[n].write_bytes(key.private_bytes_raw())
            self.public[n] = key.public_key().public_bytes_raw().hex()
        external = self.private / "external"
        external.mkdir()
        self.paths, self.anchors = provision(
            self.state, external, issuer, list(self.public.values()), self.profile
        )
        self.cfg = self.private / "mounts.json"
        save(
            self.cfg,
            dict(paths={k: str(v) for k, v in self.paths.items()}, pins=self.anchors),
        )
        save(self.out / "anchors.json", dict(pins=self.anchors, executors=self.public))
        self.transition("genesis", "a")
        self.start("a")
        self.start("b")
        self.active("a")
        self.snapshot("genesis")

    def active(self, n):
        self.endpoint = self.dirs[n]
        self.gate = SimpleNamespace(pid=reader_pid(self.faces[n]))

    def role_args(self, n, role, state=None):
        state = state or self.state
        if role == "serve":
            mounts = [("--bind", self.dirs[n], self.dirs[n])]
        else:
            mounts = []
        mounts += [
            ("--ro-bind", self.cfg, self.cfg),
            ("--bind", state, state),
            ("--ro-bind", self.keys[n], self.keys[n]),
            ("--ro-bind", self.paths["control"].parent, self.paths["control"].parent),
            ("--bind", self.paths["witness"].parent, self.paths["witness"].parent),
        ]
        return box("role", mounts) + [
            role,
            str(self.cfg),
            str(state),
            str(self.keys[n]),
        ]

    def start(self, n, mode="normal"):
        if n in self.faces:
            stop(self.faces[n])
        args = self.role_args(n, "serve") + [str(self.dirs[n] / "gate.sock"), mode]
        self.faces[n] = self.spawn(args, preexec_fn=gate_limits)
        result = line(self.faces[n])
        if result.get("status") != "READY":
            raise RuntimeError(result)

    def signed(self, payload):
        send(self.issuer, payload)
        return line(self.issuer)

    def transition_payload(self, n):
        epoch, head = self.head
        return dict(
            schema=TRANSITION,
            gate=self.anchors["gate"],
            target=self.anchors["target"],
            epoch=epoch + 1,
            previous=head,
            executor=self.public[n],
        )

    def admin(self, doc, mode="transition", pause=False, trace=False):
        p = self.spawn(
            [sys.executable, "-B", "-m", "research.schism.role", mode, self.cfg]
            + (["pause"] if pause else [])
            + (["trace"] if trace else [])
        )
        send(p, doc)
        if line(p)["phase"] != "attempt":
            raise RuntimeError("control worker")
        return p

    def transition(self, label, n, doc=None):
        record = doc or self.signed(self.transition_payload(n))
        proc = self.admin(record)
        result = line(proc)
        proc.wait(4)
        self.actions[label] = dict(record=record, reply=result)
        if result["status"] == "APPLIED":
            self.head = (record["payload"]["epoch"], digest(record))
        return record

    def material(self, name, signed=True):
        req = super().material(name, signed)
        if signed:
            epoch, head = self.head
            n = next(n for n, v in self.dirs.items() if v == self.endpoint)
            cert = self.signed(
                dict(
                    schema=PERMIT,
                    gate=self.anchors["gate"],
                    target=self.anchors["target"],
                    epoch=epoch,
                    head=head,
                    executor=self.public[n],
                    op=req["operation_id"],
                    request=digest(req),
                    grant=digest(req["grant"]),
                )
            )
            p = self.admin(cert, "register")
            result = line(p)
            if p.wait(3) or result["status"] != "APPLIED":
                raise RuntimeError(result)
            self.bound_epochs[name] = cert
        return req

    def submit_to(self, label, n, name):
        p = self.spawn(sandbox("client", self.dirs[n]) + ["rpc"])
        send(p, {"op": "execute", "request": self.materials[name]["request"]})
        self.replies[label] = line(p)
        p.wait(4)

    def revoke(self, label, n, name):
        req = self.materials[name]["request"]
        p = self.spawn(
            self.role_args(n, "revoke") + [req["grant"]["payload"]["grant_id"]]
        )
        self.replies[label] = line(p)
        p.wait(4)

    def isolated(self, role, identity, mounts):
        if role != "reader":
            return super().isolated(role, identity, mounts)
        mounts = mounts + [
            ("--ro-bind", self.private / identity, "/identity"),
            ("--ro-bind", self.cfg, self.cfg),
        ]
        for key in ("control", "witness"):
            parent = self.paths[key].parent
            mounts.append(("--ro-bind", parent, parent))
        return box("role", mounts) + ["reader", str(self.cfg)]

    def coordinator(self, name, route, material, resume=False):
        queue = self.private / ("queue-" + name)
        if not resume:
            queue.mkdir(mode=0o700)
        p = self.spawn(
            box(
                "coordinator",
                [
                    ("--bind", queue, "/queue"),
                    ("--ro-bind", self.dirs[route], "/endpoint"),
                ],
            )
        )
        if not resume:
            send(
                p, dict(name=name, epoch=1, request=self.materials[material]["request"])
            )
        claim = line(p)
        claim["host_pid"] = reader_pid(p)
        self.faults["claims"]["resumed" if resume else name] = claim
        return p

    def functional(self):
        for n in ("old", "inflight", "delayed", "rev-before", "rev-after"):
            self.material(n)
        self.faults["claims"] = {}
        first_leader = self.coordinator("first", "a", "old")
        rival_leader = self.coordinator("rival", "b", "delayed")
        # Both claims remain live while competing submissions enter separate gates.
        command(first_leader, "submit")
        command(rival_leader, "submit")
        self.replies["original"] = line(first_leader)
        self.replies["simultaneous-claim"] = line(rival_leader)
        os.kill(self.faults["claims"]["first"]["host_pid"], signal.SIGKILL)
        self.faults["coordinator_exit"] = first_leader.wait(5)
        self.snapshot("before_transition")
        backup(self.journal, self.private / "epoch1.db")
        # Freeze an actual submitted frame for later delivery to the replacement gate.
        relaydir = self.private / "partition"
        relaydir.mkdir()
        req = self.materials["delayed"]["request"]
        relay = self.spawn(
            [
                sys.executable,
                "-B",
                "-m",
                "research.blackout.relay",
                relaydir / "gate.sock",
                self.dirs["b"] / "gate.sock",
                "delay",
                digest(req),
            ]
        )
        assert line(relay) == "ready"
        client = self.spawn(sandbox("client", relaydir) + ["rpc"])
        send(client, {"op": "execute", "request": req})
        self.faults["buffered"] = line(relay)
        self.replies["disconnect"] = line(client)
        client.wait(4)

        candidate = self.signed(self.transition_payload("b"))
        # Interrupt the serving gate and the separate control writer at the precommit boundary.
        proc = self.admin(candidate, pause=True)
        assert line(proc)["phase"] == "writer_held"
        pid = reader_pid(self.faces["a"])
        os.kill(pid, signal.SIGKILL)
        self.faults["interrupted-gate"] = self.faces["a"].wait(5)
        proc.kill()
        self.faults["interrupted-transition"] = proc.wait(4)
        inspect = self.spawn(
            [sys.executable, "-B", "-m", "research.schism.role", "inspect", self.cfg]
        )
        self.actions["crash-recovery"] = line(inspect)
        inspect.wait(4)
        self.start("a")
        self.active("a")

        self.revoke("revocation-before", "a", "rev-before")
        self.submit_to("revoked-before", "a", "rev-before")
        rival = self.signed(self.transition_payload("a"))
        self.start("a", "pause")
        frame = self.spawn(sandbox("client", self.dirs["a"]) + ["rpc"])
        send(frame, {"op": "execute", "request": self.materials["inflight"]["request"]})
        old_held = line(self.faces["a"])
        first = self.admin(candidate, pause=True, trace=True)
        first_begin = line(first)
        release_old = time.monotonic_ns()
        command(self.faces["a"], "release")
        self.replies["inflight"] = line(frame)
        frame.wait(4)
        held = line(first)
        second = self.admin(rival, trace=True)
        second_begin = line(second)
        self.faults["writer_order"] = [
            old_held,
            first_begin,
            {"phase": "release_old", "ns": release_old},
            held,
            second_begin,
            {"phase": "release_transition", "ns": time.monotonic_ns()},
        ]
        assert held["phase"] == "writer_held" and second.poll() is None
        command(first, "release")
        self.actions["winner"] = {"record": candidate, "reply": line(first)}
        self.actions["loser"] = {"record": rival, "reply": line(second)}
        first.wait(4)
        second.wait(4)
        self.head = (2, digest(candidate))
        self.active("b")
        self.snapshot("epoch2")
        self.revoke("revocation-after", "b", "rev-after")
        self.submit_to("revoked-after", "b", "rev-after")
        self.transition("transition-replay", "b", candidate)
        forged = sign_record(
            Ed25519PrivateKey.generate(), dict(self.transition_payload("a"), epoch=9000)
        )
        self.transition("forged-higher", "a", forged)
        # The coordinator self-signs a correctly numbered proposal.
        claim = sign_record(Ed25519PrivateKey.generate(), self.transition_payload("a"))
        self.transition("self-election", "a", claim)
        self.start("a")
        resumed = self.coordinator("first", "a", "old", resume=True)
        command(resumed, "submit")
        self.replies["stale-restart"] = line(resumed)
        command(rival_leader, "submit")
        self.replies["rival-after-transition"] = line(rival_leader)
        stop(resumed)
        stop(rival_leader)
        command(relay, "deliver")
        self.faults["delivery"] = line(relay)
        relay.wait(4)
        recert = self.signed(
            dict(
                self.bound_epochs["delayed"]["payload"],
                epoch=2,
                head=self.head[1],
                executor=self.public["b"],
            )
        )
        p = self.admin(recert, "register")
        self.actions["rebind"] = {"record": recert, "reply": line(p)}
        p.wait(4)

        for n in (
            "current",
            "gap",
            "pending",
            "duplicates",
            "pair",
            "mass0",
            "mass1",
            "mass2",
            "mass3",
        ):
            self.material(n)
        self.submit_to("current", "b", "current")
        self.material("withheld", False)
        backup(self.journal, self.private / "same-epoch.db")
        self.submit_to("gap-first", "b", "duplicates")
        self.snapshot("pre_restore")
        backup(self.journal, self.private / "current.db")
        self.setup_reader()
        self.snapshot("native_complete")
        for name, filename in (
            ("old-epoch-restore", "epoch1.db"),
            ("same-epoch-restore", "same-epoch.db"),
        ):
            backup(self.private / filename, self.journal)
            self.submit_to(name, "b", "gap")
            self.recover(name, ["old"])
            backup(self.private / "current.db", self.journal)
        clone = self.private / "clone"
        shutil.copytree(self.state, clone)
        # Intentional divergence on a disposable clone, never on the protected target.
        with sqlite3.connect(clone / "journal.sqlite3") as c:
            c.execute("UPDATE counter SET value=value+1")
        before = (clone / "journal.sqlite3").read_bytes()
        probe = self.spawn(self.role_args("b", "probe", clone))
        send(probe, self.materials["gap"]["request"])
        self.replies["clone"] = line(probe)
        probe.wait(5)
        self.faults["clone_unchanged"] = (
            before == (clone / "journal.sqlite3").read_bytes()
        )

        self.start("b", "pause")
        p = self.spawn(sandbox("client", self.dirs["b"]) + ["rpc"])
        send(p, {"op": "execute", "request": self.materials["gap"]["request"]})
        self.faults["gap-held"] = line(self.faces["b"])
        path = self.paths["control"]
        missing = path.with_suffix(".offline")
        path.rename(missing)
        try:
            command(self.faces["b"], "release")
            self.replies["checkpoint-loss"] = line(p)
            p.wait(5)
            self.recover("checkpoint-offline", ["old"])
        finally:
            missing.rename(path)
        self.start("b")
        self.active("b")
        self.submit_to("healed", "b", "gap")
        self.recover("cross-epoch", ["old"])
        self.recover("durable-negative", ["rev-before"])
        self.recover("pending", ["pending"])
        self.recover("cross-principal", ["old"], "bob")
        self.recover("bob-own", ["duplicates"], "bob")
        self.recover("wrong-digest", ["old"], change={"request_sha256": "0" * 64})
        self.recover("expired-certificate", ["old"], "expired")
        self.faults["expired_handshake"] = line(self.reader)
        received = next(
            iter(self.events["cross-epoch"]["groups"][0]["proofs"].values())
        )
        self.replies["read-proof-execute"] = self.call(
            {"op": "execute", "request": received["proof"]}
        )
        changed = dict(
            self.materials["old"]["request"],
            grant=self.materials["current"]["request"]["grant"],
        )
        self.replies["conflicting-original"] = self.call(
            {"op": "execute", "request": changed}
        )
        self.snapshot("healed")

    def wave(self, kind):
        routes = ("a", "b") if kind == "contention" else ("b",)
        labels = (
            ("mass0", "mass1", "mass2", "mass3")
            if kind == "contention"
            else (("pair",) if kind == "duplicates" else ("withheld",))
        )
        docs = [self.materials[n]["request"] for n in labels]
        procs = {}
        services = {}
        samples = {n: [] for n in routes}
        for n in routes:
            self.start(n, "trace")
            services[n] = reader_pid(self.faces[n])
            samples[n].append(usage(services[n], self.journal))
        if kind == "contention":
            for pid in services.values():
                os.kill(pid, signal.SIGSTOP)
        try:
            for n in routes:
                args = (
                    box("workers", [("--ro-bind", self.dirs[n], "/endpoint")])
                    if kind == "contention"
                    else sandbox("client", self.dirs[n]) + [kind]
                )
                procs[n] = self.spawn(args)
                send(procs[n], docs)
            if kind == "contention":
                self.faults["sockets"] = {n: line(p, 35) for n, p in procs.items()}
        finally:
            if kind == "contention":
                self.faults["release"] = time.monotonic_ns()
                for pid in services.values():
                    os.kill(pid, signal.SIGCONT)
        end = time.monotonic() + 180
        while len(
            select.select([p.stdout for p in procs.values()], [], [], 0.012)[0]
        ) != len(procs):
            for n, pid in services.items():
                samples[n].append(usage(pid, self.journal))
            if time.monotonic() > end:
                raise TimeoutError(kind)
            time.sleep(0.003)
        for n, p in procs.items():
            save(self.out / f"{kind}-{n}.json", buffered(p))
            samples[n].append(usage(services[n], self.journal))
            self.start(n)
            log = self.dirs[n] / "decisions.jsonl"
            shutil.move(log, self.out / f"{kind}-{n}-admission.jsonl")
        save(self.out / (kind + "-usage.json"), samples)
        self.active("b")
        self.snapshot(kind)

    def stress(self):
        self.wave("contention")
        for name in ("mass0", "mass1", "mass2", "mass3"):
            self.submit_to("retry-" + name, "b", name)
        self.snapshot("mass-settled")
        self.wave("duplicates")
        self.wave("overload")
        self.faults["recovery_restarts"] = []
        for i in range(3):
            previous = reader_pid(self.faces["b"])
            self.start("b")
            self.faults["recovery_restarts"].append(
                dict(
                    previous=previous,
                    serving=reader_pid(self.faces["b"]),
                    ready_ns=time.monotonic_ns(),
                )
            )
            self.active("b")
            self.recover(
                "storm-" + str(i), ["old", "rev-before", "pending"], storm=True
            )
        for n in (
            "old",
            "inflight",
            "current",
            "gap",
            "duplicates",
            "pair",
            "mass0",
            "mass1",
            "mass2",
            "mass3",
        ):
            self.recover("final-" + n, [n], "bob" if n == "duplicates" else "alice")
        self.snapshot("final")
        with closing(
            sqlite3.connect(self.paths["witness"].as_uri() + "?mode=ro", uri=True)
        ) as c:
            self.events_log = [
                dict(seq=i, kind=k, record=json.loads(r))
                for i, k, r in c.execute(
                    "SELECT seq,kind,record FROM events ORDER BY seq"
                )
            ]
        save(self.out / "ledger.json", self.events_log)
        with closing(
            sqlite3.connect(self.paths["control"].as_uri() + "?mode=ro", uri=True)
        ) as c:
            save(
                self.out / "authority-store.json",
                {
                    "checkpoints": [
                        list(row)
                        for row in c.execute("SELECT * FROM checkpoints ORDER BY epoch")
                    ],
                    "transitions": [
                        json.loads(r)
                        for (r,) in c.execute(
                            "SELECT record FROM transitions ORDER BY epoch"
                        )
                    ],
                    "permits": {
                        op: json.loads(r)
                        for op, r in c.execute("SELECT op,record FROM permits")
                    },
                },
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    out = parser.parse_args().output.resolve()
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", BASE, "HEAD"], cwd=ROOT, check=True
    )
    out.mkdir(parents=True, exist_ok=False)
    shutil.copy(BUDGET, out / "budgets.json")
    with tempfile.TemporaryDirectory(prefix="wt003-") as temp, ExitStack() as stack:
        lab = Experiment(Path(temp), out, stack)
        try:
            lab.bootstrap()
            lab.functional()
            lab.stress()
        finally:
            for name, value in (
                ("events", lab.events),
                ("faults", lab.faults),
                ("replies", lab.replies),
                ("transitions", lab.actions),
                ("permits", lab.bound_epochs),
                ("usage", lab.trace),
                ("checkpoints", lab.checkpoints),
            ):
                save(lab.out / (name + ".json"), value)
    save(
        out / "environment.json",
        dict(
            kernel=platform.release(),
            python=platform.python_version(),
            sqlite=sqlite3.sqlite_version,
            architecture=platform.machine(),
            cpu_count=os.cpu_count(),
            crypto=cryptography.__version__,
            file_limit=list(resource.getrlimit(resource.RLIMIT_NOFILE)),
            memory_limit=Path("/sys/fs/cgroup/memory.max").read_text().strip(),
            pid_limit=Path("/sys/fs/cgroup/pids.max").read_text().strip(),
            cpu=Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
            actual_human_approval="NOT_RUN",
            paid_model_calls=0,
            assessments="FABRICATED",
            private_state_removed=not Path(temp).exists(),
        ),
    )


if __name__ == "__main__":
    main()
