"""WT-SWARM-002 local-only experiment. Start with a new output directory."""

import argparse
from contextlib import ExitStack
from unittest.mock import patch
import gzip
import json
import os
from pathlib import Path
import platform
import select
import sqlite3
import subprocess
import sys
import tempfile
import time

from research.wt_swarm.run import (
    Run,
    ROOT,
    CLI,
    sandbox,
    gate_limits,
    proc_sample,
    save,
    send,
    line,
    command,
)
from research.blackout.credentials import provision
from research.blackout.reader import locator
from shirudo_adapter.action_gate import make_grant_payload
from shirudo_adapter.owner import validate_bundle, MIN_REMAINING_MS
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import verify_record

BASE = "f2d8b928f34ecb20f81f2270b7a2a62b5590ce96"
BUDGET = Path(__file__).with_name("budgets.json")


def read(p):
    return json.loads(p.read_bytes())


def binding(req, m, profile, principal):
    grant = verify_record(req["grant"], profile["owner_public_key"])
    bundle = m["bundle"]
    validate_bundle(
        bundle,
        profile,
        intent=m["owner_review"]["intent"],
        ready_at_ms=m["owner_review"]["ready"]["ready_at_ms"],
        now_ms=grant["issued_at_ms"],
        min_remaining_ms=MIN_REMAINING_MS,
    )
    expected = make_grant_payload(
        bundle["action_challenge"],
        bundle["assessment"],
        grant_id=grant["grant_id"],
        issued_at_ms=grant["issued_at_ms"],
        expires_at_ms=bundle["action_challenge"]["payload"]["expires_at_ms"],
    )
    if (
        grant != expected
        or req["operation_id"] != grant["operation_id"]
        or req["assessment"] != bundle["assessment"]
    ):
        raise ValueError("enrollment requires the exact authorized request")
    return dict(
        principal=principal,
        target_id=profile["target_id"],
        gate_instance_id=profile["gate_instance_id"],
        operation_id=req["operation_id"],
        request_sha256=digest(req),
        grant_id=grant["grant_id"],
        grant_sha256=digest(req["grant"]),
        assessment_sha256=digest(req["assessment"]),
        challenge_sha256=digest(bundle["action_challenge"]),
    )


def usage(pid, journal):
    r = proc_sample(pid)
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    r.update(
        cpu_ticks=int(stat[11]) + int(stat[12]),
        clock_ticks=os.sysconf("SC_CLK_TCK"),
        db_bytes=journal.stat().st_size,
    )
    sizes = []
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            sizes.append(Path(str(journal) + suffix).stat().st_size)
        except FileNotFoundError:
            pass
    r["sqlite_sidecar_bytes"] = sum(sizes)
    return r


def reader_pid(process):
    pid = process.pid
    while Path(f"/proc/{pid}/comm").read_text().strip() == "bwrap":
        children = []
        for stat in Path("/proc").glob("[0-9]*/stat"):
            try:
                fields = stat.read_text().rsplit(")", 1)[1].split()
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            if fields[0] != "Z" and int(fields[1]) == pid:
                children.append(int(stat.parent.name))
        if len(children) != 1:
            raise RuntimeError("cannot identify isolated reader process")
        pid = int(children[0])
    return pid


class Experiment(Run):
    def __init__(self, private, output, stack):
        self.base = output
        self.private = private
        native = output / "native"
        native.mkdir()
        super().__init__(private, native, stack)
        self.trace = {}
        self.events = {}
        self.measuring = None

    def start_gate(self, mode="normal"):
        if self.measuring:
            self.trace[self.measuring].append(usage(self.gate.pid, self.journal))
        super().start_gate(mode)
        self.measuring = (
            mode if mode in ("contention", "duplicates", "overload") else None
        )
        if self.measuring:
            self.trace[mode] = [usage(self.gate.pid, self.journal)]

    def batch(self, name, docs):
        # Extend only the original supervisor sampler, retaining the gate,
        # clients, barrier, operation mix and native admission observer.
        with patch(
            "research.wt_swarm.run.proc_sample",
            side_effect=lambda pid: usage(pid, self.journal),
        ):
            super().batch(name, docs)

    def native(self):
        self.setup()
        self.load_cases()
        self.interrupt()
        self.order(False)
        self.order(True)
        self.snapshot("final")
        save(self.out / "faults.json", self.faults)
        save(self.out / "replies.json", self.replies)
        save(self.out / "environment.json", {"actual_human_approval": "NOT_RUN"})
        self.profile = read(self.out / "profile.json")
        self.out = self.base / "recovery"
        self.out.mkdir()
        self.snapshots, self.inventory, self.faults, self.replies = {}, {}, {}, {}
        self.snapshot("native_complete")

    def isolated(self, role, identity, mounts):
        args = sandbox("client")
        args = args[: args.index("--chdir")]
        args += [
            "--ro-bind",
            str(ROOT / "research/blackout"),
            "/src/research/blackout",
            "--ro-bind",
            str(self.private / identity),
            "/identity",
        ]
        for kind, source, dest in mounts:
            args += [kind, str(source), dest]
        return args + [
            "--chdir",
            "/src",
            sys.executable,
            "-B",
            "-m",
            "research.blackout." + role,
        ]

    def setup_reader(self):
        self.socket_dir = self.private / "read-only-socket"
        self.socket_dir.mkdir()
        principals = provision(self.private)
        self.bound = {}
        for name, m in self.materials.items():
            req = m["request"]
            if req["grant"]:
                self.bound[name] = binding(
                    req,
                    m,
                    self.profile,
                    principals["bob" if name == "duplicates" else "alice"],
                )
        cfg = {
            "profile": self.profile,
            "bindings": {b["request_sha256"]: b for b in self.bound.values()},
        }
        config = self.private / "recovery.json"
        save(config, cfg)
        mask = self.private / "empty"
        mask.touch(mode=0o400)
        proc = self.spawn(
            self.isolated(
                "reader",
                "reader",
                [
                    ("--ro-bind", config, "/config.json"),
                    ("--ro-bind", self.state, "/journal"),
                    ("--ro-bind", mask, "/journal/signing.key"),
                    ("--bind", self.socket_dir, "/endpoint"),
                ],
            ),
            preexec_fn=gate_limits,
        )
        ready = line(proc)
        self.reader = proc
        self.reader_pid = reader_pid(proc)
        self.pins = dict(
            principals,
            proof_key=ready["proof_key"],
            gate_public_key=self.profile["gate_public_key"],
        )
        save(
            self.out / "reader.json",
            dict(pins=self.pins, bindings=self.bound, custody=ready),
        )
        for role in principals:
            (self.out / (role + ".pem")).write_bytes(
                (self.private / role / "cert.pem").read_bytes()
            )
        (self.out / "ca.pem").write_bytes(
            (self.private / "reader" / "ca.pem").read_bytes()
        )

    def recover(self, label, names, role="alice", change=None, storm=False):
        self.snapshot("at-" + label)
        queries = [locator(self.bound[n]) for n in names]
        if change:
            queries[0].update(change)
        p = self.spawn(
            self.isolated("client", role, [("--ro-bind", self.socket_dir, "/endpoint")])
            + (["storm"] if storm else ["one"])
        )
        samples = [usage(self.reader_pid, self.journal)]
        if storm:
            self.trace[label + "-gate"] = [usage(self.gate.pid, self.journal)]
        args = {
            "pins": self.pins,
            "role": role,
            "queries": queries,
            "bindings": {self.bound[n]["request_sha256"]: self.bound[n] for n in names},
        }
        send(p, args)
        deadline = time.monotonic() + 180
        while not select.select([p.stdout], [], [], 0.025)[0]:
            samples.append(usage(self.reader_pid, self.journal))
            if time.monotonic() > deadline:
                raise TimeoutError(label)
        # Buffered reads avoid a byte-at-a-time readline on large batch output.
        with os.fdopen(os.dup(p.stdout.fileno()), "rb") as data:
            result = json.load(data)
        if p.wait(5):
            raise RuntimeError("recovery client failed")
        samples.append(usage(self.reader_pid, self.journal))
        record = dict(queries=queries, role=role, **result)
        if storm:
            self.trace[label + "-gate"].append(usage(self.gate.pid, self.journal))
            self.trace[label] = samples
            with gzip.open(self.out / (label + ".json.gz"), "wt") as stream:
                json.dump(record, stream, separators=(",", ":"))
        else:
            self.events[label] = record
        return record

    def partition(self, name, mode):
        req = self.materials[name]["request"]
        exchange = self.private / name
        exchange.mkdir()
        proxy = self.spawn(
            [
                sys.executable,
                "-B",
                "-m",
                "research.blackout.relay",
                exchange / "gate.sock",
                self.endpoint / "gate.sock",
                mode,
                digest(req),
            ]
        )
        if line(proxy) != "ready":
            raise RuntimeError("relay startup")
        client = self.spawn(sandbox("client", exchange) + ["rpc"])
        send(client, {"op": "execute", "request": req})
        self.faults[name] = {"first": line(proxy)}
        if mode == "delay":
            self.replies[name + "-disconnect"] = line(client)
            client.wait(5)
            self.recover(name + "-before", [name])
            if name == "cancel":
                grant_id = req["grant"]["payload"]["grant_id"]
                subprocess.run(
                    CLI
                    + ["revoke-grant", "--state", self.state, "--grant-id", grant_id],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                self.snapshot("revoked_in_partition")
                self.recover("cancel-revoked", [name])
            command(proxy, "deliver")
            self.faults[name]["delivery"] = line(proxy)
        else:
            client.kill()
            self.faults[name]["coordinator_exit"] = client.wait(3)
            command(proxy, "disconnect")
        if proxy.wait(5):
            raise RuntimeError("relay exit")
        self.snapshot(name)
        self.recover(name + "-after", [name])

    def cases(self):
        for name in ("late", "cancel", "replacement", "interrupted", "waiting"):
            self.material(name)
        self.setup_reader()
        self.partition("late", "delay")
        self.partition("cancel", "delay")
        self.partition("replacement", "drop_after")
        req = self.materials["interrupted"]["request"]
        self.start_gate("before")
        self.submit("settlement-loss", req)
        self.faults["settlement_exit"] = self.gate.wait(5)
        self.start_gate()
        self.snapshot("rollback")
        self.recover("settlement-pending", ["interrupted"])
        self.submit("settlement-retry", req)
        self.snapshot("settled")
        self.recover("settlement-committed", ["interrupted"])
        self.recover("cross-principal", ["replacement"], "bob")
        self.recover(
            "wrong-digest", ["replacement"], change={"request_sha256": "0" * 64}
        )
        self.recover(
            "wrong-gate", ["replacement"], change={"gate_instance_id": "0" * 32}
        )
        self.recover("wrong-target", ["replacement"], change={"target_id": "other"})
        self.recover("expired-certificate", ["replacement"], "expired")
        self.faults["expired_handshake"] = line(self.reader)
        self.recover("bob-own", ["duplicates"], "bob")
        self.recover("still-pending", ["waiting"])
        # Verify the same principal's genuine proof has no execute semantics.
        group = self.events["replacement-after"]["groups"][0]
        proof = next(iter(group["proofs"].values()))["proof"]
        self.replies["read-proof-as-execute"] = self.call(
            {"op": "execute", "request": proof}
        )
        self.snapshot("before_storms")
        for i in range(3):
            previous = self.gate.pid
            self.start_gate()
            label = f"storm-{i}"
            self.faults[label] = {
                "stopped_pid": previous,
                "ready_pid": self.gate.pid,
                "ready_ns": time.monotonic_ns(),
            }
            self.recover(label, ["replacement", "cancel", "waiting"], storm=True)
            self.snapshot(label)
        # Request authenticated recovery for every committed row using its enrolled principal.
        committed = {r["operation_id"] for r in self.snapshots["storm-2"]["ledger"]}
        for name, b in self.bound.items():
            if b["operation_id"] in committed:
                self.recover(
                    "final-" + name,
                    [name],
                    role="bob" if name == "duplicates" else "alice",
                )
        self.snapshot("final")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    out = parser.parse_args().output.resolve()
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", BASE, "HEAD"], cwd=ROOT, check=True
    )
    subprocess.run(
        [
            "git",
            "diff",
            "--exit-code",
            BASE,
            "--",
            "research/wt_swarm",
            "shirudo_adapter",
            "scripts",
            "tests",
        ],
        cwd=ROOT,
        check=True,
    )
    out.mkdir(parents=True, exist_ok=False)
    (out / "budgets.json").write_bytes(BUDGET.read_bytes())
    with tempfile.TemporaryDirectory(prefix="wt002-") as private, ExitStack() as stack:
        lab = Experiment(Path(private), out, stack)
        try:
            lab.native()
            lab.cases()
        finally:
            save(out / "usage.json", lab.trace)
            save(lab.out / "faults.json", lab.faults)
            save(lab.out / "replies.json", lab.replies)
            save(lab.out / "events.json", lab.events)
    save(
        out / "environment.json",
        dict(
            python=platform.python_version(),
            kernel=platform.release(),
            sqlite=sqlite3.sqlite_version,
            base=BASE,
            cpu_quota=Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
            private_directory_removed=not Path(private).exists(),
            paid_model_calls=0,
            verifier="DISPOSABLE_SIGNED_FIXTURE",
            approval="SCRIPTED_PTY",
            human_approval="NOT_RUN",
            tls=__import__("ssl").OPENSSL_VERSION,
            architecture=platform.machine(),
        ),
    )


if __name__ == "__main__":
    main()
