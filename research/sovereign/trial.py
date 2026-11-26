"""Standalone Tier A trial restricted to newly created disposable directories."""

import argparse
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from research.blackout.experiment import reader_pid
from research.wt_swarm.run import sandbox, gate_limits, line, send, stop
from research.sovereign.cluster import Cluster, issue, write, read, tls, rpc, key
from research.sovereign.wire import Session
from shirudo_adapter.action_gate import Gate, make_grant_payload
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import verify_record

ROOT = Path(__file__).resolve().parents[2]
ZERO = "0" * 64


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def box(module, mounts, network=False):
    args = sandbox("client")
    args = args[: args.index("--chdir")]
    if network:
        args.insert(args.index("--unshare-all") + 1, "--share-net")
    for pkg in ("sovereign", "blackout", "schism"):
        args += ["--ro-bind", str(ROOT / "research" / pkg), "/src/research/" + pkg]
    for mode, src, dst in mounts:
        args.extend([mode, str(src), str(dst)])
    return args + [
        "--chdir",
        "/src",
        sys.executable,
        "-B",
        "-m",
        "research.sovereign." + module,
    ]


def sample(pid):
    status = dict(
        x.split(":", 1)
        for x in Path(f"/proc/{pid}/status").read_text().splitlines()
        if ":" in x
    )
    ticks = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return dict(
        cpu=(int(ticks[11]) + int(ticks[12])) / os.sysconf("SC_CLK_TCK"),
        rss_kib=int(status["VmHWM"].split()[0]),
        fds=len(list(Path(f"/proc/{pid}/fd").iterdir())),
        threads=int(status["Threads"]),
    )


class Trial:
    def __init__(self, base, out, stack, binary):
        self.base, self.out, self.stack = base, out, stack
        names = [
            "m0",
            "m1",
            "m2",
            "root",
            "publisher",
            "target",
            "auditor",
            "alice",
            "bob",
            "coordinator",
            "a",
            "b",
        ]
        roles = ("owner", "verifier", "a", "b")
        names += ["history"] + [
            prefix + n for n in roles for prefix in ("service-", "control-")
        ]
        issue(base, names)
        peer_ca = base / "member-credentials"
        peer_ca.mkdir()
        issue(peer_ca, ["m0", "m1", "m2"])
        for i in range(3):
            shutil.copytree(peer_ca / f"m{i}", base / f"m{i}" / "peer")
        self.cert = {
            n: x509.load_pem_x509_certificate((base / n / "cert.pem").read_bytes())
            .fingerprint(hashes.SHA256())
            .hex()
            for n in names
        }
        self.ctx = {n: tls(base / n) for n in names if not n.startswith("m")}
        for ctx in self.ctx.values():
            ctx.endpoint = self.cert["target"]
        self.c = Cluster(base, binary)
        stack.callback(self.c.close)
        for i in range(3):
            self.c.start(i)
        self.c.wait([0, 1, 2])
        self.c.secure()
        self.roles = {}
        self.service_pids = {}
        enrolled = {}
        for n, kind in (
            ("owner", "owner"),
            ("verifier", "verifier"),
            ("a", "executor"),
            ("b", "executor"),
        ):
            rpc_proc = self.spawn(
                box(
                    "roles", [("--ro-bind", base / ("service-" + n), "/identity")], True
                )
                + [kind, self.cert["control-" + n]]
            )
            ready = line(rpc_proc)
            self.service_pids["signer-" + n] = reader_pid(rpc_proc)
            ctx = self.ctx["control-" + n]
            ctx.endpoint = self.cert["service-" + n]
            self.roles[n] = (ready["port"], ctx)
            enrolled[n] = ready["identity"]
        v = enrolled["verifier"]
        self.v = v
        self.trust = dict(
            schema="wolfalibi.shirudo.action-trust.v1",
            target_id=v["policy"]["target_id"],
            policy=v["policy"],
            owner_public_key=enrolled["owner"],
            verifier_public_key=v["key"],
            verifier_instance_id=v["instance"],
        )
        self.state = base / "counter"
        native = Gate.initialize(self.state, self.trust)
        identity = native.public_identity()
        del native
        self.gate = identity["gate_instance_id"]
        self.keys = {n: enrolled[n] for n in "ab"}
        self.config = dict(
            members=self.c.clients,
            member_pins={
                str(port): self.cert[f"m{i}"] for i, port in enumerate(self.c.clients)
            },
            holders={self.keys[n]: self.cert[n] for n in "ab"},
            preparer=self.cert["coordinator"],
            principal=self.cert["alice"],
        )
        cfg = base / "config.json"
        save(cfg, self.config)
        token = base / "token"
        token.write_text(self.c.reader.token)
        self.target_args = box(
            "wire",
            [
                ("--bind", self.state, "/state"),
                ("--ro-bind", base / "target", "/identity"),
                ("--ro-bind", cfg, "/public.json"),
                ("--ro-bind", token, "/token"),
            ],
            True,
        )
        self.proc = self.spawn(self.target_args, True)
        ready = line(self.proc)
        self.boot, self.port = ready["boot"], ready["port"]
        self.pid = reader_pid(self.proc)
        self.orders = []
        self.ops = {}
        self.faults = {}
        self.replies = {}
        self.times = []
        self.idx = 0
        self.prev = ZERO
        self.epoch = 0
        self.holder = None
        save(
            out / "enrollment.json",
            dict(
                trust=self.trust,
                identity=identity,
                holders=self.keys,
                cert=self.cert,
                boot=self.boot,
                cluster=self.c.status(0)["header"]["cluster_id"],
            ),
        )

    def spawn(self, args, limit=False):
        p = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=0,
            preexec_fn=gate_limits if limit else None,
        )
        self.stack.callback(stop, p)
        return p

    def sign(self, n, p):
        with Session(*self.roles[n]) as peer:
            return peer.call(p)

    def call(self, role, body):
        with Session(self.port, self.ctx[role]) as s:
            return s.call(body)

    def proposal(self, holder, revoked=None):
        return self.sign(
            "owner",
            dict(
                schema="wolfalibi.sovereign.order.v1",
                target=self.trust["target_id"],
                gate=self.gate,
                boot=self.boot,
                previous=self.prev,
                index=self.idx + 1,
                epoch=self.epoch + int(revoked is None),
                kind="activate" if revoked is None else "revoke",
                holder=self.keys[holder],
                revoked=revoked,
            ),
        )

    def publish(self, doc, i=0):
        t = time.monotonic_ns()
        assert write(self.c.clients[i], self.c.writer, self.idx + 1, doc)
        self.times.append(dict(kind="quorum-order", ns=time.monotonic_ns() - t))

    def install(self, doc):
        t = time.monotonic_ns()
        r = self.call("coordinator", dict(op="sync"))
        assert r["state"] == "APPLIED", r
        ack = verify_record(r["ack"], self.boot)
        assert ack["order"] == digest(doc)
        self.times.append(dict(kind="target-install", ns=time.monotonic_ns() - t))
        self.idx += 1
        self.prev = digest(doc)
        self.epoch = ack["epoch"]
        self.holder = doc["payload"]["holder"]
        self.orders.append(dict(command=doc, ack=r["ack"]))

    def order(self, h, rev=None, i=0):
        d = self.proposal(h, rev)
        self.publish(d, i)
        self.install(d)

    def material(self, name, role):
        chall = self.sign("verifier", "collect")
        act = self.call("coordinator", dict(op="prepare", challenge=chall))
        assess = self.sign("verifier", chall)
        grant = self.sign(
            "owner",
            make_grant_payload(
                act,
                assess,
                grant_id=secrets.token_hex(16),
                issued_at_ms=time.time_ns() // 1000000,
                expires_at_ms=act["payload"]["expires_at_ms"],
            ),
        )
        op = act["payload"]["operation_id"]
        req = dict(operation_id=op, grant=grant, assessment=assess)
        common = dict(
            target=self.trust["target_id"],
            gate=self.gate,
            boot=self.boot,
            op=op,
            request=digest(req),
        )
        permit = self.sign(
            "owner",
            dict(
                common,
                schema="wolfalibi.sovereign.permit.v1",
                epoch=self.epoch,
                head=self.prev,
                holder=self.keys[role],
                grant=digest(grant),
            ),
        )
        frame = dict(
            request=req,
            permit=permit,
            sender=self.sign(
                role,
                dict(
                    schema="wolfalibi.sovereign.submit.v1",
                    permit=digest(permit),
                    request=digest(req),
                ),
            ),
        )
        binding = self.sign(
            "owner",
            dict(
                common,
                schema="wolfalibi.sovereign.recover.v1",
                principal=self.cert["alice"],
                grant=grant["payload"]["grant_id"],
            ),
        )
        assert (
            self.call("coordinator", dict(op="enroll", frame=frame, binding=binding))[
                "state"
            ]
            == "ENROLLED"
        )
        self.ops[name] = dict(frame=frame, binding=binding, challenge=chall, action=act)
        return frame

    def execute(self, name, role):
        t = time.monotonic_ns()
        r = self.call(role, dict(op="execute", frame=self.ops[name]["frame"]))
        self.times.append(
            dict(kind="execution-attempt", name=name, ns=time.monotonic_ns() - t)
        )
        return r

    def observe(self):
        with closing(
            sqlite3.connect(
                (self.state / "journal.sqlite3").as_uri() + "?mode=ro", uri=True
            )
        ) as c:
            c.row_factory = sqlite3.Row
            c.execute("BEGIN")
            return {
                t: [dict(r) for r in c.execute(f"SELECT * FROM {t} ORDER BY rowid")]
                for t in (
                    "counter",
                    "commands",
                    "operations",
                    "settlements",
                    "revoked_grants",
                    "bindings",
                    "recovery_acl",
                )
            }

    def functional(self):
        self.order("a")
        self.material("original", "a")
        self.replies["original"] = self.execute("original", "a")
        assert self.replies["original"].get("result") == "COMMITTED", self.replies[
            "original"
        ]
        shutil.copyfile(self.state / "journal.sqlite3", self.base / "early.sqlite3")
        self.material("revoked", "a")
        self.material("racing", "a")
        # Stop inside native SQLite after the tentative counter and receipt writes.
        self.proc.stdin.write(b"arm\n")
        self.proc.stdin.flush()
        assert line(self.proc)["event"] == "armed"
        rev = self.proposal(
            "a", self.ops["racing"]["frame"]["request"]["grant"]["payload"]["grant_id"]
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            effect = pool.submit(self.execute, "racing", "a")
            held = line(self.proc)
            self.publish(rev)
            start = time.monotonic_ns()
            # Interrupt the directory while the target owns its writer.
            for i in range(3):
                self.c.pause(i)
            try:
                self.proc.stdin.write(b"release\n")
                self.proc.stdin.flush()
                self.replies["inflight"] = effect.result(5)
                assert self.replies["inflight"]["result"] == "COMMITTED"
                self.replies["quorum-down"] = self.execute("revoked", "a")
                assert (
                    self.replies["quorum-down"].get("reason") == "QUORUM_UNAVAILABLE"
                ), self.replies["quorum-down"]
            finally:
                for i in range(3):
                    self.c.resume(i)
            self.c.wait([0, 1, 2])
            self.install(rev)
            self.faults["settlement"] = dict(
                held=held, unavailable_ns=time.monotonic_ns() - start
            )
        self.order(
            "a", self.ops["revoked"]["frame"]["request"]["grant"]["payload"]["grant_id"]
        )
        self.replies["revoked"] = self.execute("revoked", "a")
        assert self.replies["revoked"]["state"] == "DENIED"
        self.material("delayed", "a")
        # Two independently authorized, contradictory candidates race for one slot.
        proposals = [self.proposal(h) for h in "ab"]
        barrier = threading.Barrier(2)

        def contend(i):
            barrier.wait()
            return write(self.c.clients[i], self.c.writer, self.idx + 1, proposals[i])

        with ThreadPoolExecutor(max_workers=2) as pool:
            wins = list(pool.map(contend, [0, 1]))
        assert wins.count(True) == 1
        winner = wins.index(True)
        self.install(proposals[winner])
        self.faults["conflict"] = dict(candidates=proposals, accepted=wins)
        self.replies["replay-cas"] = write(
            self.c.clients[0], self.c.writer, self.idx, proposals[winner]
        )
        assert not self.replies["replay-cas"]
        ids = [self.c.status(i)["header"]["member_id"] for i in range(3)]
        old = ids.index(self.c.status(0)["leader"])
        others = [i for i in range(3) if i != old]
        self.c.partition(old, False)
        begin = time.monotonic_ns()
        try:
            # old leader's clients remain reachable, but all six directions
            # crossing the minority cut are controlled by the fixture.
            until = time.monotonic() + 12
            while time.monotonic() < until:
                try:
                    new = self.c.status(others[0])["leader"]
                    if (
                        new
                        and new != "0"
                        and new != ids[old]
                        and read(self.c.clients[others[0]], self.c.auditor, self.idx)
                    ):
                        break
                except (OSError, RuntimeError):
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("no replacement leader")
            d = self.proposal("b")
            self.publish(d, others[0])
            self.install(d)
            try:
                read(self.c.clients[old], self.c.auditor, self.idx, 0.6)
            except (OSError, RuntimeError):
                minority = "UNAVAILABLE"
            else:
                raise AssertionError("minority produced linearizable read")
            stale = rpc(
                self.c.clients[old],
                self.c.auditor,
                "kv/range",
                dict(key=key(self.idx), serializable=True),
            )
            assert not stale.get("kvs")
            self.faults["partition"] = dict(
                old=ids[old],
                replacement=new,
                minority=minority,
                stale_revision=stale["header"]["revision"],
                unavailable_ns=time.monotonic_ns() - begin,
            )
        finally:
            self.c.partition(old, True)
        self.c.wait([0, 1, 2])
        self.replies["late"] = self.execute("delayed", "a")
        assert self.replies["late"]["reason"] == "STALE_EXECUTOR"
        self.material("lost", "b")
        args = box("client", [("--ro-bind", self.base / "b", "/identity")], True)
        client = self.spawn(args)
        body = dict(
            lose=True,
            port=self.port,
            endpoint=self.cert["target"],
            body=dict(op="execute", frame=self.ops["lost"]["frame"]),
        )
        send(client, body)
        assert line(client) == dict(sent=True)
        stop(client)
        # Original coordinator is gone. Wait only for independently observable settlement.
        until = time.monotonic() + 5
        while self.observe()["counter"][0]["value"] != 3:
            if time.monotonic() > until:
                raise TimeoutError("lost reply settlement")
            time.sleep(0.01)
        replacement = self.spawn(args)
        send(replacement, dict(body, lose=False))
        self.replies["retry"] = line(replacement)
        assert self.replies["retry"]["result"] == "ALREADY_COMMITTED"
        self.material("pending", "b")
        self.replies["cross-principal"] = self.call(
            "bob", dict(op="recover", binding=self.ops["lost"]["binding"])
        )
        assert self.replies["cross-principal"] == dict(
            state="UNRESOLVED", reason="ACCESS_DENIED"
        )

    def finish(self):
        for n, d in (
            ("orders", self.orders),
            ("materials", self.ops),
            ("replies", self.replies),
            ("faults", self.faults),
            ("times", self.times),
            ("oracle", self.observe()),
        ):
            save(self.out / (n + ".json"), d)
        copies = [
            [read(port, self.c.auditor, i + 1) for i in range(self.idx)]
            for port in self.c.clients
        ]
        assert all(v == [r["command"] for r in self.orders] for v in copies)
        save(self.out / "quorum-audit.json", copies)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument("--etcd", required=True, type=Path)
    p.add_argument("--stress", action="store_true")
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory() as t, ExitStack() as s:
        lab = Trial(Path(t), out, s, a.etcd)
        lab.functional()
        if a.stress:
            from research.sovereign.workload import stress

            stress(lab)
        from research.sovereign.failures import exercise

        exercise(lab)
        lab.finish()
        from research.sovereign.history import historical_trial

        historical_trial(lab)


if __name__ == "__main__":
    main()
