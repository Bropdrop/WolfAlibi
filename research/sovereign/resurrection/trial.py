"""Local stationary-target recovery experiment with fresh disposable custody."""

import argparse, hashlib, json, os, shutil, signal, sqlite3, subprocess, tempfile, time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from pathlib import Path
from research.blackout.experiment import reader_pid
from research.sovereign.cluster import rpc, write, key
from research.sovereign.failures import backup
from research.sovereign.history import FILES
from research.sovereign.trial import Trial, box, save
from research.sovereign.wire import Session
from research.sovereign.resurrection.gate import seal, schema_hash
from research.sovereign.resurrection.witness import AUTH
from research.wt_swarm.run import send, line, stop, gate_limits
from shirudo_adapter.model import canonical_json, digest
from shirudo_adapter.receipt import verify_record


class Lab(Trial):
    extra_identities = ("witness", "witness-probe")

    def recovery(self, name, role="alice"):
        return self.call(role, dict(op="recover", binding=self.ops[name]["binding"]))

    def commission(self):
        self.order("a")
        for n in ("lost", "pending", "revoked"):
            self.material(n, "a")
        self.replies["lost"] = self.execute("lost", "a")
        self.db = self.state / "journal.sqlite3"
        self.enrollment = json.loads((self.out / "enrollment.json").read_bytes())
        with closing(sqlite3.connect(self.db, isolation_level=None)) as c:
            c.execute("BEGIN IMMEDIATE")
            r = self.recovery("lost")
            proof = verify_record(r["proof"], self.boot)
            assert (
                proof["state"] == "COMMITTED"
                and proof["binding"] == digest(self.ops["lost"]["binding"])
                and r["receipt"] == self.replies["lost"]["receipt"]
            )
            self.offline = time.monotonic_ns()
            stop(self.proc)
            s = self.db.stat()
            self.pin = dict(
                owner=self.trust["owner_public_key"],
                native=self.enrollment["identity"]["public_key"],
                origin=self.boot,
                target=self.trust["target_id"],
                gate=self.gate,
                volume=[s.st_dev, s.st_ino],
                enrollment=digest(self.enrollment),
                initial_seal=seal(c),
                schema_hash=schema_hash(c),
            )
            c.rollback()
        self.store = self.base / "witness-store"
        self.store.mkdir()
        self.witness = self.spawn(
            box(
                "resurrection.witness",
                [
                    ("--bind", self.store, "/store"),
                    ("--ro-bind", self.base / "witness", "/identity"),
                ],
                True,
            )
            + [self.cert["target"]]
        )
        send(
            self.witness,
            dict(pin=self.pin, boot=self.boot, seal=self.pin["initial_seal"]),
        )
        ready = line(self.witness)
        self.wkey = ready["identity"]
        probe = self.spawn(
            box(
                "resurrection.probe",
                [
                    ("--ro-bind", self.store, "/store"),
                    ("--ro-bind", self.base / "witness-probe", "/identity"),
                ],
                True,
            )
            + [self.cert["auditor"]]
        )
        self.wpport = line(probe)["port"]
        self.config.update(
            recovery_pin=self.pin,
            witness_port=ready["port"],
            witness_tls=self.cert["witness"],
            witness_key=self.wkey,
        )
        save(self.base / "config.json", self.config)
        self.args = [
            (
                "research.sovereign.resurrection.gate"
                if v == "research.sovereign.wire"
                else v
            )
            for v in self.target_args
        ]
        self.jumps = []
        self.offline_orders = []
        self.initial_journal = self.observe()
        save(
            self.out / "commission.json",
            dict(pin=self.pin, public=self.wkey, proof=r, initial=self.initial_journal),
        )
        backup(self.db, self.base / "original.db")

    def records(self):
        with closing(
            sqlite3.connect(
                (self.store / "reservations.sqlite3").as_uri() + "?mode=ro", uri=True
            )
        ) as c:
            return [
                json.loads(s)
                for (s,) in c.execute(
                    "SELECT record FROM reservations ORDER BY version"
                )
            ]

    def launch(self, args):
        p = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            preexec_fn=gate_limits,
        )
        self.stack.callback(stop, p)
        return p

    def process(self, args):
        return self.ready(self.launch(args))

    def ready(self, p):
        data = p.stdout.readline()
        if data:
            return p, json.loads(data)
        p.wait(8)
        error = p.stderr.read()
        try:
            return p, json.loads(error)
        except ValueError:
            raise RuntimeError(error.decode())

    def start(self, race=False):
        t = time.monotonic_ns()
        self.cold_started = t
        if race:
            candidates = [self.launch(self.args) for _ in range(2)]
            pair = [self.ready(candidate) for candidate in candidates]
            accepted = [v for v in pair if "port" in v[1]]
            assert len(accepted) == 1, pair
            rejected = next(v for _, v in pair if "port" not in v)
            assert rejected["reason"] == "WRITER_HELD", rejected
            self.faults["concurrent"] = rejected
            self.proc, ready = accepted[0]
        else:
            self.proc, ready = self.process(self.args)
        assert "port" in ready, ready
        self.port = ready["port"]
        self.boot = ready["boot"]
        self.pid = reader_pid(self.proc)
        self.times.append(dict(kind="startup", ns=time.monotonic_ns() - t))

    def rejected(self, reason, args=None):
        _, answer = self.process(args or self.args)
        assert answer == dict(startup="RECOVERY_UNRESOLVED", reason=reason), answer
        return answer

    def leader_loss(self):
        c = self.c
        ids = [c.status(i)["header"]["member_id"] for i in range(3)]
        leader = ids.index(c.status(0)["leader"])
        survivors = [i for i in range(3) if i != leader]
        os.kill(c.pids[leader], signal.SIGKILL)
        c.procs[leader].wait(6)
        c.wait(survivors)
        replacement = c.status(survivors[0])["leader"]
        assert replacement != ids[leader]
        c.start(leader)
        until = time.monotonic() + 12
        while True:
            try:
                c.ctx.token = rpc(
                    c.clients[leader],
                    c.ctx,
                    "auth/authenticate",
                    dict(name="root", password=c.passwords["root"]),
                )["token"]
                break
            except (OSError, RuntimeError):
                if time.monotonic() > until:
                    raise
                time.sleep(0.08)
        c.wait(survivors + [leader])
        for n, ctx in (
            ("publisher", c.writer),
            ("auditor", c.auditor),
            ("target", c.reader),
        ):
            ctx.token = rpc(
                c.clients[leader],
                ctx,
                "auth/authenticate",
                dict(name=n, password=c.passwords[n]),
            )["token"]
        (self.base / "token").write_text(c.reader.token)
        self.faults["leader-downtime"] = [ids[leader], replacement]
        minority = next(i for i in survivors if ids[i] != replacement)
        c.partition(minority, False)
        try:
            grant = self.ops["revoked"]["frame"]["request"]["grant"]["payload"][
                "grant_id"
            ]
            d = self.proposal("a", grant)
            assert write(c.clients[ids.index(replacement)], c.writer, self.idx + 1, d)
            self.offline_orders = [d]
            stale = rpc(
                c.clients[minority],
                c.auditor,
                "kv/range",
                dict(key=key(self.idx + 1), serializable=True),
            )
            assert not stale.get("kvs")
            self.faults["stale-minority"] = stale["header"]["revision"]
        finally:
            c.partition(minority, True)
        c.wait([0, 1, 2])

    def plan(self, holder):
        records = self.records()
        last = self.idx + len(self.offline_orders) + 1
        epoch = (
            self.epoch
            + 1
            + sum(d["payload"]["kind"] == "activate" for d in self.offline_orders)
        )
        prev = digest(self.offline_orders[-1]) if self.offline_orders else self.prev
        doc = self.sign(
            "owner",
            dict(
                schema="wolfalibi.sovereign.order.v1",
                target=self.pin["target"],
                gate=self.gate,
                boot=self.boot,
                previous=prev,
                index=last,
                epoch=epoch,
                kind="activate",
                holder=self.keys[holder],
                revoked=None,
            ),
        )
        assert write(self.c.clients[0], self.c.writer, last, doc)
        with Session(self.probe_port, self.c.auditor) as probe:
            observed = probe.call("sealed-snapshot")
        j = observed["journal"]
        self.before_snapshot = j
        self.before_seal = observed["seal"]
        auth = self.sign(
            "owner",
            dict(
                schema=AUTH,
                parent=digest(records[-1]),
                boot=self.boot,
                target=self.pin["target"],
                gate=self.gate,
                volume=self.pin["volume"],
                snapshot=digest(j),
                command=digest(doc),
                first=self.idx + 1,
                last=last,
                epoch=epoch,
            ),
        )
        return dict(
            history=records, materials=self.ops, enrollment=self.enrollment, auth=auth
        ), doc

    def control(self, plan):
        send(self.proc, plan)
        return line(self.proc, 30)

    def activate_new(self, holder, exercise=False, old=None):
        plan, doc = self.plan(holder)
        if old:
            r = self.control(old)
            assert r["state"] == "RECOVERY_UNRESOLVED", r
            self.faults["replayed-activation"] = r
        if exercise:
            for i in range(3):
                self.c.pause(i)
            try:
                r = self.control(plan)
                assert r.get("reason") == "QUORUM_UNAVAILABLE", r
                self.faults["partition"] = r
            finally:
                for i in range(3):
                    self.c.resume(i)
                self.c.wait([0, 1, 2])
            wrong = dict(plan, materials={})
            r = self.control(wrong)
            assert r["state"] == "RECOVERY_UNRESOLVED", r
            self.faults["missing-material"] = r
        r = self.control(plan)
        assert r["state"] == "ACTIVE", r
        self.jumps.append(
            dict(
                before=self.before_snapshot,
                before_seal=self.before_seal,
                cold_ns=time.monotonic_ns() - self.cold_started,
                auth=plan["auth"],
                result=r,
                unavailable_ns=time.monotonic_ns() - self.offline,
            )
        )
        j = self.observe()
        self.idx = len(j["commands"])
        self.epoch = doc["payload"]["epoch"]
        self.prev = digest(doc)
        self.holder = self.keys[holder]
        self.offline_orders = []
        self.orders = [
            dict(
                command=json.loads(row["command"]),
                ack=json.loads(row["acknowledgement"]),
            )
            for row in j["commands"]
        ]
        return plan

    def scenario(self, stress):
        self.commission()
        self.leader_loss()
        self.start(race=True)
        # Interrupt a genuinely authorized candidate before installation.
        abandoned, ordered = self.plan("b")
        self.faults["interrupted-recovery"] = abandoned["auth"]
        self.offline_orders.append(ordered)
        stop(self.proc)
        self.start()
        if stress:
            from research.sovereign.resurrection.load import overlap

            overlap(self)
        assert self.execute("pending", "a").get("reason") == "RECOVERY_CLOSED"
        first = self.activate_new("b", exercise=True)
        assert self.recovery("lost")["receipt"] == self.replies["lost"]["receipt"]
        assert (
            self.recovery("revoked")["state"] == "NOT_COMMITTED"
            and self.recovery("pending")["state"] == "UNRESOLVED"
        )
        self.faults["retired-first"] = self.execute("pending", "a")
        assert self.faults["retired-first"]["state"] == "DENIED"
        for n in ("new-lost", "crash"):
            self.material(n, "b")
        # Send a real native submission and discard its acknowledgement.
        with Session(self.port, self.ctx["b"]) as sock:
            sock.peer.sendall(
                canonical_json(dict(op="execute", frame=self.ops["new-lost"]["frame"]))
                + b"\n"
            )
        until = time.monotonic() + 8
        while self.observe()["counter"][0]["value"] != 2:
            if time.monotonic() > until:
                raise TimeoutError("settlement")
            time.sleep(0.01)
        self.proc.stdin.write(b"arm\n")
        self.proc.stdin.flush()
        assert line(self.proc)["event"] == "armed"
        with ThreadPoolExecutor(1) as pool:
            task = pool.submit(self.execute, "crash", "b")
            held = line(self.proc)
            assert held["event"] == "native_writer_held"
            self.offline = time.monotonic_ns()
            os.kill(self.pid, signal.SIGKILL)
            self.proc.wait(6)
            try:
                task.result(6)
            except OSError:
                pass
            else:
                raise AssertionError("received interrupted commit reply")
        self.faults["interrupted-settlement"] = held
        # Allow SQLite to recover any hot rollback journal in the original volume.
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("BEGIN IMMEDIATE")
            c.rollback()
        backup(self.db, self.base / "latest.db")
        clone = self.base / "clone"
        shutil.copytree(self.state, clone)
        self.faults["cloned-credentials"] = self.rejected(
            "VOLUME_IDENTITY",
            [str(clone) if v == str(self.state) else v for v in self.args],
        )
        backup(self.base / "original.db", self.db)
        self.faults["outdated-epoch"] = self.rejected("TARGET_ROLLBACK")
        backup(self.base / "latest.db", self.db)
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("DELETE FROM settlements WHERE seq=2")
            c.commit()
        self.faults["missing-settlement"] = self.rejected("TARGET_ROLLBACK")
        backup(self.base / "latest.db", self.db)
        self.start()
        self.activate_new("a", old=first)
        assert self.recovery("crash")["state"] == "UNRESOLVED"
        self.replies["new-lost"] = self.recovery("new-lost")
        assert self.replies["new-lost"]["state"] == "COMMITTED"
        self.faults["retired-second"] = self.execute("crash", "b")
        assert self.faults["retired-second"]["state"] == "DENIED"
        self.material("fresh", "a")
        self.replies["fresh"] = self.execute("fresh", "a")
        assert self.replies["fresh"]["result"] == "COMMITTED", self.replies["fresh"]
        self.replies["outsider"] = self.recovery("new-lost", "bob")
        assert self.replies["outsider"] == dict(
            state="UNRESOLVED", reason="ACCESS_DENIED"
        )
        if stress:
            from research.sovereign.resurrection.load import storm

            storm(self)
        self.material("uncertain", "a")
        self.audit_context = dict(
            witness_probe_port=self.wpport,
            witness_probe_tls=self.cert["witness-probe"],
            resurrection=dict(pin=self.pin, public=self.wkey, records=self.records()),
        )
        self.finish()
        save(self.out / "resurrection.json", self.audit_context["resurrection"])
        save(self.out / "activations.json", self.jumps)
        # D: retain a separately authenticated historical endpoint; remove the
        # entire working database only after the auditor captured its evidence.
        data = {
            n: (self.out / (n + ".json")).read_text() for n in (*FILES, "resurrection")
        }
        pins = {n: hashlib.sha256(b.encode()).hexdigest() for n, b in data.items()}
        archive = self.spawn(
            box("history", [("--ro-bind", self.base / "history", "/identity")], True)
            + [json.dumps(pins)]
        )
        send(archive, data)
        port = line(archive)["port"]
        self.proc.stdin.write(b"arm-reservation\n")
        self.proc.stdin.flush()
        assert line(self.proc)["event"] == "reservation-armed"
        with ThreadPoolExecutor(1) as pool:
            job = pool.submit(self.execute, "uncertain", "a")
            held = line(self.proc)
            assert held["event"] == "native_writer_held"
            os.kill(self.pid, signal.SIGKILL)
            self.proc.wait(6)
            try:
                job.result(6)
            except OSError:
                pass
            else:
                raise AssertionError("unsettled intent returned")
        self.faults["unsettled-intent"] = self.records()[-1]
        with closing(sqlite3.connect(self.db)) as c:
            c.execute("BEGIN IMMEDIATE")
            c.rollback()
        self.faults["reservation-gap"] = self.rejected("TARGET_ROLLBACK")
        moved = self.base / "lost-volume"
        self.db.rename(moved)
        self.faults["missing-volume"] = self.rejected("STORAGE_UNAVAILABLE")
        results = {}
        for principal, n in (
            ("alice", "new-lost"),
            ("alice", "lost"),
            ("alice", "revoked"),
            ("alice", "crash"),
            ("alice", "uncertain"),
            ("bob", "new-lost"),
        ):
            ctx = self.ctx[principal]
            ctx.endpoint = self.cert["history"]
            with Session(port, ctx) as s:
                results[principal + "/" + n] = s.call(self.ops[n]["binding"])
            ctx.endpoint = self.cert["target"]
        assert (
            results["alice/new-lost"]["receipt"] == self.replies["new-lost"]["receipt"]
            and results["alice/crash"]["state"] == "UNRESOLVED"
            and results["bob/new-lost"] == dict(state="UNRESOLVED")
        )
        save(self.out / "historical.json", results)
        self.db.parent.mkdir(exist_ok=True)
        moved.rename(self.db)
        stop(self.witness)
        self.faults["witness-unavailable"] = self.rejected("WITNESS_UNAVAILABLE")
        self.db.rename(moved)
        self.faults["all-unavailable"] = self.rejected("STORAGE_UNAVAILABLE")
        save(self.out / "faults.json", self.faults)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("out", type=Path)
    p.add_argument("--etcd", required=True, type=Path)
    p.add_argument("--stress", action="store_true")
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory() as t, ExitStack() as s:
        Lab(Path(t), a.out.resolve(), s, a.etcd).scenario(a.stress)


if __name__ == "__main__":
    main()
