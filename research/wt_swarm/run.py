"""Run WT-SWARM-001 on a new private local gate. Linux, Python 3.11+, bwrap."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import select
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

import cryptography
from research.wt_swarm.baseline import PIN as BASE
from scripts.wt_alibi_human_oracle import observe
from shirudo_adapter.model import canonical_json

ROOT = Path(__file__).resolve().parents[2]
CLI = [sys.executable, "-B", "-m", "shirudo_adapter.action_gate_cli"]
LAB = "research.wt_swarm."
LIMITS = {"nofile": 64, "address_space_bytes": 512 * 1024**2}


def save(path, data):
    path.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n")


def gate_limits():
    resource.setrlimit(resource.RLIMIT_NOFILE, (LIMITS["nofile"],) * 2)
    resource.setrlimit(resource.RLIMIT_AS, (LIMITS["address_space_bytes"],) * 2)


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(3)
    for stream in (proc.stdin, proc.stdout):
        if stream:
            stream.close()


def line(proc, timeout=12):
    if not select.select([proc.stdout], [], [], timeout)[0]:
        raise TimeoutError("timed out waiting for lab event")
    data = proc.stdout.readline()
    if not data:
        raise RuntimeError(f"missing lab event, process exit {proc.poll()}")
    return json.loads(data)


def send(proc, value):
    proc.stdin.write(canonical_json(value) + b"\n")
    proc.stdin.flush()


def command(proc, text):
    proc.stdin.write((text + "\n").encode())
    proc.stdin.flush()


def sandbox(role, endpoint=None):
    # No host home, role state, git metadata, host procfs or inherited environment.
    args = ["bwrap", "--die-with-parent", "--unshare-all", "--clearenv",
            "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
            "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/bin", "/bin",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chmod", "0700", "/tmp"]
    if Path("/lib64").exists():
        args += ["--symlink", "usr/lib64", "/lib64"]
    for prefix in sorted({sys.base_prefix, sys.prefix}):
        if not Path(prefix).is_relative_to("/usr"):
            args += ["--ro-bind", prefix, prefix]
    for name in ["shirudo_adapter", "scripts", "tests", "research/wt_swarm"]:
        args += ["--ro-bind", str(ROOT / name), "/src/" + name]
    if endpoint:
        args += ["--ro-bind", str(endpoint), "/endpoint"]
    return args + ["--chdir", "/src", sys.executable, "-B", "-m", LAB + role]


def proc_sample(pid):
    proc = Path("/proc") / str(pid)
    fields = dict(s.split(":", 1) for s in (proc / "status").read_text().splitlines() if ":" in s)
    return dict(time_ns=time.monotonic_ns(), threads=int(fields["Threads"]),
                fds=len(list((proc / "fd").iterdir())), rss_kib=int(fields["VmRSS"].split()[0]),
                peak_rss_kib=int(fields["VmHWM"].split()[0]))


class Run:
    def __init__(self, private, out, cleanup):
        self.out, self.cleanup = out, cleanup
        self.endpoint = private / "socket"
        self.endpoint.mkdir(mode=0o700)
        self.state = private / "gate"
        self.journal = self.state / "journal.sqlite3"
        self.gate = None
        self.materials = {}
        self.faults = {}
        self.snapshots = {}
        self.replies = {}
        self.inventory = {}

    def spawn(self, args, **kwargs):
        proc = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                bufsize=0, **kwargs)
        self.cleanup.callback(stop, proc)
        return proc

    def setup(self):
        self.owner = self.spawn(sandbox("roles") + ["owner"])
        self.verifier = self.spawn(sandbox("roles") + ["verifier"])
        owner, verifier = line(self.owner), line(self.verifier)
        trust = {"schema": "wolfalibi.shirudo.action-trust.v1", "target_id": verifier["policy"]["target_id"],
                 "owner_public_key": owner["public_key"], "verifier_public_key": verifier["public_key"],
                 "policy": verifier["policy"], "verifier_instance_id": verifier["instance_id"]}
        path = self.state.parent / "trust.json"
        save(path, trust)
        init = subprocess.check_output(CLI + ["init", "--state", self.state, "--trust", path], cwd=ROOT)
        identity = json.loads(init)["identity"]
        profile = dict(trust, schema="wolfalibi.shirudo.owner-profile.v1",
                       gate_instance_id=identity["gate_instance_id"], gate_public_key=identity["public_key"],
                       policy_generation=identity["policy_generation"])
        save(self.out / "profile.json", profile)
        send(self.owner, profile)
        if line(self.owner) != "pinned":
            raise RuntimeError("missing owner pin")
        self.start_gate()
        save(self.out / "custody.json", {"owner": owner["custody"], "verifier": verifier["custody"],
             "executor": self.call({"state": str(self.state)}, "custody")})
        self.snapshot("initial")

    def start_gate(self, mode="normal"):
        if self.gate:
            stop(self.gate)
        sock = self.endpoint / "gate.sock"
        if mode in ("contention", "duplicates", "overload"):
            args = [sys.executable, "-B", "-m", LAB + "admission", self.state, sock,
                    self.out / (mode + "-admission.jsonl")]
        elif mode in ("held-gate", "gate"):
            args = [sys.executable, "-B", "-m", LAB + "boundary", mode, self.state, sock]
        else:
            args = CLI + ["serve", "--state", self.state, "--socket", sock, "--replace-stale-socket"]
            if mode != "normal":
                args += [f"--exit-{mode}-commit-once"]
        self.gate = self.spawn(args, preexec_fn=gate_limits)
        if line(self.gate).get("status") != "READY":
            raise RuntimeError("gate did not become ready")

    def client(self, mode, data):
        p = self.spawn(sandbox("client", self.endpoint) + [mode])
        send(p, data)
        return p

    def call(self, doc, mode="rpc"):
        p = self.client(mode, doc)
        reply = line(p)
        if p.wait(5):
            raise RuntimeError("client exited unsuccessfully")
        return reply

    def snapshot(self, name):
        self.snapshots[name] = observe(self.journal)
        with sqlite3.connect(self.journal.as_uri() + "?mode=ro", uri=True) as con:
            con.execute("PRAGMA query_only=ON")
            con.execute("BEGIN")
            self.inventory[name] = {"operations": dict(con.execute("SELECT id,status FROM operations")),
                                    "revocations": dict(con.execute("SELECT id,revoked_at_ms FROM revoked_grants"))}
        save(self.out / "inventory.json", self.inventory)
        save(self.out / "journal.json", self.snapshots)

    def material(self, name, signed=True):
        if signed:
            send(self.owner, "begin")
            review = line(self.owner)
        send(self.verifier, "collect")
        evidence = line(self.verifier)
        prepared = self.call({"op": "prepare", "attestation_challenge": evidence["challenge"]})
        action = prepared["action_challenge"]
        bundle = {"attestation_challenge": evidence["challenge"], "action_challenge": action,
                  "assessment": evidence["assessment"]}
        grant = None
        if signed:
            bundle.update(schema="wolfalibi.shirudo.owner-bundle.v1", request_id=review["intent"]["request_id"])
            send(self.owner, bundle)
            grant = line(self.owner)["grant"]
        req = dict(operation_id=action["payload"]["operation_id"], assessment=evidence["assessment"], grant=grant)
        self.materials[name] = {"request": req, "bundle": bundle, "owner_review": review if signed else None}
        save(self.out / "materials.json", self.materials)
        return req

    def batch(self, name, docs):
        self.start_gate(name)
        if name == "contention":
            # Hold this new idle daemon until every independently scheduled
            # worker has entered its attempt and owns a distinct live socket.
            os.kill(self.gate.pid, signal.SIGSTOP)
            os.waitid(os.P_PID, self.gate.pid, os.WSTOPPED)
            paused = time.monotonic_ns()
        try:
            p = self.client(name, docs)
            if name == "contention":
                opened = line(p, 45)
                if opened.get("phase") != "all_sockets_open" or opened["count"] != 1000:
                    raise RuntimeError("missing 1,000 live sockets")
        finally:
            if name == "contention":
                resumed = time.monotonic_ns()
                os.kill(self.gate.pid, signal.SIGCONT)
        if name == "contention":
            self.faults["contention"] = dict(paused_ns=paused, opened=opened, resume_ns=resumed)
        samples = []
        deadline = time.monotonic() + 180
        while not select.select([p.stdout], [], [], 0.01)[0]:
            samples.append(proc_sample(self.gate.pid))
            if time.monotonic() >= deadline:
                raise TimeoutError(name)
        batch = line(p)
        if p.wait(5):
            raise RuntimeError("worker group failed")
        save(self.out / (name + ".json"), batch)
        save(self.out / (name + "-resources.json"), samples + [proc_sample(self.gate.pid)])
        self.replies[name + "-health"] = self.call({"op": "status", "operation_id": None})
        self.start_gate()

    def submit(self, name, req):
        self.replies[name] = self.call({"op": "execute", "request": req})

    def status(self, name, req):
        self.replies[name] = self.call({"op": "status", "operation_id": req["operation_id"]})

    def load_cases(self):
        docs = [self.material("compete-" + str(i)) for i in range(4)]
        self.batch("contention", docs)
        self.snapshot("after_contention")
        # Recover only using the original, frozen requests. Retain separate replies.
        for i, req in enumerate(docs):
            self.status("compete-status-" + str(i), req)
            self.submit("compete-retry-" + str(i), req)
        self.snapshot("after_retries")
        single = self.material("duplicates")
        self.batch("duplicates", [single])
        self.snapshot("after_duplicates")
        self.submit("changed_retry", dict(docs[0], grant=None))
        withheld = self.material("withheld", signed=False)
        self.replies["votes"] = self.call(withheld, "votes")
        self.submit("assessment_as_grant", dict(withheld, grant=withheld["assessment"]))
        tampered = dict(docs[0]["grant"], payload=dict(docs[0]["grant"]["payload"],
                                                    operation_id=withheld["operation_id"]))
        self.submit("coordinator_substitution", dict(withheld, grant=tampered))
        self.replies["coordinator_admin"] = self.call({"op": "revoke-policy"})
        self.batch("overload", [withheld])
        self.snapshot("after_overload")

    def interrupt(self):
        req = self.material("coordinator")
        p = self.client("hold", {"op": "execute", "request": req})
        sent = line(p)
        start = time.monotonic()
        while not any(r["operation_id"] == req["operation_id"] for r in observe(self.journal)["ledger"]):
            if time.monotonic() - start > 5:
                raise TimeoutError("coordinator effect")
            time.sleep(0.01)
        p.kill()
        self.faults["coordinator"] = {"sent": sent, "exit": p.wait(3), "killed_ns": time.monotonic_ns()}
        self.status("coordinator-status", req)
        self.submit("coordinator-retry", req)
        self.snapshot("coordinator")
        for side in ("before", "after"):
            req = self.material(side)
            self.start_gate(side)
            self.submit(side + "-interrupted", req)
            self.faults[side] = {"exit": self.gate.wait(5), "observed_ns": time.monotonic_ns()}
            self.start_gate()
            self.snapshot(side + "_restart")
            self.status(side + "-status", req)
            self.submit(side + "-retry", req)
            self.snapshot(side + "_retry")

    def order(self, revoke_first):
        name = "revoke-first" if revoke_first else "commit-first"
        req = self.material(name)
        self.start_gate("gate" if revoke_first else "held-gate")
        rev = self.spawn([sys.executable, "-B", "-m", LAB + "boundary",
                          "held-revoker" if revoke_first else "revoker", self.state,
                          req["grant"]["payload"]["grant_id"]])
        timeline = []
        def expect(process, who, phase):
            event = line(process)
            if event.get("phase") != phase:
                raise RuntimeError(f"expected {who} {phase}: {event}")
            timeline.append(dict(event, source=who))
        expect(rev, "revoker", "armed")
        if revoke_first:
            command(rev, "start")
            expect(rev, "revoker", "begin_immediate")
            expect(rev, "revoker", "writer_held")
        client = self.client("rpc", {"op": "execute", "request": req})
        expect(self.gate, "gate", "begin_immediate")
        if not revoke_first:
            expect(self.gate, "gate", "writer_held")
            command(rev, "start")
            expect(rev, "revoker", "begin_immediate")
        timeline.append({"phase": "release", "source": "controller", "time_ns": time.monotonic_ns()})
        command(rev if revoke_first else self.gate, "release")
        expect(rev, "revoker", "revoked")
        self.replies[name] = line(client)
        if client.wait(5) or rev.wait(5):
            raise RuntimeError("writer process failed")
        self.faults[name] = timeline
        self.start_gate()
        self.submit(name + "-retry", req)
        self.snapshot(name)


def main():
    if sys.version_info < (3, 12):
        raise SystemExit("The admission observer requires Python 3.12 or later")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    out = parser.parse_args().output.resolve()
    subprocess.run(["git", "merge-base", "--is-ancestor", BASE, "HEAD"], cwd=ROOT, check=True)
    subprocess.run(["git", "diff", "--exit-code", BASE, "--", "shirudo_adapter", "scripts", "tests",
                    "pyproject.toml"], cwd=ROOT, check=True)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="wt-swarm-") as temp, ExitStack() as stack:
        run = Run(Path(temp), out, stack)
        try:
            run.setup()
            run.load_cases()
            run.interrupt()
            run.order(False)
            run.order(True)
            run.snapshot("final")
        finally:
            save(out / "replies.json", run.replies)
            save(out / "faults.json", run.faults)
    paths = [p for name in ("shirudo_adapter", "scripts", "tests", "research/wt_swarm")
             for p in (ROOT / name).glob("*.py")]
    save(out / "source-sha256.json", {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(paths)})
    save(out / "environment.json", dict(base=BASE, kernel=platform.release(), architecture=platform.machine(),
         python=platform.python_version(), sqlite=sqlite3.sqlite_version, cryptography=cryptography.__version__,
         bwrap=subprocess.check_output(["bwrap", "--version"], text=True).strip(), gate_limits=LIMITS,
         cgroup={k: (Path("/sys/fs/cgroup") / k).read_text().strip() for k in
                 ("cpu.max", "pids.max", "memory.max") if (Path("/sys/fs/cgroup") / k).exists()},
         client_nofile=resource.getrlimit(resource.RLIMIT_NOFILE)[0], native_gate_workers=4,
         verifier="fabricated signed repository fixture", owner="SCRIPTED_PTY", actual_human_approval="NOT_RUN",
         hercules_runtime=bool(shutil.which("hercules")), kvm=Path("/dev/kvm").exists(),
         private_directory_removed=not Path(temp).exists(), paid_model_calls=0))


if __name__ == "__main__":
    main()
