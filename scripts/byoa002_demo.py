"""Reproduce a fixed single-administrator ceremony or check public historical evidence offline."""
import argparse
from contextlib import ExitStack, closing
import json
import os
from pathlib import Path
import select
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import byoa002_principal as roles
from wolfalibi.byoa002_enrollment import digest
from wolfalibi.byoa002_package import make_package, make_pins, verify_observations, verify_package
from wolfalibi.byoa002_transport import measure_gateway, request
from wolfalibi.solitary_cli import _write_new
from wolfalibi.voidcell003_revision import source_revision

GATEWAY = ROOT / "scripts/byoa002_gateway.py"
ROLE = ROOT / "scripts/byoa002_principal.py"
MANIFEST = ROOT / "examples/qualification001/agent.json"
ENV = {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _args(script, *args):
    return [sys.executable, "-I", str(script), *map(str, args)]


def _command(script, *args):
    # The legacy checkout CLI expects its directory on sys.path.
    command = _args(script, *args) if script != ROOT / "wolfalibi_cli.py" else [sys.executable, str(script), *map(str, args)]
    p = subprocess.run(command, cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=40)
    if p.returncode:
        raise ValueError(f"{script.name} {args[0]} exited {p.returncode}: {(p.stdout or p.stderr)[-1200:]}")
    return json.loads(p.stdout)


def _line(p):
    if not select.select([p.stdout], [], [], 15)[0]:
        raise ValueError("timed out awaiting local service")
    line = p.stdout.readline()
    if not line:
        raise ValueError("local service closed before reporting its result: " + p.stderr.read(2048))
    return json.loads(line)


class Child:
    def __init__(self, stack, script, *args):
        self.process = subprocess.Popen(_args(script, *args), cwd=ROOT, env=ENV, text=True,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stack.callback(self.stop)
        self.ready = _line(self.process)
        require(self.ready.get("outcome") == "READY", f"{script.name}: {self.ready}")

    def call(self, action, **kwargs):
        p = self.process
        p.stdin.write(json.dumps({"action": action, **kwargs}) + "\n")
        p.stdin.flush()
        return _line(p)

    def stop(self):
        p = self.process
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=6)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for stream in (p.stdin, p.stdout, p.stderr):
            stream.close()


def ledger_rows(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        return [json.loads(row[0]) for row in db.execute("SELECT receipt FROM effects ORDER BY rowid")]


def run_fixture(output, revision, *, operator_state=None, lose_reply=False, custody=False):
    """One disposable trial using the revision supplied by the calling harness."""
    from scripts.byoa002_roundtrip import roundtrip
    output = Path(output)
    output.mkdir(mode=0o700)
    with TemporaryDirectory(prefix="qb2-") as private, ExitStack() as stack:
        root = Path(private)
        socket_path = root / "endpoint" / "gate.sock"
        socket_path.parent.mkdir(mode=0o700)
        gateway = Child(stack, GATEWAY, socket_path)
        peer = measure_gateway(gateway.process.pid, socket_path)
        require(peer == gateway.ready["peer"], "owner and gateway observations disagree")
        trial, bootstrap, operator = root / "trial", root / "bootstrap", operator_state or root / "operator"
        owner, verifier = root / "owner", root / "verifier"
        pubs = {role: roles.provision(role, path) for role, path in
                (("operator", operator), ("owner", owner), ("verifier", verifier))}

        def legacy(*args):
            return _command(ROOT / "wolfalibi_cli.py", "byoa", *args)

        legacy("provision", "--role", "trial", "--output", trial)
        legacy("provision", "--role", "owner", "--output", bootstrap)
        legacy("enroll-owner", "--trial", trial, "--owner-pin", bootstrap / "public.json", "--approve-owner")
        enrollment = roles.enroll(manifest=MANIFEST, trial_public=roles.read(trial / "public.json"),
            bootstrap_owner=roles.read(bootstrap / "public.json"), operator_public=pubs["operator"],
            owner_public=pubs["owner"], verifier_public=pubs["verifier"], revision=revision, gateway=peer,
            owner_uid=os.geteuid(), epoch=1)
        en = root / "enrollment.json"
        _write_new(en, enrollment)
        v = ["--enrollment", en, "--keys", verifier, "--state", root / "vstate"]
        target = ["--enrollment", en, "--keys", owner, "--state", root / "tstate"]
        journal = root / "custody.sqlite"
        if custody:
            target.extend(["--custody-journal", journal])
        _command(ROLE, "init-verifier", *v)
        _command(ROLE, "init-target", *target)
        prior = root / "before.json"
        _command(ROLE, "head", *v, "--output", prior)
        _command(ROLE, "fresh", *v, "--expect-head", prior, "--output", root / "pair.json")
        pair = roles.read(root / "pair.json")
        review = root / "review"
        legacy("prepare", "--manifest", MANIFEST, "--trial-pins", trial / "public.json",
               "--owner-pin", bootstrap / "public.json", "--run-id", pair["run_id"], "--challenge", pair["challenge"],
               "--output", review, "--ttl", 180)
        ep = root / "external-trial.json"
        expected = roles.read(review / "expected.json")
        _write_new(ep, expected)
        cf, gf = root / "challenge.json", root / "grant.json"
        _command(ROLE, "approve", *v, "--expected", ep, "--expect-head", prior, "--consent", "--output", cf)
        _command(ROLE, "grant", "--keys", owner, "--enrollment", en,
                 "--expected", ep, "--challenge", cf, "--consent", "--output", gf)
        boot_grant = root / "bootstrap-grant.json"
        legacy("grant-read", "--owner", bootstrap, "--expect", ep, "--approve-read", "--output", boot_grant)
        completed = legacy("qualify", "--manifest", MANIFEST, "--trial", trial, "--review", review,
                           "--grant", boot_grant, "--consent", "--framework", "langchain", "--output", root / "run")
        require(completed["outcome"] == "COMPLETED", "measured trial did not complete")
        signed_inputs = ["--keys", operator, "--enrollment", en, "--expected", ep, "--challenge", cf,
                         "--grant", gf, "--report", root / "run" / "report.json"]
        _command(ROLE, "request", *signed_inputs, "--action", "dispatch", "--output", root / "packet.json")
        packet = roles.read(root / "packet.json")
        recovered = roundtrip(stack, root, gateway, socket_path, v, target, en, signed_inputs,
                              packet, enrollment, peer, lose_reply)
        if custody:
            from wolfalibi.byoa002_custody import verify_history
            ledger = root / "tstate" / "ledger" / "ledger.sqlite"
            with closing(sqlite3.connect(ledger.as_uri() + "?mode=ro", uri=True)) as db:
                head, = db.execute("SELECT receipt FROM decisions WHERE id=0 AND dispatch_digest='custody-head'").fetchall()
            with closing(sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True)) as db:
                history = [json.loads(row[0]) for row in db.execute("SELECT record FROM history ORDER BY seq")]
            committed_head = json.loads(head[0])
            verified = verify_history(history, enrollment=digest(enrollment),
                                      public_key=bytes.fromhex(enrollment["target_pub"]), expected_head=committed_head)
            require(committed_head["generation"] == 1 and history[-1]["payload"]["action"] == "consume"
                    and history[-1]["payload"]["subject"] == digest(packet["challenge"]),
                    "custody history must record the single authorized challenge")
            _write_new(output / "custody.json", {"history": history, "target_head": committed_head,
                                                  "historical_verification": verified})
        historical = recovered["controls"]["reconciled"]
        package = make_package(challenge=packet["challenge"], grant=packet["grant"], request=packet["request"],
                               report=packet["report"], receipt=historical["receipt"], ack=historical["ack"])
        pins = make_pins(expected_trial=expected, enrollment=enrollment, previous=roles.read(prior),
                         head=roles.read(root / "after.json"))
        checked = verify_package(package, pins)
        require(checked["outcome"] == "VERIFIED", f"offline evidence failed: {checked.get('reason')}")
        result = {"schema": "quorvane.byoa002.ceremony.v1", "outcome": "COMPLETED",
                  "administrators": 1, "cross_uid_custody": "UNSUPPORTED", "independent_verifier_custody": "UNSUPPORTED",
                  "framework_observation": completed["framework_observation"], "production": "BLOCKED",
                  "certification": "NOT_ISSUED", **recovered}
        for name, value in (("package", package), ("expectations", pins), ("result", result)):
            _write_new(output / (name + ".json"), value)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="cmd", required=True)
    p = cmds.add_parser("run")
    p.add_argument("--consent", required=True, action="store_true")
    p.add_argument("--expect-commit", required=True)
    p.add_argument("--expect-tree", required=True)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--custody", action="store_true", help="exercise the signed custody journal during both trials")
    p.add_argument("--operator-state", type=Path, help="new private operator directory for signing the local report")
    p = cmds.add_parser("verify")
    p.add_argument("--package", required=True)
    p.add_argument("--expect", required=True)
    p.add_argument("--observations", help="raw local qualification report")
    p.add_argument("--operator-attestation", help="detached operator signature for that report")
    try:
        args = parser.parse_args()
        if args.cmd == "verify":
            require(bool(args.observations) == bool(args.operator_attestation), "supply both observation files")
            package, pins = roles.read(args.package), roles.read(args.expect)
            if args.observations:
                result = verify_observations(roles.read(args.operator_attestation), package, pins,
                                             roles._read(args.observations, 4 * 1024 * 1024))
            else:
                result = verify_package(package, pins)
        else:
            revision = {"commit": args.expect_commit, "tree": args.expect_tree}
            require(source_revision() == revision, "clean source revision differs from operator pins")
            from wolfalibi.solitary_preflight import preflight
            if preflight()["outcome"] != "READY":
                result = {"outcome": "UNSUPPORTED", "reason": "measured Linux profile unavailable"}
            else:
                normal = run_fixture(args.output, revision, operator_state=args.operator_state, custody=args.custody)
                lost = run_fixture(args.output / "lost-reply", revision, lose_reply=True, custody=args.custody)
                require(source_revision() == revision, "source checkout changed during trial")
                result = {"outcome": "COMPLETED", "revision": revision, "accepted": normal["effect_count"],
                          "lost_reply": lost["effect_count"], "production": "BLOCKED", "certification": "NOT_ISSUED"}
    except (KeyError, OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        result = {"outcome": "BLOCKED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in {"VERIFIED", "COMPLETED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
