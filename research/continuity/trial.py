"""Single-retirement native continuity trial with disposable local keys."""

import argparse
import json
from pathlib import Path
from contextlib import closing
import sqlite3
import subprocess
import sys
import multiprocessing
import time
import shutil
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.test_action_gate import GateFixture
from research.schism.test_fence import FenceTests
from research.schism.storage import FENCE, provision, administer, TRANSITION, PERMIT
from research.continuity.capture import capture
from research.continuity.history import verify
from research.continuity.destination import DestinationGate, activate
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import sign_record


def public(k):
    return k.public_key().public_bytes_raw().hex()


def run(out, stress=False):
    out.mkdir(parents=True, exist_ok=False)
    lab = FenceTests()
    lab.setUp()
    try:
        f = lab.f
        dest = GateFixture(lab.root / "destination")
        executor, issuer, observer, migrator = (
            Ed25519PrivateKey.generate() for _ in range(4)
        )
        ext = lab.root / "destination-checkpoint"
        ext.mkdir()
        paths, pins = provision(
            dest.state, ext, public(issuer), [public(executor)], dest.identity
        )
        pins["migration_authorizer"] = public(migrator)
        cfg = dest.state / "state.json"
        cfg.write_text(
            json.dumps(
                dict(json.loads(cfg.read_bytes()), schema=DestinationGate.state_schema)
            )
        )
        lab.pins["migration_authorizer"] = public(migrator)
        from research.blackout.credentials import provision as tls_provision

        principals = tls_provision(lab.root)
        enrollment = dict(
            trust=f.trust,
            key=f.identity["public_key"],
            gate=f.identity["gate_instance_id"],
        )
        req, _ = lab.request()
        original = f.gate.execute(req)
        pending, _ = lab.request()
        revoked, _ = lab.request()
        rid = revoked["grant"]["payload"]["grant_id"]
        f.gate.revoke_grant(rid)
        if stress:
            from research.continuity.profile import matched

            (out / "profile.json").write_text(
                json.dumps(matched(lab.paths, lab.pins, f, [req, pending, revoked]))
                + "\n"
            )
        from research.schism.experiment import backup

        backup(lab.paths["target"], lab.root / "pre-retirement.db")
        core = dict(
            gate=lab.pins["gate"],
            target=lab.pins["target"],
            destination=digest(pins),
            epoch=2,
            previous=lab.head,
        )
        authorization = sign_record(
            migrator, dict(core, schema="wolfalibi.exodus.retire-authority.v1")
        )
        fence = sign_record(
            lab.issuer,
            dict(core, schema=FENCE, executor=None, authorization=authorization),
        )
        migration_start = time.monotonic_ns()
        if stress:
            from research.continuity.load import contention

            contention(
                lab, pending, lambda: administer(lab.paths, lab.pins, fence), out
            )
        else:
            administer(lab.paths, lab.pins, fence)
        lab.denied("STALE_EXECUTOR", f.gate.execute, pending)
        recovery = {
            digest(r): dict(
                principal=principals["alice"],
                gate_instance_id=lab.pins["gate"],
                target_id=lab.pins["target"],
                operation_id=r["operation_id"],
                request_sha256=digest(r),
                grant_id=r["grant"]["payload"]["grant_id"],
            )
            for r in (req, pending, revoked)
        }
        transfer_start = time.monotonic_ns()
        package = capture(
            lab.paths,
            lab.pins,
            digest(pins),
            observer,
            recovery,
            {digest(r): r for r in (req, pending, revoked)},
        )
        roots = dict(
            floor=package["journal"]["floor"],
            source=lab.pins,
            destination=digest(pins),
            enrollment=enrollment,
            observer=public(observer),
            checkpoint_sha256=digest(package["checkpoint"]),
        )
        for n, data in (("pins", roots), ("transfer", package)):
            (out / (n + ".json")).write_text(json.dumps(data, sort_keys=True) + "\n")
        from research.continuity.controls import omissions

        (out / "mutations.json").write_text(
            json.dumps(omissions(roots, package, observer), sort_keys=True) + "\n"
        )
        recovered = json.loads(
            subprocess.check_output(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "research.continuity.history",
                    out / "pins.json",
                    out / "transfer.json",
                ]
            )
        )
        assert (
            json.loads(recovered[req["operation_id"]]["receipt"]) == original["receipt"]
        )
        transfer_end = time.monotonic_ns()
        transition = sign_record(
            issuer,
            dict(
                schema=TRANSITION,
                epoch=3,
                previous=digest(fence),
                gate=pins["gate"],
                target=pins["target"],
                executor=public(executor),
            ),
        )
        missing = lab.paths["control"].with_suffix(".offline")
        lab.paths["control"].rename(missing)
        try:
            lab.denied(
                "CHECKPOINT_UNAVAILABLE",
                activate,
                paths,
                pins,
                roots,
                package,
                transition,
                lab.paths,
            )
            assert dest.oracle() == (0, 0)
        finally:
            missing.rename(lab.paths["control"])
        # Kill a disposable import writer with all files staged but uncommitted.
        ctx = multiprocessing.get_context("fork")
        held = ctx.Event()

        def pause():
            held.set()
            time.sleep(15)

        writer = ctx.Process(
            target=activate,
            args=(paths, pins, roots, package, transition, lab.paths, pause),
        )
        writer.start()
        try:
            assert held.wait(5)
        finally:
            writer.kill()
            writer.join(5)
        assert writer.exitcode == -9 and dest.oracle() == (0, 0)
        start_activation = time.monotonic_ns()
        activate(paths, pins, roots, package, transition, lab.paths)
        activation_end = time.monotonic_ns()
        (out / "boundaries.json").write_text(
            json.dumps(
                dict(
                    migration_start=migration_start,
                    transfer_start=transfer_start,
                    transfer_verified=transfer_end,
                    activation_start=start_activation,
                    activation_end=activation_end,
                    interrupted_writer=writer.exitcode,
                )
            )
            + "\n"
        )
        lab.denied(
            "ALREADY_ACTIVATED",
            activate,
            paths,
            pins,
            roots,
            package,
            transition,
            lab.paths,
        )
        clone = lab.root / "source-clone"
        shutil.copytree(f.state, clone)
        from research.schism.storage import FencedGate

        lab.denied("TARGET_CLONE", FencedGate, clone, lab.paths, lab.pins, lab.keys[0])
        backup(lab.paths["target"], lab.root / "retired.db")
        backup(lab.root / "pre-retirement.db", lab.paths["target"])
        lab.denied(
            "ROLLBACK_DETECTED", FencedGate, f.state, lab.paths, lab.pins, lab.keys[0]
        )
        backup(lab.root / "retired.db", lab.paths["target"])
        dest.gate = DestinationGate(dest.state, paths, pins, executor, roots, package)
        for r in (req, pending, revoked):
            lab.denied("HISTORICAL_READ_ONLY", dest.gate.execute, r)
        _, _, fresh = dest.operation()
        permit = dict(
            schema=PERMIT,
            epoch=3,
            head=digest(transition),
            executor=public(executor),
            op=fresh["operation_id"],
            gate=pins["gate"],
            target=pins["target"],
            request=digest(fresh),
            grant=digest(fresh["grant"]),
        )
        administer(paths, pins, sign_record(issuer, permit))
        from research.continuity.executor import isolated_commit

        result = isolated_commit(
            dest.state, paths, pins, executor, roots, package, fresh
        )
        assert dest.oracle() == (2, 2) and f.oracle() == (1, 1)
        with closing(sqlite3.connect(paths["target"])) as c:
            stored = c.execute(
                "SELECT receipt FROM operations WHERE id=?", (req["operation_id"],)
            ).fetchone()[0]
            assert stored == recovered[req["operation_id"]]["receipt"]
            assert c.execute("SELECT id FROM revoked_grants").fetchone()[0] == rid
        from research.continuity.tls_trial import probe

        read_results = probe(
            lab.root, paths, pins, roots, package, recovery, [req, pending, revoked]
        )
        (out / "recovery.json").write_text(
            json.dumps(read_results, sort_keys=True) + "\n"
        )
        (out / "destination.json").write_text(
            json.dumps(
                dict(
                    profile=dest.identity,
                    trust=dest.trust,
                    pins=pins,
                    activation=transition,
                    permit=sign_record(issuer, permit),
                    request=fresh,
                    receipt=result["receipt"],
                    final_counter=2,
                ),
                sort_keys=True,
            )
            + "\n"
        )
        if stress:
            from research.continuity.load import recovery_load

            recovery_load(
                lab.root,
                paths,
                pins,
                roots,
                package,
                recovery,
                [req, pending, revoked],
                out,
            )
        third = GateFixture(lab.root / "third")
        third_ext = lab.root / "third-floor"
        third_ext.mkdir()
        k3, i3 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        p3, t3 = provision(
            third.state, third_ext, public(i3), [public(k3)], third.identity
        )
        file = third.state / "state.json"
        file.write_text(
            json.dumps(
                dict(json.loads(file.read_bytes()), schema=DestinationGate.state_schema)
            )
        )
        core = dict(
            gate=pins["gate"],
            target=pins["target"],
            destination=digest(t3),
            epoch=4,
            previous=digest(transition),
        )
        authorization = sign_record(
            migrator, dict(core, schema="wolfalibi.exodus.retire-authority.v1")
        )
        fence2 = sign_record(
            issuer, dict(core, schema=FENCE, executor=None, authorization=authorization)
        )
        administer(paths, pins, fence2)
        recovery2 = dict(recovery)
        recovery2[digest(fresh)] = dict(
            principal=principals["alice"],
            gate_instance_id=pins["gate"],
            target_id=pins["target"],
            operation_id=fresh["operation_id"],
            request_sha256=digest(fresh),
            grant_id=fresh["grant"]["payload"]["grant_id"],
        )
        package2 = capture(
            paths,
            pins,
            digest(t3),
            observer,
            recovery2,
            {digest(r): r for r in (req, pending, revoked, fresh)},
        )
        package2["parent"] = package
        roots2 = dict(
            floor=package2["journal"]["floor"],
            parent=roots,
            source=pins,
            destination=digest(t3),
            enrollment=dict(
                trust=dest.trust, key=dest.identity["public_key"], gate=pins["gate"]
            ),
            observer=public(observer),
            checkpoint_sha256=digest(package2["checkpoint"]),
        )
        tr3 = sign_record(
            i3,
            dict(
                schema=TRANSITION,
                epoch=5,
                previous=digest(fence2),
                gate=t3["gate"],
                target=t3["target"],
                executor=public(k3),
            ),
        )
        activate(p3, t3, roots2, package2, tr3, paths)
        third.gate = DestinationGate(third.state, p3, t3, k3, roots2, package2)
        assert third.oracle() == (2, 2) and len(verify(roots2, package2)) == 2
        lab.denied("HISTORICAL_READ_ONLY", third.gate.execute, fresh)
        for n, v in (
            ("lineage", roots2),
            ("segments", package2),
            ("second-activation", tr3),
        ):
            (out / (n + ".json")).write_text(json.dumps(v, sort_keys=True) + "\n")
    finally:
        lab.doCleanups()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("output", type=Path)
    p.add_argument("--stress", action="store_true")
    args = p.parse_args()
    run(args.output, args.stress)
