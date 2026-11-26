"""Process and storage boundary controls using a real retired native source."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import multiprocessing
import socket
import sqlite3
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.test_action_gate import GateFixture
from research.schism.storage import FENCE, TRANSITION, provision, administer, FencedGate
from research.schism import test_fence
from research.continuity.destination import DestinationGate, activate
from research.continuity.capture import capture
from research.continuity.trial import public
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import sign_record


class Interrupt(unittest.TestCase):
    def test_killed_source_and_lost_activation_reply(self):
        lab = test_fence.FenceTests()
        lab.setUp()
        self.addCleanup(lab.doCleanups)
        req, _ = lab.request()
        dst = GateFixture(lab.root / "isolated")
        ext = lab.root / "external-destination"
        ext.mkdir()
        key, issuer, observer, authority = (
            Ed25519PrivateKey.generate() for _ in range(4)
        )
        paths, pins = provision(
            dst.state, ext, public(issuer), [public(key)], dst.identity
        )
        state = dst.state / "state.json"
        state.write_text(
            json.dumps(
                dict(
                    json.loads(state.read_bytes()), schema=DestinationGate.state_schema
                )
            )
        )
        lab.pins["migration_authorizer"] = public(authority)
        dest = digest(pins)
        args = dict(
            gate=lab.pins["gate"],
            target=lab.pins["target"],
            destination=dest,
            epoch=2,
            previous=lab.head,
        )
        fence = sign_record(
            lab.issuer,
            dict(
                args,
                schema=FENCE,
                executor=None,
                authorization=sign_record(
                    authority, dict(args, schema="wolfalibi.exodus.retire-authority.v1")
                ),
            ),
        )
        ctx = multiprocessing.get_context("fork")
        entered, waiting = ctx.Event(), ctx.Event()

        def stopped():
            entered.set()
            ctx.Event().wait(20)

        def write():
            lab.gates[0]._before_commit = stopped
            lab.gates[0].execute(req)

        worker = ctx.Process(target=write)
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            with ThreadPoolExecutor(max_workers=1) as pool:
                terminal = pool.submit(
                    administer, lab.paths, lab.pins, fence, None, waiting.set
                )
                self.assertTrue(waiting.wait(5))
                worker.kill()
                worker.join(5)
                self.assertEqual(terminal.result()["status"], "APPLIED")
        finally:
            if worker.is_alive():
                worker.kill()
            worker.join()
        self.assertEqual(lab.f.oracle(), (0, 0))
        lab.denied(
            "STALE_EXECUTOR",
            FencedGate(lab.f.state, lab.paths, lab.pins, lab.keys[0]).execute,
            req,
        )
        package = capture(lab.paths, lab.pins, dest, observer, {}, {})
        roots = dict(
            enrollment=dict(
                gate=lab.pins["gate"],
                key=lab.f.identity["public_key"],
                trust=lab.f.trust,
            ),
            source=lab.pins,
            destination=dest,
            floor=package["journal"]["floor"],
            observer=public(observer),
            checkpoint_sha256=digest(package["checkpoint"]),
        )
        tr = sign_record(
            issuer,
            dict(
                schema=TRANSITION,
                gate=pins["gate"],
                target=pins["target"],
                previous=digest(fence),
                epoch=3,
                executor=public(key),
            ),
        )
        cp = lab.paths["control"]
        offline = cp.with_suffix(".offline")
        try:
            lab.denied(
                "CHECKPOINT_UNAVAILABLE",
                activate,
                paths,
                pins,
                roots,
                package,
                tr,
                lab.paths,
                lambda: cp.rename(offline),
            )
        finally:
            offline.rename(cp)
        self.assertEqual(dst.oracle(), (0, 0))
        # The caller transmits its request, then receives EOF after the server
        # commits and disconnects without delivering an acknowledgment.
        caller, server = socket.socketpair()

        def transact():
            with server:
                self.assertEqual(server.recv(16), b"activate")
                activate(paths, pins, roots, package, tr, lab.paths)

        with caller, ThreadPoolExecutor(max_workers=1) as pool:
            task = pool.submit(transact)
            caller.sendall(b"activate")
            self.assertEqual(caller.recv(16), b"")
            task.result()
        with closing(sqlite3.connect(cp.as_uri() + "?mode=ro", uri=True)) as c:
            self.assertEqual(
                c.execute("SELECT * FROM relocations").fetchall(),
                [(digest(fence), dest)],
            )
        lab.denied(
            "ALREADY_ACTIVATED", activate, paths, pins, roots, package, tr, lab.paths
        )
        DestinationGate(dst.state, paths, pins, key, roots, package)
