"""Native compatibility observations using distinct disposable signing identities."""

import sqlite3
from pathlib import Path
import tempfile
import unittest
from tests.test_action_gate import GateFixture
from shirudo_adapter.model import AdapterError


class Continuity(unittest.TestCase):
    def test_native_history_under_destination_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            source = GateFixture(Path(temp) / "source")
            dest = GateFixture(Path(temp) / "destination")
            self.assertEqual(source.identity["target_id"], dest.identity["target_id"])
            self.assertNotEqual(
                source.identity["public_key"], dest.identity["public_key"]
            )
            _, _, req = source.operation()
            receipt = source.gate.execute(req)["receipt"]
            with sqlite3.connect(source.state / "journal.sqlite3") as c:
                c.row_factory = sqlite3.Row
                row = c.execute(
                    "SELECT * FROM operations WHERE id=?", (req["operation_id"],)
                ).fetchone()
                self.assertEqual(source.gate._decode_operation(row)["receipt"], receipt)
                with self.assertRaises(AdapterError) as error:
                    dest.gate._decode_operation(row)
                self.assertEqual(error.exception.code, "STATE_INVALID")
            self.assertEqual(dest.oracle(), (0, 0))


class SourceRetirement(unittest.TestCase):
    def setUp(self):
        from research.schism.test_fence import FenceTests
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from shirudo_adapter.model import digest
        from shirudo_adapter.receipt import sign_record
        from research.schism.storage import FENCE

        self.lab = FenceTests()
        self.lab.setUp()
        self.addCleanup(self.lab.doCleanups)
        destination = GateFixture(self.lab.root / "destination")
        migrator = Ed25519PrivateKey.generate()
        self.lab.pins["migration_authorizer"] = (
            migrator.public_key().public_bytes_raw().hex()
        )
        core = dict(
            epoch=2,
            previous=self.lab.head,
            gate=self.lab.pins["gate"],
            target=self.lab.pins["target"],
            destination=digest(destination.identity),
        )
        approval = sign_record(
            migrator, dict(core, schema="wolfalibi.exodus.retire-authority.v1")
        )
        self.record = sign_record(
            self.lab.issuer,
            dict(core, schema=FENCE, executor=None, authorization=approval),
        )

    def test_durable_source_fence(self):
        from research.schism.storage import administer, FencedGate

        r, _ = self.lab.request()
        administer(self.lab.paths, self.lab.pins, self.record)
        restored = FencedGate(
            self.lab.f.state, self.lab.paths, self.lab.pins, self.lab.keys[0]
        )
        self.lab.denied("STALE_EXECUTOR", restored.execute, r)
        self.lab.denied(
            "SOURCE_FENCED", administer, self.lab.paths, self.lab.pins, self.record
        )
        self.assertEqual(self.lab.f.oracle(), (0, 0))

    def test_fence_serializes_with_native_transaction(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        from research.schism.storage import administer

        req, _ = self.lab.request()
        held, begin, release = Event(), Event(), Event()

        def pause():
            held.set()
            if not release.wait(5):
                raise TimeoutError()

        gate = self.lab.gates[0]
        gate._before_commit = pause
        with ThreadPoolExecutor(max_workers=2) as pool:
            effect = pool.submit(gate.execute, req)
            self.assertTrue(held.wait(5))
            fence = pool.submit(
                administer, self.lab.paths, self.lab.pins, self.record, None, begin.set
            )
            self.assertTrue(begin.wait(5))
            self.assertFalse(fence.done())
            release.set()
            self.assertEqual(effect.result()["result"], "COMMITTED")
            self.assertEqual(fence.result()["status"], "APPLIED")
        self.assertEqual(self.lab.f.oracle(), (1, 1))
