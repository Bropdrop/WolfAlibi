"""Disposable gate transaction and authenticated authority regression tests."""

from pathlib import Path
import shutil
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.test_action_gate import GateFixture
from shirudo_adapter.action_gate import Gate
from shirudo_adapter.model import AdapterError, digest
from shirudo_adapter.receipt import sign_record
from research.schism.storage import (
    FencedGate,
    provision,
    administer,
    TRANSITION,
    PERMIT,
    ZERO,
)
from research.schism.experiment import backup


class FenceTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.f = GateFixture(self.root / "native")
        self.issuer = Ed25519PrivateKey.generate()
        self.keys = [Ed25519PrivateKey.generate() for _ in range(2)]
        self.pubs = [k.public_key().public_bytes_raw().hex() for k in self.keys]
        ext = self.root / "checkpoint"
        ext.mkdir()
        self.paths, self.pins = provision(
            self.f.state,
            ext,
            self.issuer.public_key().public_bytes_raw().hex(),
            self.pubs,
            self.f.identity,
        )
        self.head = ZERO
        self.epoch = 0
        self.advance(0)
        self.gates = [
            FencedGate(self.f.state, self.paths, self.pins, k) for k in self.keys
        ]
        self.f.gate = self.gates[0]

    def transition(self, index):
        return dict(
            schema=TRANSITION,
            gate=self.pins["gate"],
            target=self.pins["target"],
            epoch=self.epoch + 1,
            previous=self.head,
            executor=self.pubs[index],
        )

    def advance(self, index):
        record = sign_record(self.issuer, self.transition(index))
        administer(self.paths, self.pins, record)
        self.head = digest(record)
        self.epoch += 1
        return record

    def request(self, register=True):
        _, _, req = self.f.operation()
        p = dict(
            schema=PERMIT,
            gate=self.pins["gate"],
            target=self.pins["target"],
            epoch=self.epoch,
            head=self.head,
            executor=self.pubs[0],
            op=req["operation_id"],
            request=digest(req),
            grant=digest(req["grant"]),
        )
        if register:
            administer(self.paths, self.pins, sign_record(self.issuer, p))
        return req, p

    def denied(self, expected, fn, *args):
        with self.assertRaises(AdapterError) as raised:
            fn(*args)
        self.assertEqual(raised.exception.code, expected)

    def test_native_legacy_entry_rejects_fenced_state(self):
        self.denied("STATE_INVALID", Gate, self.f.state)

    def test_detached_epoch_permit_is_required_at_commit(self):
        req, _ = self.request(False)
        self.denied("EPOCH_PERMIT_REQUIRED", self.gates[0].execute, req)
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_replay_and_foreign_signatures(self):
        good = self.advance(1)
        self.denied("EPOCH_CAS", administer, self.paths, self.pins, good)
        self.denied(
            "INVALID_SIGNATURE",
            administer,
            self.paths,
            self.pins,
            sign_record(self.keys[0], self.transition(0)),
        )

    def test_old_permit_cannot_be_reissued_or_consumed(self):
        req, p = self.request()
        self.advance(1)
        p.update(epoch=2, head=self.head, executor=self.pubs[1])
        self.denied(
            "CROSS_EPOCH_GRANT",
            administer,
            self.paths,
            self.pins,
            sign_record(self.issuer, p),
        )
        self.denied("STALE_EXECUTOR", self.gates[0].execute, req)
        self.denied("CROSS_EPOCH_GRANT", self.gates[1].execute, req)
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_in_place_rollback_with_same_inode_and_epoch(self):
        req, _ = self.request()
        snapshot = self.root / "before.db"
        backup(self.paths["target"], snapshot)
        self.assertEqual(self.gates[0].execute(req)["result"], "COMMITTED")
        backup(snapshot, self.paths["target"])
        self.denied("ROLLBACK_DETECTED", self.gates[0].execute, req)

    def test_even_an_exact_clone_is_excluded(self):
        clone = self.root / "clone"
        shutil.copytree(self.f.state, clone)
        self.denied(
            "TARGET_CLONE", FencedGate, clone, self.paths, self.pins, self.keys[0]
        )

    def test_checkpoint_disappears_after_native_effect_writes(self):
        req, _ = self.request()
        path = self.paths["control"]
        self.gates[0]._before_commit = lambda: path.rename(path.with_suffix(".lost"))
        self.denied("CHECKPOINT_UNAVAILABLE", self.gates[0].execute, req)
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_checkpoint_lost_while_transition_is_staged(self):
        control = self.paths["control"]
        offline = control.with_suffix(".offline")
        proposal = sign_record(self.issuer, self.transition(1))
        self.denied(
            "CHECKPOINT_UNAVAILABLE",
            administer,
            self.paths,
            self.pins,
            proposal,
            lambda: control.rename(offline),
        )
        offline.rename(control)
        self.assertEqual(
            administer(self.paths, self.pins, proposal)["status"], "APPLIED"
        )

    def test_wrong_request_digest_on_issuer_permit(self):
        req, p = self.request(False)
        p["request"] = "0" * 64
        administer(self.paths, self.pins, sign_record(self.issuer, p))
        self.denied("EPOCH_PERMIT_BINDING", self.gates[0].execute, req)
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_expiry_at_fence_preserves_high_water_on_restart(self):
        req, _ = self.request()
        end = req["grant"]["payload"]["expires_at_ms"]
        self.gates[0]._before_commit = lambda: setattr(
            self.gates[0], "_clock", lambda: end
        )
        self.denied("OPERATION_EXPIRED", self.gates[0].execute, req)
        reopened = FencedGate(self.f.state, self.paths, self.pins, self.keys[0])
        reopened._clock = lambda: end - 1
        self.denied("CLOCK_ROLLBACK", reopened.execute, req)
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_replacement_exact_retry_recovers_original(self):
        req, _ = self.request()
        result = self.gates[0].execute(req)
        self.advance(1)
        retry = self.gates[1].execute(req)
        self.assertEqual(
            retry, dict(result="ALREADY_COMMITTED", receipt=result["receipt"])
        )
        self.assertEqual(self.f.oracle(), (1, 1))


if __name__ == "__main__":
    unittest.main()
