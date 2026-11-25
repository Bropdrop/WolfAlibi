"""Focused denial and settlement controls against a disposable native journal."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from research.blackout.reader import DENIAL, database, locator, response
from shirudo_adapter.model import digest
from tests.test_action_gate import GateFixture


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.f = GateFixture(Path(temp.name))
        _, action, self.req = self.f.operation()
        self.b = dict(
            principal="1" * 64,
            operation_id=self.req["operation_id"],
            request_sha256=digest(self.req),
            target_id=self.f.identity["target_id"],
            gate_instance_id=self.f.identity["gate_instance_id"],
            grant_id=self.req["grant"]["payload"]["grant_id"],
            grant_sha256=digest(self.req["grant"]),
            assessment_sha256=digest(self.req["assessment"]),
            challenge_sha256=digest(action),
        )
        self.config = {
            "profile": {
                "gate_public_key": self.f.identity["public_key"],
                "policy": self.f.policy,
            },
            "bindings": {self.b["request_sha256"]: self.b},
        }
        self.key = Ed25519PrivateKey.generate()
        self.con = database(self.f.state / "journal.sqlite3")
        self.addCleanup(self.con.close)

    def get(self, principal=None, **changes):
        return response(
            self.con,
            dict(locator(self.b), **changes),
            principal or self.b["principal"],
            self.config,
            self.key,
        )

    def test_missing_row_with_even_a_revoked_grant_is_unresolved(self):
        self.f.gate.revoke_grant(self.b["grant_id"])
        self.b["operation_id"] = "0" * 32
        self.assertEqual(self.get()["proof"]["payload"]["reason"], "NO_ROW")
        self.assertEqual(self.get()["proof"]["payload"]["outcome"], "UNRESOLVED")

    def test_prepared_is_unresolved_and_permits_later_commit(self):
        self.assertEqual(self.get()["proof"]["payload"]["outcome"], "UNRESOLVED")
        result = self.f.gate.execute(self.req)
        self.assertEqual(self.get()["receipt"], result["receipt"])

    def test_committed_before_revocation_returns_original_receipt(self):
        result = self.f.gate.execute(self.req)
        self.f.gate.revoke_grant(self.b["grant_id"])
        self.assertEqual(self.get()["receipt"], result["receipt"])

    def test_revoked_prepared_is_settled_and_late_delivery_denied(self):
        self.f.gate.revoke_grant(self.b["grant_id"])
        self.assertEqual(self.get()["proof"]["payload"]["outcome"], "NOT_COMMITTED")
        from shirudo_adapter.model import AdapterError

        with self.assertRaises(AdapterError) as raised:
            self.f.gate.execute(self.req)
        self.assertEqual(raised.exception.code, "GRANT_REVOKED")
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_denials_have_no_receipt_even_for_committed_row(self):
        self.f.gate.execute(self.req)
        self.assertEqual(self.get(principal="2" * 64), DENIAL)
        for field in locator(self.b):
            self.assertEqual(self.get(**{field: "unexpected"}), DENIAL)

    def test_journal_failure_stays_unresolved(self):
        self.con.close()
        self.assertEqual(self.get()["proof"]["payload"]["outcome"], "UNRESOLVED")

    def test_recovery_connection_cannot_write(self):
        with self.assertRaises(sqlite3.OperationalError):
            self.con.execute("UPDATE counter SET value=value WHERE id=1")

    def test_foreign_journal_identity_stays_unresolved(self):
        self.config["profile"]["gate_public_key"] = "0" * 64
        self.assertEqual(self.get()["proof"]["payload"]["reason"], "JOURNAL_IDENTITY")


if __name__ == "__main__":
    unittest.main()
