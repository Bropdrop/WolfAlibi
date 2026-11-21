"""Read-only history verification against real synthetic Gate 003 ledgers."""

from copy import deepcopy
import json
from pathlib import Path
from shutil import copyfile
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from alibi import Signer, canon
from wolfalibi import finance_records, history_archive
from wolfalibi.finance_target import FinanceTarget, init_key
from wolfalibi.voidcell002_anchor import AnchorError


class HistoryArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="wolfalibi-history-archive-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.state, self.anchors, self.archive = (root / name for name in ("state", "anchors", "archive"))
        for directory in (self.state, self.anchors, self.archive):
            directory.mkdir(mode=0o700)
        self.now = 1_700_000_000
        clock = patch("wolfalibi.finance_target._clock_time", side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)

        target_pub = init_key(self.state)
        owner, supervisor, witness, caller = (Signer() for _ in range(4))
        scope = {
            "tenant": finance_records.TENANT, "account": finance_records.ACCOUNT,
            "currency": finance_records.CURRENCY, "operation": finance_records.OPERATION,
            "target_pub": target_pub, "policy_epoch": 1, "run_id": "historical-payment-run",
            "challenge": "a9" * 32, "caller_pub": caller.pub.hex(),
            "request_id": "historical-payment", "payee": "fictional-supplier", "amount_minor": 4500,
        }
        peer = {
            "pid": 701, "uid": 1000, "gid": 1000, "start_ticks": 1002,
            "boot_id": "00000000-0000-0000-0000-000000000000", "exe_sha256": "a1" * 32,
            "argv_sha256": "a2" * 32, "source_sha256": "a3" * 32,
        }
        self.grant_id = "test-owner-grant"
        self.owner, self.caller = owner, caller
        self.qualification = finance_records.qualify(supervisor, witness, scope, peer, self.now, self.now + 10)
        self.packet = self._make_packet(scope, self.grant_id)
        witness_head = finance_records.digest(self.qualification)
        self.expectations = {
            "scope": scope, "target_pub": target_pub, "owner_pub": owner.pub.hex(),
            "supervisor_pub": supervisor.pub.hex(), "witness_pub": witness.pub.hex(),
            "peer": peer, "witness_head": witness_head,
        }
        head = root / "witness-head"
        head.write_text(witness_head, encoding="ascii")
        config = self.state / "config.json"
        config.write_bytes(canon({
            "scope": finance_records.run_scope(scope), "owner_pub": owner.pub.hex(),
            "supervisor_pub": supervisor.pub.hex(), "witness_pub": witness.pub.hex(),
            "peer": peer, "witness_head_path": str(head),
        }))
        config.chmod(0o600)
        self.ledger_path = self.archive / "ledger.sqlite"
        self.anchor_path = self.archive / "ledger-anchor.json"
        with FinanceTarget(self.state, self.anchors, create=True) as target:
            self.genesis = target.status()["anchor"]["anchor_sha256"]
        self.genesis_ledger = (self.state / self.ledger_path.name).read_bytes()
        self.genesis_anchor = (self.anchors / self.anchor_path.name).read_bytes()

    def _target(self):
        return FinanceTarget(self.state, self.anchors)

    def _archive_current(self):
        copyfile(self.state / self.ledger_path.name, self.ledger_path)
        copyfile(self.anchors / self.anchor_path.name, self.anchor_path)

    def _make_packet(self, scope, grant_id):
        grant = finance_records.owner_grant(self.owner, scope, grant_id, self.now, self.now + 10)
        return finance_records.dispatch(self.caller, scope, grant, self.qualification)

    def _admit(self, target, packet=None):
        packet = self.packet if packet is None else packet
        result = target.handle("initiate", packet, self.expectations["peer"])
        self.assertEqual(result["outcome"], "INTENT_RECORDED")
        return {"packet": packet, "receipt": result["receipt"]}

    def _read(self, anchor_sha256, *, expectations=None):
        return history_archive.read_archive(
            self.ledger_path, self.anchor_path, anchor_sha256=anchor_sha256,
            expectations=self.expectations if expectations is None else expectations,
        )

    def test_only_plain_archive_files_are_needed_after_expiry_and_revocation(self):
        with self._target() as target:
            evidence = self._admit(target)
            self.now += 10
            self.assertEqual(target.revoke(self.grant_id)["outcome"], "REVOKED")
            pin = target.status()["anchor"]["anchor_sha256"]
        self._archive_current()
        self.assertEqual(sorted(path.name for path in self.archive.iterdir()),
                         ["ledger-anchor.json", "ledger.sqlite"])
        before = (self.ledger_path.read_bytes(), self.anchor_path.read_bytes())
        self.assertEqual(self._read(pin), evidence)
        self.assertEqual(before, (self.ledger_path.read_bytes(), self.anchor_path.read_bytes()))

    def test_open_uses_read_only_uri_and_query_only_connection(self):
        with self._target() as target:
            self._admit(target)
            pin = target.status()["anchor"]["anchor_sha256"]
        self._archive_current()
        verify_policy = history_archive._verify_policy

        def observe_connection(db, *args):
            self.assertEqual(db.execute("PRAGMA query_only").fetchone(), (1,))
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("CREATE TABLE archive_write_probe (id INTEGER)")
            return verify_policy(db, *args)

        with patch.object(history_archive, "_verify_policy", side_effect=observe_connection):
            with patch.object(history_archive.sqlite3, "connect", wraps=sqlite3.connect) as connection:
                self._read(pin)
        self.assertEqual(connection.call_args.args, (self.ledger_path.as_uri() + "?mode=ro",))
        self.assertIs(connection.call_args.kwargs["uri"], True)

    def test_consistent_old_snapshot_is_rejected_against_current_independent_pin(self):
        with self._target() as target:
            self._admit(target)
            latest = target.status()["anchor"]["anchor_sha256"]
        self.ledger_path.write_bytes(self.genesis_ledger)
        self.anchor_path.write_bytes(self.genesis_anchor)
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "independent pin"):
            self._read(latest)

    def test_ledger_only_rollback_cannot_match_the_retained_checkpoint(self):
        with self._target() as target:
            self._admit(target)
            latest = target.status()["anchor"]["anchor_sha256"]
        self._archive_current()
        self.ledger_path.write_bytes(self.genesis_ledger)
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "pinned checkpoint"):
            self._read(latest)

    def test_changed_anchor_signature_fails_even_if_its_digest_was_supplied(self):
        with self._target() as target:
            self._admit(target)
        self._archive_current()
        record = json.loads(self.anchor_path.read_bytes())
        record["signature"] = "ff" * 64
        self.anchor_path.write_bytes(canon(record))
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "signature is invalid"):
            self._read(finance_records.digest(record))

    def test_valid_genesis_and_durable_fence_supply_no_historical_intent(self):
        self._archive_current()
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "intent is missing"):
            self._read(self.genesis)
        with self._target() as target:
            denied = target.handle("reconcile", self.packet, self.expectations["peer"])
            self.assertEqual(denied["reason"], "INTENT_FENCED")
            pin = target.status()["anchor"]["anchor_sha256"]
        self._archive_current()
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "fenced"):
            self._read(pin)

    def test_unanchored_intent_is_rejected_even_with_original_durable_anchor(self):
        with self._target() as target:
            with patch.object(target._anchor, "advance", side_effect=AnchorError("synthetic interruption")):
                blocked = target.handle("initiate", self.packet, self.expectations["peer"])
            self.assertEqual(blocked, {"outcome": "BLOCKED", "reason": "TARGET_STATE_UNAVAILABLE"})
        self._archive_current()
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "pinned checkpoint"):
            self._read(self.genesis)

    def test_independently_pinned_expectations_must_match_original_business_and_policy(self):
        with self._target() as target:
            self._admit(target)
            pin = target.status()["anchor"]["anchor_sha256"]
        self._archive_current()
        changes = (
            ("scope", "amount_minor", 200),
            ("scope", "challenge", "fb" * 32),
            ("peer", "start_ticks", 456),
            (None, "witness_head", "fe" * 32),
            (None, "owner_pub", Signer().pub.hex()),
        )
        for group, key, value in changes:
            with self.subTest(key=key):
                expected = deepcopy(self.expectations)
                parent = expected if group is None else expected[group]
                parent[key] = value
                with self.assertRaises(history_archive.HistoryArchiveError):
                    self._read(pin, expectations=expected)

    def test_ambiguous_decision_rows_fail_even_with_a_valid_target_anchor(self):
        with self._target() as target:
            self._admit(target)
            with target._transaction():
                target._db.execute("""
                    INSERT INTO decisions (dispatch_digest, receipt)
                    SELECT dispatch_digest, receipt FROM decisions
                """)
            pin = target._anchor.advance(target)["anchor_sha256"]
        self._archive_current()
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "evidence is missing or ambiguous"):
            self._read(pin)

    def test_orphan_decision_for_same_slot_and_different_amount_invalidates_archive(self):
        scope = dict(self.expectations["scope"], amount_minor=3200)
        packet = self._make_packet(scope, "conflicting-grant")
        with self._target() as target:
            self._admit(target)
            conflicting = {
                "outcome": "INTENT_RECORDED", "packet": packet,
                "business_sha256": finance_records.business_digest(scope),
                "receipt": finance_records.receipt(target._signer, scope, packet, self.now),
                "observed_peer": self.expectations["peer"],
                "observed_witness_head": self.expectations["witness_head"],
                "observed_at": self.now,
            }
            with target._transaction():
                target._db.execute("INSERT INTO decisions (dispatch_digest, receipt) VALUES (?, ?)",
                                   (finance_records.digest(packet), canon(conflicting)))
            pin = target._anchor.advance(target)["anchor_sha256"]
        self._archive_current()
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "conflicts with the requested intent"):
            self._read(pin)

    def test_distinct_payment_slots_are_independently_readable_from_one_archive(self):
        scope = dict(self.expectations["scope"], request_id="second-payment", amount_minor=3200)
        second = self._make_packet(scope, "second-grant")
        with self._target() as target:
            first_evidence = self._admit(target)
            second_evidence = self._admit(target, second)
            pin = target.status()["anchor"]["anchor_sha256"]
        self._archive_current()
        self.assertEqual(self._read(pin), first_evidence)
        self.assertEqual(self._read(pin, expectations=dict(self.expectations, scope=scope)), second_evidence)

    def test_matching_ledger_rows_still_need_the_original_signed_receipt(self):
        with self._target() as target:
            self._admit(target)
            with target._transaction():
                entry = json.loads(target._db.execute("SELECT receipt FROM effects").fetchone()[0])
                decision = json.loads(target._db.execute("SELECT receipt FROM decisions").fetchone()[0])
                entry["receipt"]["signature"] = "ab" * 64
                decision["receipt"] = entry["receipt"]
                target._db.execute("UPDATE effects SET receipt = ?", (canon(entry),))
                target._db.execute("UPDATE decisions SET receipt = ?", (canon(decision),))
            pin = target._anchor.advance(target)["anchor_sha256"]
        self._archive_current()
        with self.assertRaises(history_archive.HistoryArchiveError):
            self._read(pin)

    def test_sidecar_or_archive_symlink_fails_closed(self):
        with self._target() as target:
            self._admit(target)
            pin = target.status()["anchor"]["anchor_sha256"]
        self._archive_current()
        sidecar = self.ledger_path.with_name(self.ledger_path.name + "-journal")
        sidecar.touch()
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "without sidecars"):
            self._read(pin)
        sidecar.unlink()
        self.ledger_path.unlink()
        self.ledger_path.symlink_to(self.state / self.ledger_path.name)
        with self.assertRaisesRegex(history_archive.HistoryArchiveError, "ordinary single-link files"):
            self._read(pin)


if __name__ == "__main__":
    unittest.main()
