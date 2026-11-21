"""Focused direct-target lifecycle controls for fictional payment intents.

The suite uses only synthetic keys and the in-process FinanceTarget API.
Process/socket controls belong to the separate finance service and crash suites.
"""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import patch

from alibi import Signer, canon
from wolfalibi.education_target import CONFIG_FILE, LEDGER_FILE
from wolfalibi.finance_records import (
    ACCOUNT,
    CURRENCY,
    OPERATION,
    PENDING,
    TENANT,
    digest,
    dispatch,
    owner_grant,
    qualify,
    run_scope,
    verify_receipt,
)
from wolfalibi.finance_target import FinanceTarget, FinanceTargetError, init_key
from wolfalibi.voidcell002_anchor import AnchorError


def _write_new(path, data):
    """Create one owner-private synthetic fixture artifact without replacement."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        if stream.write(data) != len(data):
            raise OSError("short synthetic fixture write")
        stream.flush()
        os.fsync(stream.fileno())


class FinanceTargetTests(unittest.TestCase):
    """Durable target and hostile-boundary tests, independent of wire transport."""

    def setUp(self):
        temporary = TemporaryDirectory(prefix="wolfalibi-finance-target-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "target"
        self.anchor = self.root / "anchor"
        self.control = self.root / "control"
        for directory in (self.state, self.anchor, self.control):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)

        self.now = 1_700_010_000
        self.clock = patch("wolfalibi.finance_target._clock_time", side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)

        self.owner, self.supervisor, self.witness, self.caller = (Signer() for _ in range(4))
        self.target_pub = init_key(self.state)
        self.peer = {
            "pid": 8181, "uid": 1000, "gid": 1000, "start_ticks": 456_789,
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
            "exe_sha256": "a1" * 32, "argv_sha256": "b2" * 32, "source_sha256": "c3" * 32,
        }
        self.scope = {
            "tenant": TENANT, "account": ACCOUNT, "currency": CURRENCY, "operation": OPERATION,
            "target_pub": self.target_pub, "policy_epoch": 1, "run_id": "finance-target-run",
            "challenge": "d4" * 32, "caller_pub": self.caller.pub.hex(),
            "request_id": "payment-one", "payee": "fictional-supplier", "amount_minor": 4500,
        }
        self.grant_id = "fictional-account-owner-grant"
        self.qualification = self._qualification()
        self.witness_path = self.control / "witness-head"
        _write_new(self.witness_path, digest(self.qualification).encode("ascii"))
        config = {
            "scope": run_scope(self.scope), "owner_pub": self.owner.pub.hex(),
            "supervisor_pub": self.supervisor.pub.hex(), "witness_pub": self.witness.pub.hex(),
            "peer": self.peer, "witness_head_path": str(self.witness_path),
        }
        _write_new(self.state / CONFIG_FILE, canon(config))
        with FinanceTarget(self.state, self.anchor, create=True) as target:
            self.assertEqual(target.status()["outcome"], "READY")
            self.assertEqual(target.status()["intent_count"], 0)
            self.assertEqual(target.target_pub.hex(), self.target_pub)

    def _target(self):
        return FinanceTarget(self.state, self.anchor)

    def _grant(self, *, signer=None, scope=None, grant_id=None, start=None, end=None):
        return owner_grant(
            self.owner if signer is None else signer,
            self.scope if scope is None else scope,
            self.grant_id if grant_id is None else grant_id,
            self.now if start is None else start,
            self.now + 90 if end is None else end,
        )

    def _qualification(self, *, supervisor=None, witness=None, scope=None, peer=None, start=None, end=None):
        return qualify(
            self.supervisor if supervisor is None else supervisor,
            self.witness if witness is None else witness,
            self.scope if scope is None else scope,
            self.peer if peer is None else peer,
            self.now if start is None else start,
            self.now + 60 if end is None else end,
        )

    def _packet(self, *, caller=None, scope=None, grant=None, qualification=None):
        scope = self.scope if scope is None else scope
        return dispatch(
            self.caller if caller is None else caller, scope,
            self._grant(scope=scope) if grant is None else grant,
            self.qualification if qualification is None else qualification,
        )

    def _deny(self, result, reason=None):
        self.assertIn(result["outcome"], {"DENIED", "BLOCKED"}, result)
        if reason is not None:
            self.assertEqual(result.get("reason"), reason, result)
        self.assertNotIn("receipt", result, result)
        self.assertNotIn("settlement", result, result)

    def _intent(self, target, packet):
        result = target.handle("initiate", packet, target.peer)
        self.assertEqual(result["outcome"], "INTENT_RECORDED", result)
        self.assertEqual(set(result), {"outcome", "receipt"}, result)
        payload = verify_receipt(
            result["receipt"], target_pub=target.target_pub, scope=packet["scope"], packet=packet,
        )
        self.assertEqual(payload["outcome"], PENDING)
        self.assertNotIn("SETTLED", str(payload))
        return result

    def _replace_witness_head(self, qualification):
        data = digest(qualification).encode("ascii")
        flags = os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
        with os.fdopen(os.open(self.witness_path, flags), "wb") as stream:
            if stream.write(data) != len(data):
                raise OSError("short synthetic witness update")
            stream.flush()
            os.fsync(stream.fileno())

    def test_initial_intent_is_pending_and_exact_retry_is_historical(self):
        packet = self._packet()
        with self._target() as target:
            initial = self._intent(target, packet)
            historical = target.handle("initiate", packet, target.peer)
            reconciled = target.handle("reconcile", packet, target.peer)
            self.assertEqual(historical, {"outcome": "HISTORICAL_INTENT", "receipt": initial["receipt"]})
            self.assertEqual(reconciled, {"outcome": "RECONCILED", "receipt": initial["receipt"]})
            self.assertEqual(target.status()["intent_count"], 1)

    def test_changed_payee_or_amount_under_signed_same_id_conflicts(self):
        with self._target() as target:
            self._intent(target, self._packet())
            for field, value in (("payee", "fictional-alternate-supplier"), ("amount_minor", 4501)):
                with self.subTest(field=field):
                    changed_scope = dict(self.scope, **{field: value})
                    packet = self._packet(scope=changed_scope, grant=self._grant(scope=changed_scope))
                    self._deny(target.handle("initiate", packet, target.peer), "REQUEST_ID_CONFLICT")
                    self.assertEqual(target.status()["intent_count"], 1)

    def test_unrelated_request_id_is_a_distinct_durable_intent(self):
        with self._target() as target:
            first = self._intent(target, self._packet())
            other_scope = dict(self.scope, request_id="payment-two")
            second_packet = self._packet(scope=other_scope, grant=self._grant(scope=other_scope))
            second = self._intent(target, second_packet)
            self.assertNotEqual(first["receipt"], second["receipt"])
            self.assertEqual(target.status()["intent_count"], 2)

    def test_renewed_authorization_cannot_replace_the_original_packet(self):
        with self._target() as target:
            self._intent(target, self._packet())
            renewal = self._packet(grant=self._grant(grant_id="renewed-account-owner-grant"))
            self._deny(target.handle("initiate", renewal, target.peer), "NONIDENTICAL_PACKET")
            self.assertEqual(target.status()["intent_count"], 1)

    def test_invalid_owner_qualification_or_settlement_is_denied(self):
        foreign_owner = self._grant(signer=Signer())
        expired_owner = self._grant(start=self.now - 60, end=self.now - 1)
        forged_qualification = deepcopy(self.qualification)
        forged_qualification["supervisor_signature"] = "00" * 64
        expired_qualification = self._qualification(start=self.now - 60, end=self.now - 1)
        with self._target() as target:
            for grant, qualification in ((foreign_owner, self.qualification), (expired_owner, self.qualification),
                                         (self._grant(), forged_qualification),
                                         (self._grant(), expired_qualification)):
                with self.subTest(expired=qualification is expired_qualification):
                    self._replace_witness_head(qualification)
                    packet = self._packet(grant=grant, qualification=qualification)
                    self._deny(target.handle("initiate", packet, target.peer),
                               "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
                    self.assertEqual(target.status()["intent_count"], 0)
            valid = self._packet()
            self._deny(target.handle("settle", valid, target.peer), "UNKNOWN_TARGET_ACTION")
            self._deny(target.handle("initiate", dict(valid, settlement="SETTLED"), target.peer),
                       "INVALID_TARGET_REQUEST")
            self.assertEqual(target.status()["intent_count"], 0)

    def test_mismatched_run_peer_or_witness_is_denied(self):
        changed_scope = dict(self.scope, run_id="other-finance-run")
        changed_packet = self._packet(
            scope=changed_scope, grant=self._grant(scope=changed_scope),
            qualification=self._qualification(scope=changed_scope),
        )
        with self._target() as target:
            self._deny(target.handle("initiate", changed_packet, target.peer),
                       "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            bad_peer = dict(target.peer, source_sha256="00" * 32)
            self._deny(target.handle("initiate", self._packet(), bad_peer), "PEER_MISMATCH")
            self._replace_witness_head(self._qualification(start=self.now, end=self.now + 59))
            self._deny(target.handle("initiate", self._packet(), target.peer),
                       "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            self.assertEqual(target.status()["intent_count"], 0)

    def test_unauthenticated_reconcile_does_not_fence_a_later_valid_intent(self):
        forged = self._packet(grant=self._grant(signer=Signer()))
        with self._target() as target:
            self._deny(target.handle("reconcile", forged, target.peer),
                       "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            self._intent(target, self._packet())
            self.assertEqual(target.status()["intent_count"], 1)

    def test_authenticated_reconcile_first_durably_fences_later_intent(self):
        packet = self._packet()
        with self._target() as target:
            self._deny(target.handle("reconcile", packet, target.peer), "INTENT_FENCED")
            self._deny(target.handle("initiate", packet, target.peer), "INTENT_FENCED")
            self.assertEqual(target.status()["intent_count"], 0)
        with self._target() as reopened:
            self._deny(reopened.handle("initiate", packet, reopened.peer), "INTENT_FENCED")
            self.assertEqual(reopened.status()["intent_count"], 0)

    def test_serialized_admit_then_revoke_does_not_interleave(self):
        packet = self._packet()
        verified, release, revoke_started = Event(), Event(), Event()
        with self._target() as target:
            original = target._check_packet

            def pause_after_authentication(*args, **kwargs):
                value = original(*args, **kwargs)
                verified.set()
                if not release.wait(5):
                    raise AssertionError("admission was not released")
                return value

            def revoke_after_start():
                revoke_started.set()
                return target.revoke(self.grant_id)

            with patch.object(target, "_check_packet", side_effect=pause_after_authentication):
                with ThreadPoolExecutor(max_workers=2) as workers:
                    admission = workers.submit(target.handle, "initiate", packet, target.peer)
                    self.assertTrue(verified.wait(5))
                    revocation = workers.submit(revoke_after_start)
                    self.assertTrue(revoke_started.wait(5))
                    self.assertFalse(revocation.done(), "revocation interleaved inside admission")
                    release.set()
                    accepted = admission.result(timeout=5)
                    revoked = revocation.result(timeout=5)
            self.assertEqual(accepted["outcome"], "INTENT_RECORDED", accepted)
            self.assertEqual(revoked, {"outcome": "REVOKED"})
            self._deny(target.handle("initiate", packet, target.peer), "OWNER_GRANT_REVOKED")
            self.assertEqual(target.status()["intent_count"], 1)

    def test_durable_revocation_blocks_a_new_intent_after_restart(self):
        packet = self._packet()
        with self._target() as target:
            self.assertEqual(target.revoke(self.grant_id), {"outcome": "REVOKED"})
        with self._target() as reopened:
            self._deny(reopened.handle("initiate", packet, reopened.peer), "OWNER_GRANT_REVOKED")
            self.assertEqual(reopened.status()["intent_count"], 0)

    def test_retries_after_expiry_do_not_return_or_replace_the_receipt(self):
        deadline = self.now + 1
        grant = self._grant(end=deadline)
        qualification = self._qualification(end=deadline)
        self._replace_witness_head(qualification)
        packet = self._packet(grant=grant, qualification=qualification)
        with self._target() as target:
            original = self._intent(target, packet)
            self.now = deadline
            self._deny(target.handle("initiate", packet, target.peer),
                       "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            self._deny(target.handle("reconcile", packet, target.peer),
                       "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            renewal = self._qualification(start=deadline, end=deadline + 60)
            self._replace_witness_head(renewal)
            renewed_packet = self._packet(
                grant=self._grant(grant_id="renewed-grant", start=deadline, end=deadline + 90),
                qualification=renewal,
            )
            self._deny(target.handle("initiate", renewed_packet, target.peer), "NONIDENTICAL_PACKET")
            self.assertEqual(target.status()["intent_count"], 1)
        self.assertIn("receipt", original)

    def test_clock_rollback_survives_restart(self):
        packet = self._packet()
        future = self.now + 100
        with self._target() as target:
            self.now = future
            self._deny(target.handle("initiate", packet, target.peer),
                       "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
        with self._target() as reopened:
            self.now = future - 1
            self._deny(reopened.handle("initiate", packet, reopened.peer), "TARGET_CLOCK_REGRESSION")
            self._deny(reopened.handle("reconcile", packet, reopened.peer), "TARGET_CLOCK_REGRESSION")
            self.assertEqual(reopened.status()["intent_count"], 0)

    def test_precommit_expiry_creates_no_intent(self):
        deadline = self.now + 1
        qualification = self._qualification(end=deadline)
        self._replace_witness_head(qualification)
        packet = self._packet(grant=self._grant(end=deadline), qualification=qualification)
        with self._target() as target:
            with patch("wolfalibi.finance_target._clock_time", side_effect=[self.now, deadline]):
                result = target.handle("initiate", packet, target.peer)
            self._deny(result, "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            self.assertEqual(target.status()["intent_count"], 0)

    def test_post_checkpoint_expiry_withholds_receipt_but_keeps_intent(self):
        deadline = self.now + 1
        qualification = self._qualification(end=deadline)
        self._replace_witness_head(qualification)
        packet = self._packet(grant=self._grant(end=deadline), qualification=qualification)
        with self._target() as target:
            with patch("wolfalibi.finance_target._clock_time", side_effect=[self.now, self.now, deadline]):
                result = target.handle("initiate", packet, target.peer)
            self._deny(result, "AUTHORIZATION_EXPIRED_BEFORE_HANDOFF")
            self.assertEqual(target.status()["intent_count"], 1)

    def test_later_handoff_sample_is_durable_across_restart(self):
        packet = self._packet()
        later = self.now + 1
        with self._target() as target:
            with patch("wolfalibi.finance_target._clock_time",
                       side_effect=[self.now, self.now, later, later]):
                self._intent(target, packet)
            self.assertEqual(target.status()["intent_count"], 1)
        with self._target() as reopened:
            self.now -= 1
            self._deny(reopened.handle("initiate", packet, reopened.peer), "TARGET_CLOCK_REGRESSION")
            self._deny(reopened.handle("reconcile", packet, reopened.peer), "TARGET_CLOCK_REGRESSION")

    def test_committed_unanchored_checkpoint_failure_fails_closed(self):
        packet = self._packet()
        with self._target() as target:
            with patch.object(target._anchor, "advance", side_effect=AnchorError("synthetic interruption")):
                result = target.handle("initiate", packet, target.peer)
            self._deny(result, "TARGET_STATE_UNAVAILABLE")
            self._deny(target.status(), "TARGET_STATE_UNAVAILABLE")
        with self.assertRaises(FinanceTargetError):
            self._target()

    def test_retained_checkpoint_detects_an_older_ledger_snapshot(self):
        ledger = self.state / LEDGER_FILE
        before = ledger.read_bytes()
        with self._target() as target:
            self._intent(target, self._packet())
        retained = (self.anchor / "ledger-anchor.json").read_bytes()
        ledger.write_bytes(before)
        with self.assertRaises(FinanceTargetError):
            self._target()
        self.assertEqual((self.anchor / "ledger-anchor.json").read_bytes(), retained)

    def test_archive_failure_rolls_back_intent_receipt_and_archive_together(self):
        packet = self._packet()
        with self._target() as target:
            def deny_archive(action, arg1, _arg2, _database, _source):
                if action == sqlite3.SQLITE_INSERT and arg1 == "decisions":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            target._db.set_authorizer(deny_archive)
            try:
                result = target.handle("initiate", packet, target.peer)
            finally:
                target._db.set_authorizer(None)
            self._deny(result, "TARGET_STATE_UNAVAILABLE")
            self._deny(target.status(), "TARGET_STATE_UNAVAILABLE")
        with self._target() as reopened:
            self.assertEqual(reopened.status()["intent_count"], 0)
            self._intent(reopened, packet)


if __name__ == "__main__":
    unittest.main()
