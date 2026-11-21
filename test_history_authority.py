"""Integration tests for the separate, read-only historical disclosure authority.

The fixture creates only synthetic Gate 003 payment evidence in-process. It does
not import another test module: the history authority is tested against its own
independently copied ledger and anchor snapshot.
"""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from alibi import H, Signer, canon
from wolfalibi import finance_records as finance
from wolfalibi import history_records as history
from wolfalibi.education_target import CONFIG_FILE, LEDGER_FILE
from wolfalibi.finance_target import FinanceTarget, init_key
from wolfalibi.history_authority import HistoryAuthority
from wolfalibi.history_verify import verify_history
from wolfalibi.voidcell002 import KEY_FILE


def _private_directory(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _write_new(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        if stream.write(data) != len(data):
            raise OSError("short synthetic fixture write")
        stream.flush()
        os.fsync(stream.fileno())


class HistoryAuthorityTests(unittest.TestCase):
    """State-machine and role-separation tests using a real local archive."""

    def setUp(self):
        temporary = TemporaryDirectory(prefix="wolfalibi-history-authority-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.now = 1_700_040_000
        self.archive = self._make_finance_archive(self.root / "finance")
        self.history_signer, self.auditor = Signer(), Signer()
        self.scope = history.inquiry_scope(self.archive["expectations"]["scope"])
        self.grant_id = "synthetic-history-grant"
        self.challenge = "e1" * 32
        self.db_dir = _private_directory(self.root / "inquiry-state")
        self.head_dir = _private_directory(self.root / "retained-history-head")
        self.db_path = self.db_dir / "history.sqlite"
        self.head_path = self.head_dir / "history-head.sqlite"
        with self._authority(create=True):
            pass

    def _make_finance_archive(self, root, *, request_id="history-intent"):
        _private_directory(root)
        state = _private_directory(root / "target-state")
        anchors = _private_directory(root / "target-anchor")
        escrow = _private_directory(root / "escrow-snapshot")
        control = _private_directory(root / "control")
        owner, supervisor, witness, caller = (Signer() for _ in range(4))
        target_pub = init_key(state)
        peer = {
            "pid": 711, "uid": 1000, "gid": 1000, "start_ticks": 123_456,
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
            "exe_sha256": "a1" * 32, "argv_sha256": "b2" * 32,
            "source_sha256": "c3" * 32,
        }
        scope = {
            "tenant": finance.TENANT, "account": finance.ACCOUNT, "currency": finance.CURRENCY,
            "operation": finance.OPERATION, "target_pub": target_pub, "policy_epoch": 1,
            "run_id": "synthetic-history-run", "challenge": "d4" * 32,
            "caller_pub": caller.pub.hex(), "request_id": request_id,
            "payee": "fictional-supplier", "amount_minor": 4500,
        }
        finance_grant = finance.owner_grant(owner, scope, "synthetic-payment-grant", self.now, self.now + 60)
        qualification = finance.qualify(supervisor, witness, scope, peer, self.now, self.now + 60)
        packet = finance.dispatch(caller, scope, finance_grant, qualification)
        witness_head = finance.digest(qualification)
        witness_path = control / "witness-head"
        _write_new(witness_path, witness_head.encode("ascii"))
        _write_new(state / CONFIG_FILE, canon({
            "scope": finance.run_scope(scope), "owner_pub": owner.pub.hex(),
            "supervisor_pub": supervisor.pub.hex(), "witness_pub": witness.pub.hex(),
            "peer": peer, "witness_head_path": str(witness_path),
        }))
        with patch("wolfalibi.finance_target._clock_time", return_value=self.now):
            with FinanceTarget(state, anchors, create=True) as target:
                result = target.handle("initiate", packet, peer)
                self.assertEqual(result["outcome"], "INTENT_RECORDED", result)
                receipt = result["receipt"]
                anchor_sha256 = target.status()["anchor"]["anchor_sha256"]
        ledger = escrow / LEDGER_FILE
        anchor = escrow / "ledger-anchor.json"
        copyfile(state / LEDGER_FILE, ledger)
        copyfile(anchors / "ledger-anchor.json", anchor)
        self.assertEqual(H(anchor.read_bytes()).hex(), anchor_sha256)
        return {
            "state": state, "anchor_dir": anchors, "ledger": ledger, "anchor": anchor,
            "anchor_sha256": anchor_sha256, "owner": owner,
            "target_signer": Signer((state / KEY_FILE).read_bytes()),
            "packet": packet, "receipt": receipt,
            "expectations": {
                "scope": scope, "target_pub": target_pub, "owner_pub": owner.pub.hex(),
                "supervisor_pub": supervisor.pub.hex(), "witness_pub": witness.pub.hex(),
                "peer": peer, "witness_head": witness_head,
            },
        }

    def _authority(self, *, create=False, archive=None, db_path=None, head_path=None, signer=None):
        archive = self.archive if archive is None else archive
        return HistoryAuthority(
            self.db_path if db_path is None else db_path,
            self.head_path if head_path is None else head_path,
            ledger_path=archive["ledger"], anchor_path=archive["anchor"],
            expectations=self.archive["expectations"], anchor_sha256=archive["anchor_sha256"],
            signer=self.history_signer if signer is None else signer, create=create,
        )

    def _request(self, challenge=None, *, grant_id=None, end=None, auditor=None):
        challenge = self.challenge if challenge is None else challenge
        grant = history.issue_grant(
            self.archive["owner"], self.scope, self.auditor.pub if auditor is None else auditor.pub,
            self.grant_id if grant_id is None else grant_id, self.now, self.now + 60 if end is None else end,
        )
        signer = self.auditor if auditor is None else auditor
        return history.sign_inquiry(signer, self.scope, grant, challenge)

    def _inquire(self, authority, request, challenge):
        with patch("wolfalibi.history_authority._now", return_value=self.now):
            return authority.inquire(request, challenge=challenge)

    def _history_expectations(self, challenge):
        return {
            "finance": self.archive["expectations"], "history_pub": self.history_signer.pub.hex(),
            "anchor_sha256": self.archive["anchor_sha256"], "auditor_pub": self.auditor.pub.hex(),
            "challenge": challenge,
        }

    def test_disclosure_is_read_only_closed_purpose_and_independently_verifiable(self):
        request = self._request()
        before = (self.archive["ledger"].read_bytes(), self.archive["anchor"].read_bytes())
        with self._authority() as authority:
            result = self._inquire(authority, request, self.challenge)
        self.assertEqual(result["outcome"], "DISCLOSED", result)
        self.assertEqual(set(result["evidence"]), {"original", "request", "attestation"})
        original = result["evidence"]["original"]
        self.assertEqual(set(original), {"packet", "receipt"})
        self.assertEqual(original["receipt"]["payload"]["outcome"], finance.PENDING)
        self.assertNotIn("settlement", original)
        self.assertEqual(before, (self.archive["ledger"].read_bytes(), self.archive["anchor"].read_bytes()))
        verified = verify_history(self._history_expectations(self.challenge), result["evidence"], challenge=self.challenge)
        self.assertEqual(verified["outcome"], "VERIFIED", verified)
        self.assertEqual(verified["settlement"], "UNESTABLISHED")

    def test_discarded_first_reply_is_consumed_and_rejected_after_restart(self):
        request = self._request()
        with self._authority() as authority:
            self.assertEqual(self._inquire(authority, request, self.challenge)["outcome"], "DISCLOSED")
        with self._authority() as reopened:
            retry = self._inquire(reopened, request, self.challenge)
        self.assertEqual(retry, {"outcome": "DENIED", "reason": "CHALLENGE_USED"})

    def test_simultaneous_identical_challenge_discloses_once(self):
        request = self._request()

        def invoke():
            with self._authority() as authority:
                return authority.inquire(request, challenge=self.challenge)

        with patch("wolfalibi.history_authority._now", return_value=self.now):
            with ThreadPoolExecutor(max_workers=2) as workers:
                results = list(workers.map(lambda _unused: invoke(), range(2)))
        outcomes = sorted(item["outcome"] for item in results)
        self.assertEqual(outcomes, ["DENIED", "DISCLOSED"], results)
        denial = next(item for item in results if item["outcome"] == "DENIED")
        self.assertEqual(denial["reason"], "CHALLENGE_USED")

    def test_revocation_is_durable_and_fences_a_later_history_request(self):
        request = self._request()
        with self._authority() as authority:
            self.assertEqual(authority.revoke(self.grant_id), {"outcome": "REVOKED"})
        with self._authority() as reopened:
            denied = self._inquire(reopened, request, self.challenge)
        self.assertEqual(denied, {"outcome": "DENIED", "reason": "HISTORY_GRANT_REVOKED"})

    def test_history_database_rollback_against_retained_head_fails_closed(self):
        first = self._request("e2" * 32)
        second = self._request("e3" * 32)
        third = self._request("e4" * 32)
        with self._authority() as authority:
            self.assertEqual(self._inquire(authority, first, "e2" * 32)["outcome"], "DISCLOSED")
        older_db = self.db_path.read_bytes()
        with self._authority() as authority:
            self.assertEqual(self._inquire(authority, second, "e3" * 32)["outcome"], "DISCLOSED")
        self.db_path.write_bytes(older_db)
        with self._authority() as authority:
            result = self._inquire(authority, third, "e4" * 32)
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertNotIn("evidence", result)

    def test_retained_head_rollback_after_revocation_fails_closed(self):
        request = self._request()
        older_head = self.head_path.read_bytes()
        with self._authority() as authority:
            self.assertEqual(authority.revoke(self.grant_id), {"outcome": "REVOKED"})
        self.head_path.write_bytes(older_head)
        with self._authority() as reopened:
            result = self._inquire(reopened, request, self.challenge)
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertNotIn("evidence", result)

    def test_opposite_anchored_snapshot_cannot_disclose_original_history(self):
        other = self._make_finance_archive(self.root / "other-finance", request_id="other-intent")
        other_db_dir = _private_directory(self.root / "other-inquiry-state")
        other_head_dir = _private_directory(self.root / "other-retained-head")
        other_db, other_head = other_db_dir / "history.sqlite", other_head_dir / "history-head.sqlite"
        with self._authority(create=True, archive=other, db_path=other_db, head_path=other_head) as authority:
            result = self._inquire(authority, self._request(), self.challenge)
        self.assertEqual(result["outcome"], "BLOCKED", result)
        self.assertEqual(result["reason"], "HISTORY_ARCHIVE_UNAVAILABLE")
        self.assertNotIn("evidence", result)

    def test_expiry_during_archive_verification_withholds_disclosure(self):
        challenge = "e5" * 32
        request = self._request(challenge, end=self.now + 1)
        calls = 0

        def clock():
            nonlocal calls
            calls += 1
            return self.now if calls == 1 else self.now + 1

        with self._authority() as authority, patch("wolfalibi.history_authority._now", side_effect=clock):
            result = authority.inquire(request, challenge=challenge)
        self.assertEqual(result["outcome"], "DENIED", result)
        self.assertEqual(result["reason"], "HISTORY_AUTHORIZATION_INVALID")
        self.assertNotIn("evidence", result)

    def test_expired_grant_then_backwards_clock_after_restart_cannot_reenable_it(self):
        challenge = "e6" * 32
        request = self._request(challenge, end=self.now + 1)
        with self._authority() as authority, patch(
            "wolfalibi.history_authority._now", return_value=self.now + 1,
        ):
            expired = authority.inquire(request, challenge=challenge)
        self.assertEqual(expired, {"outcome": "DENIED", "reason": "HISTORY_AUTHORIZATION_INVALID"})
        with self._authority() as reopened, patch(
            "wolfalibi.history_authority._now", return_value=self.now,
        ):
            backward = reopened.inquire(request, challenge=challenge)
        self.assertEqual(backward["outcome"], "BLOCKED", backward)
        self.assertNotIn("evidence", backward)

    def test_financial_and_history_roles_and_storage_are_separate(self):
        with self.assertRaises(ValueError):
            self._authority(signer=self.archive["owner"])
        with self.assertRaises(ValueError):
            self._authority(signer=self.archive["target_signer"])
        with self.assertRaises(ValueError):
            HistoryAuthority(
                self.db_dir / "same.sqlite", self.db_dir / "same-head.sqlite",
                ledger_path=self.archive["ledger"], anchor_path=self.archive["anchor"],
                expectations=self.archive["expectations"], anchor_sha256=self.archive["anchor_sha256"],
                signer=self.history_signer, create=False,
            )
        with self._authority() as authority:
            result = self._inquire(authority, self.archive["packet"], self.challenge)
        self.assertEqual(result, {"outcome": "DENIED", "reason": "HISTORY_AUTHORIZATION_INVALID"})


if __name__ == "__main__":
    unittest.main()
