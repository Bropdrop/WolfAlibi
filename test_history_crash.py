"""Stop a disposable inquiry authority exactly before or after its durable commit."""

import hashlib
import multiprocessing
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from alibi import Signer
from examples.quorvane_finance_demo import fixture
from wolfalibi.history_authority import HistoryAuthority
from wolfalibi.history_records import inquiry_scope, issue_grant, sign_inquiry


def _interrupt_disclosure(authority, request, challenge, phase):
    connect = sqlite3.connect

    class InterruptedCommit(sqlite3.Connection):
        def commit(self):
            if phase == "before":
                os.kill(os.getpid(), signal.SIGKILL)
            super().commit()
            os.kill(os.getpid(), signal.SIGKILL)

    def open_database(database, **kwargs):
        if database.endswith("?mode=rw"):
            kwargs["factory"] = InterruptedCommit
        return connect(database, **kwargs)

    with patch("sqlite3.connect", side_effect=open_database):
        authority.inquire(request, challenge=challenge)
    raise AssertionError("disclosure did not reach its commit boundary")


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'pidfd_open'), 'Linux finance fixture required')
class HistoryCrashTests(unittest.TestCase):
    def exercise(self, phase):
        with TemporaryDirectory() as tmp, fixture(tmp) as resource:
            packet = resource.invoke("sign")["packet"]
            payment = resource.invoke(packet=packet)["result"]
            self.assertEqual(payment["outcome"], "INTENT_RECORDED")
            resource.close()
            finance_state = resource.target_state / "ledger.sqlite"
            original_file = finance_state.read_bytes()
            anchor = resource.anchor / "ledger-anchor.json"
            retained = anchor.read_bytes()
            root = Path(tmp)
            history = root / "history"
            head = root / "head"
            for path in (history, head):
                path.mkdir(mode=0o700)
            stores = (history / 'access.sqlite', head / 'retained.sqlite')
            settings = dict(ledger_path=finance_state, anchor_path=anchor, expectations=resource.expectations,
                            anchor_sha256=hashlib.sha256(retained).hexdigest(), signer=Signer())
            authority = HistoryAuthority(*stores, **settings, create=True)
            auditor = Signer()
            scope = inquiry_scope(resource.scope)
            now = int(time.time())
            grant = issue_grant(resource.owner, scope, auditor.pub, 'audit-crash', now, now + 100)
            challenge = secrets.token_hex(32)
            request = sign_inquiry(auditor, scope, grant, challenge)
            child = multiprocessing.get_context("fork").Process(
                target=_interrupt_disclosure, args=(authority, request, challenge, phase),
            )
            child.start()
            try:
                child.join(10)
                self.assertFalse(child.is_alive(), "inquiry did not reach the expected SQLite commit")
                self.assertEqual(child.exitcode, -signal.SIGKILL)
            finally:
                if child.is_alive():
                    child.kill()
                    child.join()
                child.close()
            restarted = HistoryAuthority(*stores, **settings)
            recovered = restarted.inquire(request, challenge=challenge)
            if phase == "after":
                self.assertEqual(recovered, {"outcome": "DENIED", "reason": "CHALLENGE_USED"})
                challenge = secrets.token_hex(32)
                recovered = restarted.inquire(sign_inquiry(auditor, scope, grant, challenge), challenge=challenge)
            self.assertEqual(recovered["outcome"], "DISCLOSED", recovered)
            self.assertEqual(recovered["evidence"]["original"], {"packet": packet, "receipt": payment["receipt"]})
            self.assertEqual(finance_state.read_bytes(), original_file)
            self.assertEqual(anchor.read_bytes(), retained)

    def test_inquiry_death_before_commit_leaves_challenge_available(self):
        self.exercise("before")

    def test_inquiry_death_after_commit_requires_fresh_challenge(self):
        self.exercise("after")
