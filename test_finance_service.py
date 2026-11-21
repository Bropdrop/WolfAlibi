"""Qualify the synthetic finance intent with real local caller and target processes."""

import json
import os
from pathlib import Path
import socket
import stat
import sys
from tempfile import TemporaryDirectory
import time
import unittest

from examples.quorvane_finance_demo import FixtureError, demo, fixture
from wolfalibi.finance_records import PENDING, business_digest, digest, idempotency_key
from wolfalibi.finance_verify import verify_admission


@unittest.skipUnless(sys.platform == "linux" and hasattr(socket, "SCM_CREDENTIALS")
                     and hasattr(os, "pidfd_open"), "requires Linux peer credentials and pidfds")
class FinanceServiceTests(unittest.TestCase):
    def _deny(self, result, reason):
        self.assertEqual(result, {"outcome": "DENIED", "reason": reason})

    def _check_intent(self, resource, packet, result):
        self.assertEqual(set(result), {"outcome", "receipt"}, result)
        self.assertEqual(result["outcome"], "INTENT_RECORDED")
        receipt = result["receipt"]
        payload = resource.verify(packet, receipt)
        self.assertEqual(payload["outcome"], PENDING)
        self.assertEqual(payload["packet_sha256"], digest(packet))
        self.assertEqual(payload["business_sha256"], business_digest(resource.scope))
        self.assertEqual(payload["idempotency_key"], idempotency_key(resource.scope))
        return receipt

    def _stored_intents(self, resource):
        resource.stop_target()
        result = resource.offline_status()
        self.assertEqual(result["outcome"], "READY", result)
        return result["intent_count"]

    def test_demo_recovers_without_resend_and_verifies_with_external_pins(self):
        with TemporaryDirectory(prefix="fin-demo-") as root:
            pins = Path(root) / "expectations.json"
            challenge = "ca" * 32
            report = demo(root, expectations_out=pins, challenge=challenge)
            self.assertEqual(report["outcome"], "PASS", report)
            self.assertEqual(report["observed"], report["expected"])
            self.assertEqual(report["observed"]["lost_reply"], {"outcome": "UNKNOWN", "response_read": False})
            self.assertIs(report["observed"]["checkpoint_advanced_before_restart"], True)
            self.assertEqual(report["observed"]["restart_reconciliation"], "RECONCILED")
            self.assertEqual(report["observed"]["second_reconciliation"], "SAME_RECEIPT")
            self.assertEqual(report["observed"]["intent_count"], 1)
            self.assertEqual(report["observed"]["receipt_outcome"], PENDING)
            self.assertEqual(report["cross_uid_custody"], "UNSUPPORTED")
            self.assertEqual(report["production"], "BLOCKED")
            for measure in ("executable", "source", "argv"):
                measurement = report["caller_preflight"]
                self.assertEqual(measurement[f"expected_{measure}_sha256"],
                                 measurement[f"observed_{measure}_sha256"])
            self.assertEqual(stat.S_IMODE(pins.stat().st_mode), 0o600)
            expected = json.loads(pins.read_bytes())
            self.assertEqual(expected["scope"]["challenge"], challenge)
            self.assertEqual(set(report["evidence"]), {"packet", "receipt"})
            dispatch_path = Path(root) / "control" / "dispatch.json"
            self.assertEqual(stat.S_IMODE(dispatch_path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(dispatch_path.read_bytes()), report["evidence"]["packet"])
            verified = verify_admission(expected, report["evidence"])
            self.assertEqual(verified["outcome"], "VERIFIED", verified)
            self.assertEqual(verified["verified"], "HISTORICAL_SYNTHETIC_PAYMENT_INTENT")
            self.assertEqual(verified["effect"], PENDING)
            bad = dict(expected, scope=dict(expected["scope"], challenge="db" * 32))
            with self.assertRaises(ValueError):
                verify_admission(bad, report["evidence"])

    def test_owner_revocation_blocks_live_history_but_preserves_the_committed_intent(self):
        with TemporaryDirectory(prefix="fin-revoke-") as root, fixture(root) as resource:
            now = int(time.time())
            expired = resource.make_grant(start=now - 60, end=now - 1)
            self._deny(resource.invoke(grant=expired)["result"], "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            authorized = resource.invoke()
            receipt = self._check_intent(resource, authorized["packet"], authorized["result"])
            resource.stop_target()
            self.assertEqual(resource.revoke()["outcome"], "REVOKED")
            resource.start_target()
            self._deny(resource.invoke()["result"], "OWNER_GRANT_REVOKED")
            self._deny(resource.invoke("reconcile", packet=authorized["packet"])["result"], "OWNER_GRANT_REVOKED")
            self.assertEqual(self._stored_intents(resource), 1)
            historic = verify_admission(resource.expectations, {"packet": authorized["packet"], "receipt": receipt})
            self.assertEqual(historic["effect"], PENDING)

    def test_concurrent_identical_packets_return_one_new_and_one_original_intent(self):
        with TemporaryDirectory(prefix="fin-dupe-") as root, fixture(root) as resource:
            frame = resource.invoke("parallel")
            outcomes = sorted(item["outcome"] for item in frame["results"])
            self.assertEqual(outcomes, ["HISTORICAL_INTENT", "INTENT_RECORDED"], frame)
            by_outcome = {item["outcome"]: item for item in frame["results"]}
            receipt = self._check_intent(resource, frame["packet"], by_outcome["INTENT_RECORDED"])
            expected = {"outcome": "HISTORICAL_INTENT", "receipt": receipt}
            self.assertEqual(by_outcome["HISTORICAL_INTENT"], expected)
            resource.restart_target()
            self.assertEqual(resource.invoke()["result"], expected)
            self.assertEqual(self._stored_intents(resource), 1)

    def test_owner_signed_same_request_changes_conflict_and_cannot_replace_original(self):
        with TemporaryDirectory(prefix="fin-conflict-") as root, fixture(root) as resource:
            first = resource.invoke()
            receipt = self._check_intent(resource, first["packet"], first["result"])
            for change in ({"amount_minor": 4700}, {"payee": "fictional-other-supplier"}):
                with self.subTest(fields=tuple(change)):
                    changed = dict(resource.scope, **change)
                    result = resource.invoke(scope=changed, grant=resource.make_grant(scope=changed))
                    self.assertEqual(result["packet"]["scope"]["request_id"], resource.scope["request_id"])
                    self._deny(result["result"], "REQUEST_ID_CONFLICT")
            now = int(time.time())
            renewed = resource.make_grant(start=now - 1, end=now + 55)
            self._deny(resource.invoke(grant=renewed)["result"], "NONIDENTICAL_PACKET")
            replay = resource.invoke("reconcile", packet=first["packet"])["result"]
            self.assertEqual(replay, {"outcome": "RECONCILED", "receipt": receipt})
            self.assertEqual(self._stored_intents(resource), 1)

    def test_reconcile_before_send_durably_fences_later_delivery(self):
        with TemporaryDirectory(prefix="fin-fence-") as root, fixture(root) as resource:
            packet = resource.invoke("sign")["packet"]
            self._deny(resource.invoke("reconcile", packet=packet)["result"], "INTENT_FENCED")
            resource.restart_target()
            self._deny(resource.invoke()["result"], "INTENT_FENCED")
            self.assertEqual(self._stored_intents(resource), 0)

    def test_exited_caller_has_no_replacement_enrollment(self):
        with TemporaryDirectory(prefix="fin-caller-exit-") as root, fixture(root) as resource:
            packet = resource.invoke("sign")["packet"]
            resource.caller.stdin.close()
            resource.caller.wait(timeout=5)
            with self.assertRaisesRegex(FixtureError, "enrollment is unusable"):
                resource.invoke("reconcile", packet=packet)
            self.assertEqual(self._stored_intents(resource), 0)


if __name__ == "__main__":
    unittest.main()
