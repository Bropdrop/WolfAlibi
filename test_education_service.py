"""Real local-process/synthetic-socket controls for the Education fixture."""

import json
import os
from pathlib import Path
import socket
import stat
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import MagicMock, patch

from alibi import Signer
from examples.quorvane_education_demo import FICTIONAL_RESPONSE, FixtureError, demo, fixture
from wolfalibi.education_records import digest
from wolfalibi.education_verify import verify_admission


@unittest.skipUnless(sys.platform == "linux" and hasattr(socket, "SCM_CREDENTIALS")
                     and hasattr(os, "pidfd_open"), "requires Linux peer credentials and pidfds")
class EducationServiceTests(unittest.TestCase):
    def _deny(self, result, reason):
        self.assertEqual(result, {"outcome": "DENIED", "reason": reason})

    def _verified_release(self, resource, frame):
        result = frame["result"]
        self.assertEqual(result["outcome"], "RELEASED", result)
        self.assertEqual(result["response"], FICTIONAL_RESPONSE)
        verified = resource.verify(frame["packet"], result["response"], result["receipt"])
        self.assertEqual(verified["scope_sha256"], digest(resource.scope))
        self.assertEqual(verified["response_sha256"], digest(FICTIONAL_RESPONSE))
        return result["receipt"]

    def test_demo_processes_and_historical_verification_under_external_pins(self):
        with TemporaryDirectory(prefix="edu-demo-test-") as root:
            expectations = Path(root) / "public-expectations.json"
            challenge = "a3" * 32
            report = demo(root, expectations_out=expectations, challenge=challenge)
            expected = json.loads(expectations.read_bytes())
            self.assertEqual(expected["scope"]["challenge"], challenge)
            self.assertEqual(report["evidence"]["packet"]["scope"]["challenge"], challenge)
            self.assertEqual(stat.S_IMODE(expectations.stat().st_mode), 0o600)
            self.assertEqual(report["outcome"], "PASS", report)
            self.assertEqual(report["cross_uid_custody"], "UNSUPPORTED")
            self.assertEqual(report["assurance"], "SIMULATED_POLICY_ONLY")
            self.assertEqual(report["production"], "BLOCKED")
            self.assertEqual(report["observed"], report["expected"])
            self.assertEqual(report["observed"]["committed_read_count"], 1)
            measured = report["caller_preflight"]
            self.assertEqual(measured["expected_executable_sha256"], measured["observed_executable_sha256"])
            self.assertEqual(measured["expected_source_sha256"], measured["observed_source_sha256"])
            self.assertEqual(measured["expected_argv_sha256"], measured["observed_argv_sha256"])
            self.assertTrue(measured["fixed_argv_matched"])
            self.assertNotEqual(expected["peer"]["pid"], os.getpid())
            verified = verify_admission(expected, report["evidence"])
            self.assertEqual(verified["outcome"], "VERIFIED", verified)
            self.assertEqual(verified["verified"], "HISTORICAL_SYNTHETIC_ADMISSION")
            wrong_target = Signer().pub.hex()
            with self.assertRaises(ValueError):
                verify_admission(dict(expected, target_pub=wrong_target), report["evidence"])

    def test_client_classifies_an_unread_response_as_unknown(self):
        from wolfalibi.education_transport import request

        session = MagicMock()
        session.receive.side_effect = ConnectionResetError()
        with patch("wolfalibi.education_transport._open_client_session", return_value=session):
            result = request("unused", "read", {}, expected_target_pid=1234)
        session.send.assert_called_once_with("read", {})
        self.assertEqual(result, {"outcome": "UNKNOWN", "reason": "RECONCILE_ORIGINAL_DISPATCH"})

    def test_transport_reply_loss_then_restart_recovers_only_the_one_receipt(self):
        with TemporaryDirectory(prefix="edu-loss-") as root, fixture(root) as resource:
            before = resource.retained_anchor()
            sent = resource.invoke("lost-reply")
            self.assertEqual(sent["result"], {"outcome": "UNKNOWN", "response_read": False})
            resource.wait_for_checkpoint_change(before)
            resource.restart_target()
            result = resource.invoke("reconcile", packet=sent["packet"])["result"]
            self.assertEqual(result["outcome"], "RECONCILED", result)
            self.assertNotIn("response", result)
            checked = resource.verify(sent["packet"], FICTIONAL_RESPONSE, result["receipt"])
            self.assertEqual(checked["packet_sha256"], digest(sent["packet"]))
            self._deny(resource.invoke()["result"], "READ_ALREADY_RECORDED")
            repeated = resource.invoke("reconcile", packet=sent["packet"])["result"]
            self.assertEqual(repeated, result)
            resource.stop_target()
            self.assertEqual(resource.offline_status()["release_count"], 1)

    def test_one_concurrent_request_releases_once_and_replay_does_not(self):
        with TemporaryDirectory(prefix="edu-concurrency-") as root, fixture(root) as resource:
            parallel = resource.invoke("parallel")
            self.assertEqual(len(parallel["results"]), 2)
            accepted = [item for item in parallel["results"] if item["outcome"] == "RELEASED"]
            denied = [item for item in parallel["results"] if item["outcome"] != "RELEASED"]
            self.assertEqual(len(accepted), 1, parallel)
            self._deny(denied[0], "READ_ALREADY_RECORDED")
            self._verified_release(resource, {"packet": parallel["packet"], "result": accepted[0]})
            self._deny(resource.invoke()["result"], "READ_ALREADY_RECORDED")
            resource.stop_target()
            self.assertEqual(resource.offline_status()["release_count"], 1)

    def test_expired_authority_cannot_be_restored_by_caller_time(self):
        with TemporaryDirectory(prefix="edu-expiry-") as root, fixture(root) as resource:
            now = int(time.time())
            expired = resource.make_grant(start=now - 15, end=now - 5)
            actual = resource.invoke(grant=expired)["result"]
            self._deny(actual, "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
            self._deny(resource.invoke("caller-time", grant=expired)["result"], "INVALID_TARGET_REQUEST")
            self._verified_release(resource, resource.invoke())
            resource.stop_target()
            self.assertEqual(resource.offline_status()["release_count"], 1)

    def test_revocation_survives_target_restart_and_denies_the_live_caller(self):
        with TemporaryDirectory(prefix="edu-revocation-") as root, fixture(root) as resource:
            resource.stop_target()
            self.assertEqual(resource.revoke()["outcome"], "REVOKED")
            resource.start_target()
            revoked = resource.invoke()["result"]
            self._deny(revoked, "OWNER_GRANT_REVOKED")
            resource.stop_target()
            self.assertEqual(resource.offline_status()["release_count"], 0)

    def test_live_caller_cannot_replace_exact_scope_or_owner_grant(self):
        with TemporaryDirectory(prefix="edu-scope-") as root, fixture(root) as resource:
            alternate = dict(resource.scope, request_id="other-fictional-read")
            reason = "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED"
            self._deny(resource.invoke(scope=alternate)["result"], reason)
            signed_elsewhere = resource.make_grant(scope=alternate)
            self._deny(resource.invoke(grant=signed_elsewhere)["result"], reason)
            student_grant = resource.make_grant(scope=dict(resource.scope, student="fictional-other"))
            self._deny(resource.invoke(grant=student_grant)["result"], reason)
            self._deny(resource.invoke(grant=resource.make_grant(signer=Signer()))["result"], reason)
            self._verified_release(resource, resource.invoke())
            resource.stop_target()
            self.assertEqual(resource.offline_status()["release_count"], 1)

    def test_reconciling_an_unspent_read_fences_the_exact_later_request(self):
        with TemporaryDirectory(prefix="edu-fence-") as root, fixture(root) as resource:
            packet = resource.invoke("sign")["packet"]
            fenced = resource.invoke("reconcile", packet=packet)["result"]
            self._deny(fenced, "READ_FENCED")
            resource.restart_target()
            late = resource.invoke()["result"]
            self._deny(late, "READ_FENCED")
            resource.stop_target()
            self.assertEqual(resource.offline_status()["release_count"], 0)

    def test_restoring_only_the_ledger_blocks_reopen_against_the_retained_checkpoint(self):
        with TemporaryDirectory(prefix="edu-rollback-") as root, fixture(root) as resource:
            ledger = resource.target_state / "ledger.sqlite"
            resource.stop_target()
            old_ledger = ledger.read_bytes()
            resource.start_target()
            self._verified_release(resource, resource.invoke())
            resource.stop_target()
            newer_anchor = resource.retained_anchor()
            ledger.write_bytes(old_ledger)
            with self.assertRaises(FixtureError):
                resource.start_target()
            self.assertEqual(resource.retained_anchor(), newer_anchor)


if __name__ == "__main__":
    unittest.main()
