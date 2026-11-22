"""Scope of the trusted external LangChain adapter for the measured local trial."""

from argparse import Namespace
import json
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from wolfalibi import byoa_langchain as bridge
from wolfalibi.agent_langchain import langchain_status


class LinkedLangChainTests(unittest.TestCase):
    def test_no_sdk_or_trial_without_consent(self):
        with patch.object(bridge, "_observe") as observed:
            with self.assertRaisesRegex(ValueError, "consent"):
                bridge.run_linked(Namespace(consent=False))
        observed.assert_not_called()

    @unittest.skipUnless(langchain_status()["outcome"] == "SUPPORTED", "qualified LangChain versions unavailable")
    def test_registered_tool_requests_one_trial_and_reports_wrapped_scope(self):
        result = {"outcome": "COMPLETED", "opaque_local_detail": "private fictional fixture value"}
        callback = Mock(return_value=result)
        received, summary = bridge._observe(callback)
        self.assertIs(received, result)
        callback.assert_called_once_with()
        self.assertEqual(summary["counts"], {"tool.invoke.success": 1})
        self.assertEqual(summary["coverage"], "EXPLICITLY_WRAPPED_CALLS_ONLY")
        self.assertEqual(summary["assurance"], "OBSERVATIONAL_ONLY")
        self.assertNotIn(result["opaque_local_detail"], json.dumps(summary))

    @unittest.skipUnless(langchain_status()["outcome"] == "SUPPORTED", "qualified LangChain versions unavailable")
    def test_tool_completion_preserves_inner_refusal(self):
        refused = {"outcome": "BLOCKED", "reason": "No current authorization"}
        result, summary = bridge._observe(lambda: refused)
        self.assertEqual(result, refused)
        self.assertEqual(summary["counts"], {"tool.invoke.success": 1})

    def test_missing_pins_do_not_request_a_trial(self):
        local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with local, remote, patch("wolfalibi.agent_langchain.langchain_status",
                                  return_value={"outcome": "UNSUPPORTED"}):
            bridge._sdk_worker(local)
            self.assertEqual(remote.recv(32), b"unsupported")

    def test_true_framework_observation_cannot_upgrade_an_unverified_record(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "report.json").write_text("{}", encoding="utf-8")
            (root / "expected.json").write_text("{}", encoding="utf-8")
            args = Namespace(consent=True, review=root, output=root)
            fake = ({"outcome": "COMPLETED"}, {"counts": {"tool.invoke.success": 1}})
            with patch.object(bridge, "_observe", return_value=fake):
                with self.assertRaisesRegex(ValueError, "does not verify"):
                    bridge.run_linked(args)
            self.assertFalse((root / "framework-observation.json").exists())
