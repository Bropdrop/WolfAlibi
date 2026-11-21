"""End-to-end controls for the separate read-only Gate 004 history demonstration."""

import json
import os
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
import unittest

from examples.quorvane_history_demo import demo
from wolfalibi.history_verify import verify_history


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(socket, "SCM_CREDENTIALS") and hasattr(os, "pidfd_open"),
    "requires the Linux finance fixture",
)
class HistoryDemoTests(unittest.TestCase):
    def test_lost_reply_expired_original_grant_and_read_only_history_disclosure(self):
        challenge = "91" * 32
        with TemporaryDirectory(prefix="wolfalibi-history-demo-") as root:
            expectations_path = Path(root) / "history-expectations.json"
            artifact = demo(root, expectations_out=expectations_path, challenge=challenge)
            expected = json.loads(expectations_path.read_bytes())

        self.assertEqual(artifact["outcome"], "PASS", artifact)
        self.assertEqual(artifact["settlement"], "UNESTABLISHED")
        self.assertNotIn("experimental_evidence", artifact)
        self.assertNotIn("experimental_settlement", artifact)
        self.assertEqual(expected["challenge"], challenge)
        self.assertNotEqual(expected["finance"]["scope"]["challenge"], challenge)
        self.assertEqual(artifact["observed"], artifact["expected"])
        checked = verify_history(expected, artifact["evidence"], challenge=challenge)
        self.assertEqual(checked["outcome"], "VERIFIED", checked)
        with self.assertRaises(ValueError):
            verify_history(expected, artifact["evidence"], challenge="92" * 32)

    def test_optional_settlement_is_a_separate_synthetic_observation(self):
        with TemporaryDirectory(prefix="wolfalibi-history-settlement-") as root:
            settlement_pins_path = Path(root) / "settlement-pins.json"
            artifact = demo(
                root,
                challenge="93" * 32,
                experimental_settlement=True,
                settlement_expectations_out=settlement_pins_path,
            )
            settlement_pins = json.loads(settlement_pins_path.read_bytes())

        settlement = artifact["experimental_settlement"]
        self.assertEqual(artifact["outcome"], "PASS", artifact)
        self.assertEqual(settlement["outcome"], "SETTLEMENT_VERIFIED", settlement)
        self.assertEqual(settlement["verified"], "HISTORICAL_SYNTHETIC_SETTLEMENT")
        self.assertEqual(settlement["initiation_effect"], "PENDING_EXTERNAL_SETTLEMENT")
        self.assertEqual(settlement["settlement_effect"], "SYNTHETIC_SETTLED")
        self.assertEqual(settlement["source_sha256"], settlement_pins["expected_source_sha256"])
        self.assertEqual(set(artifact["experimental_evidence"]), {"source_record", "settlement_record"})


if __name__ == "__main__":
    unittest.main()
