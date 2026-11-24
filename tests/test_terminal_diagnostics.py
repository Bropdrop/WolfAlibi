"""Retain a real child failure before the scripted owner prompt is available."""

import hashlib
import json
import sys
import unittest

from scripts.shirudo_prototype_host import OwnerTerminal
from scripts.shirudo_prototype_lab import capture_owner_terminal_failure
from scripts.shirudo_real_lab import EnvironmentFailure


class OwnerTerminalDiagnosticsTests(unittest.TestCase):
    def test_early_exit_retains_public_json_and_terminal_error(self):
        child = (
            "import json,os,sys;"
            "os.write(2,b'Public terminal startup failure\\n');"
            "print(json.dumps({'status':'BLOCKED','reason':'TERMINAL_REQUIRED'}),flush=True);"
            "sys.exit(2)"
        )
        with OwnerTerminal([sys.executable, "-I", "-c", child]) as terminal:
            with self.assertRaises(EnvironmentFailure):
                terminal.wait_prompt("Type READY", timeout=3)
            terminal.process.wait(timeout=3)
            record, channels = capture_owner_terminal_failure(terminal)
        self.assertEqual(record["exit_code"], 2)
        self.assertEqual(record["actual_human_approval"], "NOT_RUN")
        self.assertEqual(json.loads(channels["pending_stdout"]),
                         {"status": "BLOCKED", "reason": "TERMINAL_REQUIRED"})
        self.assertIn(b"Public terminal startup failure", channels["terminal_transcript"])
        for name, data in channels.items():
            self.assertEqual(record["channels"][name], {
                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "at_capture_limit": False,
            })


if __name__ == "__main__":
    unittest.main()
