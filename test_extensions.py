"""Tests for explicit extension contracts, not claims of universal coverage."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from wolfalibi.adapters import AdapterRegistry, ResourceEvent
from wolfalibi.isolation import isolation_status, run_isolated


HERE = os.path.dirname(os.path.abspath(__file__))


class AdapterContracts(unittest.TestCase):
    def test_resource_events_have_namespaced_canonical_keys(self):
        event = ResourceEvent("api-v1", b"https://synthetic.invalid/items/7", "request", "denied")
        self.assertEqual(event.canonical_key(), b"api-v1\0https://synthetic.invalid/items/7")
        with self.assertRaises(ValueError):
            ResourceEvent("", b"x", "read", "completed").canonical_key()

    def test_registry_refuses_ambiguous_adapter_kinds(self):
        class Adapter:
            kind = "synthetic"
        registry = AdapterRegistry()
        adapter = Adapter()
        registry.register(adapter)
        self.assertEqual(registry.get("synthetic"), adapter)
        with self.assertRaises(ValueError):
            registry.register(Adapter())


class IsolationContracts(unittest.TestCase):
    def test_launcher_never_claims_verified_confinement(self):
        status = isolation_status()
        self.assertEqual(status["assurance"], "BLOCKED")
        self.assertIn(status["outcome"], {"READY", "UNSUPPORTED", "BLOCKED"})
        with tempfile.TemporaryDirectory(prefix="isolation-work-") as work, \
             tempfile.TemporaryDirectory(prefix="isolation-protected-") as protected:
            marker = pathlib.Path(protected, "synthetic-secret.txt")
            marker.write_text("synthetic only")
            result = run_isolated(["/usr/bin/test", "!", "-e", str(marker)], work)
        self.assertEqual(result["assurance"], "BLOCKED")
        self.assertIn(result["outcome"], {"COMPLETED", "UNSUPPORTED", "BLOCKED"})
        if result["outcome"] == "COMPLETED" and result["returncode"] == 0:
            # This exact synthetic marker is absent from this exact mount view.
            # It is not evidence that every future host/resource escape is closed.
            self.assertIn("no broker IPC", result["reason"])


class CliContracts(unittest.TestCase):
    def test_demo_and_explicit_verifier_roundtrip(self):
        with tempfile.TemporaryDirectory(prefix="cli-receipt-") as temp:
            receipt = os.path.join(temp, "receipt.json")
            inputs = os.path.join(temp, "inputs.json")
            state = os.path.join(temp, "state")
            generated = subprocess.run(
                [sys.executable, "wolfalibi_cli.py", "demo-receipt", "--output", receipt,
                 "--inputs", inputs, "--state-dir", state],
                cwd=HERE, capture_output=True, text=True, check=False)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertEqual(json.loads(generated.stdout)["outcome"], "GENERATED")
            expected = json.loads(pathlib.Path(inputs).read_text())
            command = [
                sys.executable, "wolfalibi_cli.py", "verify", "--receipt", receipt,
                "--broker-pub", expected["broker_pub"], "--witness-pub", expected["witness_pub"],
                "--challenge", expected["challenge"], "--policy", inputs,
            ]
            # The generated input file also contains a policy, but verifier
            # input must be a policy-only JSON document, not receipt-derived.
            policy_path = os.path.join(temp, "policy.json")
            pathlib.Path(policy_path).write_text(json.dumps(expected["policy"]))
            command[command.index(inputs)] = policy_path
            command.extend([
                "--lo", expected["lo"], "--hi", expected["hi"], "--run-id", expected["run_id"],
                "--code-digest", expected["code_digest"], "--epoch-from", str(expected["epochs"][0]),
                "--epoch-to", str(expected["epochs"][1]),
            ])
            verified = subprocess.run(command, cwd=HERE, capture_output=True, text=True, check=False)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(json.loads(verified.stdout)["outcome"], "VERIFIED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
