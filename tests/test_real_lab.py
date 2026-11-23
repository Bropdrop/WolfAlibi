"""Harness boundary tests with simulated transport/verifier reports.

These tests do not boot a target or qualify a TPM. Real Service signatures,
durability, nonce consumption and expiry are exercised; TPM verification is
explicitly mocked in the orchestration tests.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import shirudo_real_lab as lab
from shirudo_adapter.model import canonical_json
from shirudo_adapter.service import Service
from support import fixture_verifier_result


VERSION = "ab" * 32
TARGET_VERSION = "bc" * 32
VM = "qualification-fixture"
ROOT_HASH = "12" * 32
CHAIN = "34" * 32
SIGNATURE = "0018000b0020" + "a1" * 32 + "0020" + "b2" * 32
TEMPLATE = b"""# Host-side fixture for the reviewed runtime template.
config.image = /var/lib/shirudo/images/@config_image@
config.verification_key = /run/shirudo/runtime/etc/shirudo/config-cert.der
config.pcr = 14
tpm.tcti = device:/dev/tpmrm0
"""


def enrollment() -> bytes:
    return canonical_json({"source": "test-vm", "nodes": [{
        "node_id": VM, "ak_name": "000b" + "a1" * 32,
        "ek_name": "000b" + "e1" * 32,
    }]})


def baseline_status() -> dict:
    return {
        "schema": 1, "version_id": TARGET_VERSION,
        "lsm_attached": True, "keyring_mode": "bpf",
        "config": {"root_hash": ROOT_HASH, "activation_pending": False, "error": None},
        "tpm": {"bound_in": "initrd", "reachable": True, "register_bound": True,
                "chain": CHAIN, "pcr_before": "0" * 64, "phase_before": "0" * 64},
    }


def policy() -> dict:
    return lab.make_policy(VM, enrollment(), ROOT_HASH, 14,
                           {"register_at_boot": CHAIN}, baseline_status(),
                           TARGET_VERSION, VERSION)


def evidence(challenge: dict) -> bytes:
    return canonical_json({
        "schema": 1, "kind": "shirudo-attestation", "pcr_bank": "sha256",
        "nonce": challenge["payload"]["nonce"],
        "ak": {"name": "000b" + "a1" * 32},
        "ek": {"name": "000b" + "e1" * 32},
        "register": {"value": CHAIN},
        "quote": {"attest": "fixture", "signature": SIGNATURE},
    })


class FixtureLab(lab.RealLab):
    """All target interaction is simulated, never a real qualification."""

    def prepare(self):
        self.baseline = policy()
        self.frozen_baseline = copy.deepcopy(self.baseline)
        self.collected = []
        return self.baseline

    def collect(self, challenge, case):
        self.collected.append((case, copy.deepcopy(challenge)))
        return evidence(challenge)


def fixture_verifier(_path, raw, requested_policy, _nonce):
    """Simulated reports; no executable or TPM is invoked by this fixture."""
    value = json.loads(raw)
    reason = None
    if value["quote"]["signature"] != SIGNATURE:
        reason = "quote: ECDSA signature by the attestation key"
    elif requested_policy["expected"]["config_root"] != ROOT_HASH:
        reason = "config: config root was not approved by the operator"
    elif requested_policy["expected"]["binding_pcrs"]["9"] != "0" * 64:
        reason = "binding: PCR 9 held the expected value"
    result = fixture_verifier_result(requested_policy, accepted=reason is None)
    result["execution_profile"] = "UPSTREAM_CLI"
    if reason:
        result["report"]["checks"] = [{"result": "fail", "text": reason}]
    return result


class RealLabInputTests(unittest.TestCase):
    def test_policy_uses_host_enrollment_and_independent_state_inputs(self):
        result = policy()
        self.assertEqual(result["assurance"], "LAB_VTPM")
        self.assertEqual(result["enrollment"]["method"], "trusted_builder")
        self.assertEqual(result["enrollment"]["record_sha256"], hashlib.sha256(enrollment()).hexdigest())
        self.assertEqual(result["expected"]["chain"], CHAIN)
        self.assertEqual(result["expected"]["config_root"], ROOT_HASH)
        self.assertEqual(result["expected"]["config_pcr"], 14)
        self.assertEqual(result["expected"]["binding_pcrs"], {"9": "0" * 64, "11": "0" * 64})
        self.assertEqual(result["verifier"]["sha256"], lab.VERIFIER_SHA256)

    def test_target_cannot_choose_expected_config_or_chain(self):
        for field in ("root", "chain"):
            with self.subTest(field=field):
                baseline = baseline_status()
                if field == "root":
                    baseline["config"]["root_hash"] = "ff" * 32
                else:
                    baseline["tpm"]["chain"] = "ff" * 32
                with self.assertRaises(lab.EnvironmentFailure) as raised:
                    lab.make_policy(VM, enrollment(), ROOT_HASH, 14,
                                    {"register_at_boot": CHAIN}, baseline, TARGET_VERSION, VERSION)
                self.assertEqual(raised.exception.code, "BASELINE_EXPECTATIONS")

    def test_builder_record_rejects_wrong_target_or_ambiguous_keys(self):
        for mutation in ("target", "duplicate", "template"):
            with self.subTest(mutation=mutation):
                value = json.loads(enrollment())
                if mutation == "target":
                    value["nodes"][0]["node_id"] = "another-target"
                elif mutation == "duplicate":
                    value["nodes"].append(copy.deepcopy(value["nodes"][0]))
                else:
                    value["nodes"][0]["ak_name"] = "0004" + "a1" * 32
                with self.assertRaises(lab.EnvironmentFailure):
                    lab.enrollment_names(canonical_json(value), VM)

    def test_baseline_must_match_target_build_and_completed_init(self):
        for field in ("build", "phase", "pending"):
            with self.subTest(field=field):
                baseline = baseline_status()
                if field == "build":
                    baseline["version_id"] = "ff" * 32
                elif field == "phase":
                    baseline["tpm"]["bound_in"] = "root"
                else:
                    baseline["config"]["activation_pending"] = True
                with self.assertRaises(lab.EnvironmentFailure):
                    lab.make_policy(VM, enrollment(), ROOT_HASH, 14,
                                    {"register_at_boot": CHAIN}, baseline, TARGET_VERSION, VERSION)

    def test_runtime_selection_uses_only_reviewed_host_template(self):
        self.assertEqual(lab.runtime_selection(TEMPLATE), ("config-boot-keys", 14))
        for changed in (
            TEMPLATE.replace(b"@config_image@", b"../../target-chosen"),
            TEMPLATE.replace(b"config.pcr = 14", b"config.pcr = 9"),
            TEMPLATE + b"config.pcr = 12\n",
            TEMPLATE + b"config.nvpcr = 000b1234\n",
        ):
            with self.subTest(template=changed):
                with self.assertRaises(lab.EnvironmentFailure):
                    lab.runtime_selection(changed)

    def test_signature_mutant_preserves_preflight_and_tpm_structure(self):
        raw = evidence({"payload": {"nonce": "12" * 32}})
        before = json.loads(raw)
        after = json.loads(lab.signature_control(raw))
        self.assertEqual(before["quote"]["signature"][:-1], after["quote"]["signature"][:-1])
        self.assertNotEqual(before["quote"]["signature"][-1], after["quote"]["signature"][-1])
        before["quote"]["signature"] = after["quote"]["signature"]
        self.assertEqual(before, after)

    def test_signature_control_rejects_missing_or_nonhex_signature(self):
        for replacement in (None, "not-hex", "001"):
            value = json.loads(evidence({"payload": {"nonce": "12" * 32}}))
            value["quote"]["signature"] = replacement
            with self.subTest(replacement=replacement):
                with self.assertRaises(lab.LabFailure):
                    lab.signature_control(canonical_json(value))

    def test_public_output_refuses_existing_directory_and_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(lab.EnvironmentFailure):
                lab.PublicArtifacts(root)
            artifacts = lab.PublicArtifacts(root / "public")
            for name in ("../signing.key", "state/journal.sqlite3/../../key", "/tmp/out.json"):
                with self.subTest(name=name):
                    with self.assertRaises(lab.LabFailure):
                        artifacts.write(name, b"not exported")
            self.assertEqual(list((root / "public").iterdir()), [])

    def test_vm_name_cannot_inject_shell_or_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for name in ("../target", "target;echo bad", "-option", "a" * 64):
                with self.subTest(name=name):
                    with self.assertRaises(lab.EnvironmentFailure):
                        lab.RealLab(path, name, path / "verifier", path / "out")
            self.assertFalse((path / "out").exists())

    def test_wrong_source_revision_fails_before_reading_target_or_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            harness = lab.RealLab(path, VM, path / "verifier", path / "out")
            with patch.object(harness, "command", return_value=b"0" * 40 + b"\n"), \
                    patch.object(harness, "target") as target:
                with self.assertRaises(lab.EnvironmentFailure) as raised:
                    harness.prepare()
            self.assertEqual(raised.exception.code, "SOURCE_REVISION")
            target.assert_not_called()


class RealLabProcessTests(unittest.TestCase):
    def test_command_capture_is_bounded_during_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(lab.EnvironmentFailure) as raised:
                lab.bounded_command([sys.executable, "-c", "print('x' * 100000)"],
                                    Path(directory), timeout=5, stdout_limit=1024)
        self.assertEqual(raised.exception.code, "COMMAND_OUTPUT_LIMIT")

    def test_descendant_holding_pipes_cannot_bypass_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            started = time.monotonic()
            with self.assertRaises(lab.EnvironmentFailure) as raised:
                lab.bounded_command(
                    [sys.executable, "-c", "import os,time; pid=os.fork(); time.sleep(10) if pid==0 else None"],
                    Path(directory), timeout=0.15)
        self.assertEqual(raised.exception.code, "COMMAND_TIMEOUT")
        self.assertLess(time.monotonic() - started, 3)


class RealLabOrchestrationTests(unittest.TestCase):
    def test_all_controls_use_frozen_baseline_and_export_public_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            harness = FixtureLab(path, VM, path / "never-executed", path / "public")
            with patch("shirudo_adapter.service.run_verifier", side_effect=fixture_verifier):
                summary = harness.run()
            self.assertEqual(summary["result"], "PASS")
            self.assertTrue(summary["positive_evidence_accepted"])
            self.assertFalse(summary["current_authorization"])
            self.assertFalse(summary["hardware_qualification"])
            self.assertTrue(summary["private_adapter_state_removed"])
            self.assertEqual(len(summary["cases"]), 10)
            self.assertTrue(all(case["result"] == "PASS" for case in summary["cases"]))
            self.assertEqual(harness.baseline, harness.frozen_baseline)
            self.assertEqual(len(harness.collected), 8)
            nonces = [item[1]["payload"]["nonce"] for item in harness.collected]
            self.assertEqual(len(set(nonces)), len(nonces))
            root = path / "public"
            inventory = json.loads((root / "artifact-manifest.json").read_bytes())
            self.assertFalse(inventory["private_state_exported"])
            for name, info in inventory["files"].items():
                raw = (root / name).read_bytes()
                self.assertEqual(info["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(info["bytes"], len(raw))
            names = {item.name for item in root.rglob("*")}
            self.assertFalse({"signing.key", "journal.sqlite3", "state.json", "tpm"} & names)
            original = json.loads((root / "cases/tampered-signature/original-evidence.json").read_bytes())
            mutated = json.loads((root / "cases/tampered-signature/evidence.json").read_bytes())
            self.assertEqual(original["nonce"], mutated["nonce"])
            self.assertNotEqual(original["quote"]["signature"], mutated["quote"]["signature"])
            positive = json.loads((root / "cases/positive/challenge.json").read_bytes())
            stale = json.loads((root / "cases/new-nonce-stale-evidence/challenge.json").read_bytes())
            self.assertNotEqual(positive["payload"]["nonce"], stale["payload"]["nonce"])
            self.assertEqual((root / "cases/positive/evidence.json").read_bytes(),
                             (root / "cases/new-nonce-stale-evidence/evidence.json").read_bytes())

    def test_unrelated_block_or_wrong_crypto_failure_cannot_pass_a_control(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            service = Service.initialize(path / "private")
            selected = policy()
            sha = service.register_policy(selected)
            challenge = service.issue_challenge(sha)
            result = fixture_verifier_result(selected, accepted=False)
            result["execution_profile"] = "UPSTREAM_CLI"
            with patch("shirudo_adapter.service.run_verifier", return_value=result):
                receipt = service.assess(challenge["payload"]["challenge_id"],
                                         evidence(challenge), "/not-executed")
            with self.assertRaises(lab.LabFailure) as raised:
                lab.expect_receipt(receipt, outcome="REJECTED", reason="UPSTREAM_REJECTED",
                                   crypto_failure="quote: ECDSA signature by the attestation key")
            self.assertEqual(raised.exception.code, "EXPECTED_CRYPTO_FAILURE")
            blocked = copy.deepcopy(receipt)
            blocked["payload"]["outcome"] = "BLOCKED"
            blocked["payload"]["reason_code"] = "VERIFIER_TIMEOUT"
            with self.assertRaises(lab.EnvironmentFailure) as raised:
                lab.expect_receipt(blocked, outcome="REJECTED", reason="UPSTREAM_REJECTED")
            self.assertEqual(raised.exception.code, "VERIFIER_TIMEOUT")

    def test_retained_challenge_and_evidence_bindings_are_checked_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            service = Service.initialize(Path(directory) / "private")
            selected = policy()
            challenge = service.issue_challenge(service.register_policy(selected))
            raw = evidence(challenge)
            with patch("shirudo_adapter.service.run_verifier", side_effect=fixture_verifier):
                receipt = service.assess(challenge["payload"]["challenge_id"], raw, "/not-executed")
            lab.check_receipt_bindings(receipt, selected, challenge, raw)
            for key in ("nonce", "evidence_sha256", "enrollment_record_sha256"):
                with self.subTest(key=key):
                    changed = copy.deepcopy(receipt)
                    changed["payload"][key] = "ff" * 32
                    with self.assertRaises(lab.LabFailure):
                        lab.check_receipt_bindings(changed, selected, challenge, raw)

    def test_private_state_is_removed_after_assertion_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            harness = FixtureLab(path, VM, path / "never-executed", path / "public")
            seen = []
            original = Service.initialize

            def initialize(state):
                seen.append(state)
                return original(state)

            with patch.object(Service, "initialize", side_effect=initialize), \
                    patch.object(harness, "run_cases", side_effect=lab.LabFailure("TEST_STOP", "fixture")):
                with self.assertRaises(lab.LabFailure):
                    harness.run()
            self.assertEqual(len(seen), 1)
            self.assertFalse(seen[0].exists())
            self.assertTrue(harness.state_removed)
            self.assertFalse(any((path / "public").rglob("signing.key")))


if __name__ == "__main__":
    unittest.main()
