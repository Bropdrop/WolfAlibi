"""Offline provisioning tests; all image/TPM records below are invented fixtures.

These tests authenticate and reject contracts. They never qualify a real boot,
kernel dm-verity mapping, upstream verifier execution, or owner ceremony.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shirudo_adapter.bootstrap import (ENTRYPOINT, MOUNT_POINT, _immutable_runtime,
    prepare_boot_policy, validate_anchors, validate_boot_report, verify_boot_policy)
from shirudo_adapter.model import AdapterError, digest
from shirudo_adapter.receipt import sign_record

try:
    from .support import policy_for, write_nonexecuted_fixture
except ImportError:
    from support import policy_for, write_nonexecuted_fixture


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="wolfalibi-bootstrap-test-")
        self.addCleanup(temporary.cleanup)
        self.owner = Ed25519PrivateKey.generate()
        verifier = Ed25519PrivateKey.generate()
        policy = policy_for(write_nonexecuted_fixture(Path(temporary.name) / "not-a-real-verifier"))
        policy["assurance"] = "LAB_VTPM"
        policy["enrollment"]["method"] = "trusted_builder"
        policy["challenge_ttl_seconds"] = 30
        policy["expected"]["config_pcr"] = 14
        self.trust = {"schema": "wolfalibi.shirudo.action-trust.v1", "target_id": policy["target_id"],
                      "owner_public_key": self.owner.public_key().public_bytes_raw().hex(),
                      "verifier_public_key": verifier.public_key().public_bytes_raw().hex(),
                      "verifier_instance_id": "12" * 16, "policy": policy}
        self.anchors = {"schema": "wolfalibi.shirudo.bootstrap-anchors.v1",
            **{key: self.trust[key] for key in ("target_id", "owner_public_key", "verifier_public_key", "verifier_instance_id")},
            "verifier": {key: policy["verifier"][key] for key in ("source_commit", "sha256", "version_id")},
            "assurance": "LAB_VTPM", "action": {"name": "increment_counter", "delta": 1},
            "max_challenge_ttl_seconds": 30, "config_pcr": 14}
        self.manifest = {"schema": "wolfalibi.shirudo.gate-image.v1", "gate_image_root": "ab" * 32,
                         "anchors_sha256": digest(self.anchors), "source_manifest_sha256": "cd" * 32,
                         "entrypoint": list(ENTRYPOINT), "mount_point": MOUNT_POINT,
                         "authority": "NO_SHIRUDO_RUNTIME_AUTHORITY"}
        self.payload = prepare_boot_policy(self.anchors, self.trust, self.manifest, self.trust["owner_public_key"])
        self.envelope = sign_record(self.owner, self.payload)
        config_root = policy["expected"]["config_root"]
        control = {"mapping_created": True, "read_rejected": True, "read_exit_code": 1, "block": 0}
        self.report = {"schema": "wolfalibi.shirudo.image-boot.v1", "scope": "LAB_TRUSTED_INITRD",
            "gate_image_root": self.manifest["gate_image_root"], "config_root": config_root,
            "anchors_sha256": digest(self.anchors), "mount_point": MOUNT_POINT,
            "mapper_name": "wolfalibi-gate", "read_only": True, "full_read": True,
            "data_bytes": 4096 * 10, "image_device": 12345,
            "dm_table": f"0 80 verity 1 7:1 7:2 4096 4096 10 1 sha256 {self.manifest['gate_image_root']} {'12' * 32}",
            "config_witness": {"root_hash": config_root, "mount_point": "/run/wolfalibi/config-witness",
                "mapper_name": "wolfalibi-config-witness", "read_only": True, "full_read": True,
                "data_bytes": 4096 * 10,
                "dm_table": f"0 80 verity 1 7:3 7:4 4096 4096 10 1 sha256 {config_root} {'34' * 32}"},
            "corruption_control": dict(control), "wrong_root_control": dict(control)}

    def denied(self, callback, code=None):
        with self.assertRaises(AdapterError) as raised:
            callback()
        if code:
            self.assertEqual(raised.exception.code, code)

    def test_owner_signed_postbuild_policy_resolves_nonrecursive_binding(self):
        actual = verify_boot_policy(self.envelope, self.anchors, self.manifest, boot_report=self.report)
        self.assertEqual(actual, self.trust)
        self.assertNotIn("config_root", self.anchors)
        self.assertNotIn("gate_image_root", self.anchors)
        self.assertNotIn("config_root", self.manifest)
        self.assertEqual(self.payload["scope"], "LAB_IMMUTABLE_GATE_BOOTSTRAP")

    def test_wrong_owner_signature_and_tampered_trust_are_rejected(self):
        wrong = sign_record(Ed25519PrivateKey.generate(), self.payload)
        self.denied(lambda: verify_boot_policy(wrong, self.anchors, self.manifest), "INVALID_SIGNATURE")
        altered = copy.deepcopy(self.envelope)
        altered["payload"]["trust"]["policy"]["expected"]["config_root"] = "ee" * 32
        self.denied(lambda: verify_boot_policy(altered, self.anchors, self.manifest), "INVALID_SIGNATURE")

    def test_owner_signature_cannot_change_immutable_authorities_or_verifier(self):
        changes = [("target_id", "different-target"), ("owner_public_key", "11" * 32),
                   ("verifier_public_key", "22" * 32), ("verifier_instance_id", "33" * 16)]
        for key, value in changes:
            with self.subTest(field=key):
                payload = copy.deepcopy(self.payload)
                payload["trust"][key] = value
                if key == "target_id":
                    payload["trust"]["policy"][key] = value
                self.denied(lambda: verify_boot_policy(sign_record(self.owner, payload), self.anchors, self.manifest))
        for key in ("sha256", "version_id"):
            with self.subTest(pin=key):
                payload = copy.deepcopy(self.payload)
                payload["trust"]["policy"]["verifier"][key] = "44" * 32
                self.denied(lambda: verify_boot_policy(sign_record(self.owner, payload), self.anchors, self.manifest), "BOOTSTRAP_PIN")

    def test_signed_image_config_and_anchor_substitutions_are_rejected(self):
        for key in ("gate_image_root", "config_root", "anchors_sha256"):
            with self.subTest(field=key):
                payload = copy.deepcopy(self.payload)
                payload[key] = "99" * 32
                self.denied(lambda: verify_boot_policy(sign_record(self.owner, payload), self.anchors, self.manifest), "BOOTSTRAP_BINDING")

    def test_native_config_manifest_must_match_immutable_anchor(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["anchors_sha256"] = "66" * 32
        self.denied(lambda: verify_boot_policy(self.envelope, self.anchors, manifest), "BOOTSTRAP_AUTHORITY")
        anchors = copy.deepcopy(self.anchors)
        anchors["verifier_instance_id"] = "77" * 16
        self.denied(lambda: verify_boot_policy(self.envelope, anchors, self.manifest), "BOOTSTRAP_AUTHORITY")

    def test_bootstrap_signature_is_not_an_action_grant(self):
        payload = copy.deepcopy(self.payload)
        payload["scope"] = "LAB_OWNER_GRANT"
        self.denied(lambda: verify_boot_policy(sign_record(self.owner, payload), self.anchors, self.manifest), "BOOTSTRAP_BINDING")

    def test_signed_scope_expansion_is_rejected(self):
        for key, value in (("assurance", "SYNTHETIC"), ("assurance", "HARDWARE_TPM"),
                           ("challenge_ttl_seconds", 31)):
            with self.subTest(key=key, value=value):
                payload = copy.deepcopy(self.payload)
                payload["trust"]["policy"][key] = value
                self.denied(lambda: verify_boot_policy(sign_record(self.owner, payload), self.anchors, self.manifest))
        payload = copy.deepcopy(self.payload)
        payload["trust"]["policy"]["expected"]["config_pcr"] = 13
        self.denied(lambda: verify_boot_policy(sign_record(self.owner, payload), self.anchors, self.manifest), "BOOTSTRAP_SCOPE")

    def test_anchors_refuse_bool_integer_aliases_and_extra_keys(self):
        for key, value in (("config_pcr", True), ("max_challenge_ttl_seconds", True),
                           ("action", {"name": "increment_counter", "delta": True}),
                           ("arbitrary_authority", "YES")):
            with self.subTest(key=key):
                anchors = copy.deepcopy(self.anchors)
                anchors[key] = value
                self.denied(lambda: validate_anchors(anchors))

    def test_manifest_cannot_select_interpreter_flags_entrypoint_or_authority(self):
        for key, value in (("entrypoint", ENTRYPOINT[:2]), ("entrypoint", ["/state/python"]),
                           ("mount_point", "/tmp/image"), ("authority", "SHIRUDO_RUNTIME_AUTHORITY")):
            with self.subTest(key=key):
                manifest = copy.deepcopy(self.manifest)
                manifest[key] = value
                self.denied(lambda: verify_boot_policy(self.envelope, self.anchors, manifest), "BOOTSTRAP_IMAGE")

    def test_report_requires_successful_full_read_and_real_negative_controls(self):
        mutations = [("read_only", False), ("full_read", False), ("image_device", 0),
                     ("gate_image_root", "00" * 32), ("config_root", "00" * 32),
                     ("data_bytes", 1), ("dm_table", self.report["dm_table"].replace("verity", "linear"))]
        for key, value in mutations:
            with self.subTest(field=key):
                report = copy.deepcopy(self.report)
                report[key] = value
                self.denied(lambda: verify_boot_policy(self.envelope, self.anchors, self.manifest, boot_report=report))
        for control in ("corruption_control", "wrong_root_control"):
            for key, value in (("mapping_created", False), ("read_rejected", False), ("read_exit_code", 0), ("block", 10)):
                with self.subTest(control=control, field=key):
                    report = copy.deepcopy(self.report)
                    report[control][key] = value
                    self.denied(lambda: verify_boot_policy(self.envelope, self.anchors, self.manifest, boot_report=report))

    def test_config_witness_must_verify_same_root_under_same_geometry(self):
        for key, value in (("root_hash", "88" * 32), ("full_read", False), ("read_only", False),
                           ("mapper_name", "other"), ("data_bytes", 4096),
                           ("dm_table", self.report["config_witness"]["dm_table"].replace("7:3", "not-a-device"))):
            with self.subTest(field=key):
                report = copy.deepcopy(self.report)
                report["config_witness"][key] = value
                self.denied(lambda: validate_boot_report(report, manifest=self.manifest, config_root=self.payload["config_root"]))

    def test_another_readonly_process_root_cannot_reuse_verified_mapping_report(self):
        flags = SimpleNamespace(isolated=1, dont_write_bytecode=1, no_site=1)
        with patch("shirudo_adapter.bootstrap.sys.flags", flags):
            self.denied(lambda: _immutable_runtime(os.stat("/").st_dev + 1), "BOOTSTRAP_RUNTIME")

    def test_unsigned_or_extra_provisioning_fields_fail_even_when_owner_signs(self):
        payload = copy.deepcopy(self.payload)
        payload["execute_without_grant"] = True
        self.denied(lambda: verify_boot_policy(sign_record(self.owner, payload), self.anchors, self.manifest))
        self.denied(lambda: verify_boot_policy(self.payload, self.anchors, self.manifest))


if __name__ == "__main__":
    unittest.main()
