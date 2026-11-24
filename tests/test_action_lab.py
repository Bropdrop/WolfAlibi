"""Adversarial checks of the genuine action harness's result boundaries.

These tests inject explicitly fabricated authority/transport observations.
They never qualify a VM, execute Shirudo, install a gate, or report a real
action-lab PASS. Actual Unix-socket and TPM qualification remain CI gates.
"""

from __future__ import annotations

import copy
import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import shirudo_action_lab as lab
from shirudo_adapter.model import AdapterError, canonical_json, digest
from shirudo_adapter.receipt import sign_record

try:
    from .test_action_gate import GateFixture
except ImportError:
    from test_action_gate import GateFixture


class ActionHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="action-harness-boundary-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = GateFixture(self.root / "synthetic")
        self.harness = lab.ActionLab(self.root, self.fixture.policy["target_id"],
                                    self.root / "never-executed", self.root / "public")
        self.harness.identity = self.fixture.identity
        self.harness.policy = self.fixture.policy
        self.harness.policy_sha = digest(self.fixture.policy)

    def material_fixture(self):
        challenge, action, request = self.fixture.operation()
        return {"name": "boundary-fixture", "challenge": challenge, "action": action, "request": request}

    def committed_fixture(self):
        material = self.material_fixture()
        response = self.fixture.gate.execute(material["request"])
        receipt = response["receipt"]
        request = material["request"]
        oracle = {"counter": 1, "committed_operations": 1,
            "operation": {"status": "COMMITTED", "receipt": receipt,
                "request_sha256": digest(request), "grant_id": request["grant"]["payload"]["grant_id"],
                "assessment_sha256": digest(request["assessment"]), "counter_before": 0, "counter_after": 1}}
        return material, response, oracle

    def assert_case_failure(self, material, response, after, *, denial=None, outcome=None, code):
        before = {"counter": 0, "committed_operations": 0}
        with patch.object(self.harness, "oracle", side_effect=[before, after]), \
                patch.object(self.harness, "rpc", return_value={"client_exit_code": 0, "document": response}):
            with self.assertRaises(lab.LabFailure) as raised:
                self.harness.case("adversarial-observation", material, denial=denial,
                                  outcome=outcome, delta=1 if outcome == "COMMITTED" else 0)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(self.harness.cases, [])

    def test_unexpected_acceptance_cannot_pass_a_denial_control(self):
        material, response, oracle = self.committed_fixture()
        self.assert_case_failure(material, response, oracle, denial="GRANT_REVOKED", code="UNEXPECTED_DENIAL")

    def test_denial_message_cannot_hide_an_observed_counter_effect(self):
        material, _, oracle = self.committed_fixture()
        response = {"status": "DENIED", "reason": "GRANT_REVOKED", "message": "fixture"}
        self.assert_case_failure(material, response, oracle, denial="GRANT_REVOKED", code="UNEXPECTED_COUNTER_DELTA")

    def test_valid_effect_receipt_cannot_hide_an_extra_counter_increment(self):
        material, response, oracle = self.committed_fixture()
        oracle.update(counter=2, committed_operations=2)
        self.assert_case_failure(material, response, oracle, outcome="COMMITTED", code="EFFECT_COUNTER_DELTA")

    def test_independent_ledger_must_match_request_and_signed_effect(self):
        material, response, oracle = self.committed_fixture()
        self.assertTrue(self.harness.verify_effect(response, material, oracle)["signature_valid"])
        for key, changed in (("request_sha256", "45" * 32), ("assessment_sha256", "46" * 32),
                             ("grant_id", "47" * 16), ("counter_after", 2)):
            with self.subTest(key=key):
                altered = copy.deepcopy(oracle)
                altered["operation"][key] = changed
                with self.assertRaises(lab.LabFailure) as raised:
                    self.harness.verify_effect(response, material, altered)
                self.assertEqual(raised.exception.code, "EFFECT_DATABASE_BINDING")

    def test_untrusted_target_signature_cannot_validate_an_effect(self):
        material, response, oracle = self.committed_fixture()
        forged = sign_record(Ed25519PrivateKey.generate(), response["receipt"]["payload"])
        oracle["operation"]["receipt"] = forged
        with self.assertRaises(AdapterError) as raised:
            self.harness.verify_effect({"receipt": forged}, material, oracle)
        self.assertEqual(raised.exception.code, "INVALID_SIGNATURE")

    def test_precommit_recovery_happens_before_readonly_oracle_without_another_execute(self):
        material = self.material_fixture()
        events = []
        def oracle(_operation):
            events.append("oracle")
            return {"counter": 0, "committed_operations": 0}
        def rpc(document, _stage):
            events.append("execute")
            self.assertEqual(document, {"op": "execute", "request": material["request"]})
            return {"client_exit_code": 2, "document": {"status": "AMBIGUOUS", "reason": "TRANSPORT_LOST"}}
        def recover():
            events.append("trusted-restart")
            return "fixture recovery observation"
        with patch.object(self.harness, "oracle", side_effect=oracle), \
                patch.object(self.harness, "rpc", side_effect=rpc):
            self.harness.case("interrupted-boundary", material, outcome="AMBIGUOUS", delta=0,
                              after_response=recover)
        self.assertEqual(events, ["oracle", "execute", "trusted-restart", "oracle"])
        self.assertEqual(self.harness.cases[0]["observed_counter_delta"], 0)
        self.assertEqual(self.fixture.oracle(), (0, 0))

    def test_transport_exit_and_result_must_agree(self):
        cases = [(0, {"status": "AMBIGUOUS", "reason": "TRANSPORT_LOST"}),
                 (2, {"status": "DENIED", "reason": "POLICY_REVOKED"})]
        for exit_code, document in cases:
            with self.subTest(exit_code=exit_code):
                wrapper = {"client_exit_code": exit_code, "document": document,
                           "stderr_bytes": 0, "stderr_sha256": hashlib.sha256(b"").hexdigest()}
                with patch.object(self.harness, "guest_json", return_value=wrapper):
                    with self.assertRaises(lab.LabFailure) as raised:
                        self.harness.rpc({"op": "status", "operation_id": None}, "transport fixture")
                self.assertEqual(raised.exception.code, "TRANSPORT_STATUS")

    def test_synthetic_profile_and_wrong_executable_never_reach_grant_creation(self):
        for mutation, expected_code in (("synthetic", "UNEXPECTED_ASSESSMENT"),
                                        ("profile", "REAL_VERIFIER_REQUIRED"),
                                        ("unapproved-elf", "REAL_VERIFIER_DIGEST")):
            with self.subTest(mutation=mutation):
                challenge, action, request = self.fixture.operation()
                payload = copy.deepcopy(request["assessment"]["payload"])
                if mutation == "synthetic":
                    payload.update(assurance="SYNTHETIC", outcome="SIMULATED_POLICY_ONLY")
                    payload["upstream"]["execution_profile"] = "SYNTHETIC"
                elif mutation == "profile":
                    payload["upstream"]["execution_profile"] = "SYNTHETIC"
                assessment = sign_record(self.fixture.verifier_key, payload)
                class ResponseFixture:
                    def issue_challenge(_self, policy_sha):
                        self.assertEqual(policy_sha, self.harness.policy_sha)
                        return challenge
                    def assess_file(_self, *_args):
                        return assessment
                response = {"client_exit_code": 0, "document": {"status": "PREPARED", "action_challenge": action}}
                with patch.object(self.harness, "rpc", return_value=response), \
                        patch.object(self.harness, "collect", return_value=b'{"fixture":true}'), \
                        patch.object(lab, "make_grant_payload") as make_grant:
                    with self.assertRaises(lab.LabFailure) as raised:
                        self.harness.material(ResponseFixture(), mutation)
                self.assertEqual(raised.exception.code, expected_code)
                make_grant.assert_not_called()
                self.assertEqual(self.harness.fresh_assessments, 0)
                self.assertFalse(self.harness.positive_accepted)

    def test_wrong_signed_action_binding_fails_before_evidence_collection(self):
        challenge, action, _ = self.fixture.operation()
        payload = dict(action["payload"], attestation_nonce="12" * 32)
        wrong = sign_record(self.fixture.gate._key, payload)
        class ChallengeFixture:
            def issue_challenge(_self, _digest):
                return challenge
        response = {"client_exit_code": 0, "document": {"status": "PREPARED", "action_challenge": wrong}}
        with patch.object(self.harness, "rpc", return_value=response), \
                patch.object(self.harness, "collect") as collect:
            with self.assertRaises(lab.LabFailure) as raised:
                self.harness.material(ChallengeFixture(), "wrong-binding")
        self.assertEqual(raised.exception.code, "ACTION_CHALLENGE_BINDING")
        collect.assert_not_called()

    def test_disposable_ci_guard_precedes_target_and_verifier_work(self):
        with patch.dict(lab.os.environ, {"GITHUB_ACTIONS": "false", "WOLFALIBI_DISPOSABLE_CI": "0"}), \
                patch.object(self.harness, "prepare") as prepare, \
                patch.object(self.harness, "setup_target") as target:
            with self.assertRaises(lab.EnvironmentFailure) as raised:
                self.harness.run()
        self.assertEqual(raised.exception.code, "DISPOSABLE_CI_REQUIRED")
        prepare.assert_not_called()
        target.assert_not_called()

    def test_public_bundle_omits_private_state_and_manifest_matches_exact_bytes(self):
        source = self.root / "source"
        package = source / "shirudo_adapter"
        package.mkdir(parents=True)
        (package / "action_gate.py").write_bytes(b"# selected public source\n")
        (package / "action_gate_cli.py").write_bytes(b"# selected public CLI\n")
        (package / "signing.key").write_bytes(b"private key fixture")
        (package / "journal.sqlite3").write_bytes(b"private database fixture")
        nested = package / "private-state"
        nested.mkdir()
        (nested / "secret.py").write_bytes(b"private nested fixture")
        with patch.object(lab, "ROOT", source):
            raw, manifest = lab.bundle_source(self.fixture.trust)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(set(archive.namelist()), {"shirudo_adapter/action_gate.py",
                              "shirudo_adapter/action_gate_cli.py", "trust.json"})
            self.assertEqual(set(manifest), set(archive.namelist()))
            for name in archive.namelist():
                body = archive.read(name)
                self.assertEqual(manifest[name], {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
                self.assertNotIn(b"private key fixture", body)
                self.assertNotIn(b"private database fixture", body)
            self.assertEqual(archive.read("trust.json"), canonical_json(self.fixture.trust) + b"\n")

    def test_public_bundle_rejects_a_symlinked_source_file(self):
        source = self.root / "linked-source"
        package = source / "shirudo_adapter"
        package.mkdir(parents=True)
        secret = self.root / "private.py"
        secret.write_bytes(b"not selected public source")
        (package / "action_gate.py").symlink_to(secret)
        with patch.object(lab, "ROOT", source):
            with self.assertRaises(lab.EnvironmentFailure) as raised:
                lab.bundle_source(self.fixture.trust)
        self.assertEqual(raised.exception.code, "FILE_UNREADABLE")


if __name__ == "__main__":
    unittest.main()
