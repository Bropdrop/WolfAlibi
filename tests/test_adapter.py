"""Independent, offline tests of evidence and durable-state trust boundaries.

These cases intentionally mock the upstream verifier and can only demonstrate
synthetic adapter behavior.  They do not qualify a TPM, a genuine Shirudo run,
target enforcement, or an independent freshness witness.
"""

from __future__ import annotations

import copy
import hashlib
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shirudo_adapter.model import AdapterError, canonical_json, strict_json, validate_policy
from shirudo_adapter.receipt import sign_record, verify_receipt
from shirudo_adapter.service import Service

try:
    from .support import (
        changed,
        different,
        encode,
        evidence_bytes,
        evidence_object,
        fixture_verifier_result,
        policy_for,
        write_nonexecuted_fixture,
    )
except ImportError:
    from support import (
        changed,
        different,
        encode,
        evidence_bytes,
        evidence_object,
        fixture_verifier_result,
        policy_for,
        write_nonexecuted_fixture,
    )


class StrictJSONTests(unittest.TestCase):
    def test_valid_object_and_canonical_encoding(self):
        self.assertEqual(strict_json(b'{"b":2,"a":1}', max_bytes=100), {"a": 1, "b": 2})
        self.assertEqual(canonical_json({"b": 2, "a": 1}), canonical_json({"a": 1, "b": 2}))

    def test_duplicate_keys_including_escaped_and_nested_duplicates_rejected(self):
        cases = [
            b'{"status":"pass","status":"fail"}',
            b'{"target":"first","\\u0074arget":"second"}',
            b'{"ak":{"name":"trusted","name":"attacker"}}',
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(AdapterError):
                strict_json(raw, max_bytes=1024)

    def test_nonfinite_values_rejected(self):
        for value in (b"NaN", b"Infinity", b"-Infinity", b"1e99999"):
            with self.subTest(value=value), self.assertRaises(AdapterError):
                strict_json(b'{"value":' + value + b"}", max_bytes=1024)

    def test_trailing_documents_garbage_and_invalid_utf8_rejected(self):
        for raw in (b"{}{}", b"{} trailing", b"diagnostic\n{}", b'{"value":"\xff"}', b""):
            with self.subTest(raw=raw), self.assertRaises(AdapterError):
                strict_json(raw, max_bytes=1024)

    def test_byte_limit_applies_before_whitespace_is_discarded(self):
        with self.assertRaises(AdapterError):
            strict_json(b" " * 200 + b"{}", max_bytes=100)

    def test_deeply_nested_input_rejected_as_adapter_error(self):
        raw = b'{"x":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}"
        with self.assertRaises(AdapterError):
            strict_json(raw, max_bytes=10000)


class AdapterCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shirudo-adapter-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.verifier = write_nonexecuted_fixture(self.root / "synthetic-verifier")
        self.state = self.root / "state"
        self.service = Service.initialize(self.state)
        self.policy = policy_for(self.verifier)
        self.digest = self.service.register_policy(self.policy)

    def issue(self):
        return self.service.issue_challenge(self.digest)

    def assess(self, challenge, evidence=None, result=None):
        raw = evidence_bytes(self.policy, challenge) if evidence is None else evidence
        outcome = fixture_verifier_result(self.policy) if result is None else result
        with patch("shirudo_adapter.service.run_verifier", return_value=outcome) as verifier:
            receipt = self.service.assess(challenge["payload"]["challenge_id"], raw, str(self.verifier))
        return receipt, verifier

    def verify(self, receipt, challenge, **overrides):
        expected = {
            "expected_target": self.policy["target_id"],
            "expected_policy_sha256": self.digest,
            "expected_challenge_id": challenge["payload"]["challenge_id"],
        }
        expected.update(overrides)
        return verify_receipt(receipt, self.service.public_key_hex(), **expected)

    def assert_consumed(self, challenge, service=None):
        instance = self.service if service is None else service
        with patch("shirudo_adapter.service.run_verifier") as verifier:
            with self.assertRaises(AdapterError) as error:
                instance.assess(
                    challenge["payload"]["challenge_id"],
                    evidence_bytes(self.policy, challenge),
                    str(self.verifier),
                )
        self.assertEqual(error.exception.code, "CHALLENGE_SPENT")
        verifier.assert_not_called()

    def assert_failed_receipt(self, receipt, challenge):
        self.assertIn(receipt["payload"]["outcome"], {"REJECTED", "BLOCKED"})
        verification = self.verify(receipt, challenge)
        self.assertFalse(verification["current_authorization"])
        self.assertEqual(verification["historical_outcome"], receipt["payload"]["outcome"])


class PolicyTests(AdapterCase):
    def test_policy_digest_binds_canonical_complete_policy(self):
        self.assertEqual(self.digest, hashlib.sha256(canonical_json(self.policy)).hexdigest())

    def test_registered_policy_is_not_a_reference_to_callers_mutable_dict(self):
        original_target = self.policy["target_id"]
        self.policy["target_id"] = "attacker-changed-target"
        challenge = self.issue()
        self.assertEqual(challenge["payload"]["target_id"], original_target)

    def test_malformed_trust_inputs_rejected(self):
        cases = [
            (("schema",), "attacker-policy-v1"),
            (("target_id",), ""),
            (("assurance",), "TRUST_ME"),
            (("enrollment", "method"), "self_declared"),
            (("enrollment", "record_sha256"), "not-a-digest"),
            (("enrollment", "ak_name"), "0004" + "ab" * 32),
            (("enrollment", "ek_name"), "000b" + "ab" * 31),
            (("expected", "chain"), "11" * 31),
            (("expected", "config_root"), "gg" * 32),
            (("expected", "binding_pcrs"), {"9": "11" * 32}),
            (("expected", "quote_pcrs"), {"0": "not-a-digest"}),
            (("expected", "config_pcr"), True),
            (("expected", "config_pcr"), -1),
            (("expected", "config_pcr"), 24),
            (("verifier", "source_commit"), "00" * 20),
            (("verifier", "sha256"), "00" * 31),
            (("verifier", "version_id"), "00" * 31),
            (("verifier", "timeout_seconds"), True),
            (("verifier", "timeout_seconds"), 0),
            (("verifier", "timeout_seconds"), 31),
            (("challenge_ttl_seconds",), True),
            (("challenge_ttl_seconds",), 0),
            (("challenge_ttl_seconds",), 301),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value), self.assertRaises(AdapterError):
                validate_policy(changed(self.policy, path, value))

    def test_synthetic_enrollment_cannot_be_promoted_to_hardware_assurance(self):
        for assurance in ("LAB_VTPM", "HARDWARE_TPM"):
            with self.subTest(assurance=assurance), self.assertRaises(AdapterError):
                validate_policy(changed(self.policy, ("assurance",), assurance))

    def test_exactly_one_config_register_is_required(self):
        missing = copy.deepcopy(self.policy)
        del missing["expected"]["config_pcr"]
        both = copy.deepcopy(self.policy)
        both["expected"]["config_nvpcr"] = "000b" + "66" * 32
        for policy in (missing, both):
            with self.subTest(policy=policy["expected"]), self.assertRaises(AdapterError):
                validate_policy(policy)

    def test_unknown_policy_cannot_issue_challenge(self):
        with self.assertRaises(AdapterError):
            self.service.issue_challenge(different(self.digest))

    def test_revoked_policy_cannot_issue_new_challenge(self):
        self.service.revoke_policy(self.digest)
        with self.assertRaises(AdapterError):
            self.service.issue_challenge(self.digest)

    def test_registering_identical_policy_does_not_resurrect_revocation(self):
        self.service.revoke_policy(self.digest)
        self.assertEqual(self.service.register_policy(self.policy), self.digest)
        with self.assertRaises(AdapterError):
            self.service.issue_challenge(self.digest)


class ChallengeAndAssessmentTests(AdapterCase):
    def test_verifier_issues_distinct_bound_challenges(self):
        first, second = self.issue(), self.issue()
        for challenge in (first, second):
            self.assertEqual(challenge["schema"], "wolfalibi.signed-record.v1")
            payload = challenge["payload"]
            self.assertEqual(payload["schema"], "wolfalibi.shirudo.challenge.v1")
            self.assertEqual(payload["target_id"], self.policy["target_id"])
            self.assertEqual(payload["policy_sha256"], self.digest)
            self.assertGreater(payload["expires_at_ms"], payload["issued_at_ms"])
            self.assertEqual(len(challenge["signature"]), 128)
        self.assertNotEqual(first["payload"]["nonce"], second["payload"]["nonce"])
        self.assertNotEqual(first["payload"]["challenge_id"], second["payload"]["challenge_id"])

    def test_synthetic_success_is_historical_simulation_not_authorization(self):
        challenge = self.issue()
        receipt, verifier = self.assess(challenge)
        verifier.assert_called_once()
        self.assertEqual(receipt["payload"]["outcome"], "SIMULATED_POLICY_ONLY")
        verified = self.verify(receipt, challenge)
        self.assertEqual(verified["historical_outcome"], "SIMULATED_POLICY_ONLY")
        self.assertIs(verified["current_authorization"], False)

    def test_successful_challenge_is_spent_after_reopen(self):
        challenge = self.issue()
        receipt, _ = self.assess(challenge)
        reopened = Service(self.state)
        self.assertEqual(reopened.public_key_hex(), self.service.public_key_hex())
        self.assert_consumed(challenge, reopened)
        self.assertEqual(reopened.get_receipt(challenge["payload"]["challenge_id"]), receipt)

    def test_unknown_challenge_never_invokes_verifier(self):
        challenge = self.issue()
        with patch("shirudo_adapter.service.run_verifier") as verifier:
            with self.assertRaises(AdapterError):
                self.service.assess(
                    different(challenge["payload"]["challenge_id"]),
                    evidence_bytes(self.policy, challenge),
                    str(self.verifier),
                )
        verifier.assert_not_called()

    def test_unsubmitted_challenge_has_no_receipt(self):
        challenge = self.issue()
        with self.assertRaises(AdapterError):
            self.service.get_receipt(challenge["payload"]["challenge_id"])

    def test_nonce_from_another_issued_challenge_rejected_and_consumed(self):
        first, second = self.issue(), self.issue()
        receipt, verifier = self.assess(first, evidence_bytes(self.policy, second))
        verifier.assert_not_called()
        self.assert_failed_receipt(receipt, first)
        self.assert_consumed(first)
        valid, _ = self.assess(second)
        self.assertEqual(valid["payload"]["outcome"], "SIMULATED_POLICY_ONLY")

    def test_evidence_identity_and_measurement_mismatches_rejected_before_runner(self):
        cases = [
            (("schema",), True),
            (("schema",), 2),
            (("kind",), "attacker-attestation"),
            (("pcr_bank",), "sha1"),
            (("ak", "name"), "000b" + "55" * 32),
            (("ek", "name"), "000b" + "55" * 32),
            (("register", "value"), "55" * 32),
        ]
        for path, value in cases:
            challenge = self.issue()
            evidence = changed(evidence_object(self.policy, challenge), path, value)
            with self.subTest(path=path, value=value):
                receipt, verifier = self.assess(challenge, encode(evidence))
                verifier.assert_not_called()
                self.assert_failed_receipt(receipt, challenge)
                self.assert_consumed(challenge)

    def test_evidence_cannot_replace_trusted_policy_or_enrollment(self):
        challenge = self.issue()
        evidence = evidence_object(self.policy, challenge)
        evidence["register"]["value"] = "55" * 32
        evidence["policy"] = changed(self.policy, ("expected", "chain"), "55" * 32)
        evidence["enrollment"] = {"method": "manufacturer_chain", "verified": True}
        receipt, verifier = self.assess(challenge, encode(evidence))
        verifier.assert_not_called()
        self.assert_failed_receipt(receipt, challenge)
        self.assert_consumed(challenge)

    def test_self_declared_genuine_and_authorized_fields_do_not_promote_fixture(self):
        challenge = self.issue()
        evidence = evidence_object(self.policy, challenge)
        evidence.update({"execution_profile": "GENUINE", "verified": True, "current_authorization": True})
        receipt, _ = self.assess(challenge, encode(evidence))
        self.assertEqual(receipt["payload"]["outcome"], "SIMULATED_POLICY_ONLY")
        self.assertIs(self.verify(receipt, challenge)["current_authorization"], False)

    def test_malformed_submissions_are_consumed(self):
        for raw in (b"{", b'{"schema":1,"schema":1}', b"NaN", b"{} trailing"):
            challenge = self.issue()
            with self.subTest(raw=raw):
                receipt, verifier = self.assess(challenge, raw)
                verifier.assert_not_called()
                self.assert_failed_receipt(receipt, challenge)
                self.assert_consumed(challenge, Service(self.state))

    def test_oversized_submission_is_consumed_without_invoking_runner(self):
        challenge = self.issue()
        receipt, verifier = self.assess(challenge, b" " * 1_048_577)
        verifier.assert_not_called()
        self.assert_failed_receipt(receipt, challenge)
        self.assert_consumed(challenge)

    def test_bad_evidence_files_consume_reservation_before_read_failure(self):
        target = self.root / "evidence-source"
        target.write_bytes(b"unchanged")
        symlink = self.root / "evidence-symlink"
        symlink.symlink_to(target)
        oversized = self.root / "evidence-too-large"
        oversized.write_bytes(b" " * 1_048_577)
        for path in (self.root / "missing-evidence", symlink, oversized):
            challenge = self.issue()
            with self.subTest(path=path.name):
                with patch("shirudo_adapter.service.run_verifier") as verifier:
                    receipt = self.service.assess_file(
                        challenge["payload"]["challenge_id"], path, str(self.verifier)
                    )
                verifier.assert_not_called()
                self.assert_failed_receipt(receipt, challenge)
                self.assertIsNone(receipt["payload"]["evidence_sha256"])
                self.assert_consumed(challenge, Service(self.state))
        self.assertEqual(target.read_bytes(), b"unchanged")

    def test_expired_challenge_is_blocked_without_runner_and_consumed(self):
        challenge = self.issue()
        self.service._clock = lambda: challenge["payload"]["expires_at_ms"] + 1
        receipt, verifier = self.assess(challenge)
        verifier.assert_not_called()
        self.assert_failed_receipt(receipt, challenge)
        self.assert_consumed(challenge)

    def test_clock_rollback_cannot_issue_another_challenge(self):
        challenge = self.issue()
        self.service._clock = lambda: challenge["payload"]["issued_at_ms"] - 1
        with self.assertRaises(AdapterError):
            self.service.issue_challenge(self.digest)

    def test_revocation_after_issue_blocks_assessment_and_consumes(self):
        challenge = self.issue()
        self.service.revoke_policy(self.digest)
        receipt, verifier = self.assess(challenge)
        verifier.assert_not_called()
        self.assert_failed_receipt(receipt, challenge)
        self.assert_consumed(challenge)

    def test_expiry_during_verifier_is_rechecked_before_acceptance(self):
        challenge = self.issue()

        def finish_late(*args, **kwargs):
            self.service._clock = lambda: challenge["payload"]["expires_at_ms"] + 1
            return fixture_verifier_result(self.policy)

        with patch("shirudo_adapter.service.run_verifier", side_effect=finish_late):
            receipt = self.service.assess(
                challenge["payload"]["challenge_id"], evidence_bytes(self.policy, challenge), str(self.verifier)
            )
        self.assert_failed_receipt(receipt, challenge)
        self.assert_consumed(challenge)

    def test_policy_revoked_during_verifier_is_rechecked_before_acceptance(self):
        challenge = self.issue()

        def revoke_during_run(*args, **kwargs):
            Service(self.state).revoke_policy(self.digest)
            return fixture_verifier_result(self.policy)

        with patch("shirudo_adapter.service.run_verifier", side_effect=revoke_during_run):
            receipt = self.service.assess(
                challenge["payload"]["challenge_id"], evidence_bytes(self.policy, challenge), str(self.verifier)
            )
        self.assert_failed_receipt(receipt, challenge)
        self.assert_consumed(challenge)

    def test_clock_rolls_back_during_verifier_cannot_produce_success(self):
        challenge = self.issue()

        def finish_after_clock_rollback(*args, **kwargs):
            self.service._clock = lambda: challenge["payload"]["issued_at_ms"] - 1
            return fixture_verifier_result(self.policy)

        with patch("shirudo_adapter.service.run_verifier", side_effect=finish_after_clock_rollback):
            receipt = self.service.assess(
                challenge["payload"]["challenge_id"], evidence_bytes(self.policy, challenge), str(self.verifier)
            )
        self.assertEqual(receipt["payload"]["outcome"], "BLOCKED")
        self.assert_failed_receipt(receipt, challenge)
        self.assert_consumed(challenge, Service(self.state))

    def test_upstream_rejection_is_not_a_success_and_consumes(self):
        challenge = self.issue()
        receipt, verifier = self.assess(challenge, result=fixture_verifier_result(self.policy, accepted=False))
        verifier.assert_called_once()
        self.assert_failed_receipt(receipt, challenge)
        self.assert_consumed(challenge)

    def test_unexpected_runner_exception_leaves_incomplete_spent_reservation(self):
        challenge = self.issue()
        with patch("shirudo_adapter.service.run_verifier", side_effect=RuntimeError("fixture failure")):
            with self.assertRaises(RuntimeError):
                self.service.assess(
                    challenge["payload"]["challenge_id"], evidence_bytes(self.policy, challenge), str(self.verifier)
                )
        reopened = Service(self.state)
        self.assert_consumed(challenge, reopened)
        with self.assertRaises(AdapterError) as error:
            reopened.get_receipt(challenge["payload"]["challenge_id"])
        self.assertEqual(error.exception.code, "RECEIPT_UNAVAILABLE")

    def test_expected_runner_error_produces_blocked_receipt_without_diagnostic_text(self):
        challenge = self.issue()
        diagnostic = "sensitive-fixture-diagnostic-must-not-be-recorded"
        with patch(
            "shirudo_adapter.service.run_verifier",
            side_effect=AdapterError("VERIFIER_TIMEOUT", diagnostic),
        ):
            receipt = self.service.assess(
                challenge["payload"]["challenge_id"], evidence_bytes(self.policy, challenge), str(self.verifier)
            )
        self.assertEqual(receipt["payload"]["outcome"], "BLOCKED")
        self.assertEqual(receipt["payload"]["reason_code"], "VERIFIER_TIMEOUT")
        self.assertNotIn(diagnostic, canonical_json(receipt).decode("ascii"))
        self.assert_failed_receipt(receipt, challenge)
        self.assert_consumed(challenge, Service(self.state))

    def test_interruption_after_claim_cannot_reuse_nonce_or_fabricate_receipt(self):
        challenge = self.issue()
        with patch("shirudo_adapter.service.run_verifier", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.service.assess(
                    challenge["payload"]["challenge_id"], evidence_bytes(self.policy, challenge), str(self.verifier)
                )
        reopened = Service(self.state)
        self.assert_consumed(challenge, reopened)
        with self.assertRaises(AdapterError):
            reopened.get_receipt(challenge["payload"]["challenge_id"])

    def test_claim_is_visible_to_competing_instance_before_verifier_returns(self):
        challenge = self.issue()
        entered, release = threading.Event(), threading.Event()

        def hold_verifier(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test did not release verifier")
            return fixture_verifier_result(self.policy)

        def submit():
            return Service(self.state).assess(
                challenge["payload"]["challenge_id"], evidence_bytes(self.policy, challenge), str(self.verifier)
            )

        with patch("shirudo_adapter.service.run_verifier", side_effect=hold_verifier) as verifier:
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(submit)
                try:
                    self.assertTrue(entered.wait(3), "first assessment never reached verifier")
                    with self.assertRaises(AdapterError):
                        Service(self.state).get_receipt(challenge["payload"]["challenge_id"])
                    second = executor.submit(submit)
                    with self.assertRaises(AdapterError):
                        second.result(timeout=2)
                finally:
                    release.set()
                receipt = first.result(timeout=3)
            verifier.assert_called_once()
        self.assertEqual(receipt["payload"]["outcome"], "SIMULATED_POLICY_ONLY")
        self.assertEqual(self.service.get_receipt(challenge["payload"]["challenge_id"]), receipt)


class ReceiptTests(AdapterCase):
    def setUp(self):
        super().setUp()
        self.challenge = self.issue()
        self.receipt, _ = self.assess(self.challenge)

    def test_changed_signed_payload_is_rejected(self):
        for field, value in (
            ("target_id", "another-target"),
            ("policy_sha256", different(self.digest)),
            ("challenge_id", "another-challenge"),
            ("outcome", "EVIDENCE_ACCEPTED"),
        ):
            tampered = changed(self.receipt, ("payload", field), value)
            with self.subTest(field=field), self.assertRaises(AdapterError):
                self.verify(tampered, self.challenge)

    def test_wrong_signature_and_missing_signature_are_rejected(self):
        tampered = changed(self.receipt, ("signature",), different(self.receipt["signature"]))
        missing = copy.deepcopy(self.receipt)
        del missing["signature"]
        for envelope in (tampered, missing):
            with self.subTest(envelope=envelope), self.assertRaises(AdapterError):
                self.verify(envelope, self.challenge)

    def test_external_expected_target_policy_and_challenge_are_required_matches(self):
        for overrides in (
            {"expected_target": "another-target"},
            {"expected_policy_sha256": different(self.digest)},
            {"expected_challenge_id": different(self.challenge["payload"]["challenge_id"])},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(AdapterError):
                self.verify(self.receipt, self.challenge, **overrides)

    def test_another_instance_key_cannot_verify_receipt(self):
        other = Service.initialize(self.root / "other-state")
        with self.assertRaises(AdapterError):
            verify_receipt(
                self.receipt,
                other.public_key_hex(),
                expected_target=self.policy["target_id"],
                expected_policy_sha256=self.digest,
                expected_challenge_id=self.challenge["payload"]["challenge_id"],
            )

    def test_payload_cannot_supply_a_replacement_verification_key(self):
        other = Service.initialize(self.root / "other-state")
        tampered = copy.deepcopy(self.receipt)
        tampered["public_key"] = other.public_key_hex()
        with self.assertRaises(AdapterError):
            verify_receipt(
                tampered,
                other.public_key_hex(),
                expected_target=self.policy["target_id"],
                expected_policy_sha256=self.digest,
                expected_challenge_id=self.challenge["payload"]["challenge_id"],
            )

    def test_historical_receipt_remains_historical_after_policy_revocation(self):
        self.service.revoke_policy(self.digest)
        result = self.verify(self.receipt, self.challenge)
        self.assertEqual(result["historical_outcome"], "SIMULATED_POLICY_ONLY")
        self.assertIs(result["current_authorization"], False)

    def test_valid_signature_does_not_excuse_malformed_receipt_semantics(self):
        # An independent fixture key distinguishes schema validation from
        # signature rejection.  No production key or identity is involved.
        fixture_key = Ed25519PrivateKey.generate()
        fixture_public = fixture_key.public_key().public_bytes_raw().hex()

        def inspect(payload):
            return verify_receipt(
                sign_record(fixture_key, payload),
                fixture_public,
                expected_target=self.policy["target_id"],
                expected_policy_sha256=self.digest,
                expected_challenge_id=self.challenge["payload"]["challenge_id"],
            )

        good = self.receipt["payload"]
        self.assertEqual(inspect(good)["historical_outcome"], "SIMULATED_POLICY_ONLY")
        cases = [
            ("null upstream", changed(good, ("upstream",), None)),
            ("wrong upstream keys", changed(good, ("upstream",), {})),
            ("wrong report digest", changed(good, ("upstream", "report_sha256"), "dd" * 32)),
            ("nonzero success exit", changed(good, ("upstream", "exit_code"), 1)),
            ("not-run success profile", changed(good, ("upstream", "execution_profile"), "NOT_RUN")),
            ("empty required checks", changed(good, ("upstream", "required_checks"), [])),
            ("binary mismatch", changed(good, ("upstream", "observed_binary_sha256"), different(self.policy["verifier"]["sha256"]))),
            ("version mismatch", changed(good, ("upstream", "observed_version_id"), different(self.policy["verifier"]["version_id"]))),
            ("unreviewed upstream", changed(good, ("upstream", "source_commit"), "00" * 20)),
            ("object reason", changed(good, ("reason_code",), {"claim": "approved"})),
            ("non-list limitations", changed(good, ("limitations",), "unbounded authority")),
            ("non-string limitation", changed(good, ("limitations",), [{"authority": True}])),
        ]
        missing = copy.deepcopy(good)
        del missing["upstream"]["required_checks"]
        cases.append(("missing required checks", missing))
        contradictory = changed(good, ("upstream", "report", "verdict"), "fail")
        contradictory["upstream"]["report_sha256"] = hashlib.sha256(canonical_json(contradictory["upstream"]["report"])).hexdigest()
        cases.append(("hash-consistent failing verdict", contradictory))
        promoted = changed(good, ("outcome",), "EVIDENCE_ACCEPTED")
        promoted["assurance"] = "LAB_VTPM"
        cases.append(("synthetic run promoted to lab acceptance", promoted))
        for name, payload in cases:
            with self.subTest(case=name), self.assertRaises(AdapterError):
                inspect(payload)


class StateCustodyTests(AdapterCase):
    def test_opening_missing_state_does_not_initialize_new_identity(self):
        missing = self.root / "missing-state"
        with self.assertRaises(AdapterError):
            Service(missing)
        self.assertFalse(missing.exists())

    def test_incomplete_state_directory_fails_closed(self):
        incomplete = self.root / "incomplete-state"
        incomplete.mkdir(mode=0o700)
        (incomplete / "unrelated-file").write_bytes(b"not a database or signing key")
        with self.assertRaises(AdapterError):
            Service(incomplete)

    def test_reinitialization_cannot_replace_existing_identity(self):
        original = self.service.public_key_hex()
        try:
            Service.initialize(self.state)
        except AdapterError:
            pass
        self.assertEqual(Service(self.state).public_key_hex(), original)

    def test_symlink_state_root_rejected(self):
        alias = self.root / "state-alias"
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(AdapterError):
            Service(alias)
        with self.assertRaises(AdapterError):
            Service.initialize(alias)

    def test_missing_signing_key_does_not_silently_generate_replacement(self):
        key = self.state / "signing.key"
        key.unlink()
        with self.assertRaises(AdapterError):
            Service(self.state)
        self.assertFalse(key.exists())

    def test_corrupt_signing_key_fails_closed(self):
        (self.state / "signing.key").write_bytes(b"corrupt")
        with self.assertRaises(AdapterError):
            Service(self.state)

    def test_corrupt_journal_fails_closed(self):
        (self.state / "journal.sqlite3").write_bytes(b"not a sqlite database")
        with self.assertRaises(AdapterError):
            Service(self.state)

    def test_signing_key_symlink_rejected(self):
        key = self.state / "signing.key"
        outside = self.root / "external-key"
        key.rename(outside)
        key.symlink_to(outside)
        with self.assertRaises(AdapterError):
            Service(self.state)

    def test_signing_key_hardlink_rejected(self):
        os.link(self.state / "signing.key", self.root / "shared-key")
        with self.assertRaises(AdapterError):
            Service(self.state)

    def test_nonprivate_signing_key_permissions_rejected(self):
        (self.state / "signing.key").chmod(0o644)
        with self.assertRaises(AdapterError):
            Service(self.state)

    def test_unsafe_sqlite_sidecar_rejected_without_touching_destination(self):
        sentinel = self.root / "unrelated-sentinel"
        sentinel.write_bytes(b"unchanged")
        (self.state / "journal.sqlite3-journal").symlink_to(sentinel)
        with self.assertRaises(AdapterError):
            Service(self.state)
        self.assertEqual(sentinel.read_bytes(), b"unchanged")


if __name__ == "__main__":
    unittest.main()
