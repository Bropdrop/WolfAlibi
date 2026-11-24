"""Offline action-gate authority and transaction tests.

The signed verifier responses here are deliberately fabricated test claims.
No TPM or upstream executable runs in these unit tests, and their passing
results cannot qualify the genuine LAB_VTPM integration workflow.
"""

from __future__ import annotations

import copy
import os
import secrets
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shirudo_adapter.action_gate import (Gate, make_grant_payload, verify_effect_receipt)
from shirudo_adapter.model import AdapterError, canonical_json, digest, strict_json
from shirudo_adapter.receipt import sign_record, verify_receipt, verify_record

try:
    from .support import different, fixture_verifier_result, policy_for, write_nonexecuted_fixture
except ImportError:
    from support import different, fixture_verifier_result, policy_for, write_nonexecuted_fixture


class GateFixture:
    """Clearly synthetic authorities, also usable by the socket boundary tests."""

    def __init__(self, root: Path, *, ttl=30, quote_pcrs=None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        verifier = write_nonexecuted_fixture(self.root / "not-a-genuine-verifier")
        self.policy = policy_for(verifier)
        self.policy["assurance"] = "LAB_VTPM"
        self.policy["enrollment"]["method"] = "trusted_builder"
        self.policy["challenge_ttl_seconds"] = ttl
        if quote_pcrs is not None:
            self.policy["expected"]["quote_pcrs"] = quote_pcrs
        self.owner_key = Ed25519PrivateKey.generate()
        self.verifier_key = Ed25519PrivateKey.generate()
        self.verifier_instance_id = secrets.token_hex(16)
        self.trust = {"schema": "wolfalibi.shirudo.action-trust.v1",
            "target_id": self.policy["target_id"],
            "owner_public_key": self.owner_key.public_key().public_bytes_raw().hex(),
            "verifier_public_key": self.verifier_key.public_key().public_bytes_raw().hex(),
            "verifier_instance_id": self.verifier_instance_id, "policy": copy.deepcopy(self.policy)}
        self.state = self.root / "gate-state"
        self.gate = Gate.initialize(self.state, self.trust)
        self.now = time.time_ns() // 1_000_000
        self.gate._clock = lambda: self.now
        self.identity = self.gate.public_identity()

    def challenge(self, *, issued_at_ms=None, challenge_id=None, nonce=None):
        issued = self.now if issued_at_ms is None else issued_at_ms
        return sign_record(self.verifier_key, {
            "schema": "wolfalibi.shirudo.challenge.v1", "instance_id": self.verifier_instance_id,
            "challenge_id": challenge_id or secrets.token_hex(16), "nonce": nonce or secrets.token_hex(32),
            "policy_sha256": digest(self.policy), "target_id": self.policy["target_id"],
            "issued_at_ms": issued, "expires_at_ms": issued + self.policy["challenge_ttl_seconds"] * 1000})

    def assessment(self, challenge):
        attestation = challenge["payload"]
        simulated = fixture_verifier_result(self.policy)
        # A signed test assertion of this profile, not an actual upstream run.
        upstream = {"source_commit": self.policy["verifier"]["source_commit"],
            "expected_binary_sha256": simulated["binary_sha256"],
            "expected_version_id": simulated["version_id"],
            "observed_binary_sha256": simulated["binary_sha256"],
            "observed_version_id": simulated["version_id"], "execution_profile": "UPSTREAM_CLI",
            "exit_code": 0, "report": simulated["report"],
            "report_sha256": digest(simulated["report"]), "required_checks": simulated["required_checks"]}
        return sign_record(self.verifier_key, {
            "schema": "wolfalibi.shirudo.receipt.v1", "receipt_id": secrets.token_hex(16),
            "instance_id": self.verifier_instance_id, "challenge_id": attestation["challenge_id"],
            "nonce": attestation["nonce"], "target_id": self.policy["target_id"],
            "policy_sha256": digest(self.policy),
            "enrollment_record_sha256": self.policy["enrollment"]["record_sha256"],
            "evidence_sha256": "a5" * 32, "assurance": "LAB_VTPM", "outcome": "EVIDENCE_ACCEPTED",
            "reason_code": "REQUIRED_CHECKS_PASSED", "issued_at_ms": attestation["issued_at_ms"],
            "expires_at_ms": attestation["expires_at_ms"], "started_at_ms": self.now,
            "completed_at_ms": self.now, "upstream": upstream,
            "scope": "HISTORICAL_EVIDENCE_ONLY", "authorization": "NONE",
            "limitations": ["Fabricated signed authority fixture; no actual TPM verification."]})

    def make_request(self, action, attestation, *, assessment=None, grant_id=None,
                     issued_at_ms=None, expires_at_ms=None):
        assessment = self.assessment(attestation) if assessment is None else assessment
        grant = sign_record(self.owner_key, make_grant_payload(action, assessment,
            grant_id=grant_id or secrets.token_hex(16),
            issued_at_ms=self.now if issued_at_ms is None else issued_at_ms,
            expires_at_ms=action["payload"]["expires_at_ms"] if expires_at_ms is None else expires_at_ms))
        return {"operation_id": action["payload"]["operation_id"], "grant": grant, "assessment": assessment}

    def operation(self):
        attestation = self.challenge()
        action = self.gate.prepare(attestation)
        return attestation, action, self.make_request(action, attestation)

    def rebind_assessment(self, request, assessment):
        result = copy.deepcopy(request)
        result["assessment"] = assessment
        grant = result["grant"]["payload"]
        grant["attestation_receipt_sha256"] = digest(assessment)
        result["grant"] = sign_record(self.owner_key, grant)
        return result

    def oracle(self):
        with sqlite3.connect(f"file:{self.state / 'journal.sqlite3'}?mode=ro", uri=True) as conn:
            return (conn.execute("SELECT value FROM counter WHERE id=1").fetchone()[0],
                    conn.execute("SELECT COUNT(*) FROM operations WHERE status='COMMITTED'").fetchone()[0])


class GateCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wolfalibi-action-gate-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.f = GateFixture(self.root / "fixture")
        self.gate = self.f.gate

    def denied(self, callback, code=None):
        with self.assertRaises(AdapterError) as raised:
            callback()
        if code is not None:
            self.assertEqual(raised.exception.code, code)
        return raised.exception

    def verify(self, receipt, action, request, **overrides):
        expected = {"expected_target": self.f.policy["target_id"],
                    "expected_gate_instance_id": self.f.identity["gate_instance_id"],
                    "expected_operation_id": request["operation_id"],
                    "expected_grant_id": request["grant"]["payload"]["grant_id"],
                    "expected_grant_sha256": digest(request["grant"]),
                    "expected_assessment_sha256": digest(request["assessment"]),
                    "expected_action_challenge": action}
        expected.update(overrides)
        return verify_effect_receipt(receipt, self.f.identity["public_key"], **expected)


class AuthorityTests(GateCase):
    def test_separate_owner_grant_commits_one_effect_and_verifiable_past_receipt(self):
        _, action, request = self.f.operation()
        result = self.gate.execute(request)
        self.assertEqual(result["result"], "COMMITTED")
        self.assertEqual(self.f.oracle(), (1, 1))
        verified = self.verify(result["receipt"], action, request)
        self.assertFalse(verified["current_authorization"])
        self.assertEqual((verified["counter_before"], verified["counter_after"]), (0, 1))
        status = self.gate.status(request["operation_id"])
        self.assertEqual(status["operation"]["receipt"], result["receipt"])
        self.assertEqual(status["operation"]["status"], "COMMITTED")

    def test_assessment_alone_missing_or_forged_owner_never_changes_counter(self):
        _, _, request = self.f.operation()
        cases = [None, request["assessment"], sign_record(Ed25519PrivateKey.generate(), request["grant"]["payload"])]
        for grant in cases:
            with self.subTest(grant_type=type(grant).__name__):
                altered = copy.deepcopy(request)
                altered["grant"] = grant
                self.denied(lambda: self.gate.execute(altered))
                self.assertEqual(self.f.oracle(), (0, 0))
        self.assertEqual(self.gate.execute(request)["result"], "COMMITTED")

    def test_owner_cannot_widen_or_substitute_bound_operation(self):
        _, _, request = self.f.operation()
        mutations = [
            ("operation_nonce", "11" * 32), ("operation_id", "12" * 16),
            ("gate_instance_id", "13" * 16), ("target_id", "other-target"),
            ("policy_sha256", "14" * 32), ("policy_generation", 2),
            ("action_challenge_sha256", "15" * 32),
            ("attestation_challenge_sha256", "16" * 32),
            ("attestation_receipt_sha256", "17" * 32),
            ("scope", "ARBITRARY_ACTION"), ("action", {"name": "increment_counter", "delta": 2}),
            ("action", {"name": "increment_counter", "delta": True}),
            ("expires_at_ms", request["grant"]["payload"]["expires_at_ms"] + 1),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                altered = copy.deepcopy(request)
                payload = altered["grant"]["payload"]
                payload[field] = value
                altered["grant"] = sign_record(self.f.owner_key, payload)
                self.denied(lambda: self.gate.execute(altered))
                self.assertEqual(self.f.oracle(), (0, 0))

    def test_valid_verifier_signature_does_not_replace_independent_pins(self):
        _, _, request = self.f.operation()
        changes = [(("instance_id",), "19" * 16), (("nonce",), "20" * 32),
                   (("enrollment_record_sha256",), "21" * 32),
                   (("issued_at_ms",), request["assessment"]["payload"]["issued_at_ms"] - 1)]
        for path, replacement in changes:
            with self.subTest(path=path):
                payload = copy.deepcopy(request["assessment"]["payload"])
                payload[path[0]] = replacement
                forged = sign_record(self.f.verifier_key, payload)
                altered = self.f.rebind_assessment(request, forged)
                self.denied(lambda: self.gate.execute(altered))
        for expected, observed in (("expected_binary_sha256", "observed_binary_sha256"),
                                   ("expected_version_id", "observed_version_id")):
            with self.subTest(pin=expected):
                payload = copy.deepcopy(request["assessment"]["payload"])
                payload["upstream"][expected] = "22" * 32
                payload["upstream"][observed] = "22" * 32
                altered = self.f.rebind_assessment(request, sign_record(self.f.verifier_key, payload))
                self.denied(lambda: self.gate.execute(altered), "ASSESSMENT_MISMATCH")
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_untrusted_verifier_signature_is_rejected_even_when_owner_signed(self):
        _, _, request = self.f.operation()
        forged = sign_record(Ed25519PrivateKey.generate(), request["assessment"]["payload"])
        altered = self.f.rebind_assessment(request, forged)
        self.denied(lambda: self.gate.execute(altered), "INVALID_SIGNATURE")
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_synthetic_assessment_cannot_earn_an_effect(self):
        _, _, request = self.f.operation()
        payload = copy.deepcopy(request["assessment"]["payload"])
        payload.update(assurance="SYNTHETIC", outcome="SIMULATED_POLICY_ONLY")
        payload["upstream"]["execution_profile"] = "SYNTHETIC"
        altered = self.f.rebind_assessment(request, sign_record(self.f.verifier_key, payload))
        self.denied(lambda: self.gate.execute(altered), "ASSESSMENT_NOT_ACCEPTED")
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_self_consistent_receipt_must_cover_every_independently_required_pcr(self):
        fixture = GateFixture(self.root / "quoted", quote_pcrs={"7": "34" * 32})
        _, action, request = fixture.operation()
        payload = copy.deepcopy(request["assessment"]["payload"])
        check = "PCR 7 matches the expected value"
        payload["upstream"]["required_checks"].remove(check)
        payload["upstream"]["report"]["checks"] = [c for c in payload["upstream"]["report"]["checks"] if c["text"] != check]
        payload["upstream"]["report_sha256"] = digest(payload["upstream"]["report"])
        forged = sign_record(fixture.verifier_key, payload)
        # The old generic historical verifier cannot reconstruct a hidden
        # policy. The gate has that full independent policy and must reject.
        verify_receipt(forged, fixture.trust["verifier_public_key"], expected_target=fixture.policy["target_id"],
            expected_policy_sha256=digest(fixture.policy), expected_challenge_id=action["payload"]["attestation_challenge_id"])
        altered = fixture.rebind_assessment(request, forged)
        self.denied(lambda: fixture.gate.execute(altered), "ASSESSMENT_MISMATCH")
        self.assertEqual(fixture.oracle(), (0, 0))

    def test_malformed_or_incomplete_upstream_report_does_not_earn_effect(self):
        _, _, request = self.f.operation()
        payload = copy.deepcopy(request["assessment"]["payload"])
        payload["upstream"]["report"]["checks"].pop()
        payload["upstream"]["report_sha256"] = digest(payload["upstream"]["report"])
        altered = self.f.rebind_assessment(request, sign_record(self.f.verifier_key, payload))
        self.denied(lambda: self.gate.execute(altered))
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_rejected_or_hardware_assessment_is_not_lab_authority(self):
        _, _, request = self.f.operation()
        for assurance, outcome in (("HARDWARE_TPM", "EVIDENCE_ACCEPTED"), ("LAB_VTPM", "REJECTED")):
            payload = copy.deepcopy(request["assessment"]["payload"])
            payload.update(assurance=assurance, outcome=outcome)
            altered = self.f.rebind_assessment(request, sign_record(self.f.verifier_key, payload))
            self.denied(lambda: self.gate.execute(altered), "ASSESSMENT_NOT_ACCEPTED")
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_unexpected_fields_types_or_oversized_requests_rejected(self):
        _, _, request = self.f.operation()
        cases = [dict(request, command="touch anything"), dict(request, operation_id=True),
                 dict(request, grant="x" * 300_000), dict(request, assessment=None)]
        for altered in cases:
            self.denied(lambda: self.gate.execute(altered))
        self.assertEqual(self.f.oracle(), (0, 0))


class FreshnessTests(GateCase):
    def test_admission_age_and_future_skew_boundaries(self):
        for offset, code in ((-5001, "ATTESTATION_STALE"), (2001, "CLOCK_SKEW")):
            record = self.f.challenge(issued_at_ms=self.f.now + offset)
            self.denied(lambda: self.gate.prepare(record), code)
        for offset in (-5000, 2000):
            record = self.f.challenge(issued_at_ms=self.f.now + offset)
            action = self.gate.prepare(record)
            self.assertEqual(action["payload"]["expires_at_ms"], min(self.f.now + 30_000, self.f.now + offset + 30_000))

    def test_operation_interval_cannot_extend_short_verifier_challenge(self):
        fixture = GateFixture(self.root / "short", ttl=1)
        attestation, action, request = fixture.operation()
        self.assertEqual(action["payload"]["expires_at_ms"], attestation["payload"]["expires_at_ms"])
        fixture.now += 1000
        self.denied(lambda: fixture.gate.execute(request), "OPERATION_EXPIRED")
        self.assertEqual(fixture.oracle(), (0, 0))

    def test_admission_window_is_rechecked_at_prepare_commit(self):
        record = self.f.challenge()
        ticks = iter([self.f.now, self.f.now + 5001])
        self.gate._clock = lambda: next(ticks)
        self.denied(lambda: self.gate.prepare(record), "ATTESTATION_STALE")
        with sqlite3.connect(self.f.state / "journal.sqlite3") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_same_attestation_id_or_nonce_is_admitted_only_once(self):
        attestation, _, request = self.f.operation()
        self.gate.execute(request)
        for record in (attestation,
                       self.f.challenge(challenge_id=attestation["payload"]["challenge_id"]),
                       self.f.challenge(nonce=attestation["payload"]["nonce"])):
            self.denied(lambda: self.gate.prepare(record), "ATTESTATION_REUSED")
        self.assertEqual(self.f.oracle(), (1, 1))

    def test_signed_challenge_wrong_key_instance_policy_or_target_rejected(self):
        record = self.f.challenge()
        self.denied(lambda: self.gate.prepare(sign_record(Ed25519PrivateKey.generate(), record["payload"])), "INVALID_SIGNATURE")
        for field, value in (("instance_id", "11" * 16), ("policy_sha256", "12" * 32), ("target_id", "other")):
            payload = dict(record["payload"], **{field: value})
            self.denied(lambda: self.gate.prepare(sign_record(self.f.verifier_key, payload)), "CHALLENGE_SCOPE_MISMATCH")
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_owner_grant_expiry_and_future_time_rejected(self):
        attestation, action, _ = self.f.operation()
        request = self.f.make_request(action, attestation, expires_at_ms=self.f.now + 10)
        self.f.now += 10
        self.denied(lambda: self.gate.execute(request), "GRANT_EXPIRED")
        request = self.f.make_request(action, attestation, issued_at_ms=self.f.now + 2001)
        self.denied(lambda: self.gate.execute(request), "CLOCK_SKEW")
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_expiry_at_last_commit_check_rolls_back_tentative_effect(self):
        _, action, request = self.f.operation()
        calls = iter([self.f.now, self.f.now, action["payload"]["expires_at_ms"]])
        self.gate._clock = lambda: next(calls)
        self.denied(lambda: self.gate.execute(request), "OPERATION_EXPIRED")
        self.assertEqual(self.f.oracle(), (0, 0))
        self.f.now = action["payload"]["expires_at_ms"]
        self.gate._clock = lambda: self.f.now
        self.assertEqual(self.gate.status(request["operation_id"])["operation"]["status"], "PREPARED")

    def test_denied_attempt_preserves_clock_high_water_across_restart(self):
        _, action, request = self.f.operation()
        self.f.now = action["payload"]["expires_at_ms"]
        self.denied(lambda: self.gate.execute(request), "OPERATION_EXPIRED")
        self.assertEqual(self.f.oracle(), (0, 0))
        reopened = Gate(self.f.state)
        reopened._clock = lambda: self.f.now - 1
        self.denied(reopened.status, "CLOCK_ROLLBACK")
        reopened._clock = lambda: self.f.now
        self.assertEqual(reopened.status()["counter"], 0)

    def test_clock_rollback_at_admission_execution_and_final_check_fails_closed(self):
        _, _, request = self.f.operation()
        self.f.now += 10
        self.gate.status()
        self.f.now -= 1
        self.denied(lambda: self.gate.execute(request), "CLOCK_ROLLBACK")
        self.denied(lambda: self.gate.prepare(self.f.challenge()), "CLOCK_ROLLBACK")
        self.f.now += 2
        calls = iter([self.f.now, self.f.now, self.f.now - 1])
        self.gate._clock = lambda: next(calls)
        self.denied(lambda: self.gate.execute(request), "CLOCK_ROLLBACK")
        self.assertEqual(self.f.oracle(), (0, 0))


class TransactionTests(GateCase):
    def test_exact_retry_after_restart_expiry_and_revocation_returns_same_receipt(self):
        _, _, request = self.f.operation()
        first = self.gate.execute(request)
        reopened = Gate(self.f.state)
        reopened._clock = lambda: self.f.now + 100_000
        reopened.revoke_grant(request["grant"]["payload"]["grant_id"])
        reopened.revoke_policy()
        second = reopened.execute(request)
        self.assertEqual(second, {"result": "ALREADY_COMMITTED", "receipt": first["receipt"]})
        self.assertEqual(self.f.oracle(), (1, 1))

    def test_altered_retry_is_denied_without_changing_original_effect(self):
        _, _, request = self.f.operation()
        first = self.gate.execute(request)
        altered = copy.deepcopy(request)
        altered["grant"]["payload"]["expires_at_ms"] -= 1
        altered["grant"] = sign_record(self.f.owner_key, altered["grant"]["payload"])
        self.denied(lambda: self.gate.execute(altered), "OPERATION_CONFLICT")
        self.assertEqual(self.gate.status(request["operation_id"])["operation"]["receipt"], first["receipt"])
        self.assertEqual(self.f.oracle(), (1, 1))

    def test_grant_and_policy_revocation_committed_first_prevent_effect(self):
        _, _, request = self.f.operation()
        Gate(self.f.state).revoke_grant(request["grant"]["payload"]["grant_id"])
        self.f.now = max(self.f.now, time.time_ns() // 1_000_000)
        self.denied(lambda: self.gate.execute(request), "GRANT_REVOKED")
        Gate(self.f.state).revoke_policy()
        self.f.now = max(self.f.now, time.time_ns() // 1_000_000)
        self.denied(lambda: self.gate.execute(request), "POLICY_REVOKED")
        self.denied(lambda: self.gate.prepare(self.f.challenge()), "POLICY_REVOKED")
        self.assertEqual(self.f.oracle(), (0, 0))

    def test_consumed_grant_identifier_cannot_authorize_another_operation(self):
        _, _, first = self.f.operation()
        self.gate.execute(first)
        attestation, action, _ = self.f.operation()
        second = self.f.make_request(action, attestation, grant_id=first["grant"]["payload"]["grant_id"])
        self.denied(lambda: self.gate.execute(second), "GRANT_SPENT")
        self.assertEqual(self.f.oracle(), (1, 1))

    def test_concurrent_duplicate_requests_have_one_effect_and_identical_receipts(self):
        _, _, request = self.f.operation()
        barrier = threading.Barrier(8)
        def execute():
            barrier.wait(timeout=5)
            return self.gate.execute(request)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: execute(), range(8)))
        self.assertEqual(sum(r["result"] == "COMMITTED" for r in results), 1)
        self.assertEqual(sum(r["result"] == "ALREADY_COMMITTED" for r in results), 7)
        self.assertEqual(len({canonical_json(r["receipt"]) for r in results}), 1)
        self.assertEqual(self.f.oracle(), (1, 1))

    def test_concurrent_distinct_operations_serialize_counter_values(self):
        requests = [self.f.operation()[2] for _ in range(4)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(self.gate.execute, requests))
        self.assertEqual(sorted(r["receipt"]["payload"]["counter_after"] for r in results), [1, 2, 3, 4])
        self.assertEqual(self.f.oracle(), (4, 4))

    def test_exception_immediately_before_commit_rolls_back_effect_receipt_and_consumption(self):
        _, _, request = self.f.operation()
        def interrupt():
            raise RuntimeError("deliberate precommit fixture")
        self.gate._before_commit = interrupt
        with self.assertRaisesRegex(RuntimeError, "precommit fixture"):
            self.gate.execute(request)
        self.assertEqual(self.f.oracle(), (0, 0))
        recovered = Gate(self.f.state)
        status = recovered.status(request["operation_id"])
        self.assertEqual(status["operation"]["status"], "PREPARED")
        self.assertIsNone(status["operation"]["receipt"])
        self.assertEqual(recovered.execute(request)["result"], "COMMITTED")
        self.assertEqual(self.f.oracle(), (1, 1))

    @unittest.skipUnless(hasattr(os, "fork"), "process interruption requires fork")
    def test_abrupt_process_exit_before_commit_recovers_without_effect(self):
        _, _, request = self.f.operation()
        child = os.fork()
        if child == 0:
            self.gate._before_commit = lambda: os._exit(77)
            self.gate.execute(request)
            os._exit(99)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 77)
        recovered = Gate(self.f.state)
        self.assertEqual(self.f.oracle(), (0, 0))
        self.assertIsNone(recovered.status(request["operation_id"])["operation"]["receipt"])
        self.assertEqual(recovered.execute(request)["result"], "COMMITTED")
        self.assertEqual(self.f.oracle(), (1, 1))

    def test_revoke_racing_after_effect_transaction_waits_then_prevents_future_use(self):
        _, _, request = self.f.operation()
        ready, release, revocation_started = threading.Event(), threading.Event(), threading.Event()
        def pause():
            ready.set()
            if not release.wait(5):
                raise RuntimeError("test release timed out")
        def revoke():
            revocation_started.set()
            Gate(self.f.state).revoke_grant(request["grant"]["payload"]["grant_id"])
        self.gate._before_commit = pause
        with ThreadPoolExecutor(max_workers=2) as pool:
            effect = pool.submit(self.gate.execute, request)
            self.assertTrue(ready.wait(5))
            revocation = pool.submit(revoke)
            self.assertTrue(revocation_started.wait(5))
            self.assertFalse(revocation.done())
            release.set()
            first = effect.result(timeout=5)
            revocation.result(timeout=5)
        self.assertEqual(first["result"], "COMMITTED")
        recovered = Gate(self.f.state)
        self.assertEqual(recovered.execute(request)["result"], "ALREADY_COMMITTED")
        self.assertEqual(self.f.oracle(), (1, 1))


class StateIntegrityTests(GateCase):
    def test_trust_requires_lab_target_and_distinct_authority_keys(self):
        variants = []
        synthetic = copy.deepcopy(self.f.trust)
        synthetic["policy"]["assurance"] = "SYNTHETIC"
        synthetic["policy"]["enrollment"]["method"] = "synthetic_fixture"
        variants.append(synthetic)
        variants.append(dict(self.f.trust, target_id="other-target"))
        variants.append(dict(self.f.trust, owner_public_key=self.f.trust["verifier_public_key"]))
        variants.append(dict(self.f.trust, unexpected=True))
        for index, trust in enumerate(variants):
            path = self.root / f"invalid-{index}"
            self.denied(lambda: Gate.initialize(path, trust))
            self.assertFalse(path.exists())

    def test_original_caller_trust_mutation_does_not_change_gate_pins(self):
        self.f.trust["owner_public_key"] = "1a" * 32
        self.f.trust["policy"]["expected"]["chain"] = "1b" * 32
        _, _, request = self.f.operation()
        self.assertEqual(self.gate.execute(request)["result"], "COMMITTED")

    def test_missing_database_never_initializes_new_counter_on_reopen(self):
        (self.f.state / "journal.sqlite3").unlink()
        self.denied(lambda: Gate(self.f.state), "STATE_UNAVAILABLE")
        self.denied(self.gate.status, "STATE_UNAVAILABLE")
        self.assertFalse((self.f.state / "journal.sqlite3").exists())

    def test_private_ownership_symlink_and_hardlink_requirements(self):
        for name in ("state.json", "trust.json", "signing.key", "journal.sqlite3"):
            path = self.f.state / name
            with self.subTest(name=name, mode="permissions"):
                path.chmod(0o644)
                self.denied(lambda: Gate(self.f.state), "STATE_PERMISSIONS")
                path.chmod(0o600)
            with self.subTest(name=name, mode="hardlink"):
                link = self.root / "shared-link"
                os.link(path, link)
                self.denied(lambda: Gate(self.f.state), "STATE_PERMISSIONS")
                link.unlink()
        saved = self.f.state / "signing.saved"
        (self.f.state / "signing.key").rename(saved)
        (self.f.state / "signing.key").symlink_to(saved)
        self.denied(lambda: Gate(self.f.state), "STATE_PERMISSIONS")

    def test_state_directory_or_ancestor_symlink_is_rejected(self):
        direct = self.root / "state-link"
        direct.symlink_to(self.f.state, target_is_directory=True)
        self.denied(lambda: Gate(direct), "STATE_PERMISSIONS")
        parent = self.root / "parent-link"
        parent.symlink_to(self.f.root, target_is_directory=True)
        self.denied(lambda: Gate(parent / "gate-state"), "STATE_PERMISSIONS")
        self.denied(lambda: Gate.initialize(parent / "new-gate", self.f.trust), "STATE_PERMISSIONS")

    def test_replaceable_state_parent_is_rejected(self):
        parent = self.root / "replaceable"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        self.denied(lambda: Gate.initialize(parent / "state", self.f.trust), "STATE_PERMISSIONS")
        self.assertFalse((parent / "state").exists())

    def test_unsafe_sidecar_is_rejected_before_sqlite_opens_it(self):
        sidecar = self.f.state / "journal.sqlite3-journal"
        sidecar.symlink_to(self.root / "unrelated")
        self.denied(self.gate.status, "STATE_PERMISSIONS")

    def test_trust_file_and_database_identity_are_immutable(self):
        path = self.f.state / "trust.json"
        original = path.read_bytes()
        altered = strict_json(original)
        altered["policy"]["expected"]["chain"] = "7f" * 32
        path.write_bytes(canonical_json(altered))
        self.denied(self.gate.status, "STATE_INVALID")
        self.denied(lambda: Gate(self.f.state), "STATE_INVALID")
        path.write_bytes(original)
        with sqlite3.connect(self.f.state / "journal.sqlite3") as conn:
            conn.execute("UPDATE metadata SET value=? WHERE key='trust_sha256'", ("ab" * 32,))
        self.denied(self.gate.status, "STATE_INVALID")

    def test_tampered_stored_receipt_blocks_status_retry_and_reopen(self):
        _, _, request = self.f.operation()
        result = self.gate.execute(request)
        corrupted = copy.deepcopy(result["receipt"])
        corrupted["signature"] = different(corrupted["signature"])
        with sqlite3.connect(self.f.state / "journal.sqlite3") as conn:
            conn.execute("UPDATE operations SET receipt=? WHERE id=?", (canonical_json(corrupted).decode(), request["operation_id"]))
        for callback in (self.gate.status, lambda: self.gate.status(request["operation_id"]),
                         lambda: self.gate.execute(request), lambda: Gate(self.f.state)):
            self.denied(callback, "STATE_INVALID")
        self.assertEqual(self.f.oracle(), (1, 1))

    def test_counter_without_matching_consumption_receipt_is_corrupt_state(self):
        with sqlite3.connect(self.f.state / "journal.sqlite3") as conn:
            conn.execute("UPDATE counter SET value=1 WHERE id=1")
        self.denied(self.gate.status, "STATE_INVALID")

    def test_effect_receipt_checks_external_bindings_signature_and_semantics(self):
        _, action, request = self.f.operation()
        receipt = self.gate.execute(request)["receipt"]
        for field, wrong in (("expected_target", "other-target"),
                             ("expected_gate_instance_id", "88" * 16),
                             ("expected_operation_id", "89" * 16),
                             ("expected_grant_id", "90" * 16),
                             ("expected_grant_sha256", "91" * 32),
                             ("expected_assessment_sha256", "92" * 32)):
            self.denied(lambda: self.verify(receipt, action, request, **{field: wrong}), "RECEIPT_SCOPE_MISMATCH")
        wrong_key = sign_record(Ed25519PrivateKey.generate(), receipt["payload"])
        self.denied(lambda: self.verify(wrong_key, action, request), "INVALID_SIGNATURE")
        for field, value in (("counter_after", 2), ("authorization", "CURRENT_AUTHORITY"),
                             ("action", {"name": "increment_counter", "delta": True}),
                             ("committed_at_ms", action["payload"]["expires_at_ms"])):
            forged = sign_record(self.gate._key, dict(receipt["payload"], **{field: value}))
            self.denied(lambda: self.verify(forged, action, request))


if __name__ == "__main__":
    unittest.main()
