"""Owner boundary tests with fabricated signed laboratory-shaped records.

No TPM or genuine Shirudo verifier runs here. Tests of signing and consent
plumbing do not establish human approval or genuine attestation qualification.
"""

from __future__ import annotations

import copy
import os
import secrets
import sqlite3
import stat
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shirudo_adapter.action_gate import ACTION, Gate
from shirudo_adapter.bootstrap import ENTRYPOINT, MOUNT_POINT, verify_boot_policy
from shirudo_adapter.model import AdapterError, canonical_json, digest
from shirudo_adapter.owner import Owner, validate_bundle
from shirudo_adapter.receipt import sign_record, verify_record

try:
    from .test_action_gate import GateFixture
except ImportError:
    from test_action_gate import GateFixture


class OwnerFixture:
    """Fabricated authority fixture; also used by scripted PTY unit tests."""

    def __init__(self, root, *, pin=True, ttl=30):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.f = GateFixture(self.root / "synthetic-authorities", ttl=ttl, quote_pcrs={"15": "51" * 32})
        self.f.policy["expected"]["config_pcr"] = 14
        self.state = self.root / "owner-state"
        self.owner = Owner.initialize(self.state)
        self.trust = copy.deepcopy(self.f.trust)
        self.trust["policy"] = copy.deepcopy(self.f.policy)
        self.trust["owner_public_key"] = self.owner.public_identity()["public_key"]
        self.gate = Gate.initialize(self.root / "owner-bound-gate", self.trust)
        self.identity = self.gate.public_identity()
        self.now = time.time_ns() // 1_000_000
        self.owner._clock = lambda: self.now
        self.gate._clock = lambda: self.now
        self.profile = {"schema": "wolfalibi.shirudo.owner-profile.v1",
            "target_id": self.f.policy["target_id"], "gate_instance_id": self.identity["gate_instance_id"],
            "gate_public_key": self.identity["public_key"], "policy_generation": 1,
            "owner_public_key": self.trust["owner_public_key"],
            "verifier_instance_id": self.trust["verifier_instance_id"],
            "verifier_public_key": self.trust["verifier_public_key"], "policy": copy.deepcopy(self.f.policy)}
        if pin:
            self.owner.pin_profile(self.profile)

    @property
    def now(self):
        return self.f.now

    @now.setter
    def now(self, value):
        self.f.now = value

    def intent(self):
        return {"schema": "wolfalibi.shirudo.owner-intent.v1", "request_id": secrets.token_hex(16),
            "target_id": self.profile["target_id"], "gate_instance_id": self.profile["gate_instance_id"],
            "policy_sha256": digest(self.profile["policy"]), "policy_generation": 1, "action": dict(ACTION)}

    def material(self, intent=None, ready=None):
        intent = self.intent() if intent is None else intent
        ready = self.owner.begin_attempt(intent) if ready is None else ready
        challenge = self.f.challenge()
        action = self.gate.prepare(challenge)
        bundle = {"schema": "wolfalibi.shirudo.owner-bundle.v1", "request_id": intent["request_id"],
                  "attestation_challenge": challenge, "action_challenge": action,
                  "assessment": self.f.assessment(challenge)}
        return intent, ready, bundle

    def reviewed(self, intent=None, ready=None, bundle=None):
        if bundle is None:
            intent, ready, bundle = self.material(intent, ready)
        return self.owner.review_bundle(intent, bundle, ready_at_ms=ready["ready_at_ms"])

    def approve(self, reviewed):
        return self.owner._issue_grant(reviewed, approval_phrase=reviewed.summary()["approval_phrase"])

    def provisioning(self):
        anchors = {"schema": "wolfalibi.shirudo.bootstrap-anchors.v1",
            **{key: self.trust[key] for key in ("target_id", "owner_public_key", "verifier_public_key", "verifier_instance_id")},
            "verifier": {key: self.f.policy["verifier"][key] for key in ("source_commit", "sha256", "version_id")},
            "assurance": "LAB_VTPM", "action": dict(ACTION), "max_challenge_ttl_seconds": 30, "config_pcr": 14}
        manifest = {"schema": "wolfalibi.shirudo.gate-image.v1", "gate_image_root": "71" * 32,
            "anchors_sha256": digest(anchors), "source_manifest_sha256": "72" * 32,
            "entrypoint": ENTRYPOINT, "mount_point": MOUNT_POINT, "authority": "NO_SHIRUDO_RUNTIME_AUTHORITY"}
        return anchors, copy.deepcopy(self.trust), manifest


class OwnerCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wa-owner-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.f = OwnerFixture(self.root / "fixture")
        self.owner = self.f.owner

    def denied(self, callback, code=None):
        with self.assertRaises(AdapterError) as raised:
            callback()
        if code is not None:
            self.assertEqual(raised.exception.code, code)
        return raised.exception

    def grants(self):
        with sqlite3.connect(self.f.state / "journal.sqlite3") as conn:
            return conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0]


class OwnerAuthorityTests(OwnerCase):
    def test_valid_verified_bundle_produces_one_bound_grant_and_one_effect(self):
        intent, ready, bundle = self.f.material()
        reviewed = self.f.reviewed(intent, ready, bundle)
        result = self.f.approve(reviewed)
        self.assertEqual(result["status"], "GRANT_ISSUED")
        grant = verify_record(result["grant"], self.owner.public_identity()["public_key"])
        self.assertEqual(grant["attestation_receipt_sha256"], digest(bundle["assessment"]))
        self.assertEqual(grant["action_challenge_sha256"], digest(bundle["action_challenge"]))
        execution = {"operation_id": result["operation_id"], "grant": result["grant"], "assessment": bundle["assessment"]}
        self.assertEqual(self.f.gate.execute(execution)["result"], "COMMITTED")
        self.assertEqual(self.f.gate.execute(execution)["result"], "ALREADY_COMMITTED")
        self.assertEqual(self.grants(), 1)

    def test_exact_retries_and_restart_preserve_identical_recorded_grant(self):
        reviewed = self.f.reviewed()
        first = self.f.approve(reviewed)
        self.assertEqual(first, self.f.approve(reviewed))
        restarted = Owner(self.f.state)
        recorded = restarted.grant(first["operation_id"])
        self.assertEqual(recorded["grant"], first["grant"])
        self.assertEqual(recorded["effect"], "NOT_ESTABLISHED")
        self.f.now += 60_000
        self.assertEqual(self.owner.grant(first["operation_id"])["grant"], first["grant"])
        self.assertEqual(self.grants(), 1)

    def test_concurrent_identical_approvals_record_one_grant(self):
        reviewed = self.f.reviewed()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.f.approve(reviewed), range(4)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(self.grants(), 1)

    def test_request_id_cannot_authorize_another_operation(self):
        intent, ready, bundle = self.f.material()
        self.f.approve(self.f.reviewed(intent, ready, bundle))
        self.denied(lambda: self.owner.begin_attempt(intent), "REQUEST_SPENT")
        _, _, another = self.f.material(intent, ready)
        reviewed = self.f.reviewed(intent, ready, another)
        self.denied(lambda: self.f.approve(reviewed), "GRANT_CONFLICT")
        self.assertEqual(self.grants(), 1)

    def test_untrusted_signatures_never_reach_owner_signing(self):
        intent, ready, bundle = self.f.material()
        for key in ("attestation_challenge", "action_challenge", "assessment"):
            with self.subTest(key=key):
                wrong = copy.deepcopy(bundle)
                wrong[key] = sign_record(Ed25519PrivateKey.generate(), wrong[key]["payload"])
                self.denied(lambda: self.f.reviewed(intent, ready, wrong), "INVALID_SIGNATURE")
        self.assertEqual(self.grants(), 0)

    def test_request_target_policy_generation_and_action_cannot_be_substituted(self):
        intent, ready, bundle = self.f.material()
        changes = [("target_id", "other-target"), ("gate_instance_id", "51" * 16),
                   ("policy_sha256", "52" * 32), ("policy_generation", 2),
                   ("action", {"name": "increment_counter", "delta": 2}),
                   ("action", {"name": "increment_counter", "delta": True})]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                wrong = copy.deepcopy(intent)
                wrong[key] = value
                self.denied(lambda: self.f.reviewed(wrong, ready, bundle))
        wrong = copy.deepcopy(bundle)
        wrong["request_id"] = secrets.token_hex(16)
        self.denied(lambda: self.f.reviewed(intent, ready, wrong), "BUNDLE_MISMATCH")
        self.assertEqual(self.grants(), 0)

    def test_signed_target_challenge_must_preserve_all_expected_bindings(self):
        intent, ready, bundle = self.f.material()
        for key, value in [("gate_instance_id", "81" * 16), ("policy_generation", 2),
                           ("attestation_nonce", "82" * 32), ("attestation_challenge_sha256", "83" * 32)]:
            with self.subTest(key=key):
                wrong = copy.deepcopy(bundle)
                wrong["action_challenge"]["payload"][key] = value
                wrong["action_challenge"] = sign_record(self.f.gate._key, wrong["action_challenge"]["payload"])
                self.denied(lambda: self.f.reviewed(intent, ready, wrong), "ACTION_MISMATCH")
        self.assertEqual(self.grants(), 0)

    def test_accepted_assessment_still_needs_independent_verifier_and_enrollment_pins(self):
        intent, ready, bundle = self.f.material()
        for key, value in [("instance_id", "61" * 16), ("enrollment_record_sha256", "62" * 32),
                           ("nonce", "63" * 32)]:
            with self.subTest(key=key):
                wrong = copy.deepcopy(bundle)
                wrong["assessment"]["payload"][key] = value
                wrong["assessment"] = sign_record(self.f.f.verifier_key, wrong["assessment"]["payload"])
                self.denied(lambda: self.f.reviewed(intent, ready, wrong), "ASSESSMENT_MISMATCH")
        for expected, observed in (("expected_binary_sha256", "observed_binary_sha256"),
                                   ("expected_version_id", "observed_version_id")):
            wrong = copy.deepcopy(bundle)
            upstream = wrong["assessment"]["payload"]["upstream"]
            upstream[expected] = upstream[observed] = "64" * 32
            wrong["assessment"] = sign_record(self.f.f.verifier_key, wrong["assessment"]["payload"])
            self.denied(lambda: self.f.reviewed(intent, ready, wrong), "ASSESSMENT_MISMATCH")
        self.assertEqual(self.grants(), 0)

    def test_missing_policy_required_pcr15_is_denied_even_with_consistent_signed_report(self):
        intent, ready, bundle = self.f.material()
        upstream = bundle["assessment"]["payload"]["upstream"]
        missing = "PCR 15 matches the expected value"
        upstream["required_checks"].remove(missing)
        upstream["report"]["checks"] = [check for check in upstream["report"]["checks"] if check["text"] != missing]
        upstream["report_sha256"] = digest(upstream["report"])
        bundle["assessment"] = sign_record(self.f.f.verifier_key, bundle["assessment"]["payload"])
        self.denied(lambda: self.f.reviewed(intent, ready, bundle), "ASSESSMENT_MISMATCH")
        self.assertEqual(self.grants(), 0)

    def test_simulation_hardware_or_rejected_assessment_cannot_earn_owner_grant(self):
        intent, ready, bundle = self.f.material()
        for assurance, outcome, profile in (("SYNTHETIC", "SIMULATED_POLICY_ONLY", "SYNTHETIC"),
                                          ("HARDWARE_TPM", "EVIDENCE_ACCEPTED", "UPSTREAM_CLI"),
                                          ("LAB_VTPM", "REJECTED", "UPSTREAM_CLI")):
            with self.subTest(assurance=assurance, outcome=outcome):
                wrong = copy.deepcopy(bundle)
                wrong["assessment"]["payload"].update(assurance=assurance, outcome=outcome)
                wrong["assessment"]["payload"]["upstream"]["execution_profile"] = profile
                wrong["assessment"] = sign_record(self.f.f.verifier_key, wrong["assessment"]["payload"])
                self.denied(lambda: self.f.reviewed(intent, ready, wrong), "ASSESSMENT_NOT_ACCEPTED")
        self.assertEqual(self.grants(), 0)

    def test_confirmation_and_frozen_review_are_required(self):
        reviewed = self.f.reviewed()
        self.denied(lambda: self.owner._issue_grant(reviewed, approval_phrase="APPROVE other"), "APPROVAL_MISMATCH")
        changed = reviewed.summary()
        changed["bundle_sha256"] = "91" * 32
        forged_review = replace(reviewed, summary_bytes=canonical_json(changed))
        self.denied(lambda: self.f.approve(forged_review), "APPROVAL_MISMATCH")
        self.assertEqual(self.grants(), 0)

    def test_caller_mutation_after_review_cannot_change_the_signed_bundle(self):
        intent, ready, bundle = self.f.material()
        original = copy.deepcopy(bundle)
        reviewed = self.f.reviewed(intent, ready, bundle)
        bundle["assessment"]["payload"]["target_id"] = "mutated"
        intent["target_id"] = "mutated"
        self.f.profile["policy"]["expected"]["chain"] = "92" * 32
        result = self.f.approve(reviewed)
        self.assertEqual(result["grant"]["payload"]["attestation_receipt_sha256"], digest(original["assessment"]))


class OwnerFreshnessTests(OwnerCase):
    def test_challenge_before_ready_beyond_skew_is_denied(self):
        intent, ready, bundle = self.f.material()
        self.f.now += 2001
        ready["ready_at_ms"] = self.f.now
        self.denied(lambda: self.f.reviewed(intent, ready, bundle), "CHALLENGE_PREDATES_READY")

    def test_expiry_during_prompt_is_rechecked_before_signing(self):
        reviewed = self.f.reviewed()
        self.f.now = reviewed.summary()["expires_at_ms"]
        self.denied(lambda: self.f.approve(reviewed), "APPROVAL_EXPIRED")
        self.assertEqual(self.grants(), 0)

    def test_final_commit_rechecks_expiry_and_rolls_back_tentative_grant(self):
        reviewed = self.f.reviewed()
        times = iter([self.f.now, reviewed.summary()["expires_at_ms"]])
        self.owner._clock = lambda: next(times)
        self.denied(lambda: self.f.approve(reviewed), "APPROVAL_EXPIRED")
        self.assertEqual(self.grants(), 0)

    def test_insufficient_transport_budget_is_denied_without_widening_expiry(self):
        intent, ready, bundle = self.f.material()
        self.f.now = bundle["action_challenge"]["payload"]["expires_at_ms"] - 1999
        self.denied(lambda: self.f.reviewed(intent, ready, bundle), "APPROVAL_EXPIRED")

    def test_target_admission_and_exact_expiry_contract_are_required(self):
        intent, ready, bundle = self.f.material()
        for key, delta in (("issued_at_ms", 5001), ("expires_at_ms", -1)):
            wrong = copy.deepcopy(bundle)
            wrong["action_challenge"]["payload"][key] += delta
            wrong["action_challenge"] = sign_record(self.f.gate._key, wrong["action_challenge"]["payload"])
            self.denied(lambda: self.f.reviewed(intent, ready, wrong), "ACTION_MISMATCH")

    def test_denied_attempt_preserves_clock_high_water_after_restart(self):
        intent, ready, bundle = self.f.material()
        self.f.now += 40_000
        self.denied(lambda: self.f.reviewed(intent, ready, bundle), "APPROVAL_EXPIRED")
        restarted = Owner(self.f.state)
        restarted._clock = lambda: self.f.now - 1
        self.denied(lambda: restarted.begin_attempt(self.f.intent()), "CLOCK_ROLLBACK")


class OwnerStateTests(OwnerCase):
    def test_private_identity_can_precede_profile_and_profile_cannot_be_replaced(self):
        owner = Owner.initialize(self.root / "new-owner")
        self.assertIsNone(owner.public_identity()["profile_sha256"])
        self.denied(lambda: owner.review(self.f.intent()), "PROFILE_NOT_PINNED")
        self.assertEqual(stat.S_IMODE(owner.path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((owner.path / "signing.key").stat().st_mode), 0o600)
        self.assertEqual(self.owner.pin_profile(self.f.profile)["status"], "PROFILE_PINNED")
        changed = copy.deepcopy(self.f.profile)
        changed["gate_instance_id"] = "a1" * 16
        self.denied(lambda: self.owner.pin_profile(changed), "PROFILE_PINNED")

    def test_reinitialization_and_missing_state_do_not_generate_replacement_identity(self):
        self.denied(lambda: Owner.initialize(self.f.state), "STATE_EXISTS")
        missing = self.root / "missing"
        self.denied(lambda: Owner(missing), "STATE_UNAVAILABLE")
        self.assertFalse(missing.exists())

    def test_wrong_owner_key_shared_authority_or_target_policy_cannot_be_pinned(self):
        for key, value in (("owner_public_key", "a2" * 32),
                           ("gate_public_key", self.f.profile["verifier_public_key"]),
                           ("target_id", "other-target")):
            wrong = copy.deepcopy(self.f.profile)
            wrong[key] = value
            self.denied(lambda: self.owner.pin_profile(wrong), "PROFILE_MISMATCH")

    def test_state_replacement_inplace_key_change_and_unsafe_sidecar_fail_closed(self):
        key = self.f.state / "signing.key"
        original = key.read_bytes()
        key.write_bytes(b"x" * 32)
        self.denied(self.owner.public_identity, "STATE_INVALID")
        key.write_bytes(original)
        sidecar = self.f.state / "journal.sqlite3-wal"
        sidecar.symlink_to(self.root / "other")
        self.denied(self.owner.public_identity, "STATE_PERMISSIONS")
        sidecar.unlink()
        replacement = self.f.state / "new-state.json"
        replacement.write_bytes((self.f.state / "state.json").read_bytes())
        replacement.chmod(0o600)
        replacement.replace(self.f.state / "state.json")
        self.denied(self.owner.public_identity, "STATE_INVALID")

    def test_symlink_hardlink_shared_permissions_and_unsafe_ancestors_are_denied(self):
        key = self.f.state / "signing.key"
        key.chmod(0o640)
        self.denied(lambda: Owner(self.f.state), "STATE_PERMISSIONS")
        key.chmod(0o600)
        alias = self.root / "key-link"
        os.link(key, alias)
        self.denied(lambda: Owner(self.f.state), "STATE_PERMISSIONS")
        alias.unlink()
        state_link = self.root / "state-link"
        state_link.symlink_to(self.f.state, target_is_directory=True)
        self.denied(lambda: Owner(state_link), "STATE_PERMISSIONS")
        parent = self.root / "writable"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        self.denied(lambda: Owner.initialize(parent / "state"), "STATE_PERMISSIONS")

    def test_corrupted_recorded_grant_is_not_returned_or_ignored(self):
        result = self.f.approve(self.f.reviewed())
        with sqlite3.connect(self.f.state / "journal.sqlite3") as conn:
            conn.execute("UPDATE grants SET bundle_sha256=?", ("ff" * 32,))
        self.denied(lambda: self.owner.grant(result["operation_id"]), "STATE_INVALID")
        self.denied(lambda: Owner(self.f.state), "STATE_INVALID")

    def test_mutated_pinned_database_profile_invalidates_an_open_owner_session(self):
        replacement = copy.deepcopy(self.f.profile)
        replacement["gate_instance_id"] = "b1" * 16
        with sqlite3.connect(self.f.state / "journal.sqlite3") as conn:
            conn.execute("UPDATE metadata SET value=? WHERE key='profile_document'", (canonical_json(replacement).decode(),))
            conn.execute("UPDATE metadata SET value=? WHERE key='profile_sha256'", (digest(replacement),))
        self.denied(self.owner.public_identity, "PROFILE_CHANGED")


class OwnerProvisioningTests(OwnerCase):
    def test_boot_policy_is_narrow_domain_separated_and_idempotent(self):
        anchors, trust, manifest = self.f.provisioning()
        first = self.owner.sign_boot_policy(anchors, trust, manifest)
        self.assertEqual(first["action_authorization"], "NONE")
        self.assertEqual(verify_boot_policy(first["boot_policy"], anchors, manifest), trust)
        self.assertEqual(first, self.owner.sign_boot_policy(anchors, trust, manifest))
        self.assertEqual(first, Owner(self.f.state).sign_boot_policy(anchors, trust, manifest))
        self.assertEqual(self.grants(), 0)

    def test_boot_signing_before_target_identity_locks_later_profile(self):
        fixture = OwnerFixture(self.root / "bootstrap-first", pin=False)
        anchors, trust, manifest = fixture.provisioning()
        fixture.owner.sign_boot_policy(anchors, trust, manifest)
        changed = copy.deepcopy(fixture.profile)
        changed["policy"]["expected"]["chain"] = "b2" * 32
        self.denied(lambda: fixture.owner.pin_profile(changed), "PROVISIONING_MISMATCH")
        self.assertEqual(fixture.owner.pin_profile(fixture.profile)["status"], "PROFILE_PINNED")

    def test_changed_image_anchors_or_trust_cannot_replace_provisioning(self):
        anchors, trust, manifest = self.f.provisioning()
        self.owner.sign_boot_policy(anchors, trust, manifest)
        changed = copy.deepcopy(manifest)
        changed["gate_image_root"] = "b3" * 32
        self.denied(lambda: self.owner.sign_boot_policy(anchors, trust, changed), "PROVISIONING_PINNED")
        changed_trust = copy.deepcopy(trust)
        changed_trust["policy"]["expected"]["chain"] = "b4" * 32
        self.denied(lambda: self.owner.sign_boot_policy(anchors, changed_trust, manifest), "PROVISIONING_MISMATCH")
        changed_anchors = copy.deepcopy(anchors)
        changed_anchors["owner_public_key"] = "b5" * 32
        self.denied(lambda: self.owner.sign_boot_policy(changed_anchors, trust, manifest), "BOOTSTRAP_AUTHORITY")

    def test_boot_envelope_cannot_be_used_as_an_action_grant(self):
        anchors, trust, manifest = self.f.provisioning()
        signed = self.owner.sign_boot_policy(anchors, trust, manifest)["boot_policy"]
        _, _, bundle = self.f.material()
        self.denied(lambda: self.f.gate.execute({"operation_id": bundle["action_challenge"]["payload"]["operation_id"],
                                                "assessment": bundle["assessment"], "grant": signed}))
        self.assertEqual(self.grants(), 0)


if __name__ == "__main__":
    unittest.main()
