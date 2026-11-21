"""Alibi Clearance exercises only local synthetic fixtures and effects."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Lock
import time
import unittest

from alibi import DurableWitness, Signer
from wolfalibi.clearance import ClearanceGateway
from wolfalibi.clearance_records import grant, identity_pins, revoke, sign_request, verify_decision
from wolfalibi.solitary import run_solitary, solitary_contract
from wolfalibi.stage3_worker import UnsupportedWorker


class ClearanceTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(prefix="wolfalibi-clearance-")
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.gateway_state = self.state / "gateway"
        self.gateway_state.mkdir(mode=0o700)
        self.now = int(time.time())
        self.clock_time = self.now
        try:
            profile = solitary_contract("synthetic-preflight", bytes(32), self.now + 120)["profile"]
        except UnsupportedWorker as exc:
            self.skipTest(f"UNSUPPORTED static Solitary prerequisite: {exc}")
        self.identity = identity_pins(profile)
        self.broker = Signer()
        self.supervisor = Signer()
        self.witness = DurableWitness(self.state / "witness.json", Signer())
        self.addCleanup(self.witness.close)
        self.initial = self.witness.state_digest
        self.witness_available = True
        self.owner_signer = Signer()
        self.gateway_signer = Signer()
        self.agent_signer = Signer()
        self.credential = b"synthetic-upstream-credential-only-the-gateway-holds"
        self.fixture = b"synthetic upstream result"
        self.effects = []
        self.effect_lock = Lock()

    def _upstream(self, credential):
        self.assertEqual(credential, self.credential)
        with self.effect_lock:
            self.effects.append("synthetic protected read")
        return self.fixture

    def _gateway(self, *, expected=None, upstream=None):
        return ClearanceGateway(
            self.gateway_state, signer=self.gateway_signer, owner_pub=self.owner_signer.pub,
            broker_pub=self.broker.pub, witness_pub=self.witness.signer.pub,
            supervisor_pub=self.supervisor.pub, observe_identity=lambda _: deepcopy(self.identity),
            expected_witness_state_digest=self.initial if expected is None else expected,
            observe_witness_head=lambda: self.witness.state_digest if self.witness_available else None,
            upstream=self._upstream if upstream is None else upstream,
            upstream_credential=self.credential, clock=lambda: self.clock_time,
        )

    def _prepare(self, gateway, *, grant_ttl=90):
        issued = gateway.prepare("synthetic-clearance-run", agent_pub=self.agent_signer.pub)
        self._signed(issued, "ISSUED")
        contract = issued["contract"]
        result = run_solitary(
            self.state, contract=contract, signer=self.broker, witness=self.witness,
            supervisor=self.supervisor, expected_witness_state_digest=self.initial,
        )
        # Dynamic launch failures are test failures after static preflight.
        self.assertEqual(result["outcome"], "COMPLETED", result)
        owner_grant = grant(
            self.owner_signer, scope=issued["scope"], not_before=self.now,
            expires_at=self.now + grant_ttl, grant_id="synthetic-owner-grant",
        )
        return contract["challenge"], result["envelope"], owner_grant

    def _signed(self, result, *outcomes):
        self.assertIn(result["outcome"], outcomes, result)
        checked = verify_decision(result["decision"], self.gateway_signer.pub)
        self.assertEqual(checked["outcome"], result["outcome"])
        encoded = json.dumps(result["decision"])
        self.assertNotIn(self.credential.decode(), encoded)
        self.assertNotIn(self.credential.hex(), encoded)
        return checked

    def _admit(self, gateway, inputs):
        challenge, envelope, owner_grant = inputs
        admitted = gateway.admit(challenge=challenge, envelope=envelope, grant=owner_grant)
        self._signed(admitted, "ADMITTED")
        return admitted["capability"]

    def _perform(self, gateway, capability, *, signer=None, request_id="synthetic-read"):
        return gateway.perform(
            capability=capability,
            request=sign_request(
                self.agent_signer if signer is None else signer,
                capability=capability, request_id=request_id,
            ),
        )

    def test_valid_qualification_without_owner_grant_has_no_capability(self):
        with self._gateway() as gateway:
            challenge, envelope, owner_grant = self._prepare(gateway)
            denied = gateway.admit(challenge=challenge, envelope=envelope, grant=None)
            self._signed(denied, "DENIED", "BLOCKED")
            self.assertFalse(denied.get("capability"))
            wrong_owner = grant(
                Signer(), scope=owner_grant["payload"]["scope"], not_before=self.now,
                expires_at=self.now + 90, grant_id="synthetic-untrusted-grant",
            )
            denied = gateway.admit(challenge=challenge, envelope=envelope, grant=wrong_owner)
            self._signed(denied, "DENIED", "BLOCKED")
            self.assertFalse(denied.get("capability"))
            self.assertEqual(self.effects, [])
            self._admit(gateway, (challenge, envelope, owner_grant))
            self.assertEqual(self.effects, [])

    def test_valid_owner_grant_without_valid_qualification_has_no_capability(self):
        with self._gateway() as gateway:
            challenge, envelope, owner_grant = self._prepare(gateway)
            incomplete = deepcopy(envelope)
            del incomplete["supervisor_record"]["payload"]["closure"]
            for supplied in (None, incomplete):
                denied = gateway.admit(challenge=challenge, envelope=supplied, grant=owner_grant)
                self._signed(denied, "DENIED", "BLOCKED")
                self.assertFalse(denied.get("capability"))
                self.assertEqual(self.effects, [])
            self._admit(gateway, (challenge, envelope, owner_grant))

    def test_missing_witness_head_blocks_fresh_admission_and_later_effect(self):
        with self._gateway() as gateway:
            inputs = self._prepare(gateway)
            challenge, envelope, owner_grant = inputs
            self.witness_available = False
            denied = gateway.admit(challenge=challenge, envelope=envelope, grant=owner_grant)
            self._signed(denied, "DENIED", "BLOCKED")
            self.assertFalse(denied.get("capability"))
            self.assertEqual(self.effects, [])
            self.witness_available = True
            capability = self._admit(gateway, inputs)
            self.witness_available = False
            self._signed(self._perform(gateway, capability), "DENIED", "BLOCKED")
            self.assertEqual(self.effects, [])

    def test_matching_grant_and_evidence_admit_one_signed_local_effect(self):
        with self._gateway() as gateway:
            inputs = self._prepare(gateway)
            capability = self._admit(gateway, inputs)
            self.assertEqual(self.effects, [])
            applied = self._perform(gateway, capability)
            checked = self._signed(applied, "ALLOWED")
            self.assertEqual(checked["qualification"], "SYNTHETIC_CURRENT")
            self.assertEqual(checked["owner_authorization"], "CURRENT")
            self.assertEqual(checked["effect"], "OBSERVED")
            self.assertEqual(checked["broker_assurance"], "BROKER_ONLY")
            self.assertEqual(checked["production"], "BLOCKED")
            self.assertEqual(applied["data"], self.fixture)
            encoded_decision = json.dumps(applied["decision"])
            self.assertNotIn(capability, encoded_decision)
            self.assertNotIn(self.fixture.decode(), encoded_decision)
            with self.assertRaises(ValueError):
                verify_decision(applied["decision"], Signer().pub)
            self.assertEqual(self.effects, ["synthetic protected read"])
            self._signed(self._perform(gateway, capability), "DENIED", "BLOCKED")
            self._signed(self._perform(gateway, capability, request_id="another-read"),
                         "DENIED", "BLOCKED")
            self.assertEqual(self.effects, ["synthetic protected read"])

    def test_owner_scope_and_gateway_target_are_exact(self):
        with self._gateway() as gateway:
            challenge, envelope, owner_grant = self._prepare(gateway)
            scope = owner_grant["payload"]["scope"]
            for field, wrong in (
                    ("agent_pub", Signer().pub.hex()), ("gateway_pub", Signer().pub.hex()),
                    ("worker_sha256", "ff" * 32), ("policy_sha256", "ee" * 32)):
                with self.subTest(field=field):
                    mismatched = grant(
                        self.owner_signer, scope=dict(scope, **{field: wrong}), not_before=self.now,
                        expires_at=self.now + 90, grant_id=f"mismatch-{field}",
                    )
                    denied = gateway.admit(challenge=challenge, envelope=envelope, grant=mismatched)
                    self._signed(denied, "DENIED", "BLOCKED")
                    self.assertFalse(denied.get("capability"))
            for field, wrong in (("audience", "alternate"), ("resource", "other"), ("operation", "write")):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    grant(
                        self.owner_signer, scope=dict(scope, **{field: wrong}), not_before=self.now,
                        expires_at=self.now + 90, grant_id=f"mismatch-{field}",
                    )
            self.assertEqual(self.effects, [])
            self._admit(gateway, (challenge, envelope, owner_grant))

    def test_request_signed_by_another_agent_is_refused(self):
        with self._gateway() as gateway:
            capability = self._admit(gateway, self._prepare(gateway))
            self._signed(self._perform(gateway, capability, signer=Signer()), "DENIED", "BLOCKED")
            self.assertEqual(self.effects, [])

    def test_later_worker_identity_drift_is_refused(self):
        with self._gateway() as gateway:
            capability = self._admit(gateway, self._prepare(gateway))
            original = self.identity
            self.identity = {**original, "python_sha256": "ff" * 32}
            blocked = self._signed(self._perform(gateway, capability), "BLOCKED")
            self.assertEqual(blocked["reason"], "IDENTITY_CHANGED")
            self.identity = original
            fenced = self._signed(self._perform(gateway, capability), "DENIED")
            self.assertEqual(fenced["reason"], "CAPABILITY_FENCED")
            self.assertEqual(self.effects, [])

    def test_owner_expiry_is_checked_after_admission(self):
        with self._gateway() as gateway:
            capability = self._admit(gateway, self._prepare(gateway, grant_ttl=4))
            self.clock_time = self.now + 4
            self._signed(self._perform(gateway, capability), "DENIED", "BLOCKED")
            self.assertEqual(self.effects, [])

    def test_capability_expires_before_a_longer_owner_grant(self):
        with self._gateway() as gateway:
            capability = self._admit(gateway, self._prepare(gateway, grant_ttl=90))
            self.clock_time = self.now + 31
            self._signed(self._perform(gateway, capability), "DENIED", "BLOCKED")
            self.assertEqual(self.effects, [])

    def test_expired_qualification_is_not_admitted(self):
        with self._gateway() as gateway:
            challenge, envelope, owner_grant = self._prepare(gateway, grant_ttl=250)
            self.clock_time = envelope["evidence"]["payload"]["contract"]["expires_at"]
            denied = gateway.admit(challenge=challenge, envelope=envelope, grant=owner_grant)
            self._signed(denied, "DENIED", "BLOCKED")
            self.assertFalse(denied.get("capability"))
            self.assertEqual(self.effects, [])

    def test_owner_revocation_fences_an_already_admitted_capability(self):
        with self._gateway() as gateway:
            capability = self._admit(gateway, self._prepare(gateway))
            revoked = gateway.revoke(revoke(
                self.owner_signer, grant_id="synthetic-owner-grant", gateway_pub=self.gateway_signer.pub,
            ))
            self._signed(revoked, "REVOKED")
            self._signed(self._perform(gateway, capability), "DENIED", "BLOCKED")
        with self._gateway(expected=self.witness.state_digest) as reopened:
            self._signed(self._perform(reopened, capability), "DENIED", "BLOCKED")
        self.assertEqual(self.effects, [])

    def test_concurrent_admission_and_effect_attempts_do_not_double_dispatch(self):
        with self._gateway() as gateway, ThreadPoolExecutor(max_workers=2) as executor:
            challenge, envelope, owner_grant = self._prepare(gateway)
            ready = Barrier(2, timeout=5)

            def admit(_):
                ready.wait()
                return gateway.admit(challenge=challenge, envelope=envelope, grant=owner_grant)

            results = list(executor.map(admit, range(2)))
            capabilities = [result["capability"] for result in results if result["outcome"] == "ADMITTED"]
            self.assertEqual(len(capabilities), 1, results)
            for result in results:
                self._signed(result, "ADMITTED", "DENIED", "BLOCKED")
            self.assertEqual(self.effects, [])
            ready.reset()

            def perform(index):
                ready.wait()
                return self._perform(gateway, capabilities[0], request_id=f"concurrent-{index}")

            results = list(executor.map(perform, range(2)))
            self.assertEqual(sum(result["outcome"] == "ALLOWED" for result in results), 1, results)
            for result in results:
                self._signed(result, "ALLOWED", "DENIED", "BLOCKED", "INCOMPLETE")
            self.assertEqual(self.effects, ["synthetic protected read"])

    def test_ambiguous_effect_survives_reopen_without_retry_or_false_success(self):
        def ambiguous(credential):
            self._upstream(credential)
            raise TimeoutError("synthetic private upstream timeout detail")

        with self._gateway(upstream=ambiguous) as gateway:
            capability = self._admit(gateway, self._prepare(gateway))
            result = self._perform(gateway, capability)
            self._signed(result, "INCOMPLETE")
            self.assertNotIn("data", result)
            self.assertNotIn("synthetic private upstream timeout detail", json.dumps(result))
            self.assertEqual(self.effects, ["synthetic protected read"])
            terminal = self.witness.state_digest
        with self._gateway(expected=terminal) as reopened:
            for request_id in ("synthetic-read", "another-read"):
                result = self._perform(reopened, capability, request_id=request_id)
                self._signed(result, "DENIED", "BLOCKED", "INCOMPLETE")
                self.assertNotIn("data", result)
        self.assertEqual(self.effects, ["synthetic protected read"])

    def test_failed_durable_intent_never_calls_upstream(self):
        with self._gateway() as gateway:
            capability = self._admit(gateway, self._prepare(gateway))
            gateway._db.execute("""
                CREATE TRIGGER refuse_intent BEFORE UPDATE OF state ON capabilities
                WHEN NEW.state = 'PENDING'
                BEGIN SELECT RAISE(ABORT, 'synthetic commit refusal'); END
            """)
            denied = self._perform(gateway, capability)
            self._signed(denied, "BLOCKED")
            self.assertNotIn("data", denied)
            self.assertEqual(self.effects, [])

    def test_expiry_during_upstream_read_withholds_reply_and_fences_retry(self):
        def expires(credential):
            data = self._upstream(credential)
            self.clock_time = self.now + 4
            return data

        with self._gateway(upstream=expires) as gateway:
            capability = self._admit(gateway, self._prepare(gateway, grant_ttl=4))
            result = self._perform(gateway, capability)
            evidence = self._signed(result, "INCOMPLETE")
            self.assertEqual(evidence["reason"], "RELEASE_PREDICATE_LOST")
            self.assertNotIn("data", result)
            self._signed(self._perform(gateway, capability), "INCOMPLETE")
            self.assertEqual(self.effects, ["synthetic protected read"])

    def test_interrupt_before_terminal_record_leaves_no_automatic_retry(self):
        def interrupted(credential):
            self._upstream(credential)
            raise KeyboardInterrupt()

        with self._gateway(upstream=interrupted) as gateway:
            capability = self._admit(gateway, self._prepare(gateway))
            with self.assertRaises(KeyboardInterrupt):
                self._perform(gateway, capability, request_id="interrupted-read")
            terminal = self.witness.state_digest
        with self._gateway(expected=terminal) as reopened:
            replay = self._perform(reopened, capability, request_id="retry-after-interruption")
            checked = self._signed(replay, "INCOMPLETE")
            self.assertEqual(checked["reason"], "NO_AUTOMATIC_RETRY")
            self.assertEqual(checked["effect"], "UNKNOWN")
            self.assertEqual(checked["prior_request_id"], "interrupted-read")
            self.assertNotIn("data", replay)
        self.assertEqual(self.effects, ["synthetic protected read"])


if __name__ == "__main__":
    unittest.main()
