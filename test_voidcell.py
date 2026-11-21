"""Exercise VOIDCELL only with the local synthetic Stage 5 worker and counter."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Barrier, Event
import time
import unittest

from alibi import DurableWitness, Signer
from wolfalibi.agent_solitary import agent_solitary_contract, run_agent_solitary
from wolfalibi.solitary import solitary_contract
from wolfalibi.solitary_evidence import verify_solitary
from wolfalibi.stage3_worker import UnsupportedWorker
from wolfalibi.voidcell import EffectVault
from wolfalibi.voidcell_gateway import EffectGateway, EffectGatewayError
from wolfalibi.voidcell_records import dispatch_digest, grant, revoke, sign_dispatch, verify_receipt


class VoidcellTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(prefix="wolfalibi-voidcell-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.vault_path = self.root / "target.sqlite"
        self.gateway_path = self.root / "gateway.sqlite"
        self.broker, self.witness_signer, self.supervisor = Signer(), Signer(), Signer()
        self.owner, self.gateway_signer, self.target_signer = Signer(), Signer(), Signer()
        self.now = int(time.time())
        self.clock_time = self.now
        try:
            self.contract = agent_solitary_contract(
                "synthetic-voidcell", bytes(range(32)), self.now + 120,
            )
        except UnsupportedWorker as exc:
            self.skipTest(f"UNSUPPORTED static Stage 5 prerequisite: {exc}")
        with DurableWitness(self.root / "witness.json", self.witness_signer) as witness:
            self.initial_head = witness.state_digest
            result = run_agent_solitary(
                self.root, contract=self.contract, signer=self.broker, witness=witness,
                supervisor=self.supervisor, expected_witness_state_digest=self.initial_head,
            )
            self.terminal_head = witness.state_digest
        self.assertEqual(result["outcome"], "COMPLETED", result)
        self.envelope = result["envelope"]
        self.observation = result["observation"]
        self.observed_head = self.terminal_head
        self.events = []

    def _vault(self, *, contract=None):
        return EffectVault(
            self.vault_path, signer=self.target_signer, owner_pub=self.owner.pub,
            gateway_pub=self.gateway_signer.pub, broker_pub=self.broker.pub,
            witness_pub=self.witness_signer.pub, supervisor_pub=self.supervisor.pub,
            contract=self.contract if contract is None else contract, operation_id="synthetic-effect-1",
            expected_witness_state_digest=self.initial_head,
            observe_witness_head=lambda: self.observed_head, clock=lambda: self.clock_time,
        )

    def _owner_grant(self, scope, *, owner=None, ttl=45, grant_id="synthetic-grant"):
        return grant(
            self.owner if owner is None else owner, scope=scope, grant_id=grant_id,
            not_before=self.now, expires_at=self.now + ttl,
        )

    def _valid_packet(self, target, **overrides):
        arguments = {
            "scope": target.scope,
            "qualification": self.envelope,
            "owner_grant": self._owner_grant(target.scope),
        }
        arguments.update(overrides)
        return sign_dispatch(self.gateway_signer, **arguments)

    def _denied(self, result, target, *, packet=None, reason=None):
        self.assertIn(result["outcome"], ("DENIED", "BLOCKED"), result)
        self.assertEqual(target.effect_count(), 0)
        if packet is not None:
            self.assertEqual(result["outcome"], "DENIED", result)
            checked = verify_receipt(
                result["receipt"], target_pub=self.target_signer.pub, scope=target.scope,
                dispatch_sha256=dispatch_digest(packet),
            )
            self.assertEqual(checked["reason"], reason)

    def _accepted(self, result, target, packet):
        self.assertEqual(result["outcome"], "ACCEPTED_EVIDENCED", result)
        verified = verify_receipt(
            result["receipt"], target_pub=self.target_signer.pub, scope=target.scope,
            dispatch_sha256=dispatch_digest(packet),
        )
        self.assertEqual(verified["outcome"], "ACCEPTED_EVIDENCED")
        self.assertEqual(target.effect_count(), 1)
        return result["receipt"]

    def test_owner_authorization_and_current_qualification_are_independent(self):
        with self._vault() as target:
            for substitution, reason in (
                    ({"owner_grant": None}, "OWNER_GRANT_UNVERIFIED"),
                    ({"qualification": None}, "QUALIFICATION_UNVERIFIED"),
                    ({"qualification": self.observation}, "QUALIFICATION_UNVERIFIED")):
                with self.subTest(substitution=list(substitution)):
                    packet = self._valid_packet(target, **substitution)
                    self._denied(target.dispatch(packet), target, packet=packet, reason=reason)
            packet = self._valid_packet(target)
            self._accepted(target.dispatch(packet), target, packet)

    def test_legacy_solitary_profile_is_ineligible_at_provisioning(self):
        legacy = solitary_contract("legacy-effect", bytes(32), self.now + 120)
        with self.assertRaisesRegex(ValueError, "Stage 5 callback profile"):
            self._vault(contract=legacy)
        self.assertFalse(self.vault_path.exists())

    def test_direct_unsigned_wrong_owner_and_wrong_gateway_are_refused(self):
        with self._vault() as target:
            packet = self._valid_packet(target)
            unsigned = deepcopy(packet)
            del unsigned["route"]["signature"]
            self._denied(target.dispatch(unsigned), target)
            foreign_grant = self._owner_grant(target.scope, owner=Signer())
            foreign_packet = self._valid_packet(target, owner_grant=foreign_grant)
            self._denied(target.dispatch(foreign_packet), target, packet=foreign_packet,
                         reason="OWNER_GRANT_UNVERIFIED")
            rogue = Signer()
            alternate = dict(target.scope, gateway_pub=rogue.pub.hex())
            wrong_gateway = sign_dispatch(
                rogue, scope=alternate, qualification=self.envelope,
                owner_grant=self._owner_grant(alternate),
            )
            self._denied(target.dispatch(wrong_gateway), target, packet=wrong_gateway,
                         reason="GATEWAY_OR_SCOPE_UNVERIFIED")

    def test_forged_qualification_is_refused_despite_owner_approval(self):
        damaged = deepcopy(self.envelope)
        del damaged["supervisor_record"]["payload"]["closure"]
        with self._vault() as target:
            packet = self._valid_packet(target, qualification=damaged)
            self._denied(target.dispatch(packet), target, packet=packet,
                         reason="QUALIFICATION_UNVERIFIED")

    def test_other_operation_scope_is_refused_despite_both_valid_signatures(self):
        with self._vault() as target:
            alternate = dict(target.scope, operation_id="synthetic-other-effect")
            packet = self._valid_packet(
                target, scope=alternate, owner_grant=self._owner_grant(alternate),
            )
            self._denied(target.dispatch(packet), target, packet=packet,
                         reason="GATEWAY_OR_SCOPE_UNVERIFIED")

    def test_expired_owner_grant_has_no_effect(self):
        with self._vault() as target:
            packet = self._valid_packet(target, owner_grant=self._owner_grant(target.scope, ttl=5))
            self.clock_time = self.now + 5
            self._denied(target.dispatch(packet), target, packet=packet, reason="OWNER_GRANT_UNVERIFIED")

    def test_expired_qualification_has_no_effect_with_a_current_owner_grant(self):
        with self._vault() as target:
            packet = self._valid_packet(target, owner_grant=self._owner_grant(target.scope, ttl=200))
            self.clock_time = self.contract["expires_at"]
            self._denied(target.dispatch(packet), target, packet=packet,
                         reason="QUALIFICATION_EXPIRED")

    def test_owner_revocation_survives_target_reopen(self):
        with self._vault() as target:
            packet = self._valid_packet(target)
            record = revoke(self.owner, scope=target.scope, grant_id="synthetic-grant")
            self.assertEqual(target.revoke(record)["outcome"], "REVOKED")
        with self._vault() as reopened:
            self._denied(reopened.dispatch(packet), reopened, packet=packet, reason="OWNER_GRANT_REVOKED")

    def test_missing_or_stale_witness_head_is_refused(self):
        with self._vault() as target:
            denials = []
            for label, head in (("missing", None), ("stale", self.initial_head)):
                with self.subTest(available=head is not None):
                    self.observed_head = head
                    packet = self._valid_packet(
                        target, owner_grant=self._owner_grant(target.scope, grant_id=label),
                    )
                    result = target.dispatch(packet)
                    self._denied(result, target, packet=packet,
                                 reason="WITNESS_HEAD_UNAVAILABLE_OR_CONFLICTING")
                    denials.append((packet, result))
            self.observed_head = self.terminal_head
            for packet, previous in denials:
                self.assertEqual(target.dispatch(packet), previous)
                self.assertEqual(target.effect_count(), 0)
            packet = self._valid_packet(target)
            self._accepted(target.dispatch(packet), target, packet)

    def test_conflicting_authentic_witness_history_blocks_matching_qualification(self):
        alternate_contract = agent_solitary_contract(
            "synthetic-alternate-history", bytes(reversed(range(32))), self.now + 120,
        )
        alternate_state = self.root / "alternate"
        alternate_state.mkdir(mode=0o700)
        with DurableWitness(alternate_state / "witness.json", self.witness_signer) as witness:
            self.assertEqual(witness.state_digest, self.initial_head)
            alternate = run_agent_solitary(
                alternate_state, contract=alternate_contract, signer=self.broker, witness=witness,
                supervisor=self.supervisor, expected_witness_state_digest=self.initial_head,
            )
            alternate_head = witness.state_digest
        self.assertEqual(alternate["outcome"], "COMPLETED", alternate)
        self.assertNotEqual(alternate_head, self.terminal_head)
        verified = verify_solitary(
            alternate["envelope"], contract=alternate_contract, broker_pub=self.broker.pub,
            witness_pub=self.witness_signer.pub, supervisor_pub=self.supervisor.pub,
            expected_witness_state_digest=self.initial_head, now=self.now,
        )
        self.assertEqual(verified["outcome"], "VERIFIED", verified)
        self.assertEqual(verified["witness_state_digest"], alternate_head.hex())

        with self._vault() as target:
            foreign = self._valid_packet(target, qualification=alternate["envelope"])
            self._denied(target.dispatch(foreign), target, packet=foreign,
                         reason="QUALIFICATION_UNVERIFIED")
            original = self._valid_packet(target)
            self.observed_head = alternate_head
            self._denied(target.dispatch(original), target, packet=original,
                         reason="WITNESS_HEAD_UNAVAILABLE_OR_CONFLICTING")

    def test_concurrent_duplicate_dispatch_counts_exactly_one_effect(self):
        with self._vault() as target, self._vault() as second, ThreadPoolExecutor(max_workers=2) as workers:
            packet = self._valid_packet(target)
            ready = Barrier(2, timeout=5)

            def contender(vault):
                ready.wait()
                return vault.dispatch(packet)

            results = list(workers.map(contender, (target, second)))
            accepted = [entry for entry in results if entry["outcome"] == "ACCEPTED_EVIDENCED"]
            denied = [entry for entry in results if entry["outcome"] == "DENIED"]
            self.assertEqual(len(accepted), 1, results)
            self.assertEqual(len(denied), 1, results)
            self._accepted(accepted[0], target, packet)
            replay = verify_receipt(
                denied[0]["receipt"], target_pub=self.target_signer.pub, scope=target.scope,
                dispatch_sha256=dispatch_digest(packet),
            )
            self.assertEqual(replay["reason"], "OPERATION_ALREADY_FINAL")
            self.assertEqual(target.effect_count(), 1)

    def _gateway(self, target, transport):
        return EffectGateway(
            self.gateway_path, signer=self.gateway_signer, scope=target.scope,
            target_pub=self.target_signer.pub, transport=transport,
        )

    def test_reconciliation_cannot_fence_a_gateway_dispatch_in_progress(self):
        entered, release = Event(), Event()
        actions = []
        with self._vault() as target:
            def delayed(action, packet):
                actions.append(action)
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("synthetic delayed dispatch")
                return target.dispatch(packet)

            approval = self._owner_grant(target.scope)
            with self._gateway(target, delayed) as gateway, ThreadPoolExecutor(max_workers=1) as worker:
                pending = worker.submit(gateway.dispatch, qualification=self.envelope, owner_grant=approval)
                try:
                    self.assertTrue(entered.wait(5))
                    self.assertEqual(gateway.reconcile()["outcome"], "BLOCKED")
                    with self.assertRaises(EffectGatewayError):
                        self._gateway(target, delayed)
                    self.assertEqual(target.effect_count(), 0)
                finally:
                    release.set()
                self.assertEqual(pending.result(timeout=5)["outcome"], "ACCEPTED_EVIDENCED")
            self.assertEqual(actions, ["dispatch"])
            self.assertEqual(target.effect_count(), 1)

    def test_lost_ack_after_commit_reconciles_after_restart_without_dispatching_twice(self):
        actions = []
        delivered = []
        with self._vault() as target:
            def lost_ack(action, packet):
                actions.append(action)
                if action == "dispatch":
                    delivered.append((packet, target.dispatch(packet)))
                    raise TimeoutError("synthetic response loss after commit")
                self.assertEqual(action, "reconcile")
                return target.reconcile(packet)

            approval = self._owner_grant(target.scope)
            with self._gateway(target, lost_ack) as gateway:
                uncertain = gateway.dispatch(qualification=self.envelope, owner_grant=approval)
                self.assertEqual(uncertain["outcome"], "AMBIGUOUS", uncertain)
                self.assertNotIn("receipt", uncertain)
                self.assertEqual(actions, ["dispatch"])
                packet, applied = delivered[0]
                original = self._accepted(applied, target, packet)
                self.assertEqual(uncertain["dispatch_sha256"], dispatch_digest(packet))
                retry = gateway.dispatch(qualification=self.envelope, owner_grant=approval)
                self.assertEqual(retry["outcome"], "AMBIGUOUS", retry)
                self.assertEqual(actions, ["dispatch"])
            with self._gateway(target, lost_ack) as reopened:
                reconciled = reopened.reconcile()
                self.assertEqual(reconciled["outcome"], "ACCEPTED_EVIDENCED", reconciled)
                self.assertEqual(reconciled["receipt"], original)
                self.assertEqual(reopened.reconcile(), reconciled)
                substituted = reopened.dispatch(qualification=self.observation, owner_grant=approval)
                self.assertEqual(substituted["outcome"], "BLOCKED")
                self.assertNotIn("receipt", substituted)
            self.assertEqual(actions, ["dispatch", "reconcile"])
            self.assertEqual(target.effect_count(), 1)

    def test_lost_request_reconciles_absence_and_durably_fences_late_arrival(self):
        actions = []
        undelivered = []
        with self._vault() as target:
            def lost_request(action, packet):
                actions.append(action)
                if action == "dispatch":
                    undelivered.append(packet)
                    raise TimeoutError("synthetic request loss before target delivery")
                self.assertEqual(action, "reconcile")
                return target.reconcile(packet)

            with self._gateway(target, lost_request) as gateway:
                uncertain = gateway.dispatch(
                    qualification=self.envelope, owner_grant=self._owner_grant(target.scope),
                )
                self.assertEqual(uncertain["outcome"], "AMBIGUOUS", uncertain)
                self.assertEqual(target.effect_count(), 0)
                fenced = gateway.reconcile()
                self.assertEqual(fenced["outcome"], "FENCED", fenced)
                checked = verify_receipt(
                    fenced["receipt"], target_pub=self.target_signer.pub, scope=target.scope,
                    dispatch_sha256=dispatch_digest(undelivered[0]),
                )
                self.assertEqual(checked["reason"], "NO_EFFECT_AND_LATE_DISPATCH_FENCED")
                self.assertEqual(target.effect_count(), 0)
        with self._vault() as reopened:
            packet, = undelivered
            late = reopened.dispatch(packet)
            self.assertEqual(late["outcome"], "FENCED", late)
            self.assertEqual(late["receipt"], fenced["receipt"])
            self.assertEqual(reopened.effect_count(), 0)
        self.assertEqual(actions, ["dispatch", "reconcile"])

    def test_intent_write_failure_prevents_transport(self):
        with self._vault() as target:
            def transport(action, packet):
                self.events.append((action, packet))
                return target.dispatch(packet)

            with self._gateway(target, transport) as gateway:
                with sqlite3.connect(self.gateway_path) as fixture_db:
                    fixture_db.execute("""
                        CREATE TRIGGER reject_intent BEFORE INSERT ON intent
                        BEGIN SELECT RAISE(ABORT, 'synthetic intent write failure'); END
                    """)
                refused = gateway.dispatch(
                    qualification=self.envelope, owner_grant=self._owner_grant(target.scope),
                )
                self.assertEqual(refused["outcome"], "BLOCKED", refused)
                self.assertNotIn("receipt", refused)
                self.assertEqual(self.events, [])
                self.assertEqual(target.effect_count(), 0)

    def test_target_precommit_failure_cannot_leave_an_acceptance_or_effect(self):
        with self._vault() as target:
            packet = self._valid_packet(target)
            with sqlite3.connect(self.vault_path) as fixture_db:
                fixture_db.execute("""
                    CREATE TRIGGER reject_effect BEFORE INSERT ON effects
                    BEGIN SELECT RAISE(ABORT, 'synthetic target write failure'); END
                """)
                refused = target.dispatch(packet)
                self.assertEqual(refused["outcome"], "BLOCKED", refused)
                self.assertNotIn("receipt", refused)
                self.assertEqual(target.effect_count(), 0)
                decisions, = fixture_db.execute("SELECT COUNT(*) FROM decisions").fetchone()
                self.assertEqual(decisions, 0)


if __name__ == "__main__":
    unittest.main()
