"""Offline QUORVANE qualification against local synthetic resource fixtures."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
from threading import Barrier
import time
import unittest
from unittest.mock import patch

from alibi import H, Signer, canon
from wolfalibi.quorvane import ResourceGate
from wolfalibi.quorvane_live import LiveCaller, LiveCallerError
from wolfalibi.quorvane_records import grant, issue_qualification, revoke, settlement, verify_receipt


@unittest.skipUnless(sys.platform == "linux" and hasattr(socket, "SCM_CREDENTIALS")
                     and hasattr(os, "pidfd_open"), "requires Linux credentials and pidfds")
class QuorvaneTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(prefix="wolfalibi-quorvane-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "resource.sqlite"
        self.now = int(time.time())
        self.clock_time = self.now
        self.genesis = H(b"synthetic previous witness head")
        self.signer, self.qualifier, self.witness = Signer(), Signer(), Signer()
        self.owner, self.payment_owner, self.settler = Signer(), Signer(), Signer()
        self.heads = {}

    def _gate(self):
        return ResourceGate(
            self.path, signer=self.signer, qualifier_pub=self.qualifier.pub,
            witness_pub=self.witness.pub, owner_pub=self.owner.pub,
            payment_owner_pub=self.payment_owner.pub, settler_pub=self.settler.pub,
            observe_witness_head=self.heads.get, clock=lambda: self.clock_time,
        )

    def _qualify(self, gate, caller, run, *, previous_head=None):
        record = issue_qualification(
            self.qualifier, self.witness, run=run, identity=caller.identity(),
            previous_head=self.genesis if previous_head is None else previous_head,
        )
        self.heads[run["run_id"]] = H(canon(record))
        result = gate.qualify(caller, record)
        self.assertEqual(result["outcome"], "QUALIFIED", result)
        return record

    @staticmethod
    def _request(run, operation, request_id, parameters):
        return {
            **{field: run[field] for field in ("run_id", "challenge", "tenant", "policy_epoch")},
            "operation": operation,
            "request_id": request_id,
            "parameters": parameters,
        }

    def _grant(self, run, request, *, signer=None, grant_id=None, ttl=45):
        return grant(
            self.owner if signer is None else signer, run=run, request=request,
            grant_id=grant_id or request["request_id"], not_before=self.now,
            expires_at=self.now + ttl,
        )

    def _allow(self, result, outcome="ALLOWED"):
        self.assertEqual(result["outcome"], outcome, result)
        receipt = verify_receipt(result["receipt"], self.signer.pub)
        self.assertEqual(receipt["outcome"], outcome)
        return receipt

    def _deny(self, result):
        self.assertIn(result["outcome"], ("DENIED", "BLOCKED"), result)
        self.assertNotIn("data", result)

    def test_verified_live_qualification_and_owner_grant_are_independent(self):
        with self._gate() as gate:
            run = gate.issue_run("education", "school-a", previous_head=self.genesis)
            with LiveCaller(run) as caller:
                request = self._request(run, "tutor", "tutor-request", {"topic": "fractions"})
                permission = self._grant(run, request)
                self._deny(gate.perform(caller, request, grant=permission))
                self._qualify(gate, caller, run)
                self._deny(gate.perform(caller, request, grant=None))
                allowed = gate.perform(caller, request, grant=permission)
                verified = self._allow(allowed)
                self.assertEqual(allowed["qualification"], "QUALIFIED")
                self.assertEqual(allowed["owner_authorization"], "OWNER_AUTHORIZED")
                self.assertEqual(allowed["target_effect"], "TARGET_EFFECT_CONFIRMED")
                self.assertEqual(allowed["delivery"], "FIXED_PEER_ACK")
                self.assertEqual(allowed["confinement"], "BLOCKED")
                self.assertEqual(verified["request_sha256"], H(canon(request)).hex())
                self.assertEqual(verified["operation"], "tutor")

    def test_kernel_observed_worker_identity_is_bound_to_the_live_peer(self):
        with self._gate() as gate:
            run = gate.issue_run("education", "school-a", previous_head=self.genesis)
            with patch.dict(os.environ, {"QUORVANE_HOST_CREDENTIAL": "synthetic-host-canary"}), \
                    LiveCaller(run) as original, LiveCaller(run) as other:
                original_identity = original.identity()
                other_identity = other.identity()
                self.assertEqual(original_identity["environment"], {"LC_ALL": "C"})
                self.assertEqual(set(original_identity["descriptors"]), {"0", "1", "2"})
                self.assertNotEqual(original_identity["pid"], os.getpid())
                self.assertNotEqual(original_identity["pid"], other_identity["pid"])
                self.assertEqual(original_identity["credentials"]["uid"], os.getuid())
                self.assertEqual(other_identity["credentials"]["uid"], os.getuid())
                self.assertEqual(original_identity["credentials"]["gid"], os.getgid())
                wrong_credentials = dict(original_identity["credentials"], uid=os.getuid() + 1)
                wrong_uid = issue_qualification(
                    self.qualifier, self.witness, run=run,
                    identity=dict(original_identity, credentials=wrong_credentials),
                    previous_head=self.genesis,
                )
                self.heads[run["run_id"]] = H(canon(wrong_uid))
                self._deny(gate.qualify(original, wrong_uid))
                record = self._qualify(gate, original, run)
                self._deny(gate.qualify(other, record))
                request = self._request(run, "tutor", "same-run-other-process",
                                        {"topic": "fractions"})
                permission = self._grant(run, request)
                self._deny(gate.perform(other, request, grant=permission))
                receipt = self._allow(gate.perform(original, request, grant=permission))
                self.assertEqual(receipt["identity_sha256"], H(canon(original_identity)).hex())
            after_exit = self._request(run, "tutor", "worked-after-exit", {"topic": "fractions"})
            self._deny(gate.perform(original, after_exit, grant=self._grant(run, after_exit)))

    def test_response_with_wrong_kernel_peer_credentials_is_blocked(self):
        with self._gate() as gate:
            run = gate.issue_run("education", "school-a", previous_head=self.genesis)
            with LiveCaller(run) as caller:
                self._qualify(gate, caller, run)
                request = self._request(run, "tutor", "kernel-credential-control", {"topic": "fractions"})
                permission = self._grant(run, request)
                with patch("wolfalibi.quorvane_live._credentials",
                           return_value=(os.getpid(), os.getuid(), os.getgid())):
                    self._deny(gate.perform(caller, request, grant=permission))
                self._allow(gate.perform(caller, request, grant=permission))

    def test_exited_caller_between_reply_and_resource_decision_is_blocked(self):
        with self._gate() as gate:
            run = gate.issue_run("education", "school-a", previous_head=self.genesis)
            with LiveCaller(run) as caller:
                self._qualify(gate, caller, run)
                request = self._request(run, "tutor", "close-before-effect", {"topic": "fractions"})
                exchange = caller.exchange

                def exit_after_reply(message):
                    reply = exchange(message)
                    caller.close()
                    return reply

                with patch.object(caller, "exchange", side_effect=exit_after_reply):
                    self._deny(gate.perform(caller, request, grant=self._grant(run, request)))

    def test_witness_unavailable_or_a_conflicting_signed_head_blocks_the_effect(self):
        with self._gate() as gate:
            run = gate.issue_run("education", "school-a", previous_head=self.genesis)
            with LiveCaller(run) as caller, LiveCaller(run) as alternate:
                record = self._qualify(gate, caller, run)
                divergent = issue_qualification(
                    self.qualifier, self.witness, run=run, identity=alternate.identity(),
                    previous_head=self.genesis,
                )
                authentic = H(canon(record))
                conflict = H(canon(divergent))
                self.assertNotEqual(authentic, conflict)
                for index, head in enumerate((None, self.genesis, conflict)):
                    self.heads[run["run_id"]] = head
                    request = self._request(run, "tutor", f"witness-control-{index}",
                                            {"topic": "fractions"})
                    self._deny(gate.perform(caller, request, grant=self._grant(run, request)))
                self.heads[run["run_id"]] = authentic
                request = self._request(run, "tutor", "witness-positive", {"topic": "fractions"})
                self._allow(gate.perform(caller, request, grant=self._grant(run, request)))

    def test_tenant_operation_and_exact_request_scope_are_enforced(self):
        with self._gate() as gate:
            run = gate.issue_run("education", "school-a", previous_head=self.genesis)
            with LiveCaller(run) as caller:
                self._qualify(gate, caller, run)
                tutor = self._request(run, "tutor", "approved-lesson", {"topic": "fractions"})
                tutor_grant = self._grant(run, tutor)
                record = self._request(run, "student_record", "read-student",
                                       {"student_id": "synthetic-student"})
                for changed in (dict(tutor, tenant="school-b"), dict(tutor, request_id="other"),
                                dict(tutor, challenge="ff" * 32), record):
                    with self.subTest(request=changed["request_id"]):
                        self._deny(gate.perform(caller, changed, grant=tutor_grant))
                self._allow(gate.perform(caller, tutor, grant=tutor_grant))
                refused = gate.perform(caller, record, grant=self._grant(run, record))
                self._deny(refused)
                self.assertNotIn("data", refused)

    def test_expired_owner_grant_and_expired_run_are_blocked(self):
        with self._gate() as gate:
            run = gate.issue_run("education", "school-a", previous_head=self.genesis, ttl=60)
            with LiveCaller(run) as caller:
                self._qualify(gate, caller, run)
                early = self._request(run, "tutor", "expired-grant", {"topic": "fractions"})
                permission = self._grant(run, early, ttl=5)
                self.clock_time = self.now + 5
                self._deny(gate.perform(caller, early, grant=permission))
                late = self._request(run, "tutor", "expired-run", {"topic": "fractions"})
                longer_permission = self._grant(run, late, ttl=90)
                self.clock_time = run["expires_at"]
                self._deny(gate.perform(caller, late, grant=longer_permission))

    def test_revocation_is_durable_and_policy_rotation_requires_requalification(self):
        with self._gate() as gate:
            run = gate.issue_run("education", "school-a", previous_head=self.genesis)
        with LiveCaller(run) as caller:
            with self._gate() as gate:
                self._qualify(gate, caller, run)
                request = self._request(run, "tutor", "revoked", {"topic": "fractions"})
                permission = self._grant(run, request)
                revoked = gate.revoke(run, revoke(self.owner, run=run, grant_id="revoked"))
                self.assertEqual(revoked["outcome"], "REVOKED", revoked)
            with self._gate() as gate:
                self._deny(gate.perform(caller, request, grant=permission))
                epoch = gate.change_policy("education", "school-a")
                self.assertEqual(epoch, run["policy_epoch"] + 1)
                fresh = self._request(run, "tutor", "old-policy", {"topic": "fractions"})
                self._deny(gate.perform(caller, fresh, grant=self._grant(run, fresh)))
        with self._gate() as gate:
            new_run = gate.issue_run("education", "school-a", previous_head=self.genesis)
            self.assertEqual(new_run["policy_epoch"], epoch)
            with LiveCaller(new_run) as new_caller:
                self._qualify(gate, new_caller, new_run)
                request = self._request(new_run, "tutor", "new-policy", {"topic": "fractions"})
                self._allow(gate.perform(new_caller, request, grant=self._grant(new_run, request)))

    def test_clock_rollback_after_target_reopen_blocks_otherwise_current_authority(self):
        with self._gate() as gate:
            run = gate.issue_run("education", "school-a", previous_head=self.genesis)
        with LiveCaller(run) as caller:
            with self._gate() as gate:
                self._qualify(gate, caller, run)
                self.clock_time = self.now + 10
                first = self._request(run, "tutor", "clock-positive", {"topic": "fractions"})
                self._allow(gate.perform(caller, first, grant=self._grant(run, first)))
            self.clock_time = self.now + 9
            second = self._request(run, "tutor", "clock-negative", {"topic": "fractions"})
            approval = self._grant(run, second)
            with self._gate() as gate:
                result = gate.perform(caller, second, grant=approval)
                self.assertEqual(result["outcome"], "BLOCKED", result)
                self.assertNotIn("data", result)
                self.clock_time = self.now + 10
                self._allow(gate.perform(caller, second, grant=approval))

    def _payment(self, run, request_id, *, amount=425):
        return self._request(run, "initiate_payment", request_id, {
            "payment_id": "synthetic-payment", "payee": "synthetic-library", "amount_cents": amount,
        })

    def _balance(self, gate, caller, run, request_id):
        request = self._request(run, "balance", request_id, {})
        result = gate.perform(caller, request, grant=self._grant(run, request))
        receipt = self._allow(result)
        self.assertEqual(receipt["details"], result["data"])
        return result["data"]

    def test_finance_confirms_distinct_payment_authority_and_settlement(self):
        with self._gate() as gate:
            run = gate.issue_run("finance", "bank-a", previous_head=self.genesis)
            with LiveCaller(run) as caller:
                self._qualify(gate, caller, run)
                before = self._balance(gate, caller, run, "balance-before")
                self.assertEqual(before["balance_cents"], before["available_cents"])
                self.assertEqual(before["reserved_cents"], 0)
                payment = self._payment(run, "payment")
                self._deny(gate.perform(caller, payment, grant=self._grant(run, payment)))
                self.assertEqual(gate.reconcile("bank-a", "synthetic-payment")["outcome"], "UNKNOWN")
                approval = self._grant(run, payment, signer=self.payment_owner)
                initiated = gate.perform(caller, payment, grant=approval)
                receipt = self._allow(initiated, "INITIATED")
                self.assertEqual(receipt["details"]["settlement_status"], "PENDING")
                self.assertEqual(receipt["owner_pub"], self.payment_owner.pub.hex())
                pending = gate.reconcile("bank-a", "synthetic-payment")
                self.assertEqual(pending["outcome"], "INITIATED")
                self.assertEqual(pending["receipt"], initiated["receipt"])
                self.assertEqual(gate.reconcile("bank-b", "synthetic-payment")["outcome"], "UNKNOWN")
                after_initiation = self._balance(gate, caller, run, "balance-pending")
                self.assertEqual(after_initiation, {
                    "balance_cents": before["balance_cents"], "reserved_cents": 425,
                    "available_cents": before["available_cents"] - 425,
                })
                digest = H(canon(initiated["receipt"])).hex()
                unauthorized = settlement(
                    self.owner, tenant="bank-a", payment_id="synthetic-payment", initiation_sha256=digest,
                )
                self._deny(gate.settle(unauthorized))
                wrong_digest = settlement(
                    self.settler, tenant="bank-a", payment_id="synthetic-payment",
                    initiation_sha256="ff" * 32,
                )
                self._deny(gate.settle(wrong_digest))
                self.assertEqual(gate.reconcile("bank-a", "synthetic-payment"), pending)
                settlement_record = settlement(
                    self.settler, tenant="bank-a", payment_id="synthetic-payment", initiation_sha256=digest,
                )
                settled = gate.settle(settlement_record)
                checked = self._allow(settled, "SETTLED")
                self.assertEqual(checked["details"]["initiation_sha256"], digest)
                history = gate.reconcile("bank-a", "synthetic-payment")
                self.assertEqual(history["outcome"], "SETTLED")
                self.assertEqual(history["receipt"], settled["receipt"])
                repeated = gate.settle(settlement_record)
                self._allow(repeated, "SETTLED")
                self.assertIs(repeated["historical"], True)
                self.assertEqual(repeated["receipt"], settled["receipt"])
                self.assertEqual(self._balance(gate, caller, run, "balance-settled"), {
                    "balance_cents": before["balance_cents"] - 425, "reserved_cents": 0,
                    "available_cents": before["available_cents"] - 425,
                })

    def test_lost_payment_reply_reconciles_without_reinitiating_across_runs(self):
        with self._gate() as gate:
            run = gate.issue_run("finance", "bank-a", previous_head=self.genesis)
            with LiveCaller(run) as caller:
                self._qualify(gate, caller, run)
                payment = self._payment(run, "payment")
                approval = self._grant(run, payment, signer=self.payment_owner)
                exchange = caller.exchange

                def lost_reply(message):
                    if message.get("type") == "quorvane-resource-result":
                        raise LiveCallerError("synthetic response loss after target commit")
                    return exchange(message)

                with patch.object(caller, "exchange", side_effect=lost_reply):
                    unconfirmed = gate.perform(caller, payment, grant=approval)
                self.assertEqual(unconfirmed["outcome"], "UNKNOWN")
                self.assertNotIn("receipt", unconfirmed)
                first = gate.reconcile("bank-a", "synthetic-payment")
                self._allow(first, "INITIATED")
                self._deny(gate.perform(caller, payment, grant=approval))
                self.assertEqual(gate.reconcile("bank-a", "synthetic-payment"), first)
        with self._gate() as reopened:
            new_run = reopened.issue_run("finance", "bank-a", previous_head=self.genesis)
            with LiveCaller(new_run) as caller:
                self._qualify(reopened, caller, new_run)
                replay = self._payment(new_run, "fresh-request-same-payment")
                repeated = reopened.perform(
                    caller, replay, grant=self._grant(new_run, replay, signer=self.payment_owner),
                )
                if repeated["outcome"] == "INITIATED":
                    self.assertEqual(repeated["receipt"], first["receipt"])
                else:
                    self._deny(repeated)
                changed = self._payment(new_run, "fresh-request-new-amount", amount=426)
                self._deny(reopened.perform(
                    caller, changed, grant=self._grant(new_run, changed, signer=self.payment_owner),
                ))
                after = self._balance(reopened, caller, new_run, "balance-after-replies")
                self.assertEqual(after["reserved_cents"], 425)
            self.assertEqual(reopened.reconcile("bank-a", "synthetic-payment"), first)

    def test_concurrent_independent_qualified_runs_reserve_payment_once(self):
        with self._gate() as first, self._gate() as second:
            run_a = first.issue_run("finance", "bank-a", previous_head=self.genesis)
            run_b = second.issue_run("finance", "bank-a", previous_head=self.genesis)
            with LiveCaller(run_a) as caller_a, LiveCaller(run_b) as caller_b:
                self._qualify(first, caller_a, run_a)
                self._qualify(second, caller_b, run_b)
                barrier = Barrier(2, timeout=5)

                def submit(side):
                    gate, caller, run, label = side
                    payment = self._payment(run, label)
                    approval = self._grant(run, payment, signer=self.payment_owner)
                    barrier.wait()
                    return gate.perform(caller, payment, grant=approval)

                with ThreadPoolExecutor(max_workers=2) as workers:
                    outcomes = list(workers.map(submit, (
                        (first, caller_a, run_a, "race-a"), (second, caller_b, run_b, "race-b"),
                    )))
                accepted = [result for result in outcomes if result["outcome"] == "INITIATED"]
                self.assertEqual(len(accepted), 1, outcomes)
                self._allow(accepted[0], "INITIATED")
                for rejected in (result for result in outcomes if result["outcome"] != "INITIATED"):
                    self._deny(rejected)
                self.assertEqual(first.reconcile("bank-a", "synthetic-payment")["receipt"],
                                 accepted[0]["receipt"])
                after = self._balance(second, caller_b, run_b, "balance-after-race")
                self.assertEqual(after["reserved_cents"], 425)


if __name__ == "__main__":
    unittest.main()
