"""Same-UID protocol tests for the separately provisioned gateway runner."""

from contextlib import contextmanager
import multiprocessing
import os
import sys
import unittest
from unittest.mock import patch

from alibi import H, canon
import test_voidcell002 as prior_fixture
from wolfalibi.solitary_cli import _write_new
from wolfalibi.voidcell002 import TargetAuthority
from wolfalibi.voidcell003_fixture import _target_state_metadata, gateway_init, make_owner_handoff
from wolfalibi.voidcell003_gateway import (
    _Blocked, _Plan, _dispatch, _original, _prepared_packet, _proc_identity,
    _ready, _reconcile, run_trial,
)
from wolfalibi.voidcell_records import check_dispatch, dispatch_digest, make_scope


_REVISION = {"commit": "0a" * 20, "tree": "0b" * 20}
_PROTOCOL_ONLY = "SAME_UID_PROTOCOL_ONLY"


def _serve_test_rpc(state, anchor, channel):
    # Test transport uses the same UID. The operational runner separately
    # requires real owner/gateway accounts and exercises Unix peer checks.
    with channel, TargetAuthority(state, anchor) as target:
        while True:
            action, packet = channel.recv()
            if action == "stop":
                return
            if action == "status":
                channel.send(target.status())
            elif action == "dispatch":
                channel.send(target.dispatch(packet))
            elif action == "reconcile":
                channel.send(target.reconcile(packet))
            else:
                raise AssertionError("unexpected test transport action")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux test authority required")
class Voidcell003GatewayTests(unittest.TestCase):
    def setUp(self):
        self.fixture = prior_fixture.Voidcell002TargetTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        fixture = self.fixture
        directory = fixture.root / "gateway"
        directory.mkdir(mode=0o700)
        state = fixture.state.lstat()
        with fixture._target() as target:
            scope = target.scope
        self.plan = _Plan(directory, fixture.gateway_signer, {
            "qualification": fixture.envelope, "owner_grant": fixture._grant(scope),
            "scope": scope, "source_revision": _REVISION,
            "target_uid": os.geteuid(), "target_gid": state.st_gid, "gateway_uid": fixture.gateway_uid,
            "target_pub": fixture.target_pub.hex(),
            "target_state": _target_state_metadata(fixture.state, fixture.anchor, fixture.config),
        }, "44" * 32, fixture.target_pub)

    @contextmanager
    def _target_process(self, effect_count):
        ctx = multiprocessing.get_context("fork")
        caller, target_side = ctx.Pipe()
        child = ctx.Process(target=_serve_test_rpc, args=(self.fixture.state, self.fixture.anchor, target_side))
        child.start()
        target_side.close()
        try:
            def call(action, packet=None):
                caller.send((action, packet))
                self.assertTrue(caller.poll(5), f"test target did not respond to {action}")
                return caller.recv()

            ready = {**call("status"), "source_revision": _REVISION}
            _, ticks = _proc_identity(child.pid)
            ready_path = self.fixture.root / f"ready-{child.pid}.json"
            _write_new(ready_path, ready)
            parsed, _, entry = _ready(
                self.plan, target_pid=child.pid, target_start_ticks=ticks,
                target_state=self.fixture.state, inventory=ready_path, effect_count=effect_count,
            )
            self.assertEqual(parsed, ready)
            yield child.pid, ticks, parsed["inventory_v2"], entry, call
        finally:
            if child.is_alive():
                try:
                    caller.send(("stop", None))
                except OSError:
                    pass
            caller.close()
            child.join(timeout=5)
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)

    def test_pending_intent_and_exact_receipt_across_actual_target_restart(self):
        prepared = _prepared_packet(self.plan)
        self.assertFalse(self.plan.journal.exists())
        calls = []
        with self._target_process(0) as (pid, ticks, inventory, entry, call):
            def transport(action, packet):
                calls.append(action)
                self.assertEqual(canon(packet), canon(prepared))
                return call(action, packet)

            lost = _dispatch(self.plan, pid=pid, ticks=ticks, target_inventory=inventory,
                             transport=transport, custody=_PROTOCOL_ONLY)
            self.assertEqual(lost["outcome"], "AMBIGUOUS", lost)
            self.assertEqual(lost["journal"]["state"], "PENDING")
            self.assertEqual(lost["journal"]["dispatch_sha256"], dispatch_digest(prepared))
            self.assertEqual(call("status")["effect_count"], 1)
            with self.assertRaisesRegex(_Blocked, "different target process"):
                _original(self.plan, pid, entry, inventory)
            with self.assertRaisesRegex(_Blocked, "original target process is still running"):
                _original(self.plan, pid + 1, entry, inventory)
        with self._target_process(1) as (new_pid, _, inventory, entry, call):
            self.assertNotEqual(new_pid, pid)

            def transport(action, packet):
                calls.append(action)
                return call(action, packet)

            recovered = _reconcile(self.plan, pid=new_pid, target_inventory=inventory,
                                   target_state_entry=entry, transport=transport, custody=_PROTOCOL_ONLY)
            self.assertEqual(recovered["outcome"], "CONDITIONAL", recovered)
            self.assertEqual(recovered["custody"], _PROTOCOL_ONLY)
            self.assertEqual(recovered["journal"]["state"], "TERMINAL")
            self.assertEqual(H(canon(recovered["receipt"])).hex(), lost["original_receipt_sha256"])
            self.assertEqual(call("status")["effect_count"], 1)
        self.assertEqual(calls, ["dispatch", "reconcile"])

    def test_missing_acknowledgement_retains_pending_without_redispatch_or_capture(self):
        calls = []
        with self._target_process(0) as (pid, ticks, inventory, _, call):
            def incomplete_transport(action, packet):
                calls.append(action)
                self.assertEqual(call(action, packet)["outcome"], "ACCEPTED_EVIDENCED")
                return {"outcome": "BLOCKED"}

            lost = _dispatch(self.plan, pid=pid, ticks=ticks, target_inventory=inventory,
                             transport=incomplete_transport, custody=_PROTOCOL_ONLY)
            self.assertEqual(lost["outcome"], "BLOCKED", lost)
            self.assertEqual(lost["journal"]["state"], "PENDING")
            self.assertEqual(call("status")["effect_count"], 1)
            self.assertFalse(self.plan.capture.exists())
            self.assertEqual(calls, ["dispatch"])
            with self.assertRaises(_Blocked):
                _dispatch(self.plan, pid=pid, ticks=ticks, target_inventory=inventory,
                          transport=incomplete_transport, custody=_PROTOCOL_ONLY)
            self.assertEqual(calls, ["dispatch"])

    def test_unavailable_principal_is_explicit_before_loading_handoff(self):
        with patch("wolfalibi.voidcell003_gateway._ordinary_gateway", return_value=False), \
                patch("wolfalibi.voidcell003_gateway._plan") as plan:
            result = run_trial("dispatch", handoff=None, gateway_state=None, owner_pub=None)
            self.assertEqual(result["outcome"], "UNSUPPORTED")
            self.assertEqual(result["custody"], "UNSUPPORTED")
            plan.assert_not_called()

    def test_prepares_from_actual_fixture_handoff_with_external_owner_pin(self):
        fixture = self.fixture
        public = fixture.root / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        enrollment = gateway_init(self.plan.directory, public / "gateway.json")
        gateway_pub = bytes.fromhex(enrollment["gateway_pub"])
        scope = make_scope(
            fixture.contract, gateway_pub=gateway_pub, target_pub=fixture.target_pub,
            operation_id=fixture.config["operation_id"], expected_witness_state_digest=fixture.genesis,
        )
        record = make_owner_handoff(
            fixture.owner, source=_REVISION, created_at=fixture.now,
            gateway_reference_sha256=enrollment["public_ref_sha256"],
            gateway_uid=enrollment["gateway_uid"], gateway_gid=enrollment["gateway_gid"],
            gateway_pub=gateway_pub,
            # This test prepares artifacts only. The other UID is a synthetic
            # pin, while the same-UID target fixture supplies actual metadata.
            target_uid=fixture.gateway_uid, target_gid=os.getegid(), target_pub=fixture.target_pub,
            socket_path=str(public / "target.sock"), target_state=self.plan.payload["target_state"],
            contract=fixture.contract, qualification=fixture.envelope, broker_pub=fixture.broker.pub,
            witness_pub=fixture.witness_signer.pub, supervisor_pub=fixture.supervisor.pub,
            expected_witness_state_digest=fixture.genesis, terminal_witness_state_digest=fixture.terminal,
            operation_id=fixture.config["operation_id"], owner_grant=fixture._grant(scope),
        )
        handoff = public / "owner.json"
        handoff.write_bytes(canon(record))
        handoff.chmod(0o644)
        with patch("wolfalibi.voidcell003_gateway.request") as transport:
            packet = run_trial("prepare", handoff=handoff, gateway_state=self.plan.directory,
                               owner_pub=fixture.owner.pub)
            self.assertEqual(check_dispatch(packet, gateway_pub=gateway_pub, scope=scope)["scope"], scope)
            wrong = run_trial("prepare", handoff=handoff, gateway_state=self.plan.directory,
                              owner_pub=fixture.broker.pub)
            self.assertEqual(wrong["outcome"], "BLOCKED")
            transport.assert_not_called()
        self.assertFalse(self.plan.journal.exists())


if __name__ == "__main__":
    unittest.main()
