"""Synthetic VOIDCELL 002 controls without claiming cross-account custody."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import sqlite3
import sys
from tempfile import TemporaryDirectory
from threading import Barrier
import time
import unittest
from unittest.mock import patch

from alibi import DurableWitness, Signer, canon, verify_sig
from wolfalibi.agent_solitary import agent_solitary_contract, run_agent_solitary
from wolfalibi.stage3_worker import UnsupportedWorker
from wolfalibi.voidcell002 import AuthorityError, TargetAuthority, init_key, initialize
from wolfalibi.voidcell002_anchor import AnchorError, LedgerAnchor
from wolfalibi.voidcell002_probe import preflight, probe
from wolfalibi.voidcell002_transport import Voidcell002TransportError, _decode_request, request, serve
from wolfalibi.voidcell_gateway import EffectGateway
from wolfalibi.voidcell_records import dispatch_digest, grant, revoke, sign_dispatch, verify_receipt


_EVIDENCE_FILE = "WOLFALIBI_VOIDCELL002_EVIDENCE_FILE"


def _write_public_evidence(path, evidence):
    data = canon(evidence) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags, 0o600), "wb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _public_gateway_phase(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        entry = db.execute("SELECT state, outcome, dispatch_sha256 FROM intent WHERE slot = 1").fetchone()
    phase, outcome, digest = entry if entry is not None else ("EMPTY", None, None)
    return {"phase": phase, "outcome": outcome, "dispatch_sha256": digest}


def _serve_fixture(state, anchor, endpoint, gateway_uid, ready):
    with TargetAuthority(state, anchor) as authority:
        serve(authority, socket_path=endpoint, gateway_uid=gateway_uid, on_ready=ready.set)


def _exit_after_sql_commit(state, anchor, packet):
    with TargetAuthority(state, anchor) as authority:
        with patch.object(LedgerAnchor, "advance", side_effect=lambda *_: os._exit(73)):
            authority.dispatch(packet)


class Voidcell002TargetTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(prefix="wolfalibi-voidcell002-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state = self.root / "target"
        self.anchor = self.root / "anchor"
        self.gateway_path = self.root / "gateway.sqlite"
        self.state.mkdir(mode=0o700)
        self.anchor.mkdir(mode=0o700)
        self.now = int(time.time())
        self.owner, self.gateway_signer = Signer(), Signer()
        self.broker, self.witness_signer, self.supervisor = Signer(), Signer(), Signer()
        try:
            self.contract = agent_solitary_contract(
                "synthetic-voidcell002", bytes(range(32)), self.now + 120,
            )
        except UnsupportedWorker as exc:
            self.skipTest(f"UNSUPPORTED static Stage 5 prerequisite: {exc}")
        with DurableWitness(self.root / "witness.json", self.witness_signer) as witness:
            self.genesis = witness.state_digest
            result = run_agent_solitary(
                self.root, contract=self.contract, signer=self.broker, witness=witness,
                supervisor=self.supervisor, expected_witness_state_digest=self.genesis,
            )
            self.terminal = witness.state_digest
        self.assertEqual(result["outcome"], "COMPLETED", result)
        self.envelope = result["envelope"]
        self.observation = result["observation"]
        self.target_pub = bytes.fromhex(init_key(self.state))
        self.gateway_uid = 65533 if os.geteuid() == 65534 else 65534
        self.config = {
            "owner_pub": self.owner.pub.hex(), "gateway_pub": self.gateway_signer.pub.hex(),
            "broker_pub": self.broker.pub.hex(), "witness_pub": self.witness_signer.pub.hex(),
            "supervisor_pub": self.supervisor.pub.hex(),
            "contract": self.contract, "operation_id": "synthetic-effect-002",
            "expected_witness_state_digest": self.genesis.hex(),
            "initial_witness_head": self.terminal.hex(),
            "gateway_uid": self.gateway_uid,
        }
        initialize(self.state, self.anchor, self.config)

    def _target(self):
        return TargetAuthority(self.state, self.anchor)

    def _grant(self, scope):
        return grant(
            self.owner, scope=scope, grant_id="synthetic-owner-grant",
            not_before=self.now, expires_at=self.now + 90,
        )

    def _packet(self, target, **changed):
        fields = {
            "scope": target.scope, "qualification": self.envelope,
            "owner_grant": self._grant(target.scope),
        }
        fields.update(changed)
        return sign_dispatch(self.gateway_signer, **fields)

    def _verified(self, target, result, packet, outcome):
        self.assertEqual(result["outcome"], outcome, result)
        checked = verify_receipt(
            result["receipt"], target_pub=self.target_pub, scope=target.scope,
            dispatch_sha256=dispatch_digest(packet),
        )
        self.assertEqual(checked["outcome"], outcome)
        return checked

    def _gateway(self, target, transport):
        return EffectGateway(
            self.gateway_path, signer=self.gateway_signer, scope=target.scope,
            target_pub=self.target_pub, transport=transport,
        )

    def test_target_independently_checks_owner_grant_and_qualification(self):
        with self._target() as target:
            damaged = deepcopy(self.envelope)
            del damaged["supervisor_record"]["payload"]["closure"]
            for changes, reason in (
                    ({"owner_grant": None}, "OWNER_GRANT_UNVERIFIED"),
                    ({"qualification": self.observation}, "QUALIFICATION_UNVERIFIED"),
                    ({"qualification": damaged}, "QUALIFICATION_UNVERIFIED")):
                with self.subTest(changes=list(changes)):
                    packet = self._packet(target, **changes)
                    denied = target.dispatch(packet)
                    checked = self._verified(target, denied, packet, "DENIED")
                    self.assertEqual(checked["reason"], reason)
                    self.assertEqual(target.status()["effect_count"], 0)
            packet = self._packet(target)
            approved = target.dispatch(packet)
            self._verified(target, approved, packet, "ACCEPTED_EVIDENCED")
            self.assertEqual(target.status()["effect_count"], 1)
            with self.assertRaises(ValueError):
                verify_receipt(
                    approved["receipt"], target_pub=Signer().pub, scope=target.scope,
                    dispatch_sha256=dispatch_digest(packet),
                )

    def test_revocation_is_retained_before_a_later_dispatch(self):
        with self._target() as target:
            packet = self._packet(target)
            record = revoke(self.owner, scope=target.scope, grant_id="synthetic-owner-grant")
            revoked = target.revoke(record)
            self.assertEqual(revoked["outcome"], "REVOKED", revoked)
        with self._target() as reopened:
            denied = reopened.dispatch(packet)
            checked = self._verified(reopened, denied, packet, "DENIED")
            self.assertEqual(checked["reason"], "OWNER_GRANT_REVOKED")
            self.assertEqual(reopened.status()["effect_count"], 0)

    def test_lost_reply_recovers_one_target_receipt_after_reopen(self):
        output = os.environ.get(_EVIDENCE_FILE)
        calls = []
        captured = []
        gateway_journal = {}
        target_counts = {}
        with self._target() as target:
            def lose_ack(action, packet):
                self.assertEqual(action, "dispatch")
                calls.append(action)
                captured.append((packet, target.dispatch(packet)))
                raise TimeoutError("synthetic lost reply after target commit")

            with self._gateway(target, lose_ack) as gateway:
                target_counts["before_dispatch"] = target.status()["effect_count"]
                self.assertEqual(target_counts["before_dispatch"], 0)
                if output is not None:
                    gateway_journal["before_dispatch"] = _public_gateway_phase(self.gateway_path)
                approval = self._grant(target.scope)
                uncertain = gateway.dispatch(qualification=self.envelope, owner_grant=approval)
                self.assertEqual(uncertain["outcome"], "AMBIGUOUS", uncertain)
                self.assertNotIn("receipt", uncertain)
                packet, applied = captured[0]
                self._verified(target, applied, packet, "ACCEPTED_EVIDENCED")
                target_counts["after_lost_reply"] = target.status()["effect_count"]
                self.assertEqual(target_counts["after_lost_reply"], 1)
                replay = gateway.dispatch(qualification=self.envelope, owner_grant=approval)
                self.assertEqual(replay["outcome"], "AMBIGUOUS", replay)
                self.assertEqual(calls, ["dispatch"])
                if output is not None:
                    gateway_journal["after_lost_reply"] = _public_gateway_phase(self.gateway_path)
        with self._target() as reopened:
            def reconcile_only(action, record):
                self.assertEqual(action, "reconcile")
                calls.append(action)
                return reopened.reconcile(record)

            with self._gateway(reopened, reconcile_only) as gateway:
                result = gateway.reconcile()
                self._verified(reopened, result, packet, "ACCEPTED_EVIDENCED")
                self.assertEqual(result["receipt"], applied["receipt"])
                self.assertEqual(gateway.reconcile(), result)
                if output is not None:
                    gateway_journal["after_reconcile"] = _public_gateway_phase(self.gateway_path)
            target_counts["after_reconcile"] = reopened.status()["effect_count"]
            self.assertEqual(target_counts["after_reconcile"], 1)
        self.assertEqual(calls, ["dispatch", "reconcile"])
        if output is not None:
            expected = {
                "initial_dispatch": "AMBIGUOUS", "repeat_dispatch": "AMBIGUOUS",
                "reconcile": "ACCEPTED_EVIDENCED", "same_receipt": True,
                "transport_actions": ["dispatch", "reconcile"],
                "gateway_phases": ["EMPTY", "PENDING", "TERMINAL"],
            }
            observed = {
                "initial_dispatch": uncertain["outcome"], "repeat_dispatch": replay["outcome"],
                "reconcile": result["outcome"], "same_receipt": result["receipt"] == applied["receipt"],
                "transport_actions": calls,
                "gateway_phases": [entry["phase"] for entry in gateway_journal.values()],
            }
            self.assertEqual(observed, expected)
            _write_public_evidence(output, {
                "schema": "WOLFALIBI_VOIDCELL_002_LOST_REPLY_EVIDENCE_V1",
                "assurance": "SAME_UID_PROTOCOL_ONLY",
                "case": "committed_target_effect_lost_reply_reconciliation",
                "public_keys": {
                    "target": self.target_pub.hex(), "owner": self.owner.pub.hex(),
                    "gateway": self.gateway_signer.pub.hex(), "broker": self.broker.pub.hex(),
                    "witness": self.witness_signer.pub.hex(), "supervisor": self.supervisor.pub.hex(),
                },
                "witness": {
                    "expected_initial_state_sha256": self.genesis.hex(),
                    "retained_terminal_state_sha256": self.terminal.hex(),
                },
                "qualification": {
                    "type": self.envelope["supervisor_record"]["payload"]["type"],
                    "sha256": packet["route"]["payload"]["qualification_sha256"],
                },
                "dispatch_sha256": dispatch_digest(packet),
                "signed_dispatch": packet["route"],
                "signed_owner_grant": packet["grant"],
                "signed_target_receipt": result["receipt"],
                "target_ledger_counts": target_counts,
                "gateway_journal": gateway_journal,
                "expected": expected,
                "observed": observed,
            })

    def test_lost_request_fences_absence_and_late_packet_after_reopen(self):
        undelivered = []
        with self._target() as target:
            def lose_request(action, packet):
                if action == "dispatch":
                    undelivered.append(packet)
                    raise TimeoutError("synthetic request lost before the target")
                self.assertEqual(action, "reconcile")
                return target.reconcile(packet)

            with self._gateway(target, lose_request) as gateway:
                uncertain = gateway.dispatch(
                    qualification=self.envelope, owner_grant=self._grant(target.scope),
                )
                self.assertEqual(uncertain["outcome"], "AMBIGUOUS", uncertain)
                packet, = undelivered
                fenced = gateway.reconcile()
                self._verified(target, fenced, packet, "FENCED")
                self.assertEqual(target.status()["effect_count"], 0)
        with self._target() as reopened:
            late = reopened.dispatch(packet)
            self._verified(reopened, late, packet, "FENCED")
            self.assertEqual(late["receipt"], fenced["receipt"])
            self.assertEqual(reopened.status()["effect_count"], 0)

    def test_missing_target_key_blocks_reopen_and_does_not_regenerate(self):
        key = self.state / "target.key"
        prior_key = key.read_bytes()
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            init_key(self.state)
        self.assertEqual(key.read_bytes(), prior_key)
        key.unlink()
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self._target()
        self.assertFalse(key.exists())

    def test_same_uid_gateway_configuration_fails_before_a_ledger(self):
        other_state = self.root / "same-uid-target"
        other_anchor = self.root / "same-uid-anchor"
        other_state.mkdir(mode=0o700)
        other_anchor.mkdir(mode=0o700)
        init_key(other_state)
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            initialize(other_state, other_anchor, dict(self.config, gateway_uid=os.geteuid()))
        self.assertFalse((other_state / "ledger.sqlite").exists())
        self.assertFalse((other_anchor / "ledger-anchor.json").exists())

    def test_preflight_does_not_claim_custody_without_provisioned_peer(self):
        result = preflight()
        self.assertEqual(result["outcome"], "UNSUPPORTED", result)
        self.assertEqual(result["custody"], "UNSUPPORTED")
        self.assertEqual(result["uid"], os.getuid())
        self.assertEqual(result["euid"], os.geteuid())
        self.assertNotIn("observations", result)

    def test_same_directory_identity_cannot_hold_the_retained_anchor(self):
        alias = self.root / "alternate-anchor"
        alias.mkdir(mode=0o700)
        lstat = Path.lstat

        def observe(path):
            return lstat(self.state if path == alias else path)

        with patch.object(Path, "lstat", observe):
            with self.assertRaisesRegex(AuthorityError, "retain the anchor outside"):
                TargetAuthority(self.state, alias)
        self.assertEqual(list(alias.iterdir()), [])

    def test_independently_retained_anchor_detects_an_older_ledger_snapshot(self):
        ledger = self.state / "ledger.sqlite"
        anchored = self.anchor / "ledger-anchor.json"
        before = ledger.read_bytes()
        retained_before = anchored.read_bytes()
        with self._target() as target:
            packet = self._packet(target)
            self._verified(target, target.dispatch(packet), packet, "ACCEPTED_EVIDENCED")
        retained_after = anchored.read_bytes()
        self.assertNotEqual(retained_after, retained_before)
        ledger.write_bytes(before)
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self._target()
        self.assertEqual(anchored.read_bytes(), retained_after)

    def test_target_detects_a_valid_but_stale_anchor_when_ledger_advances(self):
        anchored = self.anchor / "ledger-anchor.json"
        retained_before = anchored.read_bytes()
        with self._target() as target:
            packet = self._packet(target)
            self._verified(target, target.dispatch(packet), packet, "ACCEPTED_EVIDENCED")
        anchored.write_bytes(retained_before)
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self._target()
        self.assertEqual(anchored.read_bytes(), retained_before)

    def test_changed_gateway_uid_cannot_rebind_retained_authority(self):
        config = self.state / "authority.json"
        altered = dict(self.config, gateway_uid=self.gateway_uid - 2)
        with self._target() as target:
            config.write_bytes(canon(altered))
            self.assertEqual(target.status()["outcome"], "BLOCKED")
        with self.assertRaises(AnchorError):
            self._target()

    def test_crash_window_after_sql_commit_blocks_receipt_and_reopen(self):
        anchored = self.anchor / "ledger-anchor.json"
        retained_before = anchored.read_bytes()
        with self._target() as target:
            packet = self._packet(target)
            with patch.object(LedgerAnchor, "advance", side_effect=AnchorError(
                    "synthetic anchor publication interruption")):
                result = target.dispatch(packet)
            self.assertEqual(result["outcome"], "BLOCKED", result)
            self.assertNotIn("receipt", result)
            status = target.status()
            self.assertEqual(status["outcome"], "BLOCKED", status)
            self.assertIsNone(status["effect_count"])
        self.assertEqual(anchored.read_bytes(), retained_before)
        # Owner-only inspection confirms the SQL transaction had committed.
        # A stale retained anchor still prevents using it as effect evidence.
        ledger = (self.state / "ledger.sqlite").as_uri()
        with closing(sqlite3.connect(ledger + "?mode=ro", uri=True)) as inspect_db:
            count, = inspect_db.execute(
                "SELECT COUNT(*) FROM effects WHERE outcome = 'ACCEPTED_EVIDENCED'"
            ).fetchone()
        self.assertEqual(count, 1)
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self._target()

    def test_concurrent_owner_revocation_and_dispatch_serialize_at_target(self):
        with self._target() as target, ThreadPoolExecutor(max_workers=2) as workers:
            packet = self._packet(target)
            revoke_record = revoke(self.owner, scope=target.scope, grant_id="synthetic-owner-grant")
            barrier = Barrier(2, timeout=5)

            def invoke(method, value):
                barrier.wait()
                return method(value)

            dispatched = workers.submit(invoke, target.dispatch, packet)
            revoked = workers.submit(invoke, target.revoke, revoke_record)
            result = dispatched.result(timeout=10)
            self.assertEqual(revoked.result(timeout=10)["outcome"], "REVOKED")
            self.assertIn(result["outcome"], ("DENIED", "ACCEPTED_EVIDENCED"), result)
            checked = self._verified(target, result, packet, result["outcome"])
            count = int(result["outcome"] == "ACCEPTED_EVIDENCED")
            if not count:
                self.assertEqual(checked["reason"], "OWNER_GRANT_REVOKED")
            self.assertEqual(target.status()["effect_count"], count)
        with self._target() as reopened:
            self._verified(reopened, reopened.dispatch(packet), packet, "DENIED")
            self.assertEqual(reopened.status()["effect_count"], count)

    def test_abrupt_target_exit_leaves_committed_sql_unacknowledged(self):
        with self._target() as target:
            packet = self._packet(target)
        anchor = self.anchor / "ledger-anchor.json"
        before = anchor.read_bytes()
        processes = multiprocessing.get_context("spawn")
        worker = processes.Process(target=_exit_after_sql_commit, args=(self.state, self.anchor, packet))
        worker.start()
        try:
            worker.join(10)
            self.assertEqual(worker.exitcode, 73)
        finally:
            if worker.is_alive():
                worker.kill()
                worker.join(5)
        self.assertEqual(anchor.read_bytes(), before)
        with closing(sqlite3.connect((self.state / "ledger.sqlite").as_uri() + "?mode=ro", uri=True)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM effects").fetchone(), (1,))
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            self._target()

    def test_alternate_socket_in_endpoint_directory_blocks_activation(self):
        endpoint_dir = self.root / "endpoint"
        endpoint_dir.mkdir(mode=0o711)
        endpoint_dir.chmod(0o711)
        existing, requested = endpoint_dir / "other.sock", endpoint_dir / "target.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as other, self._target() as target:
            other.bind(str(existing))
            with self.assertRaisesRegex(Voidcell002TransportError, "endpoint inventory"):
                serve(target, socket_path=requested, gateway_uid=self.gateway_uid)
            self.assertTrue(existing.is_socket())
            self.assertFalse(requested.exists())
            self.assertEqual(target.status()["effect_count"], 0)

    @unittest.skipUnless(sys.platform == "linux" and hasattr(socket, "SCM_CREDENTIALS"),
                         "requires Linux Unix peer credentials")
    def test_owner_uid_cannot_dispatch_as_configured_distinct_gateway_uid(self):
        wrong_version = canon({
            "type": "wolfalibi.voidcell002.local-transport.v999", "action": "status", "packet": None,
        })
        with self.assertRaises(Voidcell002TransportError):
            _decode_request(wrong_version)
        with self._target() as target:
            packet = self._packet(target)
        endpoint_dir = self.root / "endpoint"
        endpoint_dir.mkdir(mode=0o711)
        endpoint_dir.chmod(0o711)
        endpoint = endpoint_dir / "target.sock"
        processes = multiprocessing.get_context("spawn")
        ready = processes.Event()
        server = processes.Process(
            target=_serve_fixture, args=(self.state, self.anchor, endpoint, self.gateway_uid, ready),
        )
        server.start()
        try:
            self.assertTrue(ready.wait(10), "synthetic target endpoint did not start")
            owner_uid = os.geteuid()
            self.assertNotEqual(owner_uid, self.gateway_uid)
            status = request(endpoint, "status", expected_target_uid=owner_uid)
            self.assertEqual(status["outcome"], "READY", status)
            self.assertEqual(status["effect_count"], 0)
            inventory = status["inventory"]
            self.assertEqual(inventory["payload"]["pid"], server.pid)
            self.assertEqual(inventory["payload"]["key_mode"], 0o600)
            self.assertTrue(verify_sig(
                self.target_pub, b"wolfalibi/voidcell002/private-inventory/v1",
                canon(inventory["payload"]), bytes.fromhex(inventory["signature"]),
            ))
            denied = request(endpoint, "dispatch", packet, expected_target_uid=owner_uid)
            self.assertEqual(denied, {"outcome": "BLOCKED",
                                      "reason": "VOIDCELL002_TRANSPORT_REJECTED"})
            wrong_target = request(endpoint, "status", expected_target_uid=self.gateway_uid)
            self.assertEqual(wrong_target["outcome"], "BLOCKED", wrong_target)
            custody = probe(owner_uid, target_pid=server.pid, state_dir=self.state, socket_path=endpoint)
            self.assertEqual(custody["outcome"], "UNSUPPORTED", custody)
            self.assertNotIn("observations", custody)
            self.assertEqual(request(endpoint, "status", expected_target_uid=owner_uid)["effect_count"], 0)
        finally:
            if server.is_alive():
                os.kill(server.pid, signal.SIGINT)
            server.join(timeout=5)
            if server.is_alive():
                server.terminate()
                server.join(timeout=5)
            server.close()


if __name__ == "__main__":
    unittest.main()
