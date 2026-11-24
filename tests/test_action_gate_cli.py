"""Real-process transport tests using explicitly synthetic signed assessments.

These tests never execute Shirudo or a TPM. Mocked verifier reports exercise
the transport and target's durable transaction boundaries only; the separate
laboratory workflow is required for genuine attestation qualification.
"""

from __future__ import annotations

import concurrent.futures
import copy
import json
import os
import secrets
import selectors
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shirudo_adapter import action_gate_cli as cli
from shirudo_adapter.action_gate import Gate, make_grant_payload
from shirudo_adapter.model import canonical_json
from shirudo_adapter.receipt import sign_record, verify_record
from shirudo_adapter.service import Service

try:
    from .support import evidence_bytes, fixture_verifier_result, policy_for, write_nonexecuted_fixture
except ImportError:
    from support import evidence_bytes, fixture_verifier_result, policy_for, write_nonexecuted_fixture


REPOSITORY = Path(__file__).resolve().parents[1]
MODULE = "shirudo_adapter.action_gate_cli"


class ActionGateTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wa-gate-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.sock = self.root / "gate.sock"
        self.owner = Ed25519PrivateKey.generate()
        self.service = Service.initialize(self.root / "verifier-state")
        self.verifier = write_nonexecuted_fixture(self.root / "not-a-real-verifier")
        self.policy = policy_for(self.verifier)
        self.policy["policy_id"] = "synthetic-action-transport-test"
        self.policy["target_id"] = "synthetic-action-transport-target"
        # The signed object has the laboratory interface shape, but its
        # verifier call is explicitly mocked below. It is never qualification.
        self.policy["assurance"] = "LAB_VTPM"
        self.policy["enrollment"]["method"] = "trusted_builder"
        self.policy_sha = self.service.register_policy(self.policy)
        self.trust = {
            "schema": "wolfalibi.shirudo.action-trust.v1",
            "target_id": self.policy["target_id"],
            "owner_public_key": self.owner.public_key().public_bytes_raw().hex(),
            "verifier_public_key": self.service.public_key_hex(),
            "verifier_instance_id": self.service.instance_id,
            "policy": self.policy,
        }
        self.trust_path = self.root / "trust.json"
        self.trust_path.write_bytes(canonical_json(self.trust))
        self.gate = Gate.initialize(self.state, self.trust)
        self.servers = []
        self.addCleanup(self.stop_servers)

    def invoke(self, *args, document=None, timeout=8):
        completed = subprocess.run(
            [sys.executable, "-m", MODULE, *map(str, args)],
            cwd=REPOSITORY, input=None if document is None else canonical_json(document),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
        self.assertLess(len(completed.stdout), cli.MAX_RESPONSE_BYTES + 4096)
        try:
            result = json.loads(completed.stdout)
        except ValueError:
            self.fail(f"CLI produced no JSON: {completed.stderr[:1000]!r}; {completed.stdout[:1000]!r}")
        return result, completed.returncode

    def start_server(self, *options, patch_code=None, path=None):
        args = ["serve", "--state", str(self.state), "--socket", str(path or self.sock), *options]
        if patch_code is None:
            command = [sys.executable, "-m", MODULE, *args]
        else:
            command = [sys.executable, "-c", patch_code +
                       "\nfrom shirudo_adapter.action_gate_cli import main\nraise SystemExit(main())", *args]
        process = subprocess.Popen(command, cwd=REPOSITORY, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        self.servers.append(process)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(5):
                self.fail("Action-gate server did not become ready")
            line = process.stdout.readline(4096)
        self.assertEqual(json.loads(line).get("status"), "READY", line)
        return process

    def stop_servers(self):
        for process in self.servers:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            process.stdout.close()
            process.stderr.close()

    def rpc(self, document, timeout=3):
        return cli.request(self.sock, document, timeout=timeout)

    def status(self, operation_id=None):
        response, code = self.rpc({"op": "status", "operation_id": operation_id})
        self.assertEqual(code, 0, response)
        self.assertEqual(response["status"], "STATUS", response)
        return response["result"]

    def execution(self, *, through_socket=True):
        challenge = self.service.issue_challenge(self.policy_sha)
        prepare_request = {"op": "prepare", "attestation_challenge": challenge}
        if through_socket:
            prepared, code = self.rpc(prepare_request)
        else:
            prepared, code = cli._dispatch(self.gate, prepare_request), 0
        self.assertEqual(code, 0, prepared)
        self.assertEqual(prepared["status"], "PREPARED", prepared)
        action = prepared["action_challenge"]
        result = fixture_verifier_result(self.policy)
        result["execution_profile"] = "UPSTREAM_CLI"
        with patch("shirudo_adapter.service.run_verifier", return_value=result):
            assessment = self.service.assess(challenge["payload"]["challenge_id"],
                                              evidence_bytes(self.policy, challenge), str(self.verifier))
        now = time.time_ns() // 1_000_000
        payload = make_grant_payload(action, assessment, grant_id=secrets.token_hex(16),
                                     issued_at_ms=now, expires_at_ms=action["payload"]["expires_at_ms"])
        return {"operation_id": action["payload"]["operation_id"],
                "grant": sign_record(self.owner, payload), "assessment": assessment}

    def raw_request(self, raw: bytes, *, timeout=2):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(self.sock))
            sock.sendall(raw)
            sock.shutdown(socket.SHUT_WR)
            data = bytearray()
            while True:
                try:
                    chunk = sock.recv(65_536)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
                self.assertLessEqual(len(data), cli.MAX_RESPONSE_BYTES + 4)
        self.assertGreaterEqual(len(data), 4)
        self.assertEqual(struct.unpack("!I", data[:4])[0], len(data) - 4)
        return json.loads(data[4:])

    def test_init_and_local_status_keep_private_state_and_export_only_identity(self):
        destination = self.root / "second-state"
        result, code = self.invoke("init", "--state", destination, "--trust", self.trust_path)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["status"], "INITIALIZED")
        self.assertEqual(result["identity"], Gate(destination).public_identity())
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        observed, code = self.invoke("status", "--state", destination)
        self.assertEqual(code, 0, observed)
        self.assertEqual(observed["result"]["counter"], 0)
        again, code = self.invoke("init", "--state", destination, "--trust", self.trust_path)
        self.assertEqual(code, 2)
        self.assertEqual(again["status"], "BLOCKED")

    def test_socket_is_private_unless_explicit_group_is_configured(self):
        first = self.start_server()
        self.assertEqual(stat.S_IMODE(self.sock.stat().st_mode), 0o600)
        first.terminate()
        first.wait(timeout=3)
        self.assertFalse(self.sock.exists())
        self.start_server("--socket-gid", str(os.getegid()))
        info = self.sock.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o660)
        self.assertEqual(info.st_gid, os.getegid())

    def test_direct_dispatch_matches_core_effect_and_status_interfaces(self):
        execution = self.execution(through_socket=False)
        first = cli._dispatch(self.gate, {"op": "execute", "request": execution})
        cli._validate_response(first)
        self.assertEqual(first["result"], "COMMITTED")
        repeated = cli._dispatch(self.gate, {"op": "execute", "request": execution})
        self.assertEqual(repeated["result"], "ALREADY_COMMITTED")
        self.assertEqual(first["receipt"], repeated["receipt"])
        status = cli._dispatch(self.gate, {"op": "status", "operation_id": execution["operation_id"]})
        cli._validate_response(status)
        self.assertEqual(status["result"]["counter"], 1)

    def test_normal_denial_is_json_and_cli_exit_zero(self):
        self.start_server()
        response, code = self.invoke("request", "--socket", self.sock,
                                      document={"op": "revoke-policy"})
        self.assertEqual(code, 0, response)
        self.assertEqual(response["status"], "DENIED")
        self.assertEqual(response["reason"], "UNKNOWN_OPERATION")
        self.assertTrue(self.status()["policy_active"])

    def test_local_revocations_are_effective_but_never_rpc_operations(self):
        self.start_server()
        execution = self.execution()
        grant_id = execution["grant"]["payload"]["grant_id"]
        response, code = self.invoke("revoke-grant", "--state", self.state, "--grant-id", grant_id)
        self.assertEqual((code, response["status"]), (0, "REVOKED"))
        response, code = self.rpc({"op": "execute", "request": execution})
        self.assertEqual(code, 0, response)
        self.assertEqual(response["reason"], "GRANT_REVOKED")
        response, code = self.invoke("revoke-policy", "--state", self.state)
        self.assertEqual((code, response["status"]), (0, "REVOKED"))
        self.assertFalse(self.status()["policy_active"])
        self.assertEqual(self.status()["counter"], 0)

    def test_malicious_frames_and_unknown_fields_never_dispatch_an_effect(self):
        self.start_server()
        bodies = [b'{"op":"status","op":"execute","operation_id":null}',
                  b'{"op":"status","operation_id":null,"fault":true}',
                  b'{"op":"status","operation_id":null}{}', b'\xff',
                  b'{"op":"exit-before-commit-once"}', b'[]']
        raw_cases = [struct.pack("!I", len(b)) + b for b in bodies]
        raw_cases.extend([struct.pack("!I", 0), struct.pack("!I", cli.MAX_REQUEST_BYTES + 1),
                          struct.pack("!I", 8) + b"{}", b"\0\0"])
        good = canonical_json({"op": "status", "operation_id": None})
        raw_cases.append(struct.pack("!I", len(good)) + good + b"extra frame")
        for raw in raw_cases:
            with self.subTest(raw=raw[:100]):
                response = self.raw_request(raw)
                self.assertEqual(response["status"], "DENIED", response)
        self.assertEqual(self.status()["counter"], 0)

    def test_client_sends_one_request_then_half_closes(self):
        self.start_server()
        request_file = self.root / "request.json"
        request_file.write_bytes(canonical_json({"op": "status", "operation_id": None}))
        response, code = self.invoke("request", "--socket", self.sock, "--request", request_file)
        self.assertEqual(code, 0, response)
        self.assertEqual(response["result"]["counter"], 0)

    def test_incomplete_connections_are_bounded_and_workers_recover(self):
        self.start_server("--connection-timeout", "0.25", "--workers", "2")
        peers = []
        try:
            for _ in range(2):
                peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                peer.settimeout(2)
                peer.connect(str(self.sock))
                peer.sendall(b"\0")
                peers.append(peer)
            time.sleep(0.05)
            response, code = self.rpc({"op": "status", "operation_id": None})
            self.assertIn(response.get("status"), ("DENIED", "AMBIGUOUS"))
            self.assertIn(code, (0, 2))
            time.sleep(0.3)
        finally:
            for peer in peers:
                peer.close()
        self.assertEqual(self.status()["counter"], 0)

    def test_live_socket_cannot_be_replaced_even_by_explicit_admin_request(self):
        process = self.start_server()
        before = self.sock.stat()
        response, code = self.invoke("serve", "--state", self.state, "--socket", self.sock,
                                     "--replace-stale-socket")
        self.assertEqual(code, 2, response)
        self.assertEqual(response["reason"], "SOCKET_IN_USE")
        after = self.sock.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertIsNone(process.poll())
        self.assertEqual(self.status()["counter"], 0)

    def test_stale_socket_replacement_requires_explicit_flag(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
            stale.bind(str(self.sock))
        response, code = self.invoke("serve", "--state", self.state, "--socket", self.sock)
        self.assertEqual(code, 2, response)
        self.assertEqual(response["reason"], "SOCKET_EXISTS")
        self.start_server("--replace-stale-socket")
        self.assertEqual(self.status()["counter"], 0)

    def test_unknown_path_and_symlink_are_never_deleted(self):
        marker = b"do not replace this file"
        original = self.root / "original"
        original.write_bytes(marker)
        for symlink in (False, True):
            if symlink:
                self.sock.symlink_to(original)
            else:
                self.sock.write_bytes(marker)
            response, code = self.invoke("serve", "--state", self.state, "--socket", self.sock,
                                         "--replace-stale-socket")
            self.assertEqual(code, 2, response)
            self.assertEqual(response["reason"], "SOCKET_EXISTS")
            self.assertEqual(self.sock.read_bytes(), marker)
            self.sock.unlink()
        self.assertEqual(original.read_bytes(), marker)

    def test_writable_or_symlink_parent_is_refused(self):
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        alias = self.root / "alias"
        alias.symlink_to(unsafe, target_is_directory=True)
        for parent in (unsafe, alias):
            response, code = self.invoke("serve", "--state", self.state, "--socket", parent / "gate.sock")
            self.assertEqual(code, 2, response)
            self.assertEqual(response["reason"], "SOCKET_PARENT")
            self.assertFalse((parent / "gate.sock").exists())

    def test_oversized_server_response_never_claims_success(self):
        self.start_server(patch_code=(
            "from shirudo_adapter.action_gate import Gate\n"
            f"Gate.status = lambda self, operation_id=None: {{'oversized': 'x' * {cli.MAX_RESPONSE_BYTES}}}\n"
        ))
        response, code = self.invoke("status", "--socket", self.sock)
        self.assertEqual(code, 2, response)
        self.assertEqual((response["status"], response["reason"]), ("AMBIGUOUS", "RESPONSE_TOO_LARGE"))

    def test_missing_socket_peer_eof_and_timeout_are_ambiguous_transport_loss(self):
        response, code = self.invoke("status", "--socket", self.sock)
        self.assertEqual(code, 2, response)
        self.assertEqual((response["status"], response["reason"]), ("AMBIGUOUS", "TRANSPORT_LOST"))

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.sock))
            listener.listen(1)
            def close_connection():
                conn, _ = listener.accept()
                conn.close()
            worker = threading.Thread(target=close_connection, daemon=True)
            worker.start()
            try:
                response, code = self.invoke("status", "--socket", self.sock)
                self.assertEqual(code, 2, response)
                self.assertEqual(response["reason"], "TRANSPORT_LOST")
            finally:
                worker.join(timeout=2)

        self.sock.unlink()
        release = threading.Event()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.sock))
            listener.listen(1)
            listener.settimeout(2)
            def hold_response():
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(2)
                    while conn.recv(65_536):
                        pass
                    release.wait(timeout=2)
            worker = threading.Thread(target=hold_response, daemon=True)
            worker.start()
            try:
                response, code = self.invoke("status", "--socket", self.sock, "--timeout", "0.1")
                self.assertEqual((code, response["status"], response["reason"]),
                                 (2, "AMBIGUOUS", "TRANSPORT_LOST"))
            finally:
                release.set()
                worker.join(timeout=2)

    def test_client_rejects_oversized_or_malformed_response_frames(self):
        missing_receipt = b'{"result":"COMMITTED"}'
        for response_bytes in (struct.pack("!I", cli.MAX_RESPONSE_BYTES + 1),
                               struct.pack("!I", len(missing_receipt)) + missing_receipt):
            with self.subTest(response=response_bytes):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    if self.sock.exists():
                        self.sock.unlink()
                    listener.bind(str(self.sock))
                    listener.listen(1)
                    def reply():
                        conn, _ = listener.accept()
                        with conn:
                            conn.settimeout(2)
                            while conn.recv(65_536):
                                pass
                            conn.sendall(response_bytes)
                    worker = threading.Thread(target=reply, daemon=True)
                    worker.start()
                    try:
                        response, code = self.invoke("status", "--socket", self.sock)
                        self.assertEqual(code, 2, response)
                        self.assertEqual((response["status"], response["reason"]),
                                         ("AMBIGUOUS", "TRANSPORT_LOST"))
                    finally:
                        worker.join(timeout=2)

    def test_concurrent_duplicates_commit_once_and_return_one_signed_receipt(self):
        self.start_server()
        execution = self.execution()
        barrier = threading.Barrier(4)
        def invoke_duplicate():
            barrier.wait(timeout=3)
            return self.rpc({"op": "execute", "request": execution})
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda _: invoke_duplicate(), range(4)))
        self.assertTrue(all(code == 0 for _, code in responses), responses)
        self.assertEqual(sorted(r["result"] for r, _ in responses),
                         ["ALREADY_COMMITTED"] * 3 + ["COMMITTED"])
        receipts = [r["receipt"] for r, _ in responses]
        self.assertTrue(all(receipt == receipts[0] for receipt in receipts))
        effect = verify_record(receipts[0], self.gate.public_identity()["public_key"])
        self.assertEqual((effect["counter_before"], effect["counter_after"]), (0, 1))
        status = self.status(execution["operation_id"])
        self.assertEqual((status["counter"], status["committed_operations"]), (1, 1))

    def test_process_exit_before_commit_rolls_back_and_retry_applies_once(self):
        process = self.start_server("--exit-before-commit-once")
        execution = self.execution()
        response, code = self.invoke("request", "--socket", self.sock,
                                      document={"op": "execute", "request": execution})
        self.assertEqual((code, response["status"], response["reason"]),
                         (2, "AMBIGUOUS", "TRANSPORT_LOST"))
        self.assertEqual(process.wait(timeout=3), cli.EXIT_BEFORE_COMMIT)
        local, code = self.invoke("status", "--state", self.state,
                                  "--operation-id", execution["operation_id"])
        self.assertEqual(code, 0, local)
        self.assertEqual(local["result"]["counter"], 0)
        self.assertEqual(local["result"]["operation"]["status"], "PREPARED")
        self.start_server("--replace-stale-socket")
        response, code = self.rpc({"op": "execute", "request": execution})
        self.assertEqual((code, response["result"]), (0, "COMMITTED"))
        response, code = self.rpc({"op": "execute", "request": execution})
        self.assertEqual((code, response["result"]), (0, "ALREADY_COMMITTED"))
        self.assertEqual(self.status()["counter"], 1)

    def test_process_exit_after_commit_recovers_receipt_without_extra_effect(self):
        process = self.start_server("--exit-after-commit-once")
        execution = self.execution()
        response, code = self.invoke("request", "--socket", self.sock,
                                      document={"op": "execute", "request": execution})
        self.assertEqual((code, response["status"], response["reason"]),
                         (2, "AMBIGUOUS", "TRANSPORT_LOST"))
        self.assertEqual(process.wait(timeout=3), cli.EXIT_AFTER_COMMIT)
        local, code = self.invoke("status", "--state", self.state,
                                  "--operation-id", execution["operation_id"])
        self.assertEqual(code, 0, local)
        self.assertEqual(local["result"]["counter"], 1)
        self.assertEqual(local["result"]["operation"]["status"], "COMMITTED")
        stored = local["result"]["operation"]["receipt"]
        self.start_server("--replace-stale-socket", "--exit-after-commit-once")
        response, code = self.rpc({"op": "execute", "request": execution})
        self.assertEqual((code, response["result"]), (0, "ALREADY_COMMITTED"))
        self.assertEqual(response["receipt"], stored)
        self.assertEqual(self.status()["counter"], 1)
        changed = copy.deepcopy(execution)
        changed["grant"]["signature"] = "00" * 64
        response, code = self.rpc({"op": "execute", "request": changed})
        self.assertEqual(code, 0, response)
        self.assertEqual(response["status"], "DENIED")
        self.assertEqual(self.status()["counter"], 1)


if __name__ == "__main__":
    unittest.main()
