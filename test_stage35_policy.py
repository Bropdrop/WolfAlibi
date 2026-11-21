"""Synthetic transport, durability, and denied-attempt qualification."""

import array
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from alibi import (Broker, BrokerClosed, DENIED, H, NotEmpty, OPS, Signer, Witness,
                   canon, dec_entry, exact, verify_alibi)
from wolfalibi import stage3


def _reference():
    contract = {
        "run_id": "synthetic-policy-qualification",
        "challenge": "ab" * 32,
        "key": stage3.FIXTURE_KEY,
        "fixture_sha256": H(stage3.FIXTURE_BYTES).hex(),
    }
    request = {
        "type": "read", "run_id": contract["run_id"], "challenge": contract["challenge"],
        "seq": 1, "key": contract["key"], "direct_denied": True, "canary_closed": True,
    }
    return contract, request


class Stage35PacketBoundaryTests(unittest.TestCase):
    def test_malformed_or_noncanonical_request_is_never_dispatched(self):
        contract, request = _reference()
        for label, packet in (
            ("invalid UTF-8", b"\xff"),
            ("incomplete JSON", canon(request)[:-1]),
            ("noncanonical JSON", json.dumps(request, sort_keys=True).encode()),
        ):
            with self.subTest(label=label):
                broker = Mock(spec=Broker)
                server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                with server, client, patch.object(stage3, "_send") as send:
                    client.sendall(packet)
                    with self.assertRaisesRegex(stage3.TrialBlocked, "did not match"):
                        stage3._serve(server, broker, contract, time.monotonic() + 2)
                    self.assertEqual(broker.mock_calls, [])
                    send.assert_not_called()

    def test_oversized_packet_is_rejected_before_dispatch(self):
        contract, request = _reference()
        broker = Mock(spec=Broker)
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with server, client, patch.object(stage3, "_send") as send:
            client.sendall(canon(request) + b" " * stage3.MAX_PACKET)
            with self.assertRaisesRegex(stage3.TrialBlocked, "truncated packet"):
                stage3._serve(server, broker, contract, time.monotonic() + 2)
            self.assertEqual(broker.mock_calls, [])
            send.assert_not_called()

    def test_request_with_test_descriptor_is_rejected_and_descriptor_discarded(self):
        contract, request = _reference()
        broker = Mock(spec=Broker)
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with server, client, tempfile.TemporaryFile() as canary, patch.object(stage3, "_send") as send:
            canary.write(b"synthetic ancillary descriptor")
            expected = os.fstat(canary.fileno())

            def canary_descriptors():
                found = []
                for entry in Path("/proc/self/fd").iterdir():
                    fd = int(entry.name)
                    try:
                        current = os.fstat(fd)
                    except OSError:
                        continue
                    if (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino):
                        found.append(fd)
                return found

            self.assertEqual(canary_descriptors(), [canary.fileno()])
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [canary.fileno()]))]
            self.assertEqual(client.sendmsg([canon(request)], ancillary), len(canon(request)))
            with self.assertRaisesRegex(stage3.TrialBlocked, "unexpected control data"):
                stage3._serve(server, broker, contract, time.monotonic() + 2)
            self.assertEqual(canary_descriptors(), [canary.fileno()])
            self.assertEqual(broker.mock_calls, [])
            send.assert_not_called()


class Stage35PolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="wolfalibi-stage35-policy-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "resources"
        self.root.mkdir()
        (self.root / stage3.FIXTURE_KEY).write_bytes(stage3.FIXTURE_BYTES)
        self.journal = Path(directory.name) / "broker.wal"
        self.signer = Signer()
        self.witness = Witness()
        self.contract, self.request = _reference()

    def _broker(self, **options):
        return Broker(self.root, self.signer, self.witness, journal=self.journal, **options)

    def test_allowed_read_returns_fixture_and_commits_the_read_key(self):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with self._broker() as broker, server, client:
            client.sendall(canon(self.request))
            client.sendall(canon({"type": "done", "data_sha256": self.contract["fixture_sha256"]}))
            digest = stage3._serve(server, broker, self.contract, time.monotonic() + 2)
            client.settimeout(2)
            self.assertEqual(client.recv(stage3.MAX_PACKET),
                             canon({"type": "data", "data": stage3.FIXTURE_BYTES.hex()}))
            self.assertEqual(digest, self.contract["fixture_sha256"])
            epoch = broker.seal()["epoch"]
            self.assertEqual([dec_entry(leaf) for leaf in broker.sealed[epoch]["leaves"]], [
                (self.contract["key"].encode(), (OPS["r"], 1, 1)),
            ])
            with self.assertRaises(NotEmpty):
                broker.prove_empty(*exact(self.contract["key"]), epoch, epoch)

    def test_in_range_denial_refutes_absence_without_a_response(self):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with self._broker(deny=(self.contract["key"],)) as broker, server, client:
            start = broker.seal()["epoch"]
            lo, hi = exact(self.contract["key"])
            before = broker.prove_empty(lo, hi, start, start)
            verified = verify_alibi(before, self.signer.pub, self.witness.signer.pub,
                                    lo, hi, (start, start))
            self.assertEqual(verified["events_covered"], 0)
            client.sendall(canon(self.request))
            with patch.object(stage3, "_send") as send:
                with self.assertRaises(PermissionError):
                    stage3._serve(server, broker, self.contract, time.monotonic() + 2)
                send.assert_not_called()
            end = broker.seal()["epoch"]
            self.assertEqual([dec_entry(leaf) for leaf in broker.sealed[end]["leaves"]], [
                (self.contract["key"].encode(), (OPS["r"] | DENIED, 1, 1)),
            ])
            with self.assertRaises(NotEmpty):
                broker.prove_empty(lo, hi, start, end)

    def test_wal_sync_failure_closes_broker_before_open_or_release(self):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with self._broker() as broker, server, client:
            client.sendall(canon(self.request))
            with patch("alibi.os.fsync", side_effect=OSError("synthetic WAL sync failure")) as sync, \
                    patch.object(broker, "_safe_open", wraps=broker._safe_open) as open_file, \
                    patch.object(stage3, "_send") as send:
                with self.assertRaisesRegex(OSError, "synthetic WAL sync failure"):
                    stage3._serve(server, broker, self.contract, time.monotonic() + 2)
                sync.assert_called_once()
                open_file.assert_not_called()
                send.assert_not_called()
            with self.assertRaises(BrokerClosed):
                broker.seal()
            self.assertEqual(broker.sealed, {})
            self.assertEqual(self.witness.heads, {})

        # The completed write is visible on this live host despite the failed
        # sync. Recovery keeps the attempt, with no terminal checkpoint.
        with self._broker() as recovered:
            self.assertEqual(recovered.seq, 1)
            self.assertIn(self.contract["key"].encode(), recovered.cur)
            self.assertEqual(recovered.sealed, {})


if __name__ == "__main__":
    unittest.main()
