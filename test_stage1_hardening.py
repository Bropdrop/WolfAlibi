"""Stage 1 regressions for durable, single-writer filesystem evidence.

All fixtures are temporary directories with the synthetic data from alibi.py.
These tests deliberately exercise fault paths that ordinary filesystems rarely
hit, so that a passing happy-path run is not mistaken for durable evidence.
"""
import errno
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import alibi
from alibi import (Broker, BrokerClosed, JournalError, NotEmpty, Signer,
                   Witness, _sandbox, subtree)


HERE = os.path.dirname(os.path.abspath(__file__))


class JournalHardening(unittest.TestCase):
    SEED = bytes(range(32))

    def _broker(self, seed=SEED):
        root = tempfile.TemporaryDirectory(prefix="stage1-journal-")
        _sandbox(root.name)
        journal = os.path.join(root.name, "events.wal")
        signer, witness = Signer(seed), Witness()
        return root, journal, signer, witness, Broker(root.name, signer, witness, journal=journal)

    def test_short_write_is_retried_before_data_release_and_survives_restart(self):
        root, journal, signer, witness, broker = self._broker()
        self.addCleanup(root.cleanup)
        real_write, injected = os.write, []

        def short_once(fd, data):
            if fd == broker._jfd and not injected:
                injected.append(True)
                return real_write(fd, data[:max(1, len(data) // 3)])
            return real_write(fd, data)

        with patch("alibi.os.write", side_effect=short_once):
            self.assertEqual(broker.read("finance/q3.xlsx"), b"REVENUE ...")
        self.assertEqual(injected, [True])
        broker.close()

        restarted = Broker(root.name, signer, witness, journal=journal)
        self.addCleanup(restarted.close)
        restarted.seal()
        with self.assertRaises(NotEmpty):
            restarted.prove_empty(*subtree("finance"), 0, 0)

    def test_eintr_is_retried_but_zero_progress_fails_closed(self):
        root, _journal, _signer, _witness, broker = self._broker()
        self.addCleanup(root.cleanup)
        self.addCleanup(broker.close)
        real_write, interrupted = os.write, []

        def eintr_once(fd, data):
            if fd == broker._jfd and not interrupted:
                interrupted.append(True)
                raise OSError(errno.EINTR, "synthetic interruption")
            return real_write(fd, data)

        with patch("alibi.os.write", side_effect=eintr_once):
            self.assertEqual(broker.read("docs/notes.txt"), b"meeting notes")
        self.assertEqual(interrupted, [True])

        root2, _journal2, _signer2, _witness2, broken = self._broker(bytes(reversed(self.SEED)))
        self.addCleanup(root2.cleanup)
        self.addCleanup(broken.close)

        def zero_progress(fd, data):
            if fd == broken._jfd:
                return 0
            return real_write(fd, data)

        with patch("alibi.os.write", side_effect=zero_progress):
            with self.assertRaises(OSError):
                broken.read("finance/q3.xlsx")
        self.assertEqual(broken.cur, {})
        with self.assertRaises(BrokerClosed):
            broken.seal()

    def test_incomplete_tail_is_removed_but_complete_corruption_is_refused(self):
        root, journal, signer, witness, broker = self._broker()
        self.addCleanup(root.cleanup)
        broker.read("finance/q3.xlsx")
        broker.close()
        with open(journal, "ab", buffering=0) as f:
            f.write(alibi.JOURNAL_MAGIC + b"\x00")

        recovered = Broker(root.name, signer, witness, journal=journal)
        self.addCleanup(recovered.close)
        recovered.seal()
        with self.assertRaises(NotEmpty):
            recovered.prove_empty(*subtree("finance"), 0, 0)
        recovered.close()

        # Flip a byte in a complete frame digest.  Recovery must reject it,
        # rather than silently discarding a potentially released operation.
        payload = pathlib.Path(journal).read_bytes()
        pathlib.Path(journal).write_bytes(payload[:-1] + bytes([payload[-1] ^ 1]))
        with self.assertRaises(JournalError):
            Broker(root.name, signer, witness, journal=journal)

    def test_complete_unframed_tail_is_not_silently_omitted(self):
        root, journal, _signer, _witness, broker = self._broker()
        self.addCleanup(root.cleanup)
        broker.read("docs/notes.txt")
        broker.close()
        with open(journal, "ab", buffering=0) as f:
            f.write(b'{"t":"e","seq":2}\n')
        with self.assertRaises(JournalError):
            Broker(root.name, Signer(self.SEED), Witness(), journal=journal)


class WriterLeaseAndPathHardening(unittest.TestCase):
    def test_missing_openat2_blocks_broker_startup(self):
        with tempfile.TemporaryDirectory(prefix="stage1-openat2-") as root:
            _sandbox(root)
            with patch("alibi._openat2", side_effect=OSError(errno.ENOSYS, "synthetic unsupported")):
                with self.assertRaises(JournalError):
                    Broker(root, Signer(), Witness())

    def test_live_writer_lease_blocks_same_and_other_processes(self):
        with tempfile.TemporaryDirectory(prefix="stage1-lease-") as root:
            _sandbox(root)
            journal = os.path.join(root, "events.wal")
            first = Broker(root, Signer(), Witness(), journal=journal)
            self.addCleanup(first.close)
            with self.assertRaises(JournalError):
                Broker(root, Signer(), Witness(), journal=journal)
            first.close()

            code = (
                "import sys,time\n"
                f"sys.path.insert(0,{HERE!r})\n"
                "from alibi import Broker,Signer,Witness\n"
                f"b=Broker({root!r},Signer(),Witness(),journal={journal!r})\n"
                "print('READY', flush=True)\n"
                "time.sleep(20)\n"
            )
            proc = subprocess.Popen([sys.executable, "-c", code], cwd=HERE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
            try:
                self.assertEqual(proc.stdout.readline().strip(), "READY")
                with self.assertRaises(JournalError):
                    Broker(root, Signer(), Witness(), journal=journal)
            finally:
                proc.terminate()
                proc.communicate(timeout=5)

            replacement = Broker(root, Signer(), Witness(), journal=journal)
            replacement.close()

    def test_signing_identity_lease_blocks_in_memory_split_brain(self):
        with tempfile.TemporaryDirectory(prefix="stage1-identity-") as root:
            _sandbox(root)
            signer, witness = Signer(), Witness()
            first = Broker(root, signer, witness)
            try:
                with self.assertRaises(JournalError):
                    Broker(root, signer, Witness())
            finally:
                first.close()
            replacement = Broker(root, signer, Witness())
            replacement.close()

    def test_writes_refuse_symlinked_components_without_side_effects(self):
        with tempfile.TemporaryDirectory(prefix="stage1-path-") as root:
            pathlib.Path(root, "real").mkdir()
            os.symlink("real", os.path.join(root, "alias"))
            broker = Broker(root, Signer(), Witness())
            self.addCleanup(broker.close)
            with self.assertRaises(PermissionError):
                broker.write("alias/new.txt", b"synthetic")
            self.assertFalse(pathlib.Path(root, "real", "new.txt").exists())

    def test_invalid_write_buffer_cannot_create_an_empty_target(self):
        with tempfile.TemporaryDirectory(prefix="stage1-write-buffer-") as root:
            pathlib.Path(root, "out").mkdir()
            broker = Broker(root, Signer(), Witness())
            self.addCleanup(broker.close)
            with self.assertRaises(TypeError):
                broker.write("out/should-not-exist.txt", "not bytes")
            self.assertFalse(pathlib.Path(root, "out", "should-not-exist.txt").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
