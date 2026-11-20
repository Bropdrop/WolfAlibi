#!/usr/bin/env python3
"""WolfTrap ALIBI security regression suite — original implementation: 4 FAIL.

The tests check fail-closed properties rather than mandating any particular fix.
Run: python3 -m unittest -v test_wolftrap_alibi.py
Synthetic temporary directories only; no network or real user data.
"""
import os
import pathlib
import tempfile
import threading
import unittest
from unittest.mock import patch

from alibi import (AlibiError, Broker, NotEmpty, Signer, Witness,
                   WitnessRefused, subtree, verify_alibi, _sandbox)


class WolfTrapAlibi(unittest.TestCase):
    def test_epoch_barrier_prevents_false_nonaccess(self):
        """Do not seal an epoch between authorization log and sensitive-data release."""
        with tempfile.TemporaryDirectory(prefix="wt-alibi-epoch-") as root:
            _sandbox(root)
            signer, witness = Signer(), Witness()
            br = Broker(root, signer, witness)
            access_paused = threading.Event()
            release_access = threading.Event()
            seal_started = threading.Event()
            seal_finished = threading.Event()
            data_read, errors = [], []

            def pause_after_record(_path):
                access_paused.set()
                if not release_access.wait(4):
                    raise TimeoutError("test coordination timed out")

            def reader():
                try:
                    data_read.append(br.read("finance/q3.xlsx"))
                except Exception as exc:
                    errors.append(exc)

            def sealer():
                seal_started.set()
                try:
                    br.seal()
                except Exception as exc:
                    errors.append(exc)
                finally:
                    seal_finished.set()

            br._pre_open_hook = pause_after_record  # simulate normal inter-thread pause
            r = threading.Thread(target=reader)
            s = threading.Thread(target=sealer)
            r.start()
            try:
                self.assertTrue(access_paused.wait(3), "reader did not reach boundary")
                s.start()
                self.assertTrue(seal_started.wait(3), "sealer did not start")
                sealed_while_read_inflight = seal_finished.wait(0.3)
            finally:
                release_access.set()
                r.join(timeout=4)
                if s.ident is not None:
                    s.join(timeout=4)
                br._pre_open_hook = None
            self.assertFalse(r.is_alive())
            self.assertFalse(s.is_alive())
            self.assertFalse(errors, errors)
            self.assertEqual(data_read, [b"REVENUE ..."])
            lo, hi = subtree("finance")

            if sealed_while_read_inflight:
                # The sealer published epoch 0 before data release. The next
                # epoch must include the still-in-flight read (or refuse proof).
                br.seal()
                try:
                    proof = br.prove_empty(lo, hi, 1, 1)
                    verify_alibi(proof, signer.pub, witness.signer.pub, lo, hi, (1, 1))
                except (NotEmpty, AlibiError):
                    return
                self.fail("False nonaccess proof: finance data released in epoch 1, but epoch 1 proves empty")
            else:
                # A quiescence-barrier implementation would seal epoch 0 only
                # after the read completes, and refuse an epoch 0 exclusion.
                with self.assertRaises(NotEmpty):
                    br.prove_empty(lo, hi, 0, 0)

    def test_shared_identity_does_not_publish_partial_epoch(self):
        """Independent in-memory brokers must not silently share one signer+journal."""
        with tempfile.TemporaryDirectory(prefix="wt-alibi-identity-") as root:
            _sandbox(root)
            journal = os.path.join(root, "events.log")
            signer, witness = Signer(), Witness()
            try:
                br_a = Broker(root, signer, witness, journal=journal)
                br_b = Broker(root, signer, witness, journal=journal)
                self.assertEqual(br_a.read("docs/notes.txt"), b"meeting notes")
                self.assertEqual(br_b.read("finance/q3.xlsx"), b"REVENUE ...")
                br_a.seal()
                lo, hi = subtree("finance")
                proof = br_a.prove_empty(lo, hi, 0, 0)
                verify_alibi(proof, signer.pub, witness.signer.pub, lo, hi, (0, 0))
            except (NotEmpty, AlibiError, WitnessRefused, PermissionError, OSError, RuntimeError):
                # Any explicit fail-closed refusal is acceptable for this test.
                return
            self.fail("False nonaccess proof: second broker's finance read omitted from checkpoint")

    def test_short_journal_write_cannot_create_false_alibi_after_restart(self):
        """A successful but partial os.write must never release unlogged data."""
        with tempfile.TemporaryDirectory(prefix="wt-alibi-shortwrite-") as root:
            _sandbox(root)
            journal = os.path.join(root, "events.log")
            signer, witness = Signer(), Witness()
            br = Broker(root, signer, witness, journal=journal)
            real_write = os.write
            fault_injected = []

            def short_write(fd, data):
                if fd == br._jfd and not fault_injected:
                    fault_injected.append(True)
                    return real_write(fd, data[:15])  # legitimate short write return
                return real_write(fd, data)

            with patch("alibi.os.write", side_effect=short_write):
                try:
                    data = br.read("finance/q3.xlsx")
                except OSError:
                    # Correct: fail closed on unexpected short write.
                    self.assertTrue(fault_injected)
                    return
            self.assertTrue(fault_injected)
            self.assertEqual(data, b"REVENUE ...")

            # Simulate process crash: discard current in-memory broker state.
            # Replay must either retain the event or refuse to serve a proof.
            try:
                restarted = Broker(root, signer, witness, journal=journal)
                restarted.seal()
                lo, hi = subtree("finance")
                proof = restarted.prove_empty(lo, hi, 0, 0)
                verify_alibi(proof, signer.pub, witness.signer.pub, lo, hi, (0, 0))
            except (NotEmpty, AlibiError, WitnessRefused, OSError, ValueError):
                return
            self.fail("False nonaccess proof: successful short write lost the finance read on restart")

    def test_raced_write_never_creates_outside_file(self):
        """A blocked directory-swap race must cause no outside-root side effect."""
        with tempfile.TemporaryDirectory(prefix="wt-alibi-write-root-") as root, \
             tempfile.TemporaryDirectory(prefix="wt-alibi-write-outside-") as outside:
            pathlib.Path(root, "pub").mkdir()
            br = Broker(root, Signer(), Witness())

            def swap_parent(_path):
                os.rename(os.path.join(root, "pub"), os.path.join(root, "pub-saved"))
                os.symlink(outside, os.path.join(root, "pub"))

            br._pre_open_hook = swap_parent
            with self.assertRaises(PermissionError):
                br.write("pub/new.txt", b"SECRET")
            self.assertFalse(pathlib.Path(outside, "new.txt").exists(),
                             "O_CREAT created an outside file before race detection")


if __name__ == "__main__":
    unittest.main(verbosity=2)