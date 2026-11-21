"""Synthetic checks for VOIDCELL custody inventory and ordinary opens."""

import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from alibi import Signer, canon
from wolfalibi import voidcell002_probe as custody


@unittest.skipUnless(custody._linux() and hasattr(os, "O_PATH"), "Linux file-open controls required")
class CustodyProbeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="wolfalibi-custody-")
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.key = self.directory / "target.key"
        self.ledger = self.directory / "ledger.sqlite"
        for file, body in ((self.key, b"synthetic key placeholder"), (self.ledger, b"synthetic ledger placeholder")):
            file.write_bytes(body)
            file.chmod(0o600)
        self.target = Signer()
        self.state = {
            "uid": os.getuid() + 1, "target_uid": os.getuid(), "target_pid": os.getpid(),
            "target_start_ticks": custody._start_ticks("self"),
        }

    def _inventory(self, version=2, **changes):
        directory, key, ledger = (path.stat() for path in (self.directory, self.key, self.ledger))
        payload = {
            "type": custody._INVENTORY_V1_TYPE, "pid": self.state["target_pid"],
            "target_uid": self.state["target_uid"], "gateway_uid": self.state["uid"],
            "state_device": str(directory.st_dev), "state_inode": str(directory.st_ino),
            "key_mode": 0o600, "ledger_mode": 0o600,
        }
        domain = custody._INVENTORY_DOMAIN
        if version == 2:
            payload.update(type=custody._INVENTORY_V2_TYPE, target_start_ticks=self.state["target_start_ticks"],
                           key_device=str(key.st_dev), key_inode=str(key.st_ino),
                           ledger_device=str(ledger.st_dev), ledger_inode=str(ledger.st_ino))
            domain = custody._INVENTORY_V2_DOMAIN
        payload.update(changes)
        return {"payload": payload, "signature": self.target.sign(domain, canon(payload)).hex()}

    def _observe(self, inventory=None, target_pub=None):
        return custody._file_observations(self.directory, self.state, inventory=inventory, target_pub=target_pub)

    def test_preflight_and_same_uid_are_unsupported_without_target_contact(self):
        self.assertEqual(custody.preflight()["outcome"], "UNSUPPORTED")
        with patch.object(custody, "_probe_live") as live:
            result = custody.probe(os.getuid(), target_pid=os.getpid(), state_dir=self.directory,
                                   socket_path=self.directory / "unused")
        self.assertEqual(result["outcome"], "UNSUPPORTED")
        live.assert_not_called()

    def test_inaccessible_target_process_is_blocked_before_path_access(self):
        ordinary = custody.preflight()
        ordinary.update(uid=1000, euid=1000, gid=1000, egid=1000, linux=True)
        credentials = {"Uid": (1000,) * 4, "Gid": (1000,) * 4, "capabilities": custody._ZERO_CAPS}
        if not hasattr(os, "pidfd_open"):
            self.skipTest("Linux pidfd support required")
        with patch.object(custody, "preflight", return_value=ordinary), \
                patch.object(custody, "_status", return_value=credentials), \
                patch.object(os, "pidfd_open", side_effect=ProcessLookupError(errno.ESRCH, "synthetic exit")), \
                patch.object(custody, "_probe_live") as live:
            result = custody.probe(1001, target_pid=1, state_dir=self.directory,
                                   socket_path=self.directory / "unused")
        self.assertEqual(result["outcome"], "BLOCKED")
        live.assert_not_called()

    def test_actual_accessible_files_open_without_create_or_truncate_and_stay_unchanged(self):
        before = [(path.stat(), path.read_bytes()) for path in (self.key, self.ledger)]
        with patch.object(os, "open", wraps=os.open) as opening:
            result = self._observe(self._inventory(), self.target.pub)
        opens = [(args[0], args[1]) for args, kwargs in opening.call_args_list if "dir_fd" in kwargs]
        self.assertEqual([(path, flags & os.O_ACCMODE) for path, flags in opens], [
            ("target.key", os.O_RDONLY), ("target.key", os.O_WRONLY),
            ("ledger.sqlite", os.O_RDONLY), ("ledger.sqlite", os.O_WRONLY),
        ])
        self.assertTrue(all(not flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND) for _, flags in opens))
        self.assertEqual(result["file_identity_basis"], "INDEPENDENT_STAT")
        self.assertEqual(list(result["file_open_results"].values()),
                         [{"outcome": "OPENED", "errno": None}] * 4)
        for (original, data), path in zip(before, (self.key, self.ledger)):
            self.assertEqual(path.read_bytes(), data)
            after = path.stat()
            self.assertEqual((after.st_ino, after.st_size, after.st_mtime_ns),
                             (original.st_ino, original.st_size, original.st_mtime_ns))

    def test_hidden_metadata_uses_versioned_inventory_and_checks_four_denials(self):
        real_open = os.open

        def deny_file(path, flags, *args, **kwargs):
            if path in ("target.key", "ledger.sqlite"):
                code = errno.EPERM if flags & os.O_ACCMODE == os.O_WRONLY else errno.EACCES
                raise PermissionError(code, "simulated ordinary open denial")
            return real_open(path, flags, *args, **kwargs)

        for version, basis in ((1, "OWNER_ATTESTED_DIRECTORY_ONLY"), (2, "OWNER_ATTESTED_DEVICE_INODE")):
            inventory = self._inventory(version)
            with self.subTest(version=version), \
                    patch.object(custody, "_file_stat_pair", side_effect=PermissionError(errno.EACCES, "hidden")), \
                    patch.object(os, "open", side_effect=deny_file):
                result = self._observe(inventory, self.target.pub)
            self.assertEqual(result["file_existence_basis"], "OWNER_ATTESTED")
            self.assertEqual(result["file_identity_basis"], basis)
            self.assertEqual(result["file_open_results"], {
                "target_key_read": {"outcome": "DENIED", "errno": "EACCES"},
                "target_key_write": {"outcome": "DENIED", "errno": "EPERM"},
                "ledger_read": {"outcome": "DENIED", "errno": "EACCES"},
                "ledger_write": {"outcome": "DENIED", "errno": "EPERM"},
            })

    def test_hidden_metadata_requires_expected_signer_and_live_object_bindings(self):
        unsigned = self._inventory()
        key = unsigned["payload"]
        mismatches = (
            (None, self.target.pub),
            (unsigned, Signer().pub),
            (self._inventory(target_start_ticks=str(int(self.state["target_start_ticks"]) + 1)), self.target.pub),
            (self._inventory(state_inode=str(self.directory.stat().st_ino + 1)), self.target.pub),
            (self._inventory(ledger_device=key["key_device"], ledger_inode=key["key_inode"]), self.target.pub),
        )
        for inventory, pin in mismatches:
            with self.subTest(inventory=inventory is not None), \
                    patch.object(custody, "_file_stat_pair", side_effect=PermissionError(errno.EACCES, "hidden")), \
                    patch.object(custody, "_observe_open") as opening:
                with self.assertRaises((OSError, ValueError)):
                    self._observe(inventory, pin)
                opening.assert_not_called()

    def test_visible_state_substitutions_are_refused_even_with_signed_inventory(self):
        inventory = self._inventory()
        self.ledger.rename(self.directory / "previous-ledger")
        with self.assertRaises(FileNotFoundError):
            self._observe(inventory, self.target.pub)
        self.ledger.write_bytes(b"replaced synthetic ledger")
        self.ledger.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "visible target files differ"):
            self._observe(inventory, self.target.pub)


if __name__ == "__main__":
    unittest.main()
