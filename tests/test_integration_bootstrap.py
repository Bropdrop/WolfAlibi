"""Archive custody tests; generated ELF bytes are never executed."""

import hashlib
import io
import tarfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import prepare_shirudo_binary as prepare


def package(member_type=tarfile.REGTYPE, duplicate=False, executable=b"\x7fELFfixture"):
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w:gz") as archive:
        item = tarfile.TarInfo(prepare.EXECUTABLE_MEMBER)
        item.type = member_type
        if member_type == tarfile.REGTYPE:
            item.size = len(executable)
            archive.addfile(item, io.BytesIO(executable))
        else:
            item.linkname = "/unrelated/destination"
            archive.addfile(item)
        if duplicate:
            item = tarfile.TarInfo(prepare.EXECUTABLE_MEMBER)
            item.size = len(executable)
            archive.addfile(item, io.BytesIO(executable))
    result = io.BytesIO()
    with zipfile.ZipFile(result, mode="w") as archive:
        archive.writestr("shirudo.tar.gz", b"unused")
        archive.writestr("shirudo-static.tar.gz", tar_bytes.getvalue())
    return result.getvalue()


class ArtifactCustodyTests(unittest.TestCase):
    def extract_fixture(self, data, executable=b"\x7fELFfixture"):
        with patch.object(prepare, "ARCHIVE_SHA256", hashlib.sha256(data).hexdigest()), \
                patch.object(prepare, "EXECUTABLE_SHA256", hashlib.sha256(executable).hexdigest()):
            return prepare.extract_binary(data)

    def test_only_the_exact_regular_executable_is_returned(self):
        self.assertEqual(self.extract_fixture(package()), b"\x7fELFfixture")

    def test_unapproved_archive_is_rejected_before_parsing(self):
        with self.assertRaisesRegex(ValueError, "archive SHA-256"):
            prepare.extract_binary(b"not an approved ZIP")

    def test_symbolic_and_hard_links_are_never_followed(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "regular executable"):
                self.extract_fixture(package(member_type=kind))

    def test_duplicate_executable_member_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "one bounded regular executable"):
            self.extract_fixture(package(duplicate=True))

    def test_approved_archive_cannot_override_executable_pin(self):
        with self.assertRaisesRegex(ValueError, "ELF SHA-256"):
            self.extract_fixture(package(executable=b"\x7fELFdifferent"))


if __name__ == "__main__":
    unittest.main()
