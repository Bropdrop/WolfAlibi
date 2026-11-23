#!/usr/bin/env python3
"""Extract only the approved static executable from the pinned CI artifact."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

SOURCE_COMMIT = "fb97c1ec5908c8bdbd46760c29e57677977fce74"
ARTIFACT_ID = 14865910776
ARCHIVE_SHA256 = "e830f2384383adccba7c423e8afe81d1fd0b3d6e27e66ce2aed49eae632e989c"
EXECUTABLE_SHA256 = "be8b79cdd7efb8e635b7965bf34fa691e5e4a378957f3829530a529097abe9d2"
EXECUTABLE_MEMBER = "shirudo-static-image/root/usr/local/bin/shirudo"
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXECUTABLE = 32 * 1024 * 1024


def extract_binary(archive: bytes) -> bytes:
    if len(archive) > MAX_ARCHIVE or hashlib.sha256(archive).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("Official archive SHA-256 or size does not match")
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        entries = package.infolist()
        if (len(entries) != 2 or {item.filename for item in entries} !=
                {"shirudo.tar.gz", "shirudo-static.tar.gz"}):
            raise ValueError("Unsupported official archive layout")
        member = package.getinfo("shirudo-static.tar.gz")
        if member.file_size > MAX_ARCHIVE:
            raise ValueError("Static tar archive exceeds the size bound")
        compressed = package.read(member)
    with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as package:
        matches = [item for item in package if item.name == EXECUTABLE_MEMBER]
        if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= MAX_EXECUTABLE:
            raise ValueError("Expected one bounded regular executable member")
        stream = package.extractfile(matches[0])
        if stream is None:
            raise ValueError("Executable member is unavailable")
        data = stream.read(MAX_EXECUTABLE + 1)
    if (not data.startswith(b"\x7fELF") or len(data) > MAX_EXECUTABLE or
            hashlib.sha256(data).hexdigest() != EXECUTABLE_SHA256):
        raise ValueError("Official ELF SHA-256 does not match")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"schema": "wolfalibi.shirudo.artifact.v1", "source_commit": SOURCE_COMMIT,
              "artifact_id": ARTIFACT_ID, "archive_sha256": ARCHIVE_SHA256,
              "executable_sha256": EXECUTABLE_SHA256,
              "source_association": "UPSTREAM_GITHUB_WORKFLOW_METADATA"}
    try:
        if args.archive.stat().st_size > MAX_ARCHIVE:
            raise ValueError("Artifact ZIP exceeds the size bound")
        data = extract_binary(args.archive.read_bytes())
        destination = args.output / "shirudo"
        with destination.open("xb") as stream:
            stream.write(data)
        destination.chmod(0o500)
        report.update(result="PASS", executable_bytes=len(data))
        code = 0
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        report.update(result="BLOCKED", error=str(error))
        code = 1
    (args.output / "artifact.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
