#!/usr/bin/env python3
"""Offline intake for manually redacted, fictional public-lab findings.

This utility only validates and stores a finding in the review inbox explicitly
named by the operator.  It makes no network requests, invokes no shell, and
does not attempt automated secret detection: submitters must redact inputs
themselves and use fictional data only.

The stored representation is canonical JSON addressed by its SHA-256 digest.
The inbox is opened without following symlinks, and a completed entry is
published with an atomic hard-link operation after its contents are fsynced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any


FINDING_SCHEMA = "quorvane.public-lab.finding.v1"
RECEIPT_SCHEMA = "quorvane.public-lab.finding-receipt.v1"
DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / "public_lab" / "manifest.json"

_EXPERIMENTS = frozenset({"education", "finance", "history"})
_VARIANTS = frozenset({"genuine", "tampered"})
_FINDING_FIELDS = frozenset({
    "schema", "experiment", "variant", "artifact_sha256", "manifest_sha256",
    "environment", "steps", "expected", "observed",
})
_TEXT_FIELDS = ("environment", "steps", "expected", "observed")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_FINDING_BYTES = 32 * 1024
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_TEXT_BYTES = 4096
_MAX_STORED_BYTES = 32 * 1024


class FindingError(ValueError):
    """A submission or its local storage boundary is unsuitable."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class FindingConflict(FindingError):
    """A content-addressed destination exists with different bytes."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FindingError("MALFORMED_JSON")
        result[key] = value
    return result


def _invalid_number(_: str) -> None:
    raise FindingError("MALFORMED_JSON")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _read_regular(path: Path | str, *, maximum: int, error: str) -> bytes:
    """Read one bounded regular file without following its final symlink."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise FindingError("UNSUPPORTED_SAFE_OPEN")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow
    try:
        descriptor = os.open(os.fspath(path), flags)
    except OSError as exc:
        raise FindingError(error) from exc
    try:
        item = os.fstat(descriptor)
        if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
            raise FindingError(error)
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(8192, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > maximum:
                raise FindingError(error)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _parse_json(raw: bytes, *, code: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                          parse_constant=_invalid_number)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, FindingError) as exc:
        raise FindingError(code) from exc


def _is_hash(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def _manifest_artifact(manifest_raw: bytes, experiment: str, variant: str) -> str:
    manifest = _parse_json(manifest_raw, code="INVALID_MANIFEST")
    if not isinstance(manifest, dict) or type(manifest.get("experiments")) is not list:
        raise FindingError("INVALID_MANIFEST")
    matches = [entry for entry in manifest["experiments"]
               if isinstance(entry, dict) and entry.get("id") == experiment]
    if len(matches) != 1:
        raise FindingError("INVALID_MANIFEST")
    files = matches[0].get("files")
    if not isinstance(files, dict):
        raise FindingError("INVALID_MANIFEST")
    artifact = files.get(f"{variant}.json")
    if not _is_hash(artifact):
        raise FindingError("INVALID_MANIFEST")
    return artifact


def _validate_finding(raw: bytes, manifest_raw: bytes) -> tuple[dict[str, str], bytes, str]:
    finding = _parse_json(raw, code="MALFORMED_FINDING")
    if not isinstance(finding, dict) or set(finding) != _FINDING_FIELDS:
        raise FindingError("MALFORMED_FINDING")
    if finding.get("schema") != FINDING_SCHEMA:
        raise FindingError("MALFORMED_FINDING")
    experiment = finding.get("experiment")
    variant = finding.get("variant")
    if (type(experiment) is not str or type(variant) is not str
            or experiment not in _EXPERIMENTS or variant not in _VARIANTS):
        raise FindingError("MALFORMED_FINDING")
    if not _is_hash(finding.get("artifact_sha256")) or not _is_hash(finding.get("manifest_sha256")):
        raise FindingError("MALFORMED_FINDING")
    for field in _TEXT_FIELDS:
        value = finding[field]
        if type(value) is not str or not value.strip() or "\x00" in value:
            raise FindingError("MALFORMED_FINDING")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            # JSON permits escaped lone surrogates, but they cannot be stored
            # as canonical UTF-8 evidence.  Treat them as malformed ingress.
            raise FindingError("MALFORMED_FINDING") from exc
        if len(encoded) > _MAX_TEXT_BYTES:
            raise FindingError("MALFORMED_FINDING")

    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if finding["manifest_sha256"] != manifest_sha256:
        raise FindingError("STALE_MANIFEST_REFERENCE")
    expected_artifact = _manifest_artifact(manifest_raw, experiment, variant)
    if finding["artifact_sha256"] != expected_artifact:
        raise FindingError("STALE_ARTIFACT_REFERENCE")

    # The exact field checks above make this cast safe and preserve strict JSON types.
    typed = {key: finding[key] for key in _FINDING_FIELDS}
    stored = _canonical(typed)
    return typed, stored, hashlib.sha256(stored).hexdigest()


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise FindingError("UNSUPPORTED_SAFE_OPEN")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _open_inbox(inbox: Path | str) -> int:
    """Open or create the final inbox component through trusted directory FDs.

    Refusing ``..`` and opening each component with ``O_NOFOLLOW`` prevents a
    submitter-controlled inbox spelling from escaping through a symlink.  The
    inbox must be private to the effective user; otherwise an untrusted peer
    could replace temporary names between durable write and publication.
    """
    raw_path = os.fspath(inbox)
    if not isinstance(raw_path, str) or not raw_path:
        raise FindingError("UNSAFE_INBOX")
    path = Path(raw_path)
    parts = list(path.parts)
    absolute = path.is_absolute()
    if absolute:
        parts = parts[1:]
    parts = [part for part in parts if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise FindingError("UNSAFE_INBOX")

    flags = _directory_flags()
    try:
        current = os.open("/" if absolute else ".", flags)
    except OSError as exc:
        raise FindingError("UNSAFE_INBOX") from exc
    try:
        for part in parts[:-1]:
            try:
                following = os.open(part, flags, dir_fd=current)
            except OSError as exc:
                raise FindingError("UNSAFE_INBOX") from exc
            os.close(current)
            current = following

        leaf = parts[-1]
        try:
            inbox_fd = os.open(leaf, flags, dir_fd=current)
        except FileNotFoundError:
            try:
                os.mkdir(leaf, 0o700, dir_fd=current)
            except FileExistsError:
                pass
            except OSError as exc:
                raise FindingError("UNSAFE_INBOX") from exc
            try:
                os.fsync(current)
                inbox_fd = os.open(leaf, flags, dir_fd=current)
            except OSError as exc:
                raise FindingError("UNSAFE_INBOX") from exc
        except OSError as exc:
            raise FindingError("UNSAFE_INBOX") from exc
    finally:
        os.close(current)

    try:
        item = os.fstat(inbox_fd)
        if (not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid()
                or item.st_mode & 0o022):
            raise FindingError("UNSAFE_INBOX")
        return inbox_fd
    except BaseException:
        os.close(inbox_fd)
        raise


def _existing_entry(directory: int, name: str, expected: bytes) -> bool:
    """Return true for an exact stored duplicate; reject every other object."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise FindingError("UNSUPPORTED_SAFE_OPEN")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise FindingConflict("CONTENT_ADDRESS_CONFLICT") from exc
    try:
        item = os.fstat(descriptor)
        # A concurrent publisher exposes the final name by hard-linking its
        # already-fsynced private temporary file, then removes that temporary
        # name.  During that narrow interval the exact regular file has two
        # links; no other sharing is accepted.
        if not stat.S_ISREG(item.st_mode) or item.st_nlink not in (1, 2):
            raise FindingConflict("CONTENT_ADDRESS_CONFLICT")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(8192, _MAX_STORED_BYTES + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > _MAX_STORED_BYTES:
                raise FindingConflict("CONTENT_ADDRESS_CONFLICT")
        if b"".join(chunks) != expected:
            raise FindingConflict("CONTENT_ADDRESS_CONFLICT")
        return True
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise FindingError("STORAGE_UNAVAILABLE")
        view = view[count:]


def _store(directory: int, digest: str, content: bytes) -> str:
    """Store bytes once, atomically publishing only a fully fsynced file."""
    name = f"{digest}.json"
    if _existing_entry(directory, name, content):
        return "DUPLICATE"

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise FindingError("UNSUPPORTED_SAFE_OPEN")
    temporary = f".{digest}.tmp.{os.getpid()}.{secrets.token_hex(16)}"
    descriptor: int | None = None
    published = False
    try:
        try:
            descriptor = os.open(temporary,
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow,
                                 0o600, dir_fd=directory)
        except OSError as exc:
            raise FindingError("STORAGE_UNAVAILABLE") from exc
        _write_all(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory,
                    follow_symlinks=False)
            published = True
            os.fsync(directory)
            return "ACCEPTED"
        except FileExistsError:
            # A concurrent writer can only publish after its own fsync.
            if _existing_entry(directory, name, content):
                return "DUPLICATE"
            raise FindingConflict("CONTENT_ADDRESS_CONFLICT")
        except OSError as exc:
            raise FindingError("STORAGE_UNAVAILABLE") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
            if published:
                os.fsync(directory)
        except FileNotFoundError:
            pass
        except OSError:
            # The result is already safe: only a private inbox owner can retain a
            # failed temporary artifact.  Do not alter a published entry to clean it.
            pass


def submit_file(finding_path: Path | str, inbox: Path | str,
                *, manifest_path: Path | str | None = None) -> dict[str, str]:
    """Validate one finding against the fixed public manifest and store it locally."""
    if manifest_path is None:
        manifest_path = DEFAULT_MANIFEST
    finding_raw = _read_regular(finding_path, maximum=_MAX_FINDING_BYTES,
                                error="MALFORMED_FINDING")
    manifest_raw = _read_regular(manifest_path, maximum=_MAX_MANIFEST_BYTES,
                                 error="INVALID_MANIFEST")
    finding, stored, finding_sha256 = _validate_finding(finding_raw, manifest_raw)
    directory = _open_inbox(inbox)
    try:
        outcome = _store(directory, finding_sha256, stored)
    finally:
        os.close(directory)
    return {
        "schema": RECEIPT_SCHEMA,
        "outcome": outcome,
        "finding_sha256": finding_sha256,
        "artifact_sha256": finding["artifact_sha256"],
        "manifest_sha256": finding["manifest_sha256"],
        "stored_as": f"{finding_sha256}.json",
    }


def _error_receipt(error: FindingError) -> dict[str, str]:
    outcome = "CONFLICT" if isinstance(error, FindingConflict) else "REJECTED"
    return {"schema": RECEIPT_SCHEMA, "outcome": outcome, "reason": error.code}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    submit = commands.add_parser("submit", help="store one validated finding in a local inbox")
    submit.add_argument("finding", help="strict JSON finding file with manually redacted fictional data")
    submit.add_argument("--inbox", required=True,
                        help="private local review inbox (created if its parent already exists)")
    args = parser.parse_args(argv)
    try:
        receipt = submit_file(args.finding, args.inbox)
    except FindingError as exc:
        receipt = _error_receipt(exc)
        status = 3 if isinstance(exc, FindingConflict) else 2
    else:
        status = 0
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
