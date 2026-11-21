"""Target-owned signed checkpoint for the logical VOIDCELL ledger.

The target keeps the latest checkpoint in a separately retained directory.
Reopen checks compare that checkpoint with the SQLite ledger and fail closed
after any unanchored commit. Rolling back both stores together is outside the
local guarantee.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat

from alibi import H, canon, verify_sig
from .stage3_evidence import _hex


_LEASE = "ledger-anchor.lock"
_ANCHOR = "ledger-anchor.json"
_DOMAIN = b"wolfalibi/voidcell/002/target-ledger-anchor/v1"
_TYPE = "WOLFALIBI_VOIDCELL_002_LEDGER_ANCHOR_V1"
_MAX_ANCHOR_BYTES = 4096
_TABLES = (
    ("configuration", "pins, checked_at", "pins, checked_at", (bytes, int)),
    ("revoked", "grant_id, proof", "grant_id COLLATE BINARY", (str, bytes)),
    ("effects", "operation_id, dispatch_digest, outcome, receipt",
     "operation_id COLLATE BINARY", (str, str, str, bytes)),
    ("decisions", "id, dispatch_digest, receipt", "id", (int, str, bytes)),
)


class AnchorError(RuntimeError):
    """The separately retained ledger anchor cannot substantiate this state."""


class LedgerDivergence(AnchorError):
    """A verified retained anchor differs from the committed ledger or policy."""


def _private_file(item):
    return (stat.S_ISREG(item.st_mode) and item.st_uid == os.geteuid()
            and stat.S_IMODE(item.st_mode) == 0o600 and item.st_nlink == 1)


def _ledger_state(db, *, integrity, authority_policy_digest):
    if integrity and db.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
        raise AnchorError("target SQLite integrity check failed")
    digest = hashlib.sha256(b"wolfalibi/voidcell/002/logical-ledger/v1\n")

    def append(value):
        digest.update(canon(value))
        digest.update(b"\n")

    # Root pages and SQLite on-disk layout are not logical ledger state.
    for entry in db.execute("""
        SELECT type, name, tbl_name, sql FROM sqlite_schema
         ORDER BY type COLLATE BINARY, name COLLATE BINARY, tbl_name COLLATE BINARY
    """):
        append(["schema", list(entry)])

    policy_digest = None
    for table, columns, order, types in _TABLES:
        append(["table", table])
        # These SQL identifiers are fixed source constants.
        for row in db.execute(f"SELECT {columns} FROM {table} ORDER BY {order}"):
            if tuple(type(value) for value in row) != types:
                raise AnchorError("unexpected target ledger value type")
            if table == "configuration":
                if policy_digest is not None:
                    raise AnchorError("target ledger contains multiple policy rows")
                policy_digest = H(canon([H(row[0]).hex(), authority_policy_digest])).hex()
            append([value.hex() if type(value) is bytes else value for value in row])
    if policy_digest is None:
        raise AnchorError("target ledger policy row is missing")
    return {"ledger_sha256": digest.hexdigest(), "policy_sha256": policy_digest}


class LedgerAnchor:
    """Hold the target's exclusive lease across verification and an RPC."""

    def __init__(self, directory, *, signer, authority_policy):
        self._directory = self._lease = None
        self._current = None
        try:
            import fcntl

            if type(signer.pub) is not bytes or len(signer.pub) != 32:
                raise AnchorError("invalid target signing identity")
            self._signer = signer
            self._authority_policy_digest = H(authority_policy).hex()
            self._directory = os.open(
                Path(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            item = os.fstat(self._directory)
            if item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o700:
                raise AnchorError("anchor requires a target-owned mode-0700 directory")
            self._lease = os.open(
                _LEASE, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600, dir_fd=self._directory,
            )
            if not _private_file(os.fstat(self._lease)):
                raise AnchorError("invalid anchor lease file")
            fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._check_lease()
        except (ImportError, AttributeError, OSError, TypeError, ValueError) as exc:
            self.close()
            raise AnchorError("exclusive target anchor lease unavailable") from exc
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self._current = None
        lease, directory = self._lease, self._directory
        self._lease = self._directory = None
        try:
            if lease is not None:
                os.close(lease)
        finally:
            if directory is not None:
                os.close(directory)

    def _check_lease(self):
        if self._lease is None:
            raise AnchorError("target anchor lease is closed")
        try:
            held = os.fstat(self._lease)
            present = os.stat(_LEASE, dir_fd=self._directory, follow_symlinks=False)
        except OSError as exc:
            raise AnchorError("target anchor lease disappeared") from exc
        if not _private_file(present) or (held.st_dev, held.st_ino) != (present.st_dev, present.st_ino):
            raise AnchorError("target anchor lease was replaced")

    @contextmanager
    def _snapshot(self, vault, *, integrity):
        self._check_lease()
        try:
            if vault._signer.pub != self._signer.pub:
                raise AnchorError("target ledger signer does not match the anchor signer")
            db = vault._db
            if db.in_transaction:
                raise AnchorError("checkpoint requires a committed target ledger")
            with vault._lock:
                if db.in_transaction:
                    raise AnchorError("checkpoint requires a committed target ledger")
                db.execute("BEGIN IMMEDIATE")
                try:
                    yield _ledger_state(db, integrity=integrity,
                                        authority_policy_digest=self._authority_policy_digest)
                finally:
                    db.rollback()
        except (AttributeError, sqlite3.Error, OSError) as exc:
            raise AnchorError("target ledger unavailable for checkpointing") from exc

    def _read(self):
        try:
            fd = os.open(
                _ANCHOR, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=self._directory,
            )
            with os.fdopen(fd, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not _private_file(metadata) or not 0 < metadata.st_size <= _MAX_ANCHOR_BYTES:
                    raise AnchorError("invalid retained anchor file")
                raw = stream.read(_MAX_ANCHOR_BYTES + 1)
                if len(raw) != metadata.st_size:
                    raise AnchorError("retained anchor changed during read")
        except OSError as exc:
            raise AnchorError("could not read retained ledger anchor") from exc

        try:
            record = json.loads(raw)
            if (type(record) is not dict or record.keys() != {"payload", "signature"}
                    or canon(record) != raw):
                raise ValueError("invalid canonical anchor")
            payload = record["payload"]
            if type(payload) is not dict or payload.keys() != {
                    "type", "target_pub", "generation", "previous_anchor_sha256",
                    "ledger_sha256", "policy_sha256"}:
                raise ValueError("invalid anchor payload")
            if payload["type"] != _TYPE or payload["target_pub"] != self._signer.pub.hex():
                raise ValueError("wrong anchor target")
            generation = payload["generation"]
            previous = payload["previous_anchor_sha256"]
            if type(generation) is not int or not 0 <= generation < (1 << 63):
                raise ValueError("invalid anchor generation")
            if generation == 0:
                if previous is not None:
                    raise ValueError("unexpected genesis predecessor")
            else:
                _hex(previous, 32, "anchor predecessor")
            _hex(payload["ledger_sha256"], 32, "ledger digest")
            _hex(payload["policy_sha256"], 32, "policy digest")
            signature = _hex(record["signature"], 64, "anchor signature")
            if not verify_sig(self._signer.pub, _DOMAIN, canon(payload), signature):
                raise ValueError("invalid target anchor signature")
        except (ValueError, TypeError, RuntimeError) as exc:
            raise AnchorError("retained ledger anchor is invalid") from exc
        return payload, H(raw).hex()

    def _publish(self, state, generation, previous, *, create_only):
        payload = {
            "type": _TYPE, "target_pub": self._signer.pub.hex(), "generation": generation,
            "previous_anchor_sha256": previous, **state,
        }
        raw = canon({
            "payload": payload, "signature": self._signer.sign(_DOMAIN, canon(payload)).hex(),
        })
        temporary = ".ledger-anchor-" + secrets.token_hex(16)
        created = False
        try:
            fd = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600, dir_fd=self._directory,
            )
            created = True
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                if stream.write(raw) != len(raw):
                    raise OSError("short ledger anchor write")
                stream.flush()
                os.fsync(stream.fileno())
            self._check_lease()
            if create_only:
                os.link(temporary, _ANCHOR, src_dir_fd=self._directory,
                        dst_dir_fd=self._directory, follow_symlinks=False)
                os.unlink(temporary, dir_fd=self._directory)
            else:
                os.replace(temporary, _ANCHOR, src_dir_fd=self._directory, dst_dir_fd=self._directory)
            created = False
            os.fsync(self._directory)
        except OSError as exc:
            raise AnchorError("could not durably publish target ledger anchor") from exc
        finally:
            if created:
                try:
                    os.unlink(temporary, dir_fd=self._directory)
                except FileNotFoundError:
                    pass
        return payload, H(raw).hex()

    def initialize(self, vault):
        """Create a genesis checkpoint without replacing an existing anchor."""
        self._current = None
        with self._snapshot(vault, integrity=True) as state:
            current = self._publish(state, 0, None, create_only=True)
        self._current = current
        return self.public_summary()

    def verify(self, vault):
        """Require the latest retained checkpoint to match committed SQL state."""
        previous, self._current = self._current, None
        with self._snapshot(vault, integrity=True) as state:
            payload, digest = self._read()
            if previous is not None and previous[1] != digest:
                raise AnchorError("retained ledger anchor changed under the active lease")
            if any(payload[name] != value for name, value in state.items()):
                raise LedgerDivergence("target ledger differs from the separately retained anchor")
        self._current = payload, digest
        return self.public_summary()

    def advance(self, vault):
        """Checkpoint a trusted commit made under this verified target lease."""
        previous, self._current = self._current, None
        if previous is None:
            raise AnchorError("authenticate the retained anchor before advancing")
        with self._snapshot(vault, integrity=False) as state:
            payload, digest = self._read()
            if previous[1] != digest:
                raise AnchorError("retained ledger anchor changed under the active lease")
            if payload["policy_sha256"] != state["policy_sha256"]:
                raise AnchorError("target ledger policy changed during RPC")
            if any(payload[name] != value for name, value in state.items()):
                generation = payload["generation"] + 1
                if generation >= (1 << 63):
                    raise AnchorError("target ledger anchor generation exhausted")
                payload, digest = self._publish(state, generation, digest, create_only=False)
        self._current = payload, digest
        return self.public_summary()

    def public_summary(self):
        """Expose only the authenticated generation and digests."""
        if self._current is None:
            raise AnchorError("target ledger anchor has not been verified")
        payload, digest = self._current
        return {
            "generation": payload["generation"], "anchor_sha256": digest,
            "ledger_sha256": payload["ledger_sha256"], "policy_sha256": payload["policy_sha256"],
        }
