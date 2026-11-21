"""Resource-owner ledger for one fictional education read."""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
from threading import RLock
import time

from alibi import H, Signer, canon
from .education_records import (
    check_admission_time, check_packet, receipt, snapshot_packet,
    validate_identifier, validate_peer, validate_scope,
)
from .solitary_cli import _unique_object
from .stage3_evidence import _hex
from .voidcell002 import (
    KEY_FILE, _file_id, _owner_file, _private_directory, _read_private,
    _static_file_state, _sync_directory, init_key,
)
from .voidcell002_anchor import LedgerAnchor


CONFIG_FILE = "config.json"
LEDGER_FILE = "ledger.sqlite"
_LEASE_FILE = "education-target.lock"
_ANCHOR_FILE = "ledger-anchor.json"
_PIN_FIELDS = ("owner_pub", "supervisor_pub", "witness_pub")
_CONFIG_FIELDS = {"scope", "peer", "witness_head_path", *_PIN_FIELDS}
_RESPONSE = {"student_ref": "fictional-aster", "support_level": "scheduled-check-in"}
_MAX_HANDOFF_SAMPLES = 3


class EducationTargetError(RuntimeError):
    """The fictional resource owner cannot substantiate target state."""


def _clock_time():
    try:
        return int(time.time())
    except (OverflowError, TypeError, ValueError) as exc:
        raise EducationTargetError("invalid process clock") from exc


def _checked_now():
    now = _clock_time()
    if type(now) is not int or not 0 <= now < 2**63:
        raise EducationTargetError("invalid process clock")
    return now


def _witness_lineage(path, owner):
    lineage = []
    for directory in (path, *path.parents):
        item = directory.lstat()
        sticky_root = item.st_uid == 0 and item.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(item.st_mode)
                or item.st_uid not in {0, owner, os.geteuid()}
                or (item.st_mode & 0o022 and not sticky_root)):
            raise EducationTargetError("untrusted witness directory")
        lineage.append((item.st_dev, item.st_ino))
    return tuple(lineage)


def _deny(reason):
    return {"outcome": "DENIED", "reason": reason}


def _blocked(reason):
    return {"outcome": "BLOCKED", "reason": reason}


@dataclass(frozen=True)
class _Delivery:
    result: dict
    authorized_at: int
    deadline: int
    witness_head: bytes


class EducationTarget:
    """Authorize, record and checkpoint a single one-use fictional read.

    Admission samples the target clock after authentication and commits its
    evidence before handoff. Handoff rechecks the witnessed reference and
    deadline after checkpointing. A failed handoff leaves the admission
    terminal, so reconciliation can recover only the receipt.
    """

    def __init__(self, state_dir, anchor_dir, *, create=False):
        self._lock = RLock()
        self._resources = ExitStack()
        self._blocked = False
        try:
            self._state, self._state_lineage = _private_directory(state_dir)
            self._anchor_dir, self._anchor_lineage = _private_directory(anchor_dir)
            if (self._state_lineage[0] in self._anchor_lineage
                    or self._anchor_lineage[0] in self._state_lineage):
                raise EducationTargetError("retain the checkpoint outside the target state tree")
            self._open(create)
        except (OSError, sqlite3.Error, TypeError, ValueError, RuntimeError) as exc:
            self.close()
            if isinstance(exc, EducationTargetError):
                raise
            raise EducationTargetError("target state could not be authenticated") from exc
        except BaseException:
            self.close()
            raise

    def _open(self, create):
        lease_path = self._state / _LEASE_FILE
        fd = os.open(lease_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        self._resources.callback(os.close, fd)
        lease = _owner_file(os.fstat(fd))
        self._lease_id = (lease.st_dev, lease.st_ino)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        config_path, key_path = self._state / CONFIG_FILE, self._state / KEY_FILE
        self._config_state = _static_file_state(config_path)
        self._key_state = _static_file_state(key_path)
        config = json.loads(_read_private(config_path, 8192), object_pairs_hook=_unique_object)
        seed = _read_private(key_path, 32)
        if len(seed) != 32 or type(config) is not dict or config.keys() != _CONFIG_FIELDS:
            raise EducationTargetError("invalid provisioned target identity or configuration")
        self._signer = Signer(seed)
        self._scope = validate_scope(config["scope"])
        if self._scope["target_pub"] != self.target_pub.hex():
            raise EducationTargetError("scope does not name the provisioned target key")
        self._peer = validate_peer(config["peer"])
        self._keys = {name: _hex(config[name], 32, name) for name in _PIN_FIELDS}
        if len({self._signer.pub, bytes.fromhex(self._scope["caller_pub"]),
                *self._keys.values()}) != 5:
            raise EducationTargetError("distinct caller, target and issuer keys required")

        witness_path = config["witness_head_path"]
        if (type(witness_path) is not str or not os.path.isabs(witness_path)
                or os.path.normpath(witness_path) != witness_path):
            raise EducationTargetError("an exact absolute witness head path is required")
        self._witness = Path(witness_path)
        self._witness_owner = self._witness.lstat().st_uid
        self._witness_lineage = _witness_lineage(self._witness.parent, self._witness_owner)
        if (self._state_lineage[0] in self._witness_lineage
                or self._anchor_lineage[0] in self._witness_lineage):
            raise EducationTargetError("retain the witness head outside the target state and checkpoint")
        self._witness_head()

        self._operation_id = H(canon(self._scope)).hex()
        pins = canon({
            "profile": "education-read",
            "config": config,
            "target_pub": self.target_pub.hex(),
            "witness_owner": self._witness_owner,
            "witness_directory": [str(value) for value in self._witness_lineage[0]],
        })
        self._anchor = self._resources.enter_context(
            LedgerAnchor(self._anchor_dir, signer=self._signer, authority_policy=pins),
        )
        self._open_ledger(pins, create)
        self._files_unchanged()
        if create:
            self._anchor.initialize(self)
        else:
            self._anchor.verify(self)

    def _open_ledger(self, pins, create):
        ledger = self._state / LEDGER_FILE
        journal = self._state / (LEDGER_FILE + "-journal")
        sidecars = [self._state / (LEDGER_FILE + suffix) for suffix in ("-wal", "-shm")]
        if any(os.path.lexists(path) for path in sidecars):
            raise EducationTargetError("unexpected target ledger sidecar")
        if create:
            if any(os.path.lexists(path) for path in (journal, self._anchor_dir / _ANCHOR_FILE)):
                raise EducationTargetError("target enrollment is create-only")
            fd = os.open(ledger, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                _owner_file(os.fstat(fd))
            finally:
                os.close(fd)
        elif os.path.lexists(journal):
            _file_id(journal)
        self._ledger_id = _file_id(ledger)
        self._db = sqlite3.connect(ledger.as_uri() + "?mode=rw", uri=True, isolation_level=None,
                                   check_same_thread=False)
        self._resources.callback(self._db.close)
        self._db.execute("PRAGMA trusted_schema = OFF")
        self._db.execute("PRAGMA synchronous = FULL")
        if self._db.execute("PRAGMA journal_mode").fetchone() != ("delete",):
            raise EducationTargetError("target requires a durable SQLite rollback journal")
        if create:
            # These typed columns are shared with the signed logical checkpoint.
            self._db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE configuration (pins BLOB NOT NULL, checked_at INTEGER NOT NULL);
                CREATE TABLE revoked (grant_id TEXT PRIMARY KEY, proof BLOB NOT NULL);
                CREATE TABLE effects (
                    operation_id TEXT PRIMARY KEY,
                    dispatch_digest TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK (outcome IN ('RELEASED', 'FENCED')),
                    receipt BLOB NOT NULL
                );
                CREATE TABLE decisions (
                    id INTEGER PRIMARY KEY, dispatch_digest TEXT NOT NULL, receipt BLOB NOT NULL
                );
            """)
            self._db.execute("INSERT INTO configuration VALUES (?, ?)", (pins, _checked_now()))
            self._db.commit()
            _sync_directory(self._state)
        if self._db.execute("SELECT pins FROM configuration").fetchall() != [(pins,)]:
            raise EducationTargetError("target ledger has different authority pins")

    @property
    def target_pub(self):
        return self._signer.pub

    @property
    def scope(self):
        return json.loads(canon(self._scope))

    @property
    def peer(self):
        return self._peer.copy()

    def _witness_head(self):
        lineage = _witness_lineage(self._witness.parent, self._witness_owner)
        if lineage != self._witness_lineage:
            raise EducationTargetError("witness directory changed")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open(self._witness, flags), "rb") as stream:
            item = os.fstat(stream.fileno())
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != self._witness_owner
                    or item.st_nlink != 1 or item.st_mode & 0o022 or item.st_size not in (64, 65)):
                raise EducationTargetError("invalid retained witness file")
            raw = stream.read(66)
            current = self._witness.lstat()
            if (len(raw) != item.st_size or (len(raw) == 65 and not raw.endswith(b"\n"))
                    or (item.st_dev, item.st_ino, item.st_ctime_ns) !=
                    (current.st_dev, current.st_ino, current.st_ctime_ns)):
                raise EducationTargetError("witness head changed during read")
        if _witness_lineage(self._witness.parent, self._witness_owner) != lineage:
            raise EducationTargetError("witness directory changed during read")
        return _hex(raw[:64].decode("ascii"), 32, "witness head")

    def _files_unchanged(self):
        if (_private_directory(self._state)[1] != self._state_lineage
                or _private_directory(self._anchor_dir)[1] != self._anchor_lineage
                or _file_id(self._state / _LEASE_FILE) != self._lease_id
                or _file_id(self._state / LEDGER_FILE) != self._ledger_id
                or _static_file_state(self._state / CONFIG_FILE) != self._config_state
                or _static_file_state(self._state / KEY_FILE) != self._key_state):
            raise EducationTargetError("target ledger, checkpoint directory or trust pins changed")

    @contextmanager
    def _transaction(self):
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._db.commit()
        except BaseException:
            if self._db.in_transaction:
                self._db.rollback()
            raise

    def _observe_time(self, now):
        update = self._db.execute(
            "UPDATE configuration SET checked_at = ? WHERE checked_at <= ?", (now, now),
        )
        return update.rowcount == 1

    def _invoke(self, operation):
        with self._lock:
            if self._blocked:
                return _blocked("TARGET_STATE_UNAVAILABLE")
            try:
                self._files_unchanged()
                self._anchor.verify(self)
                with self._transaction():
                    now = _checked_now()
                    if not self._observe_time(now):
                        return _blocked("TARGET_CLOCK_REGRESSION")
                    result = operation(now)
                self._files_unchanged()
                self._anchor.advance(self)
                if isinstance(result, _Delivery):
                    return self._handoff(result)
                return result
            except (OSError, sqlite3.Error, TypeError, ValueError, RuntimeError):
                self._blocked = True
                return _blocked("TARGET_STATE_UNAVAILABLE")

    def _handoff(self, delivery):
        retained_time = delivery.authorized_at
        for _ in range(_MAX_HANDOFF_SAMPLES):
            try:
                current_head = self._witness_head()
            except (OSError, ValueError, RuntimeError):
                current_head = None
            now = _checked_now()
            if now < retained_time:
                return _blocked("TARGET_CLOCK_REGRESSION")
            resampled = now > retained_time
            if resampled:
                with self._transaction():
                    if not self._observe_time(now):
                        return _blocked("TARGET_CLOCK_REGRESSION")
                self._files_unchanged()
                self._anchor.advance(self)
                retained_time = now
            if now >= delivery.deadline:
                return _deny("AUTHORIZATION_EXPIRED_BEFORE_HANDOFF")
            if current_head != delivery.witness_head:
                return _blocked("WITNESS_HEAD_CHANGED_BEFORE_HANDOFF")
            if not resampled:
                return delivery.result
        return _blocked("TARGET_HANDOFF_CLOCK_UNSTABLE")

    def handle(self, action, packet, peer):
        """Use the authenticated transport peer for a read or reconciliation."""
        return self._invoke(lambda now: self._access(action, packet, peer, now))

    def _access(self, action, packet, peer, now):
        if type(action) is not str or action not in ("read", "reconcile"):
            return _deny("UNKNOWN_TARGET_ACTION")
        try:
            peer = validate_peer(peer)
            packet = snapshot_packet(packet)
        except (TypeError, ValueError, RuntimeError):
            return _deny("INVALID_TARGET_REQUEST")
        if peer != self._peer:
            return _deny("PEER_MISMATCH")
        try:
            witness_head = self._witness_head()
        except (OSError, TypeError, ValueError, RuntimeError):
            return _blocked("WITNESS_HEAD_UNAVAILABLE")
        try:
            grant_id = check_packet(
                packet, expected_scope=self._scope, peer=peer, now=now,
                witness_head=witness_head, **self._keys,
            )
        except (TypeError, ValueError, RuntimeError):
            return _deny("AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
        if self._db.execute("SELECT 1 FROM revoked WHERE grant_id = ?", (grant_id,)).fetchone():
            return _deny("OWNER_GRANT_REVOKED")
        if self._scope["tenant"] != "fictional-school" or self._scope["student"] != "fictional-aster":
            return _deny("FIXTURE_OUT_OF_SCOPE")

        try:
            current_head = self._witness_head()
        except (OSError, ValueError, RuntimeError):
            current_head = None
        authorized_at = _checked_now()
        if not self._observe_time(authorized_at):
            return _blocked("TARGET_CLOCK_REGRESSION")
        if current_head != witness_head:
            return _blocked("WITNESS_HEAD_CHANGED_BEFORE_ADMISSION")
        try:
            deadline = check_admission_time(packet, authorized_at)
        except ValueError:
            return _deny("AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED")
        digest = H(canon(packet)).hex()
        saved = self._db.execute(
            "SELECT dispatch_digest, outcome, receipt FROM effects WHERE operation_id = ?",
            (self._operation_id,),
        ).fetchone()
        if saved is not None:
            if saved[1] == "FENCED":
                return _deny("READ_FENCED")
            if action == "reconcile" and digest == saved[0]:
                result = {"outcome": "RECONCILED", "receipt": json.loads(saved[2])}
                return _Delivery(result, authorized_at, deadline, witness_head)
            return _deny("READ_ALREADY_RECORDED")
        if action == "reconcile":
            self._db.execute("INSERT INTO effects VALUES (?, ?, 'FENCED', ?)",
                             (self._operation_id, digest, b""))
            return _deny("READ_FENCED")

        response = _RESPONSE.copy()
        signed = receipt(self._signer, self._scope, packet, response, authorized_at)
        evidence = canon({"packet": packet, "response": response, "receipt": signed,
                          "observed_peer": peer, "observed_witness_head": witness_head.hex()})
        self._db.execute("INSERT INTO effects VALUES (?, ?, 'RELEASED', ?)",
                         (self._operation_id, digest, canon(signed)))
        self._db.execute("INSERT INTO decisions (dispatch_digest, receipt) VALUES (?, ?)",
                         (digest, evidence))
        result = {"outcome": "RELEASED", "response": response, "receipt": signed}
        return _Delivery(result, authorized_at, deadline, witness_head)

    def revoke(self, grant_id):
        """Record a revocation through the local target administrator API."""
        def record(now):
            try:
                validate_identifier(grant_id, "grant ID")
            except ValueError:
                return _deny("INVALID_GRANT_ID")
            self._db.execute("INSERT OR IGNORE INTO revoked VALUES (?, ?)", (grant_id, canon(now)))
            return {"outcome": "REVOKED"}

        return self._invoke(record)

    def status(self):
        """Report committed admissions, including any with a lost or withheld body."""
        with self._lock:
            if not self._blocked:
                try:
                    self._files_unchanged()
                    anchor = self._anchor.verify(self)
                    count, = self._db.execute(
                        "SELECT COUNT(*) FROM effects WHERE outcome = 'RELEASED'",
                    ).fetchone()
                    return {"outcome": "READY", "target_pub": self.target_pub.hex(),
                            "release_count": count, "anchor": anchor}
                except (OSError, sqlite3.Error, TypeError, ValueError, RuntimeError):
                    self._blocked = True
            return _blocked("TARGET_STATE_UNAVAILABLE")

    def close(self):
        with self._lock:
            self._blocked = True
            self._resources.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
