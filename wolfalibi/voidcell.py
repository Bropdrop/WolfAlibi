"""Resource-owned policy and durable effects for the offline VOIDCELL fixture."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import stat
from threading import Lock
import time

from alibi import canon
from .solitary_evidence import verify_solitary
from .voidcell_records import (
    check_dispatch, check_grant, check_reconcile, check_revocation, dispatch_digest,
    make_scope, sign_receipt, snapshot_dispatch,
)


class VaultError(RuntimeError):
    """Required resource-owned state is unavailable."""


class EffectVault:
    """Apply a single synthetic increment atomically with its target receipt."""

    def __init__(self, path, *, signer, owner_pub, gateway_pub, broker_pub, witness_pub,
                 supervisor_pub, contract, operation_id, expected_witness_state_digest,
                 observe_witness_head, clock=time.time):
        keys = (signer.pub, owner_pub, gateway_pub, broker_pub, witness_pub, supervisor_pub)
        if any(type(key) is not bytes or len(key) != 32 for key in keys) or len(set(keys)) != len(keys):
            raise VaultError("distinct pinned owner, target, gateway and qualification keys required")
        self._signer = signer
        self._owner = owner_pub
        self._gateway = gateway_pub
        contract = json.loads(canon(contract))
        self._scope = make_scope(
            contract, gateway_pub=gateway_pub, target_pub=signer.pub, operation_id=operation_id,
            expected_witness_state_digest=expected_witness_state_digest,
        )
        self._qualification = dict(
            contract=contract, broker_pub=broker_pub, witness_pub=witness_pub,
            supervisor_pub=supervisor_pub, expected_witness_state_digest=expected_witness_state_digest,
        )
        self._observe_head = observe_witness_head
        self._clock = clock
        self._lock = Lock()
        path = Path(path).absolute()
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise VaultError("target ledger requires a private owner-controlled directory")
        pins = canon({"scope": self._scope, "keys": [key.hex() for key in keys]})
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            fresh = False
            item = path.lstat()
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid()
                    or item.st_mode & 0o077 or item.st_nlink != 1):
                raise VaultError("invalid target ledger")
        else:
            fresh = True
            os.close(fd)
        self._db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, isolation_level=None,
                                   check_same_thread=False)
        try:
            self._db.execute("PRAGMA synchronous = FULL")
            journal, = self._db.execute("PRAGMA journal_mode").fetchone()
            if journal not in {"delete", "wal"}:
                raise VaultError("target requires a durable SQLite journal")
            if fresh:
                self._initialize(pins)
                fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            if self._db.execute("SELECT pins FROM configuration").fetchone() != (pins,):
                raise VaultError("target ledger has different trust pins")
        except BaseException:
            self.close()
            raise

    @property
    def scope(self):
        return self._scope.copy()

    def _initialize(self, pins):
        self._db.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE configuration (pins BLOB NOT NULL, checked_at INTEGER NOT NULL);
            CREATE TABLE revoked (grant_id TEXT PRIMARY KEY, proof BLOB NOT NULL);
            CREATE TABLE effects (
                operation_id TEXT PRIMARY KEY,
                dispatch_digest TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK (outcome IN ('ACCEPTED_EVIDENCED', 'FENCED')),
                receipt BLOB NOT NULL
            );
            CREATE TABLE decisions (id INTEGER PRIMARY KEY, dispatch_digest TEXT NOT NULL, receipt BLOB NOT NULL);
            CREATE INDEX decision_dispatch ON decisions(dispatch_digest);
            COMMIT;
        """)
        now = self._clock_time()
        if self._qualification["contract"]["expires_at"] > now + 120:
            raise VaultError("qualification window exceeds 120 seconds")
        self._db.execute("INSERT INTO configuration VALUES (?, ?)", (pins, now))

    def _clock_time(self):
        try:
            now = int(self._clock())
        except (TypeError, ValueError, OverflowError) as exc:
            raise VaultError("trusted resource clock unavailable") from exc
        if not 0 <= now < 2**63 - 120:
            raise VaultError("trusted resource clock outside supported range")
        return now

    def _now(self):
        now = self._clock_time()
        updated = self._db.execute("UPDATE configuration SET checked_at = ? WHERE checked_at <= ?", (now, now))
        if updated.rowcount != 1:
            raise VaultError("trusted resource clock moved backward")
        return now

    @contextmanager
    def _transaction(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.commit()
            except BaseException:
                if self._db.in_transaction:
                    self._db.rollback()
                raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        with self._lock:
            self._db.close()

    def effect_count(self):
        """Read the synthetic counter from the ledger that owns the effect."""
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM effects WHERE outcome = 'ACCEPTED_EVIDENCED'").fetchone()[0]

    def _record(self, digest, now, outcome, reason):
        receipt = sign_receipt(self._signer, scope=self._scope, dispatch_sha256=digest,
                               checked_at=now, outcome=outcome, reason=reason)
        self._db.execute("INSERT INTO decisions (dispatch_digest, receipt) VALUES (?, ?)", (digest, canon(receipt)))
        if outcome in ("ACCEPTED_EVIDENCED", "FENCED"):
            self._db.execute("INSERT INTO effects VALUES (?, ?, ?, ?)",
                             (self._scope["operation_id"], digest, outcome, canon(receipt)))
        return {"outcome": outcome, "receipt": receipt}

    def _saved_effect(self):
        return self._db.execute("SELECT dispatch_digest, outcome, receipt FROM effects WHERE operation_id = ?",
                                (self._scope["operation_id"],)).fetchone()

    def _saved_denial(self, digest):
        # Called only while no effect or fence exists, so earlier records for
        # this dispatch can only be denials.
        row = self._db.execute("SELECT receipt FROM decisions WHERE dispatch_digest = ? ORDER BY id LIMIT 1",
                               (digest,)).fetchone()
        return {"outcome": "DENIED", "receipt": json.loads(row[0])} if row else None

    def dispatch(self, packet):
        try:
            packet = snapshot_dispatch(packet)
            digest = dispatch_digest(packet)
        except (TypeError, ValueError, RuntimeError):
            return {"outcome": "DENIED", "reason": "INVALID_GATEWAY_DISPATCH"}
        try:
            with self._transaction():
                return self._dispatch(packet, digest)
        except (VaultError, OSError, sqlite3.Error):
            return {"outcome": "BLOCKED", "reason": "TARGET_STATE_UNAVAILABLE"}

    def _dispatch(self, packet, digest):
        now = self._now()
        try:
            check_dispatch(packet, gateway_pub=self._gateway, scope=self._scope)
        except ValueError:
            return self._record(digest, now, "DENIED", "GATEWAY_OR_SCOPE_UNVERIFIED")
        saved = self._saved_effect()
        if saved is not None:
            if saved[0] == digest and saved[1] == "FENCED":
                return {"outcome": "FENCED", "receipt": json.loads(saved[2])}
            return self._record(digest, now, "DENIED", "OPERATION_ALREADY_FINAL")
        denied = self._saved_denial(digest)
        if denied is not None:
            return denied
        deadline = self._qualification["contract"]["expires_at"]
        if now >= deadline:
            return self._record(digest, now, "DENIED", "QUALIFICATION_EXPIRED")
        qualified = verify_solitary(packet["qualification"], **self._qualification, now=now)
        if qualified["outcome"] != "VERIFIED":
            return self._record(digest, now, "DENIED", "QUALIFICATION_UNVERIFIED")
        try:
            owner = check_grant(packet["grant"], owner_pub=self._owner, scope=self._scope, now=now)
        except ValueError:
            return self._record(digest, now, "DENIED", "OWNER_GRANT_UNVERIFIED")
        if self._db.execute("SELECT 1 FROM revoked WHERE grant_id = ?", (owner["grant_id"],)).fetchone():
            return self._record(digest, now, "DENIED", "OWNER_GRANT_REVOKED")
        try:
            head = self._observe_head()
        except (OSError, ValueError, RuntimeError):
            head = None
        if type(head) is not bytes or head.hex() != qualified["witness_state_digest"]:
            return self._record(digest, now, "DENIED", "WITNESS_HEAD_UNAVAILABLE_OR_CONFLICTING")
        now = self._now()
        if now >= min(deadline, owner["expires_at"]):
            return self._record(digest, now, "DENIED", "AUTHORITY_EXPIRED_AT_EFFECT")
        return self._record(digest, now, "ACCEPTED_EVIDENCED", "COUNTER_INCREMENT_COMMITTED")

    def revoke(self, record):
        try:
            record = json.loads(canon(record))
            grant_id = check_revocation(record, owner_pub=self._owner, scope=self._scope)
        except (TypeError, ValueError, RuntimeError):
            return {"outcome": "DENIED", "reason": "REVOCATION_UNVERIFIED"}
        try:
            with self._transaction():
                self._db.execute("INSERT OR IGNORE INTO revoked VALUES (?, ?)", (grant_id, canon(record)))
        except (OSError, sqlite3.Error):
            return {"outcome": "BLOCKED", "reason": "TARGET_STATE_UNAVAILABLE"}
        return {"outcome": "REVOKED"}

    def reconcile(self, record):
        """Resolve an ambiguous operation at the target without dispatching it."""
        try:
            digest = check_reconcile(record, gateway_pub=self._gateway, scope=self._scope)
        except (TypeError, ValueError, RuntimeError):
            return {"outcome": "DENIED", "reason": "RECONCILIATION_UNVERIFIED"}
        try:
            with self._transaction():
                previous = self._saved_effect()
                if previous is None:
                    denied = self._saved_denial(digest)
                    return denied or self._record(digest, self._now(), "FENCED", "NO_EFFECT_AND_LATE_DISPATCH_FENCED")
                saved_digest, outcome, receipt = previous
                if saved_digest != digest:
                    return {"outcome": "BLOCKED", "reason": "DISPATCH_DIGEST_CONFLICT"}
                return {"outcome": outcome, "receipt": json.loads(receipt)}
        except (VaultError, OSError, sqlite3.Error):
            return {"outcome": "BLOCKED", "reason": "TARGET_STATE_UNAVAILABLE"}
