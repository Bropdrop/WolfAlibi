"""Local gateway for one synthetic effect intent and target-owned reconciliation."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading

from alibi import H, canon
from .voidcell_records import _scope, dispatch_digest, sign_dispatch, sign_reconcile, verify_receipt


_TERMINAL = frozenset({"ACCEPTED_EVIDENCED", "DENIED", "FENCED"})
_DATABASE_VERSION = 1


class EffectGatewayError(RuntimeError):
    """The trusted gateway state is invalid or unavailable."""


class EffectGateway:
    """Persist one intent before contacting the target.

    The operator keeps this database under gateway custody. The target owns
    the effect ledger and determines whether an ambiguous intent committed or
    can be fenced. Replays of the gateway API only read the existing intent.
    Reconciliation is the sole transport operation for an existing intent.
    """

    def __init__(self, path, *, signer, scope, target_pub, transport):
        self._db = None
        self._lease = None
        self._lock = threading.Lock()
        self._delivery = threading.Lock()
        try:
            gateway_pub = getattr(signer, "pub", None)
            if (type(gateway_pub) is not bytes or len(gateway_pub) != 32
                    or type(target_pub) is not bytes or len(target_pub) != 32 or target_pub == gateway_pub):
                raise EffectGatewayError("distinct gateway and target signing keys are required")
            if not callable(transport):
                raise EffectGatewayError("a trusted local transport is required")
            frozen = _scope(scope)
            if frozen["gateway_pub"] != gateway_pub.hex() or frozen["target_pub"] != target_pub.hex():
                raise EffectGatewayError("scope differs from the pinned gateway or target")
            self._signer = signer
            self._scope = frozen
            self._target_pub = target_pub
            self._transport = transport

            path = Path(path).absolute()
            self._check_private(path.parent.lstat(), directory=True)
            self._lease = os.open(path.with_name(path.name + ".lock"),
                                  os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            self._check_private(os.fstat(self._lease), directory=False)
            fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
                created = True
            except FileExistsError:
                created = False
            self._check_private(path.lstat(), directory=False)
            self._db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                                       isolation_level=None, check_same_thread=False)
            self._db.execute("PRAGMA synchronous = FULL")
            mode, = self._db.execute("PRAGMA journal_mode").fetchone()
            if mode not in {"delete", "wal"}:
                raise EffectGatewayError("gateway requires a durable SQLite journal")
            pins = canon({"scope": frozen, "gateway_pub": gateway_pub.hex(), "target_pub": target_pub.hex()})
            with self._transaction() as db:
                if created:
                    self._initialize(db, pins)
                version, = db.execute("PRAGMA user_version").fetchone()
                if version != _DATABASE_VERSION or db.execute("SELECT pins FROM binding").fetchone() != (pins,):
                    raise EffectGatewayError("gateway database pins or schema differ")
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except (OSError, sqlite3.Error, TypeError, ValueError, RuntimeError) as exc:
            self.close()
            if isinstance(exc, EffectGatewayError):
                raise
            raise EffectGatewayError("locally persisted gateway state is unavailable") from exc

    @staticmethod
    def _check_private(entry, *, directory):
        correct_type = stat.S_ISDIR(entry.st_mode) if directory else stat.S_ISREG(entry.st_mode)
        if (not correct_type or entry.st_uid != os.geteuid() or entry.st_mode & 0o077
                or (not directory and entry.st_nlink != 1)):
            raise EffectGatewayError("gateway storage must be private and owner-controlled")

    @staticmethod
    def _initialize(db, pins):
        db.execute("CREATE TABLE binding (pins BLOB NOT NULL)")
        db.execute("INSERT INTO binding VALUES (?)", (pins,))
        db.execute("""
            CREATE TABLE intent (
                slot INTEGER PRIMARY KEY CHECK (slot = 1),
                packet BLOB NOT NULL,
                dispatch_sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('PENDING', 'TERMINAL', 'CONFLICT')),
                outcome TEXT,
                receipt BLOB,
                CHECK (state != 'PENDING' OR (outcome IS NULL AND receipt IS NULL)),
                CHECK (state != 'TERMINAL' OR (outcome IS NOT NULL AND receipt IS NOT NULL))
            )
        """)
        db.execute(f"PRAGMA user_version = {_DATABASE_VERSION}")

    @contextmanager
    def _transaction(self):
        with self._lock:
            db = self._db
            if db is None:
                raise EffectGatewayError("gateway is closed")
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                if db.in_transaction:
                    db.rollback()
                raise

    def close(self):
        with self._delivery, self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
            if self._lease is not None:
                os.close(self._lease)
                self._lease = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @staticmethod
    def _read(db):
        row = db.execute(
            "SELECT packet, dispatch_sha256, state, outcome, receipt FROM intent WHERE slot = 1"
        ).fetchone()
        if row is not None and H(row[0]).hex() != row[1]:
            raise EffectGatewayError("stored dispatch packet digest differs")
        return row

    @staticmethod
    def _ambiguous(digest, reason):
        return {"outcome": "AMBIGUOUS", "reason": reason, "dispatch_sha256": digest}

    def _confirmed(self, receipt, digest, outcome):
        verified = verify_receipt(receipt, target_pub=self._target_pub, scope=self._scope,
                                  dispatch_sha256=digest)
        if type(outcome) is not str or outcome not in _TERMINAL or verified["outcome"] != outcome:
            raise ValueError("transport outcome differs from the target receipt")
        return {"outcome": outcome, "receipt": receipt, "dispatch_sha256": digest}

    def _existing(self, row):
        _, digest, state, outcome, receipt = row
        if state == "TERMINAL":
            try:
                return self._confirmed(json.loads(receipt), digest, outcome)
            except (KeyError, TypeError, ValueError, RecursionError):
                return self._ambiguous(digest, "stored target receipt is invalid")
        if state == "CONFLICT":
            return self._ambiguous(digest, "target returned conflicting signed outcomes")
        return self._ambiguous(digest, "durable dispatch intent requires target reconciliation")

    def dispatch(self, *, qualification, owner_grant):
        """Record and send the first intent for the pinned synthetic scope."""
        if not self._delivery.acquire(blocking=False):
            return {"outcome": "BLOCKED", "reason": "gateway delivery already in progress"}
        try:
            return self._dispatch(qualification, owner_grant)
        finally:
            self._delivery.release()

    def _dispatch(self, qualification, owner_grant):
        try:
            packet = sign_dispatch(self._signer, scope=self._scope, qualification=qualification,
                                   owner_grant=owner_grant)
            encoded = canon(packet)
            digest = dispatch_digest(packet)
            with self._transaction() as db:
                existing = self._read(db)
                if existing is not None:
                    if existing[1] != digest:
                        return {"outcome": "BLOCKED", "reason": "dispatch differs from the durable intent"}
                    return self._existing(existing)
                db.execute("INSERT INTO intent VALUES (1, ?, ?, 'PENDING', NULL, NULL)", (encoded, digest))
        except (EffectGatewayError, KeyError, TypeError, ValueError, RecursionError, OSError, sqlite3.Error):
            return {"outcome": "BLOCKED", "reason": "durable dispatch intent is unavailable"}
        return self._deliver("dispatch", json.loads(encoded), digest)

    def reconcile(self):
        """Ask the target to confirm the existing effect or fence its absence."""
        if not self._delivery.acquire(blocking=False):
            return {"outcome": "BLOCKED", "reason": "gateway delivery already in progress"}
        try:
            return self._reconcile()
        finally:
            self._delivery.release()

    def _reconcile(self):
        try:
            with self._transaction() as db:
                existing = self._read(db)
                if existing is None:
                    return {"outcome": "BLOCKED", "reason": "no durable dispatch intent"}
                _, digest, state, _, _ = existing
                if state != "PENDING":
                    return self._existing(existing)
            request = sign_reconcile(self._signer, scope=self._scope, dispatch_sha256=digest)
        except (EffectGatewayError, KeyError, TypeError, ValueError, RecursionError, OSError, sqlite3.Error):
            return {"outcome": "BLOCKED", "reason": "durable reconciliation references are unavailable"}
        return self._deliver("reconcile", request, digest)

    def _deliver(self, action, packet, digest):
        try:
            response = self._transport(action, packet)
            if type(response) is not dict or response.keys() != {"outcome", "receipt"}:
                raise ValueError("target response has no terminal receipt")
            receipt = json.loads(canon(response["receipt"]))
            result = self._confirmed(receipt, digest, response["outcome"])
        except Exception:
            return self._ambiguous(digest, "target response missing or unverified")
        try:
            with self._transaction() as db:
                existing = self._read(db)
                if existing is None or existing[1] != digest:
                    raise EffectGatewayError("intent became unavailable")
                _, _, state, saved_outcome, _ = existing
                if state == "PENDING":
                    db.execute("UPDATE intent SET state = 'TERMINAL', outcome = ?, receipt = ? WHERE slot = 1",
                               (result["outcome"], canon(receipt)))
                elif state == "TERMINAL" and saved_outcome != result["outcome"]:
                    db.execute("UPDATE intent SET state = 'CONFLICT' WHERE slot = 1")
                    return self._ambiguous(digest, "target returned conflicting signed outcomes")
                else:
                    return self._existing(existing)
        except (EffectGatewayError, TypeError, ValueError, OSError, sqlite3.Error):
            return self._ambiguous(digest, "target receipt could not be retained durably")
        return result
