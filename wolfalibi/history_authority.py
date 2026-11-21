"""Local, read-only historical disclosure for one operator-pinned Gate 003 archive."""

from contextlib import closing, contextmanager
import hashlib
import os
from pathlib import Path
import sqlite3
import time

from alibi import canon
from .clearance_records import _document, _id, _time
from .education_records import _sign, _verify_signature, digest
from .history_archive import read_archive
from .history_records import check_inquiry, inquiry_scope
from .history_verify import DISCLOSURE_DOMAIN, disclosure_payload, separate_keys
from .stage3_evidence import _hex
from .voidcell002 import AuthorityError, _file_id, _private_directory, _sync_directory


_HEAD_DOMAIN = b"quorvane/finance/history/access-state/v1"


class HistoryStateError(RuntimeError):
    """The retained inquiry state cannot establish a safe disclosure boundary."""


_STATE_ERRORS = (sqlite3.Error, OSError, AuthorityError, HistoryStateError, ValueError)


def _now():
    return int(time.time())


def _blocked(reason):
    return {"outcome": "BLOCKED", "reason": reason}


def _denied(reason):
    return {"outcome": "DENIED", "reason": reason}


class HistoryAuthority:
    """Own the inquiry state and disclosure key. Payment inputs are read-only.

    The challenge argument is supplied by the local verifier over the private
    ceremony. Concurrent submissions and owner revocations serialize at commit.
    """

    def __init__(self, db_path, head_path, *, ledger_path, anchor_path, expectations,
                 anchor_sha256, signer, create=False):
        self._db, self._head, self._ledger, self._anchor = (
            Path(p).absolute() for p in (db_path, head_path, ledger_path, anchor_path)
        )
        protected_dirs = {self._ledger.parent.resolve(), self._anchor.parent.resolve()}
        parents = {self._db.parent.resolve(), self._head.parent.resolve()}
        if len(parents) != 2 or parents & protected_dirs:
            raise ValueError("use separate inquiry and head directories outside the payment stores")
        for parent in parents:
            _private_directory(parent)
        self._finance = _document(expectations, "retained finance expectations")
        self._scope = inquiry_scope(self._finance["scope"])
        self._owner_pub = _hex(self._finance["owner_pub"], 32, "payment resource owner")
        _hex(anchor_sha256, 32, "operator's archive anchor")
        self._anchor_sha256 = anchor_sha256
        self._signer = signer
        separate_keys(self._finance, signer.pub.hex())
        self._policy = digest({"schema": "QUORVANE_HISTORY_AUTHORITY_V1", "finance": self._finance,
                               "anchor_sha256": anchor_sha256, "history_pub": signer.pub.hex()})
        if create:
            if any(os.path.lexists(store) for store in (self._db, self._head)):
                raise FileExistsError("history provisioning requires two unused store paths")
            for store in (self._db, self._head):
                fd = os.open(store, os.O_WRONLY | os.O_EXCL | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                os.close(fd)
                _sync_directory(store.parent)
        self._file_ids = (_file_id(self._db), _file_id(self._head))
        if create:
            with self._transaction(initialize=True):
                pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        # Every inquiry has its own connection and transaction.
        pass

    def _checkpoint(self, db):
        row = db.execute("SELECT policy, watermark FROM configuration WHERE id=1").fetchone()
        if row is None or row[0] != self._policy:
            raise HistoryStateError("inquiry policy differs from its provisioning")
        _time(row[1], "history watermark")
        h = hashlib.sha256(canon(["QUORVANE_HISTORY_ACCESS_STATE_V1", *row]))
        for schema in ("main", "retained"):
            for item in db.execute(f"SELECT type, name, sql FROM {schema}.sqlite_schema ORDER BY type, name"):
                h.update(b"\n" + canon([schema, *item]))
        for item in db.execute("SELECT kind, subject, binding FROM decisions ORDER BY kind, subject"):
            h.update(b"\n" + canon(list(item)))
        return {"state_sha256": h.hexdigest(), "policy_sha256": self._policy}

    @contextmanager
    def _transaction(self, *, initialize=False):
        # Attached rollback-journal databases commit together through SQLite's
        # super-journal. Neither payment file is attached to this connection.
        if (_file_id(self._db), _file_id(self._head)) != self._file_ids:
            raise HistoryStateError("inquiry store was replaced")
        with closing(sqlite3.connect(self._db.as_uri() + '?mode=rw', uri=True, isolation_level=None)) as db:
            db.execute("ATTACH DATABASE ? AS retained", (self._head.as_uri() + '?mode=rw',))
            db.execute("PRAGMA trusted_schema=OFF")
            for schema in ("main", "retained"):
                if db.execute(f"PRAGMA {schema}.journal_mode").fetchone() != ("delete",):
                    raise HistoryStateError("attached history stores require rollback journals")
                db.execute(f"PRAGMA {schema}.synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            try:
                if initialize:
                    db.execute("CREATE TABLE configuration (id INTEGER PRIMARY KEY CHECK(id=1), "
                               "policy TEXT NOT NULL, watermark INTEGER NOT NULL)")
                    db.execute("INSERT INTO configuration VALUES (1, ?, 0)", (self._policy,))
                    db.execute("CREATE TABLE decisions (kind TEXT NOT NULL, subject TEXT NOT NULL, "
                               "binding TEXT NOT NULL, PRIMARY KEY(kind, subject))")
                    db.execute("CREATE TABLE retained.head (id INTEGER PRIMARY KEY CHECK(id=1), signature TEXT NOT NULL)")
                    before = None
                else:
                    before = self._checkpoint(db)
                    saved = db.execute("SELECT signature FROM retained.head WHERE id=1").fetchone()
                    if not saved:
                        raise HistoryStateError("missing retained history head")
                    try:
                        _verify_signature(self._signer.pub, _HEAD_DOMAIN, before, saved[0])
                    except ValueError as exc:
                        raise HistoryStateError("retained history differs from inquiry state") from exc
                yield db
                after = self._checkpoint(db)
                if before != after:
                    signature = self._signer.sign(_HEAD_DOMAIN, canon(after)).hex()
                    db.execute("INSERT OR REPLACE INTO retained.head VALUES (1, ?)", (signature,))
                if (_file_id(self._db), _file_id(self._head)) != self._file_ids:
                    raise HistoryStateError("inquiry store changed during decision")
                db.commit()
            except BaseException:
                db.rollback()
                raise

    @staticmethod
    def _observe_time(db):
        now = _now()
        _time(now, "history authority time")
        watermark, = db.execute("SELECT watermark FROM configuration WHERE id=1").fetchone()
        if now < watermark:
            raise HistoryStateError("history clock moved backwards")
        if now > watermark:
            db.execute("UPDATE configuration SET watermark=? WHERE id=1", (now,))
        return now

    def revoke(self, grant_id):
        """Local operator operation, serialized with disclosures in the inquiry stores."""
        _id(grant_id, "history grant ID")
        try:
            with self._transaction() as db:
                db.execute("INSERT OR IGNORE INTO decisions VALUES ('revoked', ?, '')", (grant_id,))
            return {"outcome": "REVOKED"}
        except _STATE_ERRORS:
            return _blocked("HISTORY_STATE_UNAVAILABLE")

    def inquire(self, request, *, challenge):
        try:
            with self._transaction() as db:
                result = self._inquiry(db, request, challenge)
            return result
        except _STATE_ERRORS:
            return _blocked("HISTORY_STATE_UNAVAILABLE")

    def _inquiry(self, db, request, challenge):
        now = self._observe_time(db)
        try:
            req = _document(request, "signed history inquiry")
            grant_id = self._authenticate(req, challenge, now)
        except (TypeError, KeyError, ValueError):
            return _denied("HISTORY_AUTHORIZATION_INVALID")
        if db.execute("SELECT 1 FROM decisions WHERE kind='revoked' AND subject=?", (grant_id,)).fetchone():
            return _denied("HISTORY_GRANT_REVOKED")
        if db.execute("SELECT 1 FROM decisions WHERE kind='used' AND subject=?", (challenge,)).fetchone():
            return _denied("CHALLENGE_USED")
        try:
            original = read_archive(self._ledger, self._anchor, anchor_sha256=self._anchor_sha256,
                                    expectations=self._finance)
        except (OSError, ValueError, sqlite3.Error):
            return _blocked("HISTORY_ARCHIVE_UNAVAILABLE")
        try:
            now = self._observe_time(db)
        except HistoryStateError:
            return _blocked("HISTORY_CLOCK_ROLLBACK")
        try:
            self._authenticate(req, challenge, now)
        except ValueError:
            return _denied("HISTORY_AUTHORIZATION_INVALID")
        payload = disclosure_payload(self._finance, self._anchor_sha256, req, original, now)
        evidence = {"original": original, "request": req, "attestation": _sign(self._signer, DISCLOSURE_DOMAIN, payload)}
        db.execute("INSERT INTO decisions VALUES ('used', ?, ?)", (challenge, digest(evidence["attestation"])))
        return {"outcome": "DISCLOSED", "evidence": evidence}

    def _authenticate(self, request, challenge, now):
        if challenge == self._finance["scope"]["challenge"]:
            raise ValueError("the historical inquiry requires a separate challenge")
        grant_id = check_inquiry(request, scope=self._scope, owner_pub=self._owner_pub, challenge=challenge, now=now)
        separate_keys(self._finance, self._signer.pub.hex(), request["grant"]["payload"]["auditor_pub"])
        return grant_id
