"""Resource-owned effect gate for two offline, synthetic sector profiles."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from threading import Lock
import time

from alibi import H, canon
from . import quorvane_domains as domains
from .quorvane_live import LiveCaller, LiveCallerError
from .quorvane_records import (
    check_grant, check_qualification, check_revocation, check_settlement, sign_receipt,
)


AUDIENCE = "wolfalibi.quorvane.v1"
_ID = re.compile(r"[a-zA-Z0-9_.-]{1,128}\Z")
_PROFILES = ("education", "finance")
_MAX_TTL = 120


class GateError(RuntimeError):
    """Required resource state or trust references are unavailable."""


def _decision(outcome, reason, *, qualified=False, authorized=False):
    return {
        "outcome": outcome, "reason": reason,
        "qualification": "QUALIFIED" if qualified else "BLOCKED",
        "owner_authorization": "OWNER_AUTHORIZED" if authorized else "NOT_ESTABLISHED",
        "target_effect": "NOT_CONFIRMED", "confinement": "BLOCKED",
    }


def _sector(profile, tenant):
    if profile not in _PROFILES or type(tenant) is not str or _ID.fullmatch(tenant) is None:
        raise ValueError("invalid synthetic profile or tenant")


class ResourceGate:
    """Own the clock, authority checks and accepted-effect ledger."""

    def __init__(self, path, *, signer, qualifier_pub, witness_pub, owner_pub, payment_owner_pub,
                 settler_pub, observe_witness_head, clock=time.time):
        keys = (signer.pub, qualifier_pub, witness_pub, owner_pub, payment_owner_pub, settler_pub)
        if any(type(key) is not bytes or len(key) != 32 for key in keys) or len(set(keys)) != len(keys):
            raise GateError("six distinct pinned keys are required")
        self._signer = signer
        self._qualifier = qualifier_pub
        self._witness = witness_pub
        self._owner = owner_pub
        self._payment_owner = payment_owner_pub
        self._settler = settler_pub
        self._head = observe_witness_head
        self._clock = clock
        self._lock = Lock()
        path = Path(path).absolute()
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise GateError("private resource-owned ledger directory required")
        try:
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            created = True
        except FileExistsError:
            created = False
        entry = path.lstat()
        if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.geteuid()
                or entry.st_mode & 0o077 or entry.st_nlink != 1):
            raise GateError("invalid resource ledger")
        self._db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, isolation_level=None,
                                   check_same_thread=False)
        pins = canon([key.hex() for key in keys])
        try:
            self._db.execute("PRAGMA synchronous = FULL")
            mode, = self._db.execute("PRAGMA journal_mode").fetchone()
            if mode not in {"delete", "wal"}:
                raise GateError("resource ledger requires a durable journal")
            with self._transaction():
                if created:
                    self._initialize(pins)
                if self._db.execute("SELECT pins FROM configuration").fetchone() != (pins,):
                    raise GateError("resource ledger trust bindings differ")
            if created:
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except BaseException:
            self.close()
            raise

    def _initialize(self, pins):
        self._db.execute("CREATE TABLE configuration (pins BLOB NOT NULL, checked_at INTEGER NOT NULL)")
        self._db.execute("INSERT INTO configuration VALUES (?, 0)", (pins,))
        self._db.execute("""CREATE TABLE policies (
            profile TEXT NOT NULL, tenant TEXT NOT NULL, epoch INTEGER NOT NULL,
            PRIMARY KEY (profile, tenant)
        )""")
        self._db.execute("""CREATE TABLE runs (
            run_id TEXT PRIMARY KEY, scope BLOB NOT NULL, previous BLOB NOT NULL,
            qualification BLOB
        )""")
        self._db.execute("""CREATE TABLE revoked (
            run_id TEXT NOT NULL, owner BLOB NOT NULL, grant_id TEXT NOT NULL, record BLOB NOT NULL,
            PRIMARY KEY (run_id, owner, grant_id)
        )""")
        self._db.execute("""CREATE TABLE accepted (
            run_id TEXT NOT NULL, request_id TEXT NOT NULL, owner BLOB NOT NULL, grant_id TEXT NOT NULL,
            receipt BLOB NOT NULL, PRIMARY KEY (run_id, request_id), UNIQUE (run_id, owner, grant_id)
        )""")
        domains.create_tables(self._db)

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

    def close(self):
        with self._lock:
            self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _now(self):
        try:
            now = int(self._clock())
        except (TypeError, ValueError, OverflowError) as exc:
            raise GateError("resource clock unavailable") from exc
        if not 0 <= now < 2**63 - _MAX_TTL:
            raise GateError("invalid resource clock")
        update = self._db.execute("UPDATE configuration SET checked_at = ? WHERE checked_at <= ?", (now, now))
        if update.rowcount != 1:
            raise GateError("resource clock moved backward")
        return now

    def _epoch(self, profile, tenant):
        row = self._db.execute("SELECT epoch FROM policies WHERE profile = ? AND tenant = ?",
                               (profile, tenant)).fetchone()
        return row[0] if row is not None else 1

    def change_policy(self, profile, tenant):
        """Advance a resource-local policy epoch and fence the old runs."""
        _sector(profile, tenant)
        with self._transaction():
            epoch = self._epoch(profile, tenant) + 1
            self._db.execute("""INSERT INTO policies VALUES (?, ?, ?)
                ON CONFLICT(profile, tenant) DO UPDATE SET epoch = excluded.epoch""",
                             (profile, tenant, epoch))
            return epoch

    def issue_run(self, profile, tenant, *, previous_head, ttl=60):
        _sector(profile, tenant)
        if type(previous_head) is not bytes or len(previous_head) != 32:
            raise ValueError("previous externally retained witness head is required")
        if type(ttl) is not int or not 0 < ttl <= _MAX_TTL:
            raise ValueError("run validity must be between 1 and 120 seconds")
        with self._transaction():
            run = {
                "audience": AUDIENCE, "run_id": secrets.token_hex(16), "challenge": secrets.token_hex(32),
                "profile": profile, "tenant": tenant, "policy_epoch": self._epoch(profile, tenant),
                "expires_at": self._now() + ttl,
            }
            self._db.execute("INSERT INTO runs VALUES (?, ?, ?, NULL)", (run["run_id"], canon(run), previous_head))
            return run

    def _run(self, run, now):
        run_id = run.get("run_id")
        if type(run_id) is not str:
            raise GateError("unknown target-issued run")
        row = self._db.execute("SELECT scope, previous, qualification FROM runs WHERE run_id = ?",
                               (run_id,)).fetchone()
        if row is None or canon(run) != row[0]:
            raise GateError("unknown target-issued run")
        if run["policy_epoch"] != self._epoch(run["profile"], run["tenant"]) or now >= run["expires_at"]:
            raise GateError("run policy changed or qualification expired")
        return row[1], row[2]

    def _qualified_head(self, run, identity, previous, qualification):
        digest = check_qualification(qualification, qualifier_pub=self._qualifier, witness_pub=self._witness,
                                     run=run, identity=identity, previous_head=previous)
        try:
            head = self._head(run["run_id"])
        except Exception as exc:
            raise GateError("retained witness state unavailable") from exc
        if type(head) is not bytes or head.hex() != digest:
            raise GateError("retained witness state conflicts with qualification")
        return digest

    def qualify(self, caller, record):
        """Enroll one live identity against a target-issued challenge exactly once."""
        if type(caller) is not LiveCaller:
            return _decision("BLOCKED", "live caller required")
        try:
            record = json.loads(canon(record))
            run = caller.run
            with self._transaction():
                previous, saved = self._run(run, self._now())
                if saved is not None:
                    return _decision("BLOCKED", "run already bound")
                identity = caller.identity()
                head = self._qualified_head(run, identity, previous, record)
                if caller.identity() != identity:
                    raise GateError("live caller changed during qualification")
                self._run(run, self._now())
                self._db.execute("UPDATE runs SET qualification = ? WHERE run_id = ?",
                                 (canon(record), run["run_id"]))
            return _decision("QUALIFIED", "live identity and witness accepted", qualified=True) | {"witness_head": head}
        except (GateError, LiveCallerError, OSError, sqlite3.Error, ValueError, TypeError, RecursionError):
            return _decision("BLOCKED", "live qualification unavailable or invalid")

    def revoke(self, run, record):
        """Retain an owner-signed revocation at the resource."""
        try:
            run, record = json.loads(canon(run)), json.loads(canon(record))
            for public in (self._owner, self._payment_owner):
                try:
                    grant_id = check_revocation(record, owner_pub=public, run=run)
                except ValueError:
                    continue
                break
            else:
                return _decision("DENIED", "invalid revocation")
            with self._transaction():
                scope = self._db.execute("SELECT scope FROM runs WHERE run_id = ?", (run["run_id"],)).fetchone()
                if scope != (canon(run),):
                    return _decision("DENIED", "unknown target-issued run")
                self._db.execute("INSERT OR IGNORE INTO revoked VALUES (?, ?, ?, ?)",
                                 (run["run_id"], public, grant_id, canon(record)))
            return {"outcome": "REVOKED", "confinement": "BLOCKED"}
        except (KeyError, OSError, sqlite3.Error, ValueError, TypeError, RecursionError):
            return _decision("BLOCKED", "resource revocation unavailable")

    def perform(self, caller, request, *, grant):
        """Check the actual peer packet and commit an accepted resource operation."""
        if type(caller) is not LiveCaller:
            return _decision("BLOCKED", "live caller required")
        try:
            actual = domains.validate_request(caller.exchange(request))
            grant = json.loads(canon(grant))
            run = caller.run
            with self._transaction():
                result = self._perform(caller, run, actual, grant)
        except (GateError, LiveCallerError, OSError, sqlite3.Error, ValueError, TypeError, RecursionError):
            return _decision("BLOCKED", "live request, qualification or resource state unavailable")
        if result["outcome"] not in {"ALLOWED", "INITIATED"}:
            return result
        return self._deliver(caller, run, actual, grant, result)

    def _deliver(self, caller, run, request, grant, result):
        """Release the committed result to the same peer under current authority."""
        try:
            with self._transaction():
                payload = result["receipt"]["payload"]
                now = self._now()
                previous, saved = self._run(run, now)
                identity = caller.identity()
                if (payload["identity_sha256"] != H(canon(identity)).hex()
                        or self._qualified_head(run, identity, previous, json.loads(saved)) != payload["witness_head"]):
                    raise GateError("live qualification changed before response")
                owner = bytes.fromhex(payload["owner_pub"])
                current = check_grant(grant, owner_pub=owner, run=run, request=request, now=self._now())
                if self._db.execute("SELECT 1 FROM revoked WHERE run_id = ? AND owner = ? AND grant_id = ?",
                                    (run["run_id"], owner, current["grant_id"])).fetchone():
                    raise GateError("owner grant revoked before response")
                if self._now() >= min(run["expires_at"], current["expires_at"]):
                    raise GateError("authority expired before response")
                caller.exchange({
                    "type": "quorvane-resource-result", "request_id": request["request_id"],
                    "receipt_sha256": H(canon(result["receipt"])).hex(), "data": result["data"],
                })
            return {**result, "delivery": "FIXED_PEER_ACK"}
        except (OSError, sqlite3.Error, KeyError, ValueError, TypeError, RuntimeError):
            return {
                "outcome": "UNKNOWN", "reason": "committed result delivery unconfirmed",
                "target_effect": "UNKNOWN", "confinement": "BLOCKED",
            }

    def _perform(self, caller, run, request, grant):
        now = self._now()
        previous, record = self._run(run, now)
        if record is None:
            return _decision("BLOCKED", "live qualification required")
        identity = caller.identity()
        head = self._qualified_head(run, identity, previous, json.loads(record))
        if (any(request[key] != run[key] for key in ("run_id", "challenge", "tenant", "policy_epoch"))
                or domains.operation_profile(request["operation"]) != run["profile"]
                or request["operation"] == "student_record"):
            return _decision("DENIED", "operation or tenant outside resource policy", qualified=True)
        owner = self._payment_owner if request["operation"] == "initiate_payment" else self._owner
        try:
            authorized = check_grant(grant, owner_pub=owner, run=run, request=request, now=now)
        except ValueError:
            return _decision("DENIED", "owner grant missing or invalid", qualified=True)
        grant_id = authorized["grant_id"]
        ref = (run["run_id"], owner, grant_id)
        if self._db.execute("SELECT 1 FROM revoked WHERE run_id = ? AND owner = ? AND grant_id = ?", ref).fetchone():
            return _decision("DENIED", "owner grant revoked", qualified=True)
        if self._db.execute("""SELECT 1 FROM accepted WHERE run_id = ?
                AND (request_id = ? OR (owner = ? AND grant_id = ?))""",
                            (run["run_id"], request["request_id"], owner, grant_id)).fetchone():
            return _decision("DENIED", "request or grant already consumed", qualified=True, authorized=True)
        if caller.identity() != identity:
            raise GateError("live caller changed before effect")
        now = self._now()
        if now >= min(run["expires_at"], authorized["expires_at"]):
            return _decision("DENIED", "authority expired before effect")

        def receipt_factory(outcome, details):
            return sign_receipt(self._signer, {
                "outcome": outcome, "checked_at": now, "run": run, "operation": request["operation"],
                "request_id": request["request_id"], "request_sha256": H(canon(request)).hex(),
                "grant_id": grant_id, "grant_sha256": H(canon(grant)).hex(),
                "owner_pub": owner.hex(), "witness_head": head,
                "identity_sha256": H(canon(identity)).hex(), "details": details,
            })

        result = domains.apply_operation(self._db, request, receipt_factory=receipt_factory)
        if result["outcome"] not in {"ALLOWED", "INITIATED"}:
            return _decision("DENIED", result.get("reason", "resource declined operation"),
                             qualified=True, authorized=True)
        self._db.execute("INSERT INTO accepted VALUES (?, ?, ?, ?, ?)",
                         (run["run_id"], request["request_id"], owner, grant_id, canon(result["receipt"])))
        return {
            **result, "qualification": "QUALIFIED", "owner_authorization": "OWNER_AUTHORIZED",
            "target_effect": "TARGET_EFFECT_CONFIRMED", "confinement": "BLOCKED",
        }

    def settle(self, record):
        """Apply separately authenticated synthetic settlement evidence."""
        try:
            record = json.loads(canon(record))
            settlement = check_settlement(record, settler_pub=self._settler)
            with self._transaction():
                now = self._now()

                def receipt_factory(outcome, details):
                    return sign_receipt(self._signer, {
                        "outcome": outcome, "checked_at": now, "operation": "settle_payment",
                        "tenant": settlement["tenant"], "settler_pub": self._settler.hex(),
                        "settlement_authority_sha256": H(canon(record)).hex(), "details": details,
                    })

                result = domains.settle(self._db, settlement, receipt_factory=receipt_factory)
                if result["outcome"] == "SETTLED":
                    return {**result, "target_effect": "TARGET_EFFECT_CONFIRMED", "confinement": "BLOCKED"}
                return result
        except (OSError, sqlite3.Error, ValueError, TypeError, RuntimeError):
            return _decision("BLOCKED", "settlement authority or resource state unavailable")

    def reconcile(self, tenant, payment_id):
        """Read stored target evidence through the trusted administrative API."""
        try:
            with self._lock:
                result = domains.reconcile(self._db, tenant=tenant, payment_id=payment_id)
        except (OSError, sqlite3.Error, ValueError, RuntimeError):
            return {"outcome": "UNKNOWN", "target_effect": "NOT_CONFIRMED"}
        if result["outcome"] == "UNKNOWN_PAYMENT":
            return {"outcome": "UNKNOWN", "target_effect": "NOT_CONFIRMED"}
        return result
