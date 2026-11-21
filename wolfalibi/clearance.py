"""One-shot, offline access gate for a fixed synthetic service."""

import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time

from alibi import H, canon
from .agent_solitary import agent_solitary_contract
from .agent_solitary_worker import AGENT_PROFILE
from .clearance_records import (
    CAPABILITY_TTL, PROFILE, QUALIFICATION_TTL, check_grant, check_request, check_revocation, make_scope, sign_decision,
)
from .solitary import solitary_contract
from .stage35_verifier import VerifierStore, VerifierStoreError


_IDENTITY_FIELDS = ("python_sha256", "worker_sha256", "profile_sha256", "policy_sha256")


def _digest(value):
    return isinstance(value, bytes) and len(value) == 32


def _token(value):
    return (type(value) is str and len(value) == 64
            and all(letter in "0123456789abcdef" for letter in value))


class ClearanceError(RuntimeError):
    """Required trusted gateway state is unavailable or inconsistent."""


class ClearanceGateway:
    """Serialize admission, revocation and single-use effects in one local gateway."""

    def __init__(self, state_dir, *, signer, owner_pub, broker_pub, witness_pub, supervisor_pub,
                 expected_witness_state_digest, observe_witness_head, observe_identity,
                 upstream, upstream_credential, clock=time.time):
        import fcntl

        keys = (signer.pub, owner_pub, broker_pub, witness_pub, supervisor_pub)
        if (not all(_digest(key) for key in keys) or len(set(keys)) != len(keys)
                or not _digest(expected_witness_state_digest)):
            raise ClearanceError("distinct trusted keys and an independently retained witness head required")
        self.signer = signer
        self._owner = owner_pub
        self._pins = dict(broker_pub=broker_pub, witness_pub=witness_pub, supervisor_pub=supervisor_pub)
        self._retained_head = expected_witness_state_digest
        self._witness = observe_witness_head
        self._identity = observe_identity
        self._upstream = upstream
        self._credential = upstream_credential
        self._clock = clock
        self._lock = threading.Lock()
        self._lease = None
        self._db = None
        state = Path(state_dir).absolute()
        entry = state.lstat()
        if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or entry.st_mode & 0o077:
            raise ClearanceError("gateway state directory must be private and owner-controlled")
        db_path = state / "clearance.sqlite"
        self._verifier_path = state / "verifier.sqlite"
        try:
            self._lease = os.open(state / "clearance.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            exists = os.path.lexists(db_path)
            if exists != os.path.lexists(self._verifier_path):
                raise ClearanceError("gateway and verifier state must be recovered together")
            with self._verifier(bootstrap=not exists):
                pass
            if not exists:
                os.close(os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            self._db = sqlite3.connect(db_path.as_uri() + "?mode=rw", uri=True,
                                       isolation_level=None, check_same_thread=False)
            self._db.execute("PRAGMA synchronous = FULL")
            if not exists:
                self._initialize()
                directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            binding = self._db.execute("SELECT keys FROM metadata").fetchone()
            if binding != (canon([key.hex() for key in keys]),):
                raise ClearanceError("gateway trust pins differ from persisted state")
        except (OSError, sqlite3.Error, VerifierStoreError) as exc:
            self.close()
            raise ClearanceError("gateway state unavailable or already in use") from exc
        except BaseException:
            self.close()
            raise

    def _initialize(self):
        self._db.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE metadata (keys BLOB NOT NULL, checked_at INTEGER NOT NULL);
            CREATE TABLE challenges (nonce TEXT PRIMARY KEY, scope BLOB NOT NULL, expires_at INTEGER NOT NULL);
            CREATE TABLE revoked (grant_id TEXT PRIMARY KEY, revocation BLOB NOT NULL);
            CREATE TABLE capabilities (
                token_hash BLOB PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE,
                grant_id TEXT NOT NULL UNIQUE,
                grant_record BLOB NOT NULL,
                witness_head BLOB NOT NULL,
                qualified_digest TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('READY', 'PENDING', 'COMPLETED', 'INCOMPLETE', 'FENCED')),
                admission BLOB NOT NULL,
                request_id TEXT,
                request_digest TEXT,
                effect BLOB
            );
            COMMIT;
        """)
        pubs = [self.signer.pub, self._owner, *self._pins.values()]
        self._db.execute("INSERT INTO metadata VALUES (?, 0)", (canon([key.hex() for key in pubs]),))

    def _verifier(self, *, bootstrap=False):
        heads = {self._pins["witness_pub"]: self._retained_head}
        kwargs = {"bootstrap_heads" if bootstrap else "expected_heads": heads}
        return VerifierStore(self._verifier_path, **kwargs)

    def close(self):
        with self._lock:
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

    def _now(self):
        try:
            now = int(self._clock())
        except (ValueError, OverflowError, TypeError) as exc:
            raise ClearanceError("trusted time unavailable") from exc
        if not 0 <= now < 2**63 - QUALIFICATION_TTL:
            raise ClearanceError("trusted time outside supported range")
        advanced = self._db.execute("UPDATE metadata SET checked_at = ? WHERE checked_at <= ?", (now, now))
        if advanced.rowcount != 1:
            raise ClearanceError("trusted time moved backwards")
        return now

    def _result(self, phase, outcome, reason, *, now=None, scope=None, grant_id=None,
                qualification="UNCHECKED", authorization="UNCHECKED", effect="NONE", **bindings):
        payload = {
            "type": "WOLFALIBI_CLEARANCE_DECISION_V1",
            "phase": phase, "outcome": outcome, "reason": reason, "checked_at": now,
            "scope": scope, "grant_id": grant_id, "qualification": qualification,
            "owner_authorization": authorization, "effect": effect,
            "observation": "SYNTHETIC_GATEWAY",
            "broker_assurance": "BROKER_ONLY", "production": "BLOCKED",
            "qualification_issuers": {key: value.hex() for key, value in self._pins.items()},
            "owner_pub": self._owner.hex(), **bindings,
        }
        return {"outcome": outcome, "decision": sign_decision(self.signer, payload)}

    def _witness_head(self):
        try:
            value = self._witness()
        except Exception as exc:
            raise ClearanceError("current witness state unavailable") from exc
        if not _digest(value):
            raise ClearanceError("current witness state unavailable")
        return value

    def _identity_matches(self, scope):
        try:
            live = self._identity(bytes.fromhex(scope["agent_pub"]))
        except Exception as exc:
            raise ClearanceError("current identity unavailable") from exc
        return live == {field: scope[field] for field in _IDENTITY_FIELDS}

    def _revoked(self, grant_id):
        return self._db.execute("SELECT 1 FROM revoked WHERE grant_id = ?", (grant_id,)).fetchone() is not None

    def prepare(self, run_id, *, agent_pub, profile=PROFILE):
        """Issue verifier-owned expectations before launching the fixed worker."""
        with self._lock:
            try:
                now = self._now()
                if agent_pub in (self.signer.pub, self._owner, *self._pins.values()):
                    raise ValueError("agent requires a separate signing key")
                contract_for = {PROFILE: solitary_contract, AGENT_PROFILE: agent_solitary_contract}.get(profile)
                if contract_for is None:
                    raise ValueError("unsupported fixed Solitary profile")
                with self._verifier() as verifier:
                    if self._witness_head() != self._retained_head:
                        raise ClearanceError("witness head differs from the independently retained head")
                    contract = contract_for(run_id, secrets.token_bytes(32), now + QUALIFICATION_TTL)
                    scope = make_scope(contract, agent_pub=agent_pub, gateway_pub=self.signer.pub,
                                       expected_witness_state_digest=self._retained_head)
                    issued = verifier.issue(contract=contract, **self._pins, now=now)
                if issued["outcome"] != "ISSUED":
                    return self._result("PREPARE", "BLOCKED", "CHALLENGE_NOT_ISSUED", now=now)
                self._db.execute("INSERT INTO challenges VALUES (?, ?, ?)",
                                 (contract["challenge"], canon(scope), contract["expires_at"]))
                result = self._result("PREPARE", "ISSUED", "CHALLENGE_ISSUED", now=now, scope=scope,
                                      expires_at=contract["expires_at"])
                return {**result, "contract": contract, "scope": scope}
            except (OSError, sqlite3.Error, RuntimeError, ValueError, TypeError):
                return self._result("PREPARE", "BLOCKED", "PREREQUISITES_UNAVAILABLE")

    def admit(self, *, challenge, envelope, grant):
        """Consume a fresh Solitary envelope and an exact owner grant."""
        with self._lock:
            try:
                return self._admit(challenge, envelope, grant)
            except (ClearanceError, VerifierStoreError, OSError, sqlite3.Error, TypeError, ValueError, RecursionError):
                return self._result("ADMISSION", "BLOCKED", "ADMISSION_STATE_UNAVAILABLE")

    def _admit(self, challenge, envelope, grant):
        now = self._now()
        row = self._db.execute("SELECT scope, expires_at FROM challenges WHERE nonce = ?",
                               (challenge,)).fetchone() if _token(challenge) else None
        if row is None:
            return self._result("ADMISSION", "DENIED", "UNKNOWN_CHALLENGE", now=now,
                                qualification="BLOCKED")
        scope, deadline = json.loads(row[0]), row[1]
        reference = {"now": now, "scope": scope}
        if now >= deadline:
            return self._result("ADMISSION", "DENIED", "QUALIFICATION_EXPIRED", **reference,
                                qualification="BLOCKED")
        try:
            grant = json.loads(canon(grant))
            owner = check_grant(grant, owner_pub=self._owner, scope=scope, now=now)
        except (ValueError, TypeError, RecursionError):
            return self._result("ADMISSION", "DENIED", "OWNER_GRANT_INVALID", **reference,
                                authorization="DENIED")
        grant_id = owner["grant_id"]
        grant_blob = canon(grant)
        reference.update(grant_id=grant_id, grant_sha256=H(grant_blob).hex())
        if self._revoked(grant_id):
            return self._result("ADMISSION", "DENIED", "OWNER_REVOKED", **reference, authorization="REVOKED")
        reused = self._db.execute("SELECT 1 FROM capabilities WHERE nonce = ? OR grant_id = ?",
                                  (challenge, grant_id)).fetchone()
        if reused is not None:
            return self._result("ADMISSION", "DENIED", "ADMISSION_ALREADY_USED", **reference)
        if not self._identity_matches(scope):
            return self._result("ADMISSION", "DENIED", "IDENTITY_CHANGED", **reference, qualification="BLOCKED")
        if not isinstance(envelope, dict) or envelope.keys() != {"evidence", "supervisor_record"}:
            return self._result("ADMISSION", "BLOCKED", "QUALIFICATION_REQUIRED", **reference,
                                qualification="BLOCKED", authorization="CURRENT")
        live_head = self._witness_head()
        with self._verifier() as verifier:
            verified = verifier.accept(envelope["evidence"], challenge=challenge,
                                       supervisor_record=envelope["supervisor_record"], now=now)
            if verified["outcome"] != "VERIFIED":
                return self._result("ADMISSION", "BLOCKED", "QUALIFICATION_UNVERIFIED", **reference,
                                    qualification="BLOCKED", authorization="CURRENT")
            self._retained_head = verifier.head(self._pins["witness_pub"])
        if live_head != self._retained_head or self._witness_head() != self._retained_head:
            return self._result("ADMISSION", "BLOCKED", "WITNESS_HEAD_CHANGED", **reference,
                                qualification="BLOCKED", authorization="CURRENT")
        if not self._identity_matches(scope):
            return self._result("ADMISSION", "DENIED", "IDENTITY_CHANGED", **reference, qualification="BLOCKED")
        now = self._now()
        reference["now"] = now
        if now >= min(deadline, owner["expires_at"]):
            return self._result("ADMISSION", "DENIED", "PREDICATE_EXPIRED", **reference)
        expiry = min(deadline, owner["expires_at"], now + CAPABILITY_TTL)
        capability = secrets.token_hex(32)
        token_hash = H(capability.encode())
        qualification_digest = verified["accepted_envelope_sha256"]
        result = self._result("ADMISSION", "ADMITTED", "BOTH_PREDICATES_CURRENT", **reference,
                              qualification="SYNTHETIC_CURRENT", authorization="CURRENT",
                              qualification_sha256=qualification_digest, witness_head=self._retained_head.hex(),
                              expires_at=expiry, budget=1, capability_sha256=token_hash.hex())
        self._db.execute("""
            INSERT INTO capabilities (
                token_hash, nonce, grant_id, grant_record, witness_head, qualified_digest, expires_at, state, admission
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'READY', ?)
        """, (token_hash, challenge, grant_id, grant_blob, self._retained_head,
              qualification_digest, expiry, canon(result["decision"])))
        return {**result, "capability": capability}

    def revoke(self, revocation):
        """Fence future operations using a revocation signed by the pinned owner."""
        with self._lock:
            try:
                now = self._now()
                revocation = json.loads(canon(revocation))
                grant_id = check_revocation(revocation, owner_pub=self._owner, gateway_pub=self.signer.pub)
                self._db.execute("INSERT OR IGNORE INTO revoked VALUES (?, ?)", (grant_id, canon(revocation)))
                return self._result("REVOCATION", "REVOKED", "OWNER_REVOKED", now=now, grant_id=grant_id,
                                    authorization="REVOKED", revocation_sha256=H(canon(revocation)).hex())
            except (ValueError, TypeError, sqlite3.Error, ClearanceError, RecursionError):
                return self._result("REVOCATION", "BLOCKED", "REVOCATION_UNVERIFIED")

    def perform(self, *, capability, request):
        """Check both predicates and durably consume one use before calling upstream."""
        with self._lock:
            try:
                return self._perform(capability, request)
            except (ClearanceError, VerifierStoreError, OSError, sqlite3.Error, TypeError, ValueError, RecursionError):
                return self._result("OPERATION", "BLOCKED", "OPERATION_STATE_UNAVAILABLE", effect="UNKNOWN")

    def _perform(self, capability, request):
        now = self._now()
        token_hash = H(capability.encode()) if _token(capability) else None
        row = self._db.execute("""
            SELECT scope, challenges.expires_at, grant_id, grant_record, witness_head,
                   qualified_digest, capabilities.expires_at, state, admission, request_id, request_digest
              FROM capabilities JOIN challenges ON capabilities.nonce = challenges.nonce
             WHERE token_hash = ?
        """, (token_hash,)).fetchone()
        if row is None:
            return self._result("OPERATION", "DENIED", "UNKNOWN_CAPABILITY", now=now)
        (scope, qualification_expiry, grant_id, grant, head, digest, expiry, state, admission,
         recorded_request_id, recorded_request_digest) = row
        scope = json.loads(scope)
        reference = dict(now=now, scope=scope, grant_id=grant_id, grant_sha256=H(grant).hex(),
                         qualification_sha256=digest, admission_sha256=H(admission).hex(),
                         witness_head=head.hex())
        try:
            request = json.loads(canon(request))
            operation = check_request(request, agent_pub=bytes.fromhex(scope["agent_pub"]), capability=capability)
        except (ValueError, TypeError, RecursionError):
            return self._result("OPERATION", "DENIED", "REQUEST_UNVERIFIED", **reference)
        reference.update(request_id=operation["request_id"], request_sha256=H(canon(request)).hex())
        if state in ("PENDING", "INCOMPLETE"):
            return self._result("OPERATION", "INCOMPLETE", "NO_AUTOMATIC_RETRY", **reference, effect="UNKNOWN",
                                prior_request_id=recorded_request_id, prior_request_sha256=recorded_request_digest)
        if state == "COMPLETED":
            return self._result("OPERATION", "DENIED", "CAPABILITY_SPENT", **reference)
        if state == "FENCED":
            return self._result("OPERATION", "DENIED", "CAPABILITY_FENCED", **reference)
        if self._revoked(grant_id):
            return self._result("OPERATION", "DENIED", "OWNER_REVOKED", **reference, authorization="REVOKED")
        if now >= qualification_expiry:
            return self._result("OPERATION", "DENIED", "QUALIFICATION_EXPIRED", **reference, qualification="BLOCKED")
        try:
            check_grant(json.loads(grant), owner_pub=self._owner, scope=scope, now=now)
        except ValueError:
            return self._result("OPERATION", "DENIED", "OWNER_GRANT_INVALID", **reference, authorization="DENIED")
        if now >= expiry:
            return self._result("OPERATION", "DENIED", "CAPABILITY_EXPIRED", **reference)
        self._db.execute("""
            UPDATE capabilities SET state = 'PENDING', request_id = ?, request_digest = ?
             WHERE token_hash = ?
        """, (reference["request_id"], reference["request_sha256"], token_hash))
        try:
            failure = self._current_qualification(scope, head)
        except (ClearanceError, VerifierStoreError):
            failure = "QUALIFICATION_STATE_UNAVAILABLE"
        if failure is not None:
            result = self._result("OPERATION", "BLOCKED", failure, **reference, qualification="BLOCKED")
            self._finish(token_hash, "FENCED", result)
            return result
        reference["now"] = self._now()
        if reference["now"] >= expiry:
            result = self._result("OPERATION", "DENIED", "PREDICATE_EXPIRED_BEFORE_EFFECT", **reference)
            self._finish(token_hash, "FENCED", result)
            return result
        reference.update(qualification="SYNTHETIC_CURRENT", authorization="CURRENT")
        try:
            data = self._upstream(self._credential)
            if type(data) is not bytes or len(data) > 4096:
                raise ClearanceError("invalid synthetic upstream response")
        except Exception:
            result = self._result("OPERATION", "INCOMPLETE", "EFFECT_NOT_CONFIRMED", **reference, effect="UNKNOWN")
            self._finish(token_hash, "INCOMPLETE", result)
            return result
        try:
            current = self._current_qualification(scope, head) is None
            reference["now"] = self._now()
        except (ClearanceError, VerifierStoreError, sqlite3.Error):
            current = False
        if not current or reference["now"] >= expiry:
            reference.update(qualification="BLOCKED", authorization="UNCHECKED")
            result = self._result("OPERATION", "INCOMPLETE", "RELEASE_PREDICATE_LOST", **reference, effect="UNKNOWN")
            self._finish(token_hash, "INCOMPLETE", result)
            return result
        result = self._result("OPERATION", "ALLOWED", "PROTECTED_READ_COMPLETED", **reference,
                              effect="OBSERVED", response_sha256=H(data).hex())
        self._finish(token_hash, "COMPLETED", result)
        return {**result, "data": data}

    def _current_qualification(self, scope, head):
        if not self._identity_matches(scope):
            return "IDENTITY_CHANGED"
        with self._verifier():
            if head != self._retained_head or self._witness_head() != head:
                return "WITNESS_HEAD_CHANGED"
        return None

    def _finish(self, token_hash, state, result):
        self._db.execute("UPDATE capabilities SET state = ?, effect = ? WHERE token_hash = ?",
                         (state, canon(result["decision"]), token_hash))
