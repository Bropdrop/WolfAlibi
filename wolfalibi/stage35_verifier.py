"""Verifier-owned challenge and witness continuity state for Stage 3 evidence.

SQLite serializes acceptance in one private verifier store. Reopening requires
the latest witness heads retained by the operator independently of the DB.
Coordinated rollback of both copies and forks across disconnected stores remain
outside this guarantee. Keep the database directory under verifier custody.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import time

from alibi import H, canon
from .stage3_evidence import validate_contract, verify_execution


_SCHEMA_VERSION = 1
_MAX_SQLITE_INT = (1 << 63) - 1


class VerifierStoreError(RuntimeError):
    """The verifier database or its externally supplied anchors are unusable."""


class _ConcurrentAcceptance(Exception):
    pass


def _digest(value):
    return isinstance(value, bytes) and len(value) == 32


def _time(value):
    return type(value) is int and 0 <= value <= _MAX_SQLITE_INT


def _challenge(value):
    return (type(value) is str and len(value) == 64 and
            all(character in "0123456789abcdef" for character in value))


def _nonce_digest(challenge):
    return H(b"wolfalibi/verifier-challenge/v1\0" + bytes.fromhex(challenge))


def _rejected(reason):
    return {"outcome": "REJECTED", "reason": reason}


def _blocked(reason):
    return {"outcome": "BLOCKED", "reason": reason}


class VerifierStore:
    """Pin issued challenges and advance one trusted witness head atomically."""

    def __init__(self, path, *, expected_heads=None, bootstrap_heads=None):
        if (expected_heads is None) == (bootstrap_heads is None):
            raise VerifierStoreError("supply exactly one of expected_heads or bootstrap_heads")
        try:
            references = dict(expected_heads if bootstrap_heads is None else bootstrap_heads)
        except (ValueError, TypeError) as exc:
            raise VerifierStoreError("invalid expected witness head mapping") from exc
        if not references or any(not _digest(key) or not _digest(head)
                                 for key, head in references.items()):
            raise VerifierStoreError("expected witness keys and heads must be 32-byte values")
        self._connection = None
        try:
            path = Path(path).absolute()
            if bootstrap_heads is not None:
                # A stale or partially initialized file must never be reset
                # by an ordinary open or a retry of bootstrap.
                os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            self._connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                                               isolation_level=None)
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA synchronous = FULL")
            if bootstrap_heads is not None:
                self._bootstrap(references)
            # Serialize the initial comparison with concurrent acceptances.
            # Connected sessions use the current head and CAS on each accept.
            with self._transaction():
                version, = self._connection.execute("PRAGMA user_version").fetchone()
                if version != _SCHEMA_VERSION:
                    raise VerifierStoreError("unsupported verifier database schema")
                actual = dict(self._connection.execute("SELECT witness, head FROM witness_heads"))
                if actual != references:
                    raise VerifierStoreError(
                        "verifier database heads differ from independently retained heads")
        except (sqlite3.Error, OSError, TypeError, ValueError) as exc:
            self.close()
            raise VerifierStoreError(f"cannot open verifier database: {exc}") from exc
        except BaseException:
            self.close()
            raise

    def _bootstrap(self, heads):
        with self._transaction():
            self._connection.execute("""
                CREATE TABLE witness_heads (
                    witness BLOB PRIMARY KEY NOT NULL CHECK (length(witness) = 32),
                    head BLOB NOT NULL CHECK (length(head) = 32)
                )
            """)
            self._connection.execute("""
                CREATE TABLE issued_challenges (
                    nonce_digest BLOB PRIMARY KEY NOT NULL CHECK (length(nonce_digest) = 32),
                    run_id TEXT UNIQUE NOT NULL,
                    contract BLOB NOT NULL,
                    contract_digest BLOB NOT NULL CHECK (length(contract_digest) = 32),
                    broker BLOB NOT NULL CHECK (length(broker) = 32),
                    witness BLOB NOT NULL REFERENCES witness_heads(witness),
                    supervisor BLOB CHECK (length(supervisor) = 32),
                    issued_head BLOB NOT NULL CHECK (length(issued_head) = 32),
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
                    accepted_head BLOB CHECK (length(accepted_head) = 32),
                    accepted_envelope BLOB CHECK (length(accepted_envelope) = 32),
                    CHECK ((accepted_head IS NULL) = (accepted_envelope IS NULL))
                )
            """)
            self._connection.executemany("INSERT INTO witness_heads VALUES (?, ?)", heads.items())
            self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    @contextmanager
    def _transaction(self):
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._connection.commit()
        except BaseException:
            try:
                if self._connection.in_transaction:
                    self._connection.rollback()
            except sqlite3.Error:
                self.close()
            raise

    def close(self):
        if self._connection is not None:
            self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def head(self, witness_pub):
        """Retrieve the current witness digest for independent retention."""
        try:
            row = self._connection.execute(
                "SELECT head FROM witness_heads WHERE witness = ?", (witness_pub,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise VerifierStoreError(f"cannot read verifier head: {exc}") from exc
        if row is None:
            raise VerifierStoreError("unknown witness key")
        if not _digest(row[0]):
            raise VerifierStoreError("invalid stored witness head")
        return row[0]

    def issue(self, *, contract, broker_pub, witness_pub, supervisor_pub=None, now=None):
        """Pin the challenge and keys, optionally requiring measured evidence."""
        try:
            # Snapshot first, then validate the exact bytes that will persist.
            contract_bytes = canon(contract)
            contract = json.loads(contract_bytes)
            validate_contract(contract)
        except (ValueError, TypeError, RuntimeError) as exc:
            return _blocked(f"invalid issue contract: {exc}")
        checked_at = int(time.time()) if now is None else now
        if not _time(checked_at) or not _time(contract["expires_at"]):
            return _blocked("invalid verifier time or contract expiry")
        if not _digest(broker_pub) or not _digest(witness_pub) or broker_pub == witness_pub:
            return _blocked("expected distinct 32-byte broker and witness keys")
        if supervisor_pub is not None and (not _digest(supervisor_pub) or
                                           supervisor_pub in (broker_pub, witness_pub)):
            return _blocked("expected a distinct 32-byte supervisor key")
        if checked_at >= contract["expires_at"]:
            return _rejected("challenge expired")

        try:
            with self._transaction():
                issued_at = int(time.time()) if now is None else now
                if not checked_at <= issued_at < contract["expires_at"]:
                    return _rejected("challenge clock changed or expired before issuance")
                issued_head = self.head(witness_pub)
                self._connection.execute("""
                    INSERT INTO issued_challenges
                        (nonce_digest, run_id, contract, contract_digest, broker, witness, supervisor,
                         issued_head, issued_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (_nonce_digest(contract["challenge"]), contract["run_id"],
                      contract_bytes, H(contract_bytes), broker_pub, witness_pub, supervisor_pub,
                      issued_head, issued_at, contract["expires_at"]))
        except sqlite3.IntegrityError:
            return _rejected("challenge or run ID already issued")
        except (sqlite3.Error, VerifierStoreError) as exc:
            return _blocked(f"challenge issuance failed: {exc}")
        return {
            "outcome": "ISSUED", "challenge": contract["challenge"],
            "expected_witness_state_digest": issued_head.hex(),
        }

    def accept(self, evidence, *, challenge, supervisor_record=None, now=None):
        """Consume a pinned challenge and advance its head after verification.

        The verifier owns its time reference. By default the store uses the
        local clock and samples it again inside the transaction. An explicit
        time is trusted as a fixed reference for deterministic qualification.
        """
        checked_at = int(time.time()) if now is None else now
        if not _challenge(challenge) or not _time(checked_at):
            return _blocked("invalid challenge reference or verifier time")
        nonce = _nonce_digest(challenge)
        try:
            issued = self._connection.execute("""
                SELECT contract, contract_digest, broker, witness, supervisor, issued_head,
                       issued_at, expires_at, accepted_head, head
                  FROM issued_challenges JOIN witness_heads USING (witness)
                 WHERE nonce_digest = ?
            """, (nonce,)).fetchone()
        except sqlite3.Error as exc:
            return _blocked(f"cannot read issued challenge: {exc}")
        if issued is None:
            return _rejected("challenge was not issued")
        (contract_bytes, contract_digest, broker, witness, supervisor, expected,
         issued_at, expiry, accepted, current) = issued
        if accepted is not None:
            return _rejected("challenge was already consumed")
        if expected != current:
            return _rejected("issued witness head is stale")
        if not _time(issued_at) or not _time(expiry):
            return _blocked("invalid time in issued challenge")
        if checked_at < issued_at or checked_at >= expiry:
            return _rejected("challenge is outside its validity window")

        try:
            if H(contract_bytes) != contract_digest:
                return _blocked("issued contract digest mismatch")
            contract = json.loads(contract_bytes)
        except (TypeError, ValueError, RecursionError) as exc:
            return _blocked(f"cannot read issued contract: {exc}")
        if (not isinstance(contract, dict) or contract.get("challenge") != challenge or
                contract.get("expires_at") != expiry):
            return _blocked("issued challenge does not match its stored contract")
        try:
            # Check one stable envelope even when the caller owns the input
            # object and may modify it while the verifier is running.
            encoded = canon({"evidence": evidence, "supervisor_record": supervisor_record})
            envelope = json.loads(encoded)
        except (TypeError, ValueError, RuntimeError) as exc:
            return _rejected(f"invalid evidence encoding: {exc}")
        references = dict(contract=contract, broker_pub=broker, witness_pub=witness,
                          expected_witness_state_digest=expected, now=checked_at)
        if supervisor is not None:
            from .stage35 import verify_measured_trial

            verified = verify_measured_trial(
                envelope["evidence"], envelope["supervisor_record"],
                supervisor_pub=supervisor, **references,
            )
        elif supervisor_record is None:
            verified = verify_execution(envelope["evidence"], **references)
        else:
            return _rejected("challenge has no pinned supervisor key")
        if verified["outcome"] != "VERIFIED":
            return verified
        new_head = bytes.fromhex(verified["witness_state_digest"])
        try:
            with self._transaction():
                commit_time = int(time.time()) if now is None else now
                if not checked_at <= commit_time < expiry:
                    raise _ConcurrentAcceptance("challenge is outside its validity window")
                consumed = self._connection.execute("""
                    UPDATE issued_challenges SET accepted_head = ?, accepted_envelope = ?
                     WHERE nonce_digest = ? AND accepted_head IS NULL AND issued_head = ?
                """, (new_head, H(encoded), nonce, expected))
                if consumed.rowcount != 1:
                    raise _ConcurrentAcceptance("challenge was already consumed")
                advanced = self._connection.execute("""
                    UPDATE witness_heads SET head = ? WHERE witness = ? AND head = ?
                """, (new_head, witness, expected))
                if advanced.rowcount != 1:
                    raise _ConcurrentAcceptance("issued witness head is stale")
        except _ConcurrentAcceptance as exc:
            return _rejected(str(exc))
        except sqlite3.Error as exc:
            return _blocked(f"verifier transaction did not complete: {exc}")
        return {**verified, "accepted_envelope_sha256": H(encoded).hex()}
