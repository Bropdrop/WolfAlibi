"""One target-local laboratory counter effect under two independent authorities.

An accepted Shirudo receipt is evidence, never a grant. This gate additionally
requires an owner signature bound to a target-issued operation challenge. The
counter, consumed authority and signed historical result share one SQLite
transaction. The owner, verifier, target administrator, clock and private
journal remain trusted; this is not protection against restoring them together.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .model import (AdapterError, MAX_POLICY_BYTES, MAX_RECORD_BYTES, bounded_int,
                    canonical_json, digest, exact_keys, fail, identifier,
                    read_bounded_file, require_hex, strict_json, validate_policy)
from .receipt import sign_record, verify_receipt, verify_record
from .runner import _arguments

APPLICATION_ID = 0x57414731
MAX_ACTION_REQUEST_BYTES = MAX_RECORD_BYTES + 16_384
MAX_CHALLENGE_BYTES = 16_384
MAX_TRUST_BYTES = MAX_POLICY_BYTES + 4096
MAX_INTEGER = 2 ** 63 - 1
FRESHNESS_MS = 30_000
ADMISSION_MS = 5_000
CLOCK_SKEW_MS = 2_000
ACTION = {"name": "increment_counter", "delta": 1}
_ATTESTATION_KEYS = {"schema", "instance_id", "challenge_id", "nonce",
                     "policy_sha256", "target_id", "issued_at_ms", "expires_at_ms"}
_ACTION_KEYS = {"schema", "gate_instance_id", "operation_id", "operation_nonce",
                "target_id", "policy_sha256", "policy_generation",
                "attestation_challenge_sha256", "attestation_challenge_id",
                "attestation_nonce", "action", "issued_at_ms", "expires_at_ms"}
_GRANT_KEYS = {"schema", "scope", "grant_id", "gate_instance_id", "target_id",
               "operation_id", "operation_nonce", "policy_sha256", "policy_generation",
               "action", "action_challenge_sha256", "attestation_challenge_sha256",
               "attestation_receipt_sha256", "issued_at_ms", "expires_at_ms"}
_EFFECT_KEYS = {"schema", "scope", "authorization", "receipt_id", "gate_instance_id",
                "target_id", "operation_id", "operation_nonce", "policy_sha256",
                "policy_generation", "grant_id", "grant_sha256",
                "attestation_receipt_sha256", "attestation_challenge_sha256", "action",
                "counter_before", "counter_after", "committed_at_ms"}


def _freeze(value, limit=MAX_ACTION_REQUEST_BYTES):
    return strict_json(canonical_json(value), limit)


def _envelope_payload(envelope):
    exact_keys(envelope, {"schema", "payload", "signature"}, "signed record")
    if envelope["schema"] != "wolfalibi.signed-record.v1" or type(envelope["payload"]) is not dict:
        fail("INVALID_RECORD", "Unsupported signed record")
    require_hex(envelope["signature"], 128, "signature")
    return envelope["payload"]


def _action(value):
    exact_keys(value, {"name", "delta"}, "action")
    if value["name"] != "increment_counter":
        fail("INVALID_SCHEMA", "Only the laboratory counter action is supported")
    bounded_int(value["delta"], 1, 1, "counter delta")


def _times(payload, maximum):
    for key in ("issued_at_ms", "expires_at_ms"):
        bounded_int(payload[key], 0, MAX_INTEGER, key)
    if not 0 < payload["expires_at_ms"] - payload["issued_at_ms"] <= maximum:
        fail("INVALID_SCHEMA", "Invalid signed validity interval")


def _action_payload(payload):
    exact_keys(payload, _ACTION_KEYS, "action challenge")
    if payload["schema"] != "wolfalibi.shirudo.action-challenge.v1":
        fail("INVALID_SCHEMA", "Unsupported action challenge")
    for key in ("gate_instance_id", "operation_id", "attestation_challenge_id"):
        require_hex(payload[key], 32, key)
    for key in ("operation_nonce", "policy_sha256", "attestation_challenge_sha256", "attestation_nonce"):
        require_hex(payload[key], 64, key)
    identifier(payload["target_id"], "target")
    bounded_int(payload["policy_generation"], 1, MAX_INTEGER, "policy generation")
    _action(payload["action"])
    _times(payload, FRESHNESS_MS)
    return payload


def _grant_payload(payload):
    exact_keys(payload, _GRANT_KEYS, "owner grant")
    if payload["schema"] != "wolfalibi.shirudo.action-grant.v1" or payload["scope"] != "LAB_OWNER_GRANT":
        fail("INVALID_SCHEMA", "Unsupported owner grant")
    for key in ("grant_id", "gate_instance_id", "operation_id"):
        require_hex(payload[key], 32, key)
    for key in ("operation_nonce", "policy_sha256", "action_challenge_sha256",
                "attestation_challenge_sha256", "attestation_receipt_sha256"):
        require_hex(payload[key], 64, key)
    identifier(payload["target_id"], "target")
    bounded_int(payload["policy_generation"], 1, MAX_INTEGER, "policy generation")
    _action(payload["action"])
    _times(payload, FRESHNESS_MS)
    return payload


def _validate_trust(value):
    trust = _freeze(value, MAX_TRUST_BYTES)
    exact_keys(trust, {"schema", "target_id", "owner_public_key", "verifier_public_key",
                       "verifier_instance_id", "policy"}, "action trust")
    if trust["schema"] != "wolfalibi.shirudo.action-trust.v1":
        fail("INVALID_SCHEMA", "Unsupported action trust")
    identifier(trust["target_id"], "trusted target")
    for key in ("owner_public_key", "verifier_public_key"):
        require_hex(trust[key], 64, key)
    require_hex(trust["verifier_instance_id"], 32, "verifier instance")
    policy = validate_policy(trust["policy"])
    if policy["assurance"] != "LAB_VTPM" or policy["target_id"] != trust["target_id"]:
        fail("TRUST_MISMATCH", "The gate requires its own target's LAB_VTPM policy")
    if trust["owner_public_key"] == trust["verifier_public_key"]:
        fail("TRUST_MISMATCH", "Owner and verifier authorities must use separate keys")
    return trust


def make_grant_payload(action_challenge, assessment, *, grant_id, issued_at_ms,
                       expires_at_ms):
    """Build unsigned authority; callers must independently verify both inputs.

    This helper has no trusted public keys and cannot authenticate its inputs.
    The target independently verifies all signatures and bindings at execution.
    """
    challenge = _freeze(action_challenge, MAX_CHALLENGE_BYTES)
    assessment = _freeze(assessment, MAX_RECORD_BYTES)
    action = _action_payload(_envelope_payload(challenge))
    evidence = _envelope_payload(assessment)
    for key, expected in (("schema", "wolfalibi.shirudo.receipt.v1"),
                          ("target_id", action["target_id"]),
                          ("policy_sha256", action["policy_sha256"]),
                          ("challenge_id", action["attestation_challenge_id"]),
                          ("nonce", action["attestation_nonce"]),
                          ("outcome", "EVIDENCE_ACCEPTED"), ("assurance", "LAB_VTPM"),
                          ("authorization", "NONE"), ("scope", "HISTORICAL_EVIDENCE_ONLY")):
        if evidence.get(key) != expected:
            fail("ASSESSMENT_MISMATCH", "Assessment does not match the action challenge")
    completed = bounded_int(evidence.get("completed_at_ms"), 0, MAX_INTEGER, "assessment completion")
    payload = {
        "schema": "wolfalibi.shirudo.action-grant.v1", "scope": "LAB_OWNER_GRANT",
        "grant_id": grant_id, "gate_instance_id": action["gate_instance_id"],
        "target_id": action["target_id"], "operation_id": action["operation_id"],
        "operation_nonce": action["operation_nonce"], "policy_sha256": action["policy_sha256"],
        "policy_generation": action["policy_generation"], "action": dict(ACTION),
        "action_challenge_sha256": digest(challenge),
        "attestation_challenge_sha256": action["attestation_challenge_sha256"],
        "attestation_receipt_sha256": digest(assessment),
        "issued_at_ms": issued_at_ms, "expires_at_ms": expires_at_ms,
    }
    _grant_payload(payload)
    if (expires_at_ms > action["expires_at_ms"] or
            issued_at_ms < max(action["issued_at_ms"], completed) - CLOCK_SKEW_MS):
        fail("GRANT_MISMATCH", "Grant timing does not fit the assessment and operation")
    return payload


def verify_effect_receipt(envelope, public_key_hex, *, expected_target,
                          expected_gate_instance_id, expected_operation_id,
                          expected_grant_id, expected_grant_sha256,
                          expected_assessment_sha256, expected_action_challenge=None):
    """Authenticate a historical counter effect, returning no current authority."""
    envelope = _freeze(envelope, MAX_CHALLENGE_BYTES)
    payload = verify_record(envelope, public_key_hex)
    exact_keys(payload, _EFFECT_KEYS, "effect receipt")
    if (payload["schema"] != "wolfalibi.shirudo.effect-receipt.v1" or
            payload["scope"] != "LAB_COUNTER_EFFECT_ONLY" or
            payload["authorization"] != "CONSUMED_FOR_RECORDED_EFFECT"):
        fail("INVALID_RECEIPT", "Unsupported effect receipt")
    for key in ("receipt_id", "gate_instance_id", "operation_id", "grant_id"):
        require_hex(payload[key], 32, key)
    for key in ("operation_nonce", "policy_sha256", "grant_sha256",
                "attestation_receipt_sha256", "attestation_challenge_sha256"):
        require_hex(payload[key], 64, key)
    identifier(payload["target_id"], "effect target")
    identifier(expected_target, "expected target")
    for value, size, name in ((expected_gate_instance_id, 32, "expected gate"),
                              (expected_operation_id, 32, "expected operation"),
                              (expected_grant_id, 32, "expected grant"),
                              (expected_grant_sha256, 64, "expected grant digest"),
                              (expected_assessment_sha256, 64, "expected assessment")):
        require_hex(value, size, name)
    bounded_int(payload["policy_generation"], 1, MAX_INTEGER, "policy generation")
    _action(payload["action"])
    before = bounded_int(payload["counter_before"], 0, MAX_INTEGER - 1, "counter before")
    after = bounded_int(payload["counter_after"], 1, MAX_INTEGER, "counter after")
    bounded_int(payload["committed_at_ms"], 0, MAX_INTEGER, "commit time")
    if after != before + 1:
        fail("INVALID_RECEIPT", "Receipt does not describe exactly one counter increment")
    expected = {"target_id": expected_target, "gate_instance_id": expected_gate_instance_id,
                "operation_id": expected_operation_id, "grant_id": expected_grant_id,
                "grant_sha256": expected_grant_sha256,
                "attestation_receipt_sha256": expected_assessment_sha256}
    if any(payload[key] != value for key, value in expected.items()):
        fail("RECEIPT_SCOPE_MISMATCH", "Effect receipt does not match independent expectations")
    if expected_action_challenge is not None:
        challenge = _freeze(expected_action_challenge, MAX_CHALLENGE_BYTES)
        action = _action_payload(verify_record(challenge, public_key_hex))
        for key in ("gate_instance_id", "target_id", "operation_id", "operation_nonce",
                    "policy_sha256", "policy_generation", "attestation_challenge_sha256", "action"):
            if payload[key] != action[key]:
                fail("RECEIPT_SCOPE_MISMATCH", "Effect receipt does not match the target challenge")
        if not action["issued_at_ms"] <= payload["committed_at_ms"] < action["expires_at_ms"]:
            fail("INVALID_RECEIPT", "Recorded effect falls outside its operation interval")
    return {"signature_valid": True, "historical_outcome": "COMMITTED",
            "current_authorization": False, "scope": payload["scope"],
            "receipt_id": payload["receipt_id"], "operation_id": payload["operation_id"],
            "counter_before": before, "counter_after": after}


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


class _GateConnection(sqlite3.Connection):
    observed_clock = None


class Gate:
    state_schema = "wolfalibi.shirudo.action-state.v1"
    connection_factory = _GateConnection

    def __init__(self, state_dir):
        self.path = Path(state_dir).absolute()
        self._clock = lambda: time.time_ns() // 1_000_000
        self._before_commit = None
        self._check_paths()
        config = strict_json(read_bounded_file(self.path / "state.json", 4096), 4096)
        exact_keys(config, {"schema", "gate_instance_id", "public_key", "trust_sha256"}, "gate identity")
        if config["schema"] != self.state_schema:
            fail("STATE_INVALID", "Unsupported gate state")
        require_hex(config["gate_instance_id"], 32, "gate instance")
        require_hex(config["public_key"], 64, "gate public key")
        require_hex(config["trust_sha256"], 64, "gate trust digest")
        self._trust = _validate_trust(strict_json(read_bounded_file(self.path / "trust.json", MAX_TRUST_BYTES), MAX_TRUST_BYTES))
        self._trust_bytes = canonical_json(self._trust)
        if config["trust_sha256"] != digest(self._trust):
            fail("STATE_INVALID", "Gate identity and trusted configuration disagree")
        self._key_bytes = read_bounded_file(self.path / "signing.key", 32)
        try:
            self._key = Ed25519PrivateKey.from_private_bytes(self._key_bytes)
        except ValueError as exc:
            raise AdapterError("STATE_INVALID", "Invalid gate signing key") from exc
        self._public_key = self._key.public_key().public_bytes_raw().hex()
        if self._public_key != config["public_key"]:
            fail("STATE_INVALID", "Gate identity and signing key disagree")
        self.instance_id = config["gate_instance_id"]
        self._config_bytes = canonical_json(config)
        self._policy_sha = digest(self._trust["policy"])
        self._path_ids = {name: self._identity(self.path if name is None else self.path / name)
                          for name in (None, "state.json", "trust.json", "signing.key", "journal.sqlite3")}
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._check_database(conn)

    @staticmethod
    def _identity(path):
        info = path.lstat()
        return info.st_dev, info.st_ino

    @classmethod
    def initialize(cls, state_dir, trust):
        trust = _validate_trust(trust)
        path = Path(state_dir).absolute()
        cls._check_ancestors(path)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError as exc:
            raise AdapterError("STATE_EXISTS", "Gate initialization needs a new directory") from exc
        except OSError as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Cannot create private gate state") from exc
        key = Ed25519PrivateKey.generate()
        instance_id = secrets.token_hex(16)
        public_key = key.public_key().public_bytes_raw().hex()
        identity = {"schema": "wolfalibi.shirudo.action-state.v1", "gate_instance_id": instance_id,
                    "public_key": public_key, "trust_sha256": digest(trust)}
        try:
            _write_new(path / "signing.key", key.private_bytes(serialization.Encoding.Raw,
                       serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            _write_new(path / "state.json", canonical_json(identity))
            _write_new(path / "trust.json", canonical_json(trust))
            _write_new(path / "journal.sqlite3", b"")
            conn = sqlite3.connect(path / "journal.sqlite3", isolation_level=None)
            try:
                conn.execute("PRAGMA journal_mode=DELETE")
                conn.execute("PRAGMA synchronous=FULL")
                conn.execute(f"PRAGMA application_id={APPLICATION_ID}")
                conn.execute("PRAGMA user_version=1")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                conn.execute("CREATE TABLE counter (id INTEGER PRIMARY KEY CHECK(id=1), value INTEGER NOT NULL CHECK(value>=0))")
                conn.execute("INSERT INTO counter VALUES (1,0)")
                conn.execute("""CREATE TABLE operations (
                    id TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL,
                    attestation_id TEXT UNIQUE NOT NULL, attestation_nonce TEXT UNIQUE NOT NULL,
                    attestation_sha256 TEXT UNIQUE NOT NULL, document TEXT NOT NULL,
                    attestation_document TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PREPARED','COMMITTED')),
                    request TEXT, request_sha256 TEXT, grant_id TEXT UNIQUE,
                    grant_sha256 TEXT, assessment_sha256 TEXT UNIQUE, receipt TEXT,
                    counter_before INTEGER, counter_after INTEGER UNIQUE,
                    CHECK((status='PREPARED' AND request IS NULL AND request_sha256 IS NULL
                      AND grant_id IS NULL AND grant_sha256 IS NULL AND assessment_sha256 IS NULL
                      AND receipt IS NULL AND counter_before IS NULL AND counter_after IS NULL)
                      OR (status='COMMITTED' AND request IS NOT NULL AND request_sha256 IS NOT NULL
                      AND grant_id IS NOT NULL AND grant_sha256 IS NOT NULL AND assessment_sha256 IS NOT NULL
                      AND receipt IS NOT NULL AND counter_before>=0 AND counter_after=counter_before+1)))""")
                conn.execute("CREATE TABLE revoked_grants (id TEXT PRIMARY KEY, revoked_at_ms INTEGER NOT NULL)")
                conn.executemany("INSERT INTO metadata VALUES (?,?)", [
                    ("gate_instance_id", instance_id), ("public_key", public_key),
                    ("trust_document", canonical_json(trust).decode("ascii")),
                    ("trust_sha256", digest(trust)), ("policy_sha256", digest(trust["policy"])),
                    ("policy_active", "1"), ("policy_generation", "1"),
                    ("last_clock", str(time.time_ns() // 1_000_000))])
                conn.commit()
            finally:
                conn.close()
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except (OSError, sqlite3.Error) as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Gate initialization did not complete; preserve its directory") from exc
        return cls(path)

    @staticmethod
    def _check_ancestors(path):
        if ".." in path.parts:
            fail("STATE_PERMISSIONS", "Parent traversal is not a gate-state path")
        try:
            for parent in path.parents:
                info = parent.lstat()
                mode = stat.S_IMODE(info.st_mode)
                trusted_sticky = info.st_uid == 0 and bool(mode & stat.S_ISVTX)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                        or (mode & 0o022 and not trusted_sticky)):
                    fail("STATE_PERMISSIONS", "Gate-state ancestors must be trusted and nonreplaceable")
        except OSError as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Gate-state parent is unavailable") from exc

    def _check_paths(self):
        self._check_ancestors(self.path)
        try:
            for name in (None, "state.json", "trust.json", "signing.key", "journal.sqlite3"):
                path = self.path if name is None else self.path / name
                info = path.lstat()
                expected_type = stat.S_ISDIR(info.st_mode) if name is None else stat.S_ISREG(info.st_mode)
                if (not expected_type or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077
                        or (name is not None and info.st_nlink != 1)):
                    fail("STATE_PERMISSIONS", "Gate state requires private ownership without symlinks or hard links")
                if hasattr(self, "_path_ids") and self._path_ids[name] != (info.st_dev, info.st_ino):
                    fail("STATE_INVALID", "Gate state was replaced during use")
            for name in ("journal.sqlite3-journal", "journal.sqlite3-wal", "journal.sqlite3-shm"):
                try:
                    info = (self.path / name).lstat()
                except FileNotFoundError:
                    continue
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
                    fail("STATE_PERMISSIONS", "Unsafe gate database sidecar")
        except OSError as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Required gate state is missing or unreadable") from exc

    @contextmanager
    def _connection(self):
        self._check_paths()
        for name, expected, limit in (("state.json", self._config_bytes, 4096),
                                       ("trust.json", self._trust_bytes, MAX_TRUST_BYTES)):
            current = strict_json(read_bounded_file(self.path / name, limit), limit)
            if canonical_json(current) != expected:
                fail("STATE_INVALID", "Gate identity or trusted configuration changed")
        if read_bounded_file(self.path / "signing.key", 32) != self._key_bytes:
            fail("STATE_INVALID", "Gate signing key changed")
        conn = None
        try:
            uri = "file:" + quote(str(self.path / "journal.sqlite3"), safe="/") + "?mode=rw"
            conn = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=10, factory=self.connection_factory)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA synchronous=FULL")
            if conn.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                fail("STATE_INVALID", "Gate requires its durable rollback-journal mode")
            self._check_paths()
            yield conn
        except BaseException as exc:
            # Roll back every tentative effect, receipt and consumption first.
            # A separate clock-only transaction retains the highest valid time
            # observed by this attempt. A failed/expired request therefore
            # cannot erase the rollback-detection boundary it just established.
            if conn is not None and conn.in_transaction:
                observed = conn.observed_clock
                conn.rollback()
                if observed is not None:
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                        self._check_database(conn)
                        last = int(conn.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()[0])
                        if observed > last:
                            conn.execute("UPDATE metadata SET value=? WHERE key='last_clock'", (str(observed),))
                        conn.commit()
                    except sqlite3.Error as clock_error:
                        raise AdapterError("STATE_UNAVAILABLE", "Gate clock journal could not be preserved") from clock_error
            if isinstance(exc, sqlite3.Error):
                raise AdapterError("STATE_UNAVAILABLE", "Gate database operation failed") from exc
            raise
        finally:
            if conn is not None:
                if conn.in_transaction:
                    conn.rollback()
                conn.close()

    def _check_database(self, conn):
        if (conn.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID or
                conn.execute("PRAGMA user_version").fetchone()[0] != 1):
            fail("STATE_INVALID", "Unexpected gate database")
        metadata = dict(conn.execute("SELECT key,value FROM metadata"))
        expected = {"gate_instance_id": self.instance_id, "public_key": self._public_key,
                    "trust_document": self._trust_bytes.decode("ascii"),
                    "trust_sha256": digest(self._trust), "policy_sha256": self._policy_sha}
        if (set(metadata) != set(expected) | {"policy_active", "policy_generation", "last_clock"}
                or any(metadata.get(k) != v for k, v in expected.items())
                or (metadata["policy_active"], metadata["policy_generation"]) not in {("1", "1"), ("0", "2")}):
            fail("STATE_INVALID", "Gate database does not match its immutable trusted identity")
        try:
            last = int(metadata["last_clock"])
        except (ValueError, TypeError) as exc:
            raise AdapterError("STATE_INVALID", "Invalid gate clock journal") from exc
        if not 0 <= last <= MAX_INTEGER or str(last) != metadata["last_clock"]:
            fail("STATE_INVALID", "Invalid gate clock journal")
        counters = conn.execute("SELECT id,value FROM counter").fetchall()
        if (len(counters) != 1 or counters[0]["id"] != 1 or type(counters[0]["value"]) is not int
                or not 0 <= counters[0]["value"] <= MAX_INTEGER):
            fail("STATE_INVALID", "Invalid protected counter")
        rows = conn.execute("SELECT * FROM operations").fetchall()
        committed = []
        for row in rows:
            operation = self._decode_operation(row)
            action = operation["action_challenge"]["payload"]
            if action["issued_at_ms"] > last:
                fail("STATE_INVALID", "Operation is newer than the gate clock journal")
            if operation["receipt"] is not None:
                receipt = operation["receipt"]["payload"]
                if receipt["committed_at_ms"] > last:
                    fail("STATE_INVALID", "Receipt is newer than the gate clock journal")
                committed.append(receipt["counter_after"])
        if counters[0]["value"] != len(committed) or sorted(committed) != list(range(1, len(committed) + 1)):
            fail("STATE_INVALID", "Protected counter and committed receipt ledger disagree")
        for row in conn.execute("SELECT id,revoked_at_ms FROM revoked_grants"):
            try:
                require_hex(row["id"], 32, "revoked grant")
                bounded_int(row["revoked_at_ms"], 0, last, "grant revocation time")
            except AdapterError as exc:
                raise AdapterError("STATE_INVALID", "Invalid grant revocation journal") from exc

    def _begin(self, conn):
        conn.execute("BEGIN IMMEDIATE")
        self._check_database(conn)
        return self._tick(conn)

    def _tick(self, conn):
        now = self._clock()
        if type(now) is not int or not 0 <= now <= MAX_INTEGER:
            fail("CLOCK_INVALID", "Gate clock is invalid")
        last = int(conn.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()[0])
        if now < last:
            fail("CLOCK_ROLLBACK", "Gate clock moved backwards")
        conn.execute("UPDATE metadata SET value=? WHERE key='last_clock'", (str(now),))
        conn.observed_clock = now if conn.observed_clock is None else max(now, conn.observed_clock)
        return now

    def _attestation(self, record):
        payload = verify_record(record, self._trust["verifier_public_key"])
        exact_keys(payload, _ATTESTATION_KEYS, "verifier challenge")
        if payload["schema"] != "wolfalibi.shirudo.challenge.v1":
            fail("INVALID_SCHEMA", "Unsupported verifier challenge")
        for key in ("instance_id", "challenge_id"):
            require_hex(payload[key], 32, key)
        for key in ("nonce", "policy_sha256"):
            require_hex(payload[key], 64, key)
        identifier(payload["target_id"], "challenge target")
        _times(payload, 300_000)
        if (payload["instance_id"] != self._trust["verifier_instance_id"] or
                payload["target_id"] != self._trust["target_id"] or
                payload["policy_sha256"] != self._policy_sha or
                payload["expires_at_ms"] - payload["issued_at_ms"] !=
                self._trust["policy"]["challenge_ttl_seconds"] * 1000):
            fail("CHALLENGE_SCOPE_MISMATCH", "Verifier challenge does not match the trusted target policy")
        return payload

    def _assessment(self, record, action, attestation):
        result = verify_receipt(record, self._trust["verifier_public_key"],
                                expected_target=self._trust["target_id"],
                                expected_policy_sha256=self._policy_sha,
                                expected_challenge_id=action["attestation_challenge_id"])
        payload = record["payload"]
        if (result["historical_outcome"] != "EVIDENCE_ACCEPTED" or
                payload["assurance"] != "LAB_VTPM" or payload["upstream"]["execution_profile"] != "UPSTREAM_CLI"):
            fail("ASSESSMENT_NOT_ACCEPTED", "Gate needs a genuine accepted LAB_VTPM assessment")
        expected = {"instance_id": self._trust["verifier_instance_id"],
                    "nonce": attestation["nonce"], "issued_at_ms": attestation["issued_at_ms"],
                    "expires_at_ms": attestation["expires_at_ms"],
                    "enrollment_record_sha256": self._trust["policy"]["enrollment"]["record_sha256"]}
        pins = self._trust["policy"]["verifier"]
        upstream = payload["upstream"]
        if (any(payload[key] != value for key, value in expected.items()) or
                upstream["source_commit"] != pins["source_commit"] or
                any(upstream[key] != pins[pin] for key, pin in (
                    ("expected_binary_sha256", "sha256"), ("observed_binary_sha256", "sha256"),
                    ("expected_version_id", "version_id"), ("observed_version_id", "version_id")))):
            fail("ASSESSMENT_MISMATCH", "Assessment differs from the independently retained trust pins")
        # The generic receipt validator reconstructs its recorded assertion set.
        # Here the complete trusted policy independently determines the branch
        # and every required PCR. No executable is invoked by _arguments.
        _, required = _arguments(self._trust["policy"], attestation["nonce"], "/unused")
        if upstream["required_checks"][:-3] != required:
            fail("ASSESSMENT_MISMATCH", "Recorded checks do not match the trusted policy")
        return payload

    def _grant(self, record, action_record, assessment):
        payload = _grant_payload(verify_record(record, self._trust["owner_public_key"]))
        action = action_record["payload"]
        expected = {key: action[key] for key in ("gate_instance_id", "target_id", "operation_id",
                    "operation_nonce", "policy_sha256", "policy_generation", "action",
                    "attestation_challenge_sha256")}
        expected.update(action_challenge_sha256=digest(action_record),
                        attestation_receipt_sha256=digest(assessment))
        if any(payload[key] != value for key, value in expected.items()):
            fail("GRANT_MISMATCH", "Owner grant does not match the retained operation and assessment")
        if (payload["expires_at_ms"] > action["expires_at_ms"] or
                payload["issued_at_ms"] < max(action["issued_at_ms"], assessment["payload"]["completed_at_ms"]) - CLOCK_SKEW_MS):
            fail("GRANT_MISMATCH", "Owner grant widens or predates the permitted interval")
        return payload

    def _execution_times(self, action, attestation, assessment, grant, now):
        if now < action["issued_at_ms"]:
            fail("CLOCK_ROLLBACK", "Gate time predates its operation")
        if now >= action["expires_at_ms"]:
            fail("OPERATION_EXPIRED", "Target operation has expired")
        if now >= grant["expires_at_ms"]:
            fail("GRANT_EXPIRED", "Owner grant has expired")
        if now - attestation["issued_at_ms"] > FRESHNESS_MS:
            fail("ATTESTATION_STALE", "Admitted attestation is no longer fresh")
        if (max(attestation["issued_at_ms"], assessment["started_at_ms"],
                assessment["completed_at_ms"], grant["issued_at_ms"]) > now + CLOCK_SKEW_MS or
                assessment["started_at_ms"] < action["issued_at_ms"] - CLOCK_SKEW_MS):
            fail("CLOCK_SKEW", "Authority timestamps exceed the declared clock skew")

    @staticmethod
    def _admission_times(attestation, now):
        if attestation["issued_at_ms"] > now + CLOCK_SKEW_MS:
            fail("CLOCK_SKEW", "Verifier challenge is too far in the future")
        if now >= attestation["expires_at_ms"]:
            fail("CHALLENGE_EXPIRED", "Verifier challenge has expired")
        if now - attestation["issued_at_ms"] > ADMISSION_MS:
            fail("ATTESTATION_STALE", "Verifier challenge was not admitted within five seconds")

    def _decode_operation(self, row):
        try:
            action_record = strict_json(row["document"].encode(), MAX_CHALLENGE_BYTES)
            action = _action_payload(verify_record(action_record, self._public_key))
            attestation_record = strict_json(row["attestation_document"].encode(), MAX_CHALLENGE_BYTES)
            attestation = self._attestation(attestation_record)
            expected = {"gate_instance_id": self.instance_id, "target_id": self._trust["target_id"],
                        "policy_sha256": self._policy_sha, "policy_generation": 1,
                        "operation_id": row["id"], "operation_nonce": row["nonce"],
                        "attestation_challenge_id": row["attestation_id"],
                        "attestation_nonce": row["attestation_nonce"],
                        "attestation_challenge_sha256": row["attestation_sha256"]}
            if (any(action[key] != value for key, value in expected.items()) or
                    action["attestation_challenge_sha256"] != digest(attestation_record) or
                    action["attestation_challenge_id"] != attestation["challenge_id"] or
                    action["attestation_nonce"] != attestation["nonce"] or
                    not -CLOCK_SKEW_MS <= action["issued_at_ms"] - attestation["issued_at_ms"] <= ADMISSION_MS or
                    action["expires_at_ms"] != min(action["issued_at_ms"] + FRESHNESS_MS,
                    attestation["issued_at_ms"] + FRESHNESS_MS, attestation["expires_at_ms"])):
                fail("STATE_INVALID", "Operation does not match its signed admitted challenge")
            operation = {"operation_id": row["id"], "status": row["status"],
                         "action_challenge": action_record, "request_sha256": row["request_sha256"],
                         "grant_id": row["grant_id"], "receipt": None}
            committed_columns = ("request", "request_sha256", "grant_id", "grant_sha256",
                                 "assessment_sha256", "receipt", "counter_before", "counter_after")
            if row["status"] == "PREPARED":
                if any(row[key] is not None for key in committed_columns):
                    fail("STATE_INVALID", "Uncommitted operation contains effect records")
                return operation
            if row["status"] != "COMMITTED" or any(row[key] is None for key in committed_columns):
                fail("STATE_INVALID", "Incomplete committed operation")
            request = strict_json(row["request"].encode(), MAX_ACTION_REQUEST_BYTES)
            exact_keys(request, {"operation_id", "grant", "assessment"}, "stored execution request")
            if (request["operation_id"] != row["id"] or digest(request) != row["request_sha256"] or
                    digest(request["grant"]) != row["grant_sha256"] or
                    digest(request["assessment"]) != row["assessment_sha256"]):
                fail("STATE_INVALID", "Stored request binding is inconsistent")
            assessment = self._assessment(request["assessment"], action, attestation)
            grant = self._grant(request["grant"], action_record, request["assessment"])
            receipt = strict_json(row["receipt"].encode(), MAX_CHALLENGE_BYTES)
            verified = verify_effect_receipt(receipt, self._public_key,
                expected_target=self._trust["target_id"], expected_gate_instance_id=self.instance_id,
                expected_operation_id=row["id"], expected_grant_id=row["grant_id"],
                expected_grant_sha256=row["grant_sha256"], expected_assessment_sha256=row["assessment_sha256"],
                expected_action_challenge=action_record)
            if (grant["grant_id"] != row["grant_id"] or verified["counter_before"] != row["counter_before"]
                    or verified["counter_after"] != row["counter_after"]):
                fail("STATE_INVALID", "Stored receipt does not match the effect ledger")
            self._execution_times(action, attestation, assessment, grant, receipt["payload"]["committed_at_ms"])
            operation["receipt"] = receipt
            return operation
        except (AdapterError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise AdapterError("STATE_INVALID", "Stored operation or receipt failed integrity validation") from exc

    def _row(self, conn, operation_id):
        row = conn.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
        if row is None:
            fail("UNKNOWN_OPERATION", "Target operation is unknown")
        return row

    def _active(self, conn, action=None, grant_id=None):
        metadata = dict(conn.execute("SELECT key,value FROM metadata"))
        if metadata["policy_active"] != "1":
            fail("POLICY_REVOKED", "Target action policy is revoked")
        if action is not None and action["policy_generation"] != int(metadata["policy_generation"]):
            fail("POLICY_REVOKED", "Operation belongs to a revoked policy generation")
        if grant_id is not None and conn.execute("SELECT 1 FROM revoked_grants WHERE id=?", (grant_id,)).fetchone():
            fail("GRANT_REVOKED", "Owner grant is revoked at the target")

    def public_identity(self):
        with self._connection() as conn:
            self._begin(conn)
            generation = int(conn.execute("SELECT value FROM metadata WHERE key='policy_generation'").fetchone()[0])
            conn.commit()
        return {"schema": "wolfalibi.shirudo.action-identity.v1", "gate_instance_id": self.instance_id,
                "target_id": self._trust["target_id"], "public_key": self._public_key,
                "policy_sha256": self._policy_sha, "policy_generation": generation}

    def prepare(self, attestation_challenge):
        record = _freeze(attestation_challenge, MAX_CHALLENGE_BYTES)
        attestation = self._attestation(record)
        with self._connection() as conn:
            now = self._begin(conn)
            self._active(conn)
            if conn.execute("SELECT 1 FROM operations WHERE attestation_id=? OR attestation_nonce=? OR attestation_sha256=?",
                            (attestation["challenge_id"], attestation["nonce"], digest(record))).fetchone():
                fail("ATTESTATION_REUSED", "An admitted attestation challenge cannot authorize another operation")
            self._admission_times(attestation, now)
            payload = {"schema": "wolfalibi.shirudo.action-challenge.v1",
                "gate_instance_id": self.instance_id, "operation_id": secrets.token_hex(16),
                "operation_nonce": secrets.token_hex(32), "target_id": self._trust["target_id"],
                "policy_sha256": self._policy_sha, "policy_generation": 1,
                "attestation_challenge_sha256": digest(record),
                "attestation_challenge_id": attestation["challenge_id"], "attestation_nonce": attestation["nonce"],
                "action": dict(ACTION), "issued_at_ms": now,
                "expires_at_ms": min(now + FRESHNESS_MS, attestation["issued_at_ms"] + FRESHNESS_MS,
                                     attestation["expires_at_ms"])}
            _action_payload(payload)
            action_record = sign_record(self._key, payload)
            conn.execute("""INSERT INTO operations (id,nonce,attestation_id,attestation_nonce,
                         attestation_sha256,document,attestation_document,status)
                         VALUES (?,?,?,?,?,?,?,'PREPARED')""", (payload["operation_id"], payload["operation_nonce"],
                         attestation["challenge_id"], attestation["nonce"], digest(record),
                         canonical_json(action_record).decode("ascii"), canonical_json(record).decode("ascii")))
            final_now = self._tick(conn)
            self._active(conn)
            self._admission_times(attestation, final_now)
            self._commit_prepared(conn, action_record)
        return action_record

    def execute(self, request):
        request = _freeze(request)
        exact_keys(request, {"operation_id", "grant", "assessment"}, "execution request")
        operation_id = require_hex(request["operation_id"], 32, "operation")
        request_sha = digest(request)
        with self._connection() as conn:
            now = self._begin(conn)
            row = self._row(conn, operation_id)
            operation = self._decode_operation(row)
            if row["status"] == "COMMITTED":
                if row["request_sha256"] != request_sha or row["request"] != canonical_json(request).decode("ascii"):
                    fail("OPERATION_CONFLICT", "Completed operation received a different request")
                conn.commit()
                return {"result": "ALREADY_COMMITTED", "receipt": operation["receipt"]}
            action_record = operation["action_challenge"]
            action = action_record["payload"]
            attestation = self._attestation(strict_json(row["attestation_document"].encode(), MAX_CHALLENGE_BYTES))
            self._active(conn, action)
            assessment = self._assessment(request["assessment"], action, attestation)
            grant = self._grant(request["grant"], action_record, request["assessment"])
            self._active(conn, action, grant["grant_id"])
            self._execution_times(action, attestation, assessment, grant, now)
            if conn.execute("SELECT 1 FROM operations WHERE grant_id=?", (grant["grant_id"],)).fetchone():
                fail("GRANT_SPENT", "Owner grant has already been consumed")
            before = conn.execute("SELECT value FROM counter WHERE id=1").fetchone()[0]
            if before >= MAX_INTEGER:
                fail("COUNTER_EXHAUSTED", "Laboratory counter reached its supported limit")
            committed_at = self._tick(conn)
            self._execution_times(action, attestation, assessment, grant, committed_at)
            payload = {"schema": "wolfalibi.shirudo.effect-receipt.v1", "scope": "LAB_COUNTER_EFFECT_ONLY",
                "authorization": "CONSUMED_FOR_RECORDED_EFFECT", "receipt_id": secrets.token_hex(16),
                "gate_instance_id": self.instance_id, "target_id": self._trust["target_id"],
                "operation_id": operation_id, "operation_nonce": action["operation_nonce"],
                "policy_sha256": self._policy_sha, "policy_generation": action["policy_generation"],
                "grant_id": grant["grant_id"], "grant_sha256": digest(request["grant"]),
                "attestation_receipt_sha256": digest(request["assessment"]),
                "attestation_challenge_sha256": action["attestation_challenge_sha256"],
                "action": dict(ACTION), "counter_before": before, "counter_after": before + 1,
                "committed_at_ms": committed_at}
            receipt = sign_record(self._key, payload)
            conn.execute("UPDATE counter SET value=? WHERE id=1", (before + 1,))
            conn.execute("""UPDATE operations SET status='COMMITTED',request=?,request_sha256=?,grant_id=?,
                         grant_sha256=?,assessment_sha256=?,receipt=?,counter_before=?,counter_after=? WHERE id=?""",
                         (canonical_json(request).decode("ascii"), request_sha, grant["grant_id"],
                          payload["grant_sha256"], payload["attestation_receipt_sha256"],
                          canonical_json(receipt).decode("ascii"), before, before + 1, operation_id))
            final_now = self._tick(conn)
            self._active(conn, action, grant["grant_id"])
            self._execution_times(action, attestation, assessment, grant, final_now)
            # Only trusted local startup code may install this process-fault
            # hook. It is not a request field or a transport operation.
            if self._before_commit is not None:
                self._before_commit()
            self._commit_effect(conn, request, receipt)
        return {"result": "COMMITTED", "receipt": receipt}

    def _commit_prepared(self, conn, action_record):
        conn.commit()

    def _commit_effect(self, conn, request, receipt):
        conn.commit()

    def status(self, operation_id=None):
        if operation_id is not None:
            require_hex(operation_id, 32, "operation")
        with self._connection() as conn:
            self._begin(conn)
            metadata = dict(conn.execute("SELECT key,value FROM metadata"))
            operation = None if operation_id is None else self._decode_operation(self._row(conn, operation_id))
            result = {"schema": "wolfalibi.shirudo.action-status.v1", "gate_instance_id": self.instance_id,
                "target_id": self._trust["target_id"], "policy_sha256": self._policy_sha,
                "policy_generation": int(metadata["policy_generation"]),
                "policy_active": metadata["policy_active"] == "1",
                "counter": conn.execute("SELECT value FROM counter WHERE id=1").fetchone()[0],
                "committed_operations": conn.execute("SELECT COUNT(*) FROM operations WHERE status='COMMITTED'").fetchone()[0],
                "operation": operation}
            conn.commit()
        return result

    def revoke_grant(self, grant_id):
        require_hex(grant_id, 32, "grant")
        with self._connection() as conn:
            now = self._begin(conn)
            conn.execute("INSERT OR IGNORE INTO revoked_grants VALUES (?,?)", (grant_id, now))
            conn.commit()

    def revoke_policy(self):
        with self._connection() as conn:
            self._begin(conn)
            conn.execute("UPDATE metadata SET value='0' WHERE key='policy_active'")
            conn.execute("UPDATE metadata SET value='2' WHERE key='policy_generation'")
            conn.commit()
