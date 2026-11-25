"""Durable verifier-side challenges and atomic signed assessment receipts.

The journal and local clock are trusted inputs, not an external witness.
A claimed challenge is never automatically retried after interruption.
"""

from __future__ import annotations

import hashlib
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

from .model import (AdapterError, MAX_EVIDENCE_BYTES, MAX_POLICY_BYTES, MAX_RECORD_BYTES, canonical_json,
                    check_evidence, digest, exact_keys, fail, read_bounded_file,
                    require_hex, strict_json, validate_policy)
from .receipt import sign_record, verify_record, verify_receipt
from .runner import run_verifier, validate_recorded_report

APPLICATION_ID = 0x57415331
LIMITATIONS = [
    "Historical evidence assessment only; no authorization or deployment capability.",
    "No claim that the measured state persists after the quoted observation.",
    "Shield effectiveness and legitimate workload compatibility are not evaluated.",
    "Enrollment record and executable build provenance are supplied by the trusted operator.",
    "The local host, signing key, journal, clock and runtime dependencies are trusted.",
    "Coordinated journal and clock rollback is not prevented; no independent witness.",
]


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


class Service:
    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir).absolute()
        self._clock = lambda: time.time_ns() // 1_000_000
        self._check_paths()
        config = strict_json(read_bounded_file(self.path / "state.json", 4096), 4096)
        exact_keys(config, {"schema", "instance_id", "public_key"}, "state identity")
        if config["schema"] != "wolfalibi.shirudo.state.v1":
            fail("STATE_INVALID", "Unsupported state identity")
        require_hex(config["instance_id"], 32, "state instance")
        require_hex(config["public_key"], 64, "state public key")
        try:
            self._key = Ed25519PrivateKey.from_private_bytes(
                read_bounded_file(self.path / "signing.key", 32))
        except ValueError as exc:
            raise AdapterError("STATE_INVALID", "Invalid local signing key") from exc
        self.instance_id = config["instance_id"]
        self._public_key = self._key.public_key().public_bytes_raw().hex()
        if self._public_key != config["public_key"]:
            fail("STATE_INVALID", "State identity and signing key disagree")
        self._config_bytes = canonical_json(config)
        with self._connection() as conn:
            self._check_database(conn)

    @classmethod
    def initialize(cls, state_dir: str | Path) -> "Service":
        path = Path(state_dir).absolute()
        try:
            os.mkdir(path, 0o700)
        except FileExistsError as exc:
            raise AdapterError("STATE_EXISTS", "Initialization requires a new state directory") from exc
        except OSError as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Cannot create state directory") from exc
        key = Ed25519PrivateKey.generate()
        instance_id = secrets.token_hex(16)
        public_key = key.public_key().public_bytes_raw().hex()
        try:
            _write_new(path / "signing.key", key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))
            _write_new(path / "state.json", canonical_json({
                "schema": "wolfalibi.shirudo.state.v1", "instance_id": instance_id,
                "public_key": public_key}))
            _write_new(path / "journal.sqlite3", b"")
            conn = sqlite3.connect(path / "journal.sqlite3", isolation_level=None)
            try:
                conn.execute("PRAGMA journal_mode=DELETE")
                conn.execute("PRAGMA synchronous=FULL")
                conn.execute(f"PRAGMA application_id={APPLICATION_ID}")
                conn.execute("PRAGMA user_version=1")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                conn.execute("CREATE TABLE policies (digest TEXT PRIMARY KEY, document TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)))")
                conn.execute("CREATE TABLE challenges (id TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL, policy_digest TEXT NOT NULL REFERENCES policies(digest), document TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('issued','claimed','complete')), started_at_ms INTEGER, receipt TEXT)")
                conn.executemany("INSERT INTO metadata VALUES (?,?)", [
                    ("instance_id", instance_id), ("public_key", public_key),
                    ("last_clock", str(time.time_ns() // 1_000_000))])
                conn.commit()
            finally:
                conn.close()
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except (OSError, sqlite3.Error) as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Initialization did not complete; preserve the directory for inspection") from exc
        return cls(path)

    def _check_paths(self) -> None:
        try:
            for name in (None, "state.json", "signing.key", "journal.sqlite3"):
                path = self.path if name is None else self.path / name
                info = path.lstat()
                good_type = stat.S_ISDIR(info.st_mode) if name is None else stat.S_ISREG(info.st_mode)
                if (not good_type or info.st_uid != os.geteuid() or
                        stat.S_IMODE(info.st_mode) & 0o077 or
                        (name is not None and info.st_nlink != 1)):
                    fail("STATE_PERMISSIONS", "State must be privately owned with no symlinks or shared hard links")
            for name in ("journal.sqlite3-journal", "journal.sqlite3-wal", "journal.sqlite3-shm"):
                candidate = self.path / name
                try:
                    info = candidate.lstat()
                except FileNotFoundError:
                    continue
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
                    fail("STATE_PERMISSIONS", "Unsafe SQLite sidecar")
        except OSError as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Required verifier state is missing or unreadable") from exc

    def _check_database(self, conn) -> None:
        if conn.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID or conn.execute("PRAGMA user_version").fetchone()[0] != 1:
            fail("STATE_INVALID", "Unexpected verifier database")
        values = dict(conn.execute("SELECT key,value FROM metadata"))
        if values.get("instance_id") != self.instance_id or values.get("public_key") != self._public_key:
            fail("STATE_INVALID", "Journal belongs to a different verifier identity")
        try:
            last_clock = int(values["last_clock"])
        except (KeyError, ValueError) as exc:
            raise AdapterError("STATE_INVALID", "Invalid journal clock") from exc
        if not 0 <= last_clock < 2 ** 63:
            fail("STATE_INVALID", "Invalid journal clock")

    @contextmanager
    def _connection(self):
        self._check_paths()
        if hasattr(self, "_config_bytes"):
            current = strict_json(read_bounded_file(self.path / "state.json", 4096), 4096)
            if canonical_json(current) != self._config_bytes:
                fail("STATE_INVALID", "State identity changed during use")
        conn = None
        try:
            uri = "file:" + quote(str(self.path / "journal.sqlite3"), safe="/") + "?mode=rw"
            conn = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=5)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA synchronous=FULL")
            self._check_database(conn)
            yield conn
        except sqlite3.Error as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Verifier journal operation failed") from exc
        finally:
            if conn is not None:
                if conn.in_transaction:
                    conn.rollback()
                conn.close()

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or not 0 <= now < 2 ** 63:
            fail("CLOCK_INVALID", "Verifier clock is invalid")
        return now

    def _tick(self, conn) -> int:
        now = self._now()
        last = int(conn.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()[0])
        if now < last:
            fail("CLOCK_ROLLBACK", "Verifier clock moved backwards")
        conn.execute("UPDATE metadata SET value=? WHERE key='last_clock'", (str(now),))
        return now

    def public_key_hex(self) -> str:
        return self._public_key

    def register_policy(self, policy: dict) -> str:
        # A canonical round trip detaches caller-owned mutable objects.
        policy = validate_policy(strict_json(canonical_json(policy), MAX_POLICY_BYTES))
        sha = digest(policy)
        record = sign_record(self._key, policy)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._tick(conn)
            conn.execute("INSERT OR IGNORE INTO policies VALUES (?,?,1)",
                         (sha, canonical_json(record).decode("ascii")))
            conn.commit()
        return sha

    def _policy(self, conn, sha: str) -> tuple[dict, bool]:
        row = conn.execute("SELECT document,active FROM policies WHERE digest=?", (sha,)).fetchone()
        if row is None:
            fail("UNKNOWN_POLICY", "Policy is not registered with this verifier")
        record = strict_json(row["document"].encode(), MAX_POLICY_BYTES + 1024)
        policy = validate_policy(verify_record(record, self._public_key))
        if digest(policy) != sha:
            fail("STATE_INVALID", "Policy record digest mismatch")
        return policy, row["active"] == 1

    def revoke_policy(self, policy_sha256: str) -> None:
        require_hex(policy_sha256, 64, "policy digest")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._tick(conn)
            self._policy(conn, policy_sha256)
            conn.execute("UPDATE policies SET active=0 WHERE digest=?", (policy_sha256,))
            conn.commit()

    def issue_challenge(self, policy_sha256: str) -> dict:
        require_hex(policy_sha256, 64, "policy digest")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = self._tick(conn)
            policy, active = self._policy(conn, policy_sha256)
            if not active:
                fail("POLICY_REVOKED", "Policy is revoked")
            payload = {"schema": "wolfalibi.shirudo.challenge.v1", "instance_id": self.instance_id,
                       "challenge_id": secrets.token_hex(16), "nonce": secrets.token_hex(32),
                       "policy_sha256": policy_sha256, "target_id": policy["target_id"],
                       "issued_at_ms": now,
                       "expires_at_ms": now + 1000 * policy["challenge_ttl_seconds"]}
            record = sign_record(self._key, payload)
            conn.execute("INSERT INTO challenges(id,nonce,policy_digest,document,status) VALUES (?,?,?,?,'issued')",
                         (payload["challenge_id"], payload["nonce"], policy_sha256,
                          canonical_json(record).decode("ascii")))
            conn.commit()
        return record

    def _challenge(self, conn, challenge_id: str):
        row = conn.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
        if row is None:
            fail("UNKNOWN_CHALLENGE", "Challenge was not issued by this verifier")
        payload = verify_record(strict_json(row["document"].encode()), self._public_key)
        if (payload.get("schema") != "wolfalibi.shirudo.challenge.v1" or
                payload.get("instance_id") != self.instance_id or
                payload.get("challenge_id") != row["id"] or
                payload.get("nonce") != row["nonce"] or
                payload.get("policy_sha256") != row["policy_digest"]):
            fail("STATE_INVALID", "Challenge row does not match its signed record")
        return row, payload

    def _reserve(self, challenge_id: str):
        require_hex(challenge_id, 32, "challenge identifier")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = self._tick(conn)
            row, challenge = self._challenge(conn, challenge_id)
            if row["status"] != "issued":
                fail("CHALLENGE_SPENT", "Challenge was already claimed; retrieve its receipt or issue a new challenge")
            policy, active = self._policy(conn, row["policy_digest"])
            if challenge["target_id"] != policy["target_id"]:
                fail("STATE_INVALID", "Challenge target does not match its policy")
            conn.execute("UPDATE challenges SET status='claimed',started_at_ms=? WHERE id=? AND status='issued'",
                         (now, challenge_id))
            conn.commit()
        return challenge, policy, active, now

    def assess(self, challenge_id: str, evidence: bytes, verifier_path: str) -> dict:
        return self._assess(challenge_id, lambda: evidence, verifier_path)

    def assess_file(self, challenge_id: str, evidence_path: str | Path, verifier_path: str, *,
                    report_sink=None) -> dict:
        return self._assess(challenge_id,
                            lambda: read_bounded_file(evidence_path, MAX_EVIDENCE_BYTES),
                            verifier_path, report_sink=report_sink)

    def _assess(self, challenge_id: str, evidence_source, verifier_path: str, *, report_sink=None) -> dict:
        challenge, policy, active, started = self._reserve(challenge_id)
        result = None
        outcome, reason = "BLOCKED", "NOT_RUN"
        evidence_sha = None
        try:
            if not active:
                fail("POLICY_REVOKED", "Policy is revoked")
            if not challenge["issued_at_ms"] <= started < challenge["expires_at_ms"]:
                fail("CHALLENGE_EXPIRED", "Challenge is outside its validity interval")
            evidence = evidence_source()
            if not isinstance(evidence, bytes):
                fail("INVALID_EVIDENCE", "Evidence must be bytes")
            evidence_sha = hashlib.sha256(evidence).hexdigest()
            check_evidence(evidence, policy, challenge["nonce"])
            options = {} if report_sink is None else {"report_sink": report_sink}
            candidate = run_verifier(verifier_path, evidence, policy, challenge["nonce"], **options)
            route = "SYNTHETIC" if policy["assurance"] == "SYNTHETIC" else "UPSTREAM_CLI"
            if (type(candidate) is not dict or set(candidate) != {
                    "accepted", "execution_profile", "binary_sha256", "version_id",
                    "report", "exit_code", "required_checks"} or
                    type(candidate.get("accepted")) is not bool or
                    candidate.get("execution_profile") != route or
                    candidate.get("binary_sha256") != policy["verifier"]["sha256"] or
                    candidate.get("version_id") != policy["verifier"]["version_id"]):
                fail("RUNNER_CONTRACT", "Runner result does not match the trusted execution contract")
            if validate_recorded_report(candidate["report"], candidate["exit_code"],
                                        candidate["required_checks"]) != candidate["accepted"]:
                fail("RUNNER_CONTRACT", "Runner acceptance and recorded checks disagree")
            result = candidate
            if result["accepted"]:
                outcome = "SIMULATED_POLICY_ONLY" if route == "SYNTHETIC" else "EVIDENCE_ACCEPTED"
                reason = "REQUIRED_CHECKS_PASSED"
            else:
                outcome, reason = "REJECTED", "UPSTREAM_REJECTED"
        except AdapterError as exc:
            reason = exc.code
            rejected = {"INVALID_EVIDENCE", "NONCE_MISMATCH", "TARGET_MISMATCH", "STATE_MISMATCH",
                        "JSON_SIZE", "INVALID_JSON", "DUPLICATE_JSON_KEY", "INVALID_JSON_NUMBER",
                        "JSON_COMPLEXITY", "POLICY_REVOKED", "CHALLENGE_EXPIRED"}
            outcome = "REJECTED" if reason in rejected else "BLOCKED"
        # Unexpected exceptions and process interruption leave a non-reusable
        # reservation. They do not fabricate a completed assessment.
        return self._finalize(challenge, policy, started, evidence_sha, outcome, reason, result)

    def _finalize(self, challenge, policy, started, evidence_sha, outcome, reason, result):
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row, stored = self._challenge(conn, challenge["challenge_id"])
            if row["status"] != "claimed" or stored != challenge or row["started_at_ms"] != started:
                fail("STATE_INVALID", "Reservation changed before completion")
            current_policy, active = self._policy(conn, challenge["policy_sha256"])
            if current_policy != policy:
                fail("STATE_INVALID", "Policy changed before completion")
            now = self._now()
            last = int(conn.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()[0])
            if now < last or now < started:
                outcome, reason = "BLOCKED", "CLOCK_ROLLBACK"
            else:
                conn.execute("UPDATE metadata SET value=? WHERE key='last_clock'", (str(now),))
            if not active:
                outcome, reason = "REJECTED", "POLICY_REVOKED"
            elif now >= challenge["expires_at_ms"]:
                outcome, reason = "REJECTED", "CHALLENGE_EXPIRED"
            report = result.get("report") if type(result) is dict else None
            upstream = {"source_commit": policy["verifier"]["source_commit"],
                        "expected_binary_sha256": policy["verifier"]["sha256"],
                        "expected_version_id": policy["verifier"]["version_id"],
                        "observed_binary_sha256": result.get("binary_sha256") if type(result) is dict else None,
                        "observed_version_id": result.get("version_id") if type(result) is dict else None,
                        "execution_profile": result.get("execution_profile") if type(result) is dict else "NO_VERIFIED_RESULT",
                        "exit_code": result.get("exit_code") if type(result) is dict else None,
                        "report": report, "report_sha256": digest(report) if report is not None else None,
                        "required_checks": result.get("required_checks", []) if type(result) is dict else []}
            payload = {"schema": "wolfalibi.shirudo.receipt.v1", "receipt_id": secrets.token_hex(16),
                       "instance_id": self.instance_id, "challenge_id": challenge["challenge_id"],
                       "nonce": challenge["nonce"], "target_id": policy["target_id"],
                       "policy_sha256": challenge["policy_sha256"],
                       "enrollment_record_sha256": policy["enrollment"]["record_sha256"],
                       "evidence_sha256": evidence_sha, "assurance": policy["assurance"],
                       "outcome": outcome, "reason_code": reason,
                       "issued_at_ms": challenge["issued_at_ms"], "expires_at_ms": challenge["expires_at_ms"],
                       "started_at_ms": started, "completed_at_ms": now, "upstream": upstream,
                       "scope": "HISTORICAL_EVIDENCE_ONLY", "authorization": "NONE",
                       "limitations": LIMITATIONS}
            receipt = sign_record(self._key, payload)
            encoded = canonical_json(receipt)
            if len(encoded) > MAX_RECORD_BYTES:
                fail("RECEIPT_SIZE", "Assessment receipt exceeds its byte limit")
            conn.execute("UPDATE challenges SET status='complete',receipt=? WHERE id=? AND status='claimed'",
                         (encoded.decode("ascii"), challenge["challenge_id"]))
            conn.commit()
        return receipt

    def get_receipt(self, challenge_id: str) -> dict:
        require_hex(challenge_id, 32, "challenge identifier")
        with self._connection() as conn:
            row, challenge = self._challenge(conn, challenge_id)
            if row["status"] != "complete" or row["receipt"] is None:
                fail("RECEIPT_UNAVAILABLE", "No completed receipt; an interrupted claim remains spent")
            receipt = strict_json(row["receipt"].encode(), MAX_RECORD_BYTES)
            verify_receipt(receipt, self._public_key, expected_target=challenge["target_id"],
                           expected_policy_sha256=challenge["policy_sha256"],
                           expected_challenge_id=challenge_id)
            return receipt
