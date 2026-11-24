"""Private owner authority for one explicitly reviewed laboratory counter grant.

Only public signed records cross into this component. The owner account,
terminal, clock, installed code and private journal are trusted. This module
does not prove that a human operated a terminal and never executes a target
operation. The command-line interface supplies the interactive ceremony.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import stat
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .action_gate import (ACTION, ADMISSION_MS, CLOCK_SKEW_MS, FRESHNESS_MS,
                          MAX_CHALLENGE_BYTES, MAX_INTEGER, _action_payload,
                          make_grant_payload)
from .model import (AdapterError, MAX_POLICY_BYTES, MAX_RECORD_BYTES, bounded_int,
                    canonical_json, digest, exact_keys, fail, identifier,
                    read_bounded_file, require_hex, strict_json, validate_policy)
from .receipt import sign_record, verify_receipt, verify_record
from .runner import _arguments

APPLICATION_ID = 0x574F5731
MAX_PROFILE_BYTES = MAX_POLICY_BYTES + 4096
MAX_INTENT_BYTES = 4096
MAX_BUNDLE_BYTES = MAX_RECORD_BYTES + 2 * MAX_CHALLENGE_BYTES + 4096
MIN_REMAINING_MS = 2000
_PROFILE_KEYS = {"schema", "target_id", "gate_instance_id", "gate_public_key",
                 "policy_generation", "owner_public_key", "verifier_instance_id",
                 "verifier_public_key", "policy"}
_INTENT_KEYS = {"schema", "request_id", "target_id", "gate_instance_id",
                "policy_sha256", "policy_generation", "action"}
_BUNDLE_KEYS = {"schema", "request_id", "attestation_challenge", "action_challenge",
                "assessment"}
_ATTESTATION_KEYS = {"schema", "instance_id", "challenge_id", "nonce",
                     "policy_sha256", "target_id", "issued_at_ms", "expires_at_ms"}


def _freeze(value, limit):
    return strict_json(canonical_json(value), limit)


def validate_profile(value, *, owner_public_key=None):
    profile = _freeze(value, MAX_PROFILE_BYTES)
    exact_keys(profile, _PROFILE_KEYS, "owner profile")
    if profile["schema"] != "wolfalibi.shirudo.owner-profile.v1":
        fail("INVALID_SCHEMA", "Unsupported owner profile")
    identifier(profile["target_id"], "profile target")
    for key in ("gate_instance_id", "verifier_instance_id"):
        require_hex(profile[key], 32, key)
    keys = [require_hex(profile[key], 64, key) for key in
            ("owner_public_key", "gate_public_key", "verifier_public_key")]
    if len(set(keys)) != 3:
        fail("PROFILE_MISMATCH", "Owner, gate and verifier require separate public keys")
    if owner_public_key is not None and profile["owner_public_key"] != owner_public_key:
        fail("PROFILE_MISMATCH", "Profile does not name this owner identity")
    bounded_int(profile["policy_generation"], 1, MAX_INTEGER, "policy generation")
    policy = validate_policy(profile["policy"])
    if policy["assurance"] != "LAB_VTPM" or policy["target_id"] != profile["target_id"]:
        fail("PROFILE_MISMATCH", "Owner profile requires the selected target's LAB_VTPM policy")
    return profile


def validate_intent(value, profile):
    intent = _freeze(value, MAX_INTENT_BYTES)
    exact_keys(intent, _INTENT_KEYS, "owner intent")
    if intent["schema"] != "wolfalibi.shirudo.owner-intent.v1":
        fail("INVALID_SCHEMA", "Unsupported owner intent")
    require_hex(intent["request_id"], 32, "request id")
    identifier(intent["target_id"], "intent target")
    require_hex(intent["gate_instance_id"], 32, "intent gate")
    require_hex(intent["policy_sha256"], 64, "intent policy")
    bounded_int(intent["policy_generation"], 1, MAX_INTEGER, "intent policy generation")
    exact_keys(intent["action"], {"name", "delta"}, "intent action")
    bounded_int(intent["action"]["delta"], 1, 1, "counter delta")
    if intent["action"] != ACTION:
        fail("INTENT_MISMATCH", "Only one laboratory counter increment can be approved")
    expected = {key: profile[key] for key in
                ("target_id", "gate_instance_id", "policy_generation")}
    expected["policy_sha256"] = digest(profile["policy"])
    if any(intent[key] != value for key, value in expected.items()):
        fail("INTENT_MISMATCH", "Requested action differs from the independently pinned profile")
    return intent


def validate_bundle(bundle, profile, *, intent, ready_at_ms, now_ms,
                    min_remaining_ms=0):
    """Authenticate a frozen public bundle against independent complete pins.

    No key is read and no authority is created. ``ready_at_ms`` is the owner's
    local observation, never a time supplied by the submitted bundle.
    """
    profile = validate_profile(profile)
    intent = validate_intent(intent, profile)
    bundle = _freeze(bundle, MAX_BUNDLE_BYTES)
    exact_keys(bundle, _BUNDLE_KEYS, "owner bundle")
    if bundle["schema"] != "wolfalibi.shirudo.owner-bundle.v1":
        fail("INVALID_SCHEMA", "Unsupported owner bundle")
    if bundle["request_id"] != intent["request_id"]:
        fail("BUNDLE_MISMATCH", "Bundle belongs to a different reviewed request")
    bounded_int(now_ms, 0, MAX_INTEGER, "owner time")
    bounded_int(ready_at_ms, 0, now_ms, "owner readiness time")
    bounded_int(min_remaining_ms, 0, FRESHNESS_MS, "minimum remaining interval")
    if now_ms - ready_at_ms > FRESHNESS_MS:
        fail("APPROVAL_EXPIRED", "The owner's single fresh attempt has expired")
    for key in ("attestation_challenge", "action_challenge"):
        _freeze(bundle[key], MAX_CHALLENGE_BYTES)
    _freeze(bundle["assessment"], MAX_RECORD_BYTES)
    attestation = verify_record(bundle["attestation_challenge"], profile["verifier_public_key"])
    exact_keys(attestation, _ATTESTATION_KEYS, "verifier challenge")
    if attestation["schema"] != "wolfalibi.shirudo.challenge.v1":
        fail("INVALID_SCHEMA", "Unsupported verifier challenge")
    for key in ("instance_id", "challenge_id"):
        require_hex(attestation[key], 32, key)
    for key in ("nonce", "policy_sha256"):
        require_hex(attestation[key], 64, key)
    identifier(attestation["target_id"], "attestation target")
    for key in ("issued_at_ms", "expires_at_ms"):
        bounded_int(attestation[key], 0, MAX_INTEGER, key)
    expected = {"instance_id": profile["verifier_instance_id"],
                "target_id": profile["target_id"], "policy_sha256": digest(profile["policy"])}
    if (any(attestation[key] != value for key, value in expected.items()) or
            attestation["expires_at_ms"] - attestation["issued_at_ms"] !=
            profile["policy"]["challenge_ttl_seconds"] * 1000):
        fail("CHALLENGE_SCOPE_MISMATCH", "Verifier challenge differs from the pinned target policy")
    if attestation["issued_at_ms"] < ready_at_ms - CLOCK_SKEW_MS:
        fail("CHALLENGE_PREDATES_READY", "A prior attestation cannot replace this fresh attempt")
    action = _action_payload(verify_record(bundle["action_challenge"], profile["gate_public_key"]))
    expected = {key: intent[key] for key in
                ("target_id", "gate_instance_id", "policy_sha256", "policy_generation", "action")}
    expected.update(attestation_challenge_sha256=digest(bundle["attestation_challenge"]),
                    attestation_challenge_id=attestation["challenge_id"],
                    attestation_nonce=attestation["nonce"])
    if any(action[key] != value for key, value in expected.items()):
        fail("ACTION_MISMATCH", "Target challenge differs from the reviewed intent or verifier challenge")
    if (not -CLOCK_SKEW_MS <= action["issued_at_ms"] - attestation["issued_at_ms"] <= ADMISSION_MS or
            action["expires_at_ms"] != min(action["issued_at_ms"] + FRESHNESS_MS,
                attestation["issued_at_ms"] + FRESHNESS_MS, attestation["expires_at_ms"])):
        fail("ACTION_MISMATCH", "Target challenge does not preserve the gate's admission and expiry limits")
    result = verify_receipt(bundle["assessment"], profile["verifier_public_key"],
                            expected_target=profile["target_id"],
                            expected_policy_sha256=digest(profile["policy"]),
                            expected_challenge_id=attestation["challenge_id"])
    assessment = bundle["assessment"]["payload"]
    upstream = assessment["upstream"]
    if (result["historical_outcome"] != "EVIDENCE_ACCEPTED" or
            assessment["assurance"] != "LAB_VTPM" or upstream["execution_profile"] != "UPSTREAM_CLI"):
        fail("ASSESSMENT_NOT_ACCEPTED", "Owner requires an accepted upstream LAB_VTPM assessment")
    expected = {"instance_id": profile["verifier_instance_id"], "nonce": attestation["nonce"],
                "issued_at_ms": attestation["issued_at_ms"], "expires_at_ms": attestation["expires_at_ms"],
                "enrollment_record_sha256": profile["policy"]["enrollment"]["record_sha256"]}
    pins = profile["policy"]["verifier"]
    if (any(assessment[key] != value for key, value in expected.items()) or
            upstream["source_commit"] != pins["source_commit"] or
            any(upstream[key] != pins[pin] for key, pin in (
                ("expected_binary_sha256", "sha256"), ("observed_binary_sha256", "sha256"),
                ("expected_version_id", "version_id"), ("observed_version_id", "version_id")))):
        fail("ASSESSMENT_MISMATCH", "Assessment differs from the owner's independent enrollment and verifier pins")
    _, required = _arguments(profile["policy"], attestation["nonce"], "/unused")
    if upstream["required_checks"][:-3] != required:
        fail("ASSESSMENT_MISMATCH", "Assessment omits or changes checks required by the complete pinned policy")
    if (now_ms < action["issued_at_ms"] or
            max(attestation["issued_at_ms"], assessment["started_at_ms"], assessment["completed_at_ms"]) >
            now_ms + CLOCK_SKEW_MS or
            assessment["started_at_ms"] < action["issued_at_ms"] - CLOCK_SKEW_MS):
        fail("CLOCK_SKEW", "Authority timestamps exceed the declared clock limits")
    if (now_ms >= action["expires_at_ms"] or now_ms >= attestation["expires_at_ms"] or
            now_ms - attestation["issued_at_ms"] > FRESHNESS_MS or
            action["expires_at_ms"] - now_ms < min_remaining_ms):
        fail("APPROVAL_EXPIRED", "There is insufficient lifetime for this concrete operation")
    return {"operation_id": action["operation_id"], "target_id": action["target_id"],
            "action": dict(ACTION), "policy_sha256": action["policy_sha256"],
            "policy_generation": action["policy_generation"], "expires_at_ms": action["expires_at_ms"],
            "remaining_ms": action["expires_at_ms"] - now_ms,
            "assessment_outcome": result["historical_outcome"], "assurance": "LAB_VTPM",
            "bundle_sha256": digest(bundle), "intent_sha256": digest(intent),
            "approval_phrase": "APPROVE " + action["operation_id"][-12:]}


@dataclass(frozen=True)
class ReviewedBundle:
    """Immutable public bytes displayed by the owner before confirmation."""

    intent_bytes: bytes
    bundle_bytes: bytes
    profile_sha256: str
    ready_at_ms: int
    reviewed_at_ms: int
    summary_bytes: bytes

    def summary(self):
        return strict_json(self.summary_bytes, MAX_INTENT_BYTES)


class _Connection(sqlite3.Connection):
    observed_clock = None


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


class Owner:
    """Local owner state; a caller with this UID remains a trusted authority."""

    def __init__(self, state_dir):
        self.path = Path(state_dir).absolute()
        self._clock = lambda: time.time_ns() // 1_000_000
        self._profile_bytes = None
        self._loaded_profile = False
        self._check_paths()
        identity = strict_json(read_bounded_file(self.path / "state.json", 4096), 4096)
        exact_keys(identity, {"schema", "owner_instance_id", "public_key"}, "owner state")
        if identity["schema"] != "wolfalibi.shirudo.owner-state.v1":
            fail("STATE_INVALID", "Unsupported owner state")
        self.instance_id = require_hex(identity["owner_instance_id"], 32, "owner instance")
        self._public_key = require_hex(identity["public_key"], 64, "owner public key")
        self._identity_bytes = canonical_json(identity)
        self._key_bytes = read_bounded_file(self.path / "signing.key", 32)
        try:
            self._key = Ed25519PrivateKey.from_private_bytes(self._key_bytes)
        except ValueError as exc:
            raise AdapterError("STATE_INVALID", "Invalid owner signing key") from exc
        if self._key.public_key().public_bytes_raw().hex() != self._public_key:
            fail("STATE_INVALID", "Owner key and public identity disagree")
        self._path_ids = {name: self._path_identity(self.path if name is None else self.path / name)
                          for name in (None, "state.json", "signing.key", "journal.sqlite3")}
        with self._connection() as conn:
            conn.commit()

    @staticmethod
    def _path_identity(path):
        info = path.lstat()
        return info.st_dev, info.st_ino

    @staticmethod
    def _check_ancestors(path):
        if ".." in path.parts:
            fail("STATE_PERMISSIONS", "Parent traversal is not an owner-state path")
        try:
            for parent in path.parents:
                info = parent.lstat()
                mode = stat.S_IMODE(info.st_mode)
                sticky_root = info.st_uid == 0 and bool(mode & stat.S_ISVTX)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                        (mode & 0o022 and not sticky_root)):
                    fail("STATE_PERMISSIONS", "Owner-state ancestors must be trusted and nonreplaceable")
        except OSError as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Owner-state parent is unavailable") from exc

    def _check_paths(self):
        self._check_ancestors(self.path)
        try:
            for name in (None, "state.json", "signing.key", "journal.sqlite3"):
                path = self.path if name is None else self.path / name
                info = path.lstat()
                proper_type = stat.S_ISDIR(info.st_mode) if name is None else stat.S_ISREG(info.st_mode)
                if (not proper_type or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077 or
                        (name is not None and info.st_nlink != 1)):
                    fail("STATE_PERMISSIONS", "Owner state must be private, owned and free of links")
                if hasattr(self, "_path_ids") and self._path_ids[name] != (info.st_dev, info.st_ino):
                    fail("STATE_INVALID", "Owner state was replaced during use")
            for suffix in ("-journal", "-wal", "-shm"):
                try:
                    info = (self.path / ("journal.sqlite3" + suffix)).lstat()
                except FileNotFoundError:
                    continue
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
                    fail("STATE_PERMISSIONS", "Unsafe owner database sidecar")
        except OSError as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Required owner state is missing or unreadable") from exc

    @classmethod
    def initialize(cls, state_dir):
        path = Path(state_dir).absolute()
        cls._check_ancestors(path)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError as exc:
            raise AdapterError("STATE_EXISTS", "Owner initialization needs a new directory") from exc
        except OSError as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Cannot create private owner state") from exc
        key = Ed25519PrivateKey.generate()
        identity = {"schema": "wolfalibi.shirudo.owner-state.v1", "owner_instance_id": secrets.token_hex(16),
                    "public_key": key.public_key().public_bytes_raw().hex()}
        try:
            _write_new(path / "signing.key", key.private_bytes(serialization.Encoding.Raw,
                       serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            _write_new(path / "state.json", canonical_json(identity))
            _write_new(path / "journal.sqlite3", b"")
            with closing(sqlite3.connect(path / "journal.sqlite3", isolation_level=None)) as conn:
                conn.execute("PRAGMA journal_mode=DELETE")
                conn.execute("PRAGMA synchronous=FULL")
                conn.execute(f"PRAGMA application_id={APPLICATION_ID}")
                conn.execute("PRAGMA user_version=1")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                conn.executemany("INSERT INTO metadata VALUES (?,?)", [
                    ("owner_instance_id", identity["owner_instance_id"]), ("public_key", identity["public_key"]),
                    ("profile_document", ""), ("profile_sha256", ""),
                    ("last_clock", str(time.time_ns() // 1_000_000))])
                conn.execute("""CREATE TABLE grants (
                    operation_id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
                    grant_id TEXT UNIQUE NOT NULL, intent_document TEXT NOT NULL,
                    bundle_document TEXT NOT NULL, bundle_sha256 TEXT NOT NULL,
                    ready_at_ms INTEGER NOT NULL, reviewed_at_ms INTEGER NOT NULL,
                    approved_at_ms INTEGER NOT NULL, grant_document TEXT NOT NULL,
                    grant_sha256 TEXT NOT NULL)""")
                conn.execute("""CREATE TABLE provisioning (
                    id INTEGER PRIMARY KEY CHECK(id=1), anchors_document TEXT NOT NULL,
                    manifest_document TEXT NOT NULL, trust_document TEXT NOT NULL,
                    envelope_document TEXT NOT NULL, pinned_at_ms INTEGER NOT NULL)""")
                conn.commit()
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except (OSError, sqlite3.Error) as exc:
            raise AdapterError("STATE_UNAVAILABLE", "Owner initialization did not complete; preserve its directory") from exc
        return cls(path)

    @contextmanager
    def _connection(self):
        self._check_paths()
        if (canonical_json(strict_json(read_bounded_file(self.path / "state.json", 4096), 4096)) !=
                self._identity_bytes or read_bounded_file(self.path / "signing.key", 32) != self._key_bytes):
            fail("STATE_INVALID", "Owner identity or signing key changed during use")
        conn = None
        try:
            conn = sqlite3.connect("file:" + quote(str(self.path / "journal.sqlite3"), safe="/") + "?mode=rw",
                                   uri=True, isolation_level=None, timeout=5, factory=_Connection)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA synchronous=FULL")
            if conn.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                fail("STATE_INVALID", "Owner journal requires durable rollback-journal mode")
            self._check_paths()
            conn.execute("BEGIN IMMEDIATE")
            self._check_database(conn)
            yield conn
        except BaseException as exc:
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
                        raise AdapterError("STATE_UNAVAILABLE", "Owner clock journal could not be preserved") from clock_error
            if isinstance(exc, sqlite3.Error):
                raise AdapterError("STATE_UNAVAILABLE", "Owner database operation failed") from exc
            raise
        finally:
            if conn is not None:
                if conn.in_transaction:
                    conn.rollback()
                conn.close()

    def _check_database(self, conn):
        if (conn.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID or
                conn.execute("PRAGMA user_version").fetchone()[0] != 1):
            fail("STATE_INVALID", "Unexpected owner database")
        metadata = dict(conn.execute("SELECT key,value FROM metadata"))
        if (set(metadata) != {"owner_instance_id", "public_key", "profile_document", "profile_sha256", "last_clock"} or
                metadata["owner_instance_id"] != self.instance_id or metadata["public_key"] != self._public_key):
            fail("STATE_INVALID", "Owner journal and identity disagree")
        try:
            last = int(metadata["last_clock"])
        except (TypeError, ValueError) as exc:
            raise AdapterError("STATE_INVALID", "Invalid owner clock journal") from exc
        if not 0 <= last <= MAX_INTEGER or str(last) != metadata["last_clock"]:
            fail("STATE_INVALID", "Invalid owner clock journal")
        profile_bytes = None
        if metadata["profile_document"]:
            profile = validate_profile(strict_json(metadata["profile_document"].encode(), MAX_PROFILE_BYTES),
                                       owner_public_key=self._public_key)
            profile_bytes = canonical_json(profile)
            if metadata["profile_sha256"] != digest(profile) or profile_bytes.decode() != metadata["profile_document"]:
                fail("STATE_INVALID", "Pinned profile and its recorded digest disagree")
        elif metadata["profile_sha256"]:
            fail("STATE_INVALID", "Incomplete pinned owner profile")
        if self._loaded_profile and self._profile_bytes != profile_bytes:
            fail("PROFILE_CHANGED", "The pinned profile changed during this owner session")
        self._profile_bytes, self._loaded_profile = profile_bytes, True
        provisions = conn.execute("SELECT * FROM provisioning").fetchall()
        if len(provisions) > 1:
            fail("STATE_INVALID", "Owner has more than one immutable provisioning record")
        for provision in provisions:
            trust, _ = self._decode_provisioning(provision, last)
            if profile_bytes is not None:
                self._match_provisioned_profile(self._profile(), trust)
        rows = conn.execute("SELECT * FROM grants").fetchall()
        if rows and profile_bytes is None:
            fail("STATE_INVALID", "Grants exist without an independently pinned profile")
        for row in rows:
            self._decode_grant(row, last)

    def _tick(self, conn):
        now = self._clock()
        if type(now) is not int or not 0 <= now <= MAX_INTEGER:
            fail("CLOCK_INVALID", "Owner clock is invalid")
        last = int(conn.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()[0])
        if now < last:
            fail("CLOCK_ROLLBACK", "Owner clock moved backwards")
        conn.execute("UPDATE metadata SET value=? WHERE key='last_clock'", (str(now),))
        conn.observed_clock = now if conn.observed_clock is None else max(now, conn.observed_clock)
        return now

    def _profile(self):
        if self._profile_bytes is None:
            fail("PROFILE_NOT_PINNED", "Explicitly pin the independently provisioned target profile first")
        return strict_json(self._profile_bytes, MAX_PROFILE_BYTES)

    def public_identity(self):
        with self._connection() as conn:
            conn.commit()
        return {"schema": "wolfalibi.shirudo.owner-identity.v1", "owner_instance_id": self.instance_id,
                "public_key": self._public_key,
                "profile_sha256": None if self._profile_bytes is None else digest(self._profile())}

    def pin_profile(self, value):
        profile = validate_profile(value, owner_public_key=self._public_key)
        raw = canonical_json(profile)
        with self._connection() as conn:
            self._tick(conn)
            if self._profile_bytes is not None and raw != self._profile_bytes:
                fail("PROFILE_PINNED", "An owner profile cannot be silently replaced")
            provision = conn.execute("SELECT * FROM provisioning WHERE id=1").fetchone()
            if provision is not None:
                trust, _ = self._decode_provisioning(provision,
                    int(conn.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()[0]))
                self._match_provisioned_profile(profile, trust)
            conn.execute("UPDATE metadata SET value=? WHERE key='profile_document'", (raw.decode(),))
            conn.execute("UPDATE metadata SET value=? WHERE key='profile_sha256'", (digest(profile),))
            conn.commit()
        self._profile_bytes = raw
        return {"status": "PROFILE_PINNED", "profile_sha256": digest(profile)}

    @staticmethod
    def _match_provisioned_profile(profile, trust):
        fields = ("target_id", "owner_public_key", "verifier_public_key", "verifier_instance_id", "policy")
        if any(profile[key] != trust[key] for key in fields):
            fail("PROVISIONING_MISMATCH", "Owner profile differs from its immutable signed boot policy")

    def _decode_provisioning(self, row, last_clock):
        try:
            from .action_gate import MAX_TRUST_BYTES
            from .bootstrap import prepare_boot_policy
            anchors = strict_json(row["anchors_document"].encode(), 16_384)
            manifest = strict_json(row["manifest_document"].encode(), 16_384)
            trust = strict_json(row["trust_document"].encode(), MAX_TRUST_BYTES)
            envelope = strict_json(row["envelope_document"].encode(), MAX_TRUST_BYTES + 16_384)
            bounded_int(row["pinned_at_ms"], 0, last_clock, "provisioning time")
            expected = prepare_boot_policy(anchors, trust, manifest, self._public_key)
            if (row["id"] != 1 or verify_record(envelope, self._public_key) != expected or
                    canonical_json(anchors).decode() != row["anchors_document"] or
                    canonical_json(manifest).decode() != row["manifest_document"] or
                    canonical_json(trust).decode() != row["trust_document"] or
                    canonical_json(envelope).decode() != row["envelope_document"]):
                fail("STATE_INVALID", "Recorded immutable provisioning bindings disagree")
            return trust, envelope
        except (AdapterError, ValueError, TypeError, KeyError) as exc:
            raise AdapterError("STATE_INVALID", "Owner provisioning journal is invalid") from exc

    def sign_boot_policy(self, anchors, trust, manifest):
        """Explicit trusted LAB provisioning, independent of action approval.

        The target identity is created only after bootstrap, so this may precede
        pin_profile. The later profile must match these exact public trust pins.
        """
        from .action_gate import MAX_TRUST_BYTES
        from .bootstrap import prepare_boot_policy
        anchors = _freeze(anchors, 16_384)
        manifest = _freeze(manifest, 16_384)
        trust = _freeze(trust, MAX_TRUST_BYTES)
        payload = prepare_boot_policy(anchors, trust, manifest, self._public_key)
        with self._connection() as conn:
            now = self._tick(conn)
            if self._profile_bytes is not None:
                self._match_provisioned_profile(self._profile(), trust)
            existing = conn.execute("SELECT * FROM provisioning WHERE id=1").fetchone()
            if existing is not None:
                if any(existing[column] != canonical_json(value).decode() for column, value in (
                    ("anchors_document", anchors), ("manifest_document", manifest), ("trust_document", trust))):
                    fail("PROVISIONING_PINNED", "Immutable boot provisioning cannot be silently replaced")
                _, envelope = self._decode_provisioning(existing, now)
            else:
                envelope = sign_record(self._key, payload)
                conn.execute("INSERT INTO provisioning VALUES (1,?,?,?,?,?)", (
                    canonical_json(anchors).decode(), canonical_json(manifest).decode(),
                    canonical_json(trust).decode(), canonical_json(envelope).decode(), now))
            conn.commit()
        return {"status": "BOOT_POLICY_SIGNED", "boot_policy": envelope,
                "boot_policy_sha256": digest(envelope), "action_authorization": "NONE"}

    def review(self, intent):
        with self._connection() as conn:
            profile = self._profile()
            intent = validate_intent(intent, profile)
            conn.commit()
        return {"status": "REVIEW", "intent": intent, "intent_sha256": digest(intent),
                "profile_sha256": digest(profile), "assurance": "LAB_VTPM",
                "gate_public_key": profile["gate_public_key"], "verifier_public_key": profile["verifier_public_key"],
                "owner_public_key": self._public_key, "authorization": "NONE"}

    def begin_attempt(self, intent):
        with self._connection() as conn:
            now = self._tick(conn)
            intent = validate_intent(intent, self._profile())
            if conn.execute("SELECT 1 FROM grants WHERE request_id=?", (intent["request_id"],)).fetchone():
                fail("REQUEST_SPENT", "This reviewed request already has a recorded grant")
            conn.commit()
        return {"status": "READY", "owner_instance_id": self.instance_id,
                "request_id": intent["request_id"], "intent_sha256": digest(intent),
                "profile_sha256": digest(self._profile()), "ready_at_ms": now}

    def review_bundle(self, intent, bundle, *, ready_at_ms):
        intent_bytes = canonical_json(_freeze(intent, MAX_INTENT_BYTES))
        bundle_bytes = canonical_json(_freeze(bundle, MAX_BUNDLE_BYTES))
        with self._connection() as conn:
            now = self._tick(conn)
            profile = self._profile()
            summary = validate_bundle(strict_json(bundle_bytes, MAX_BUNDLE_BYTES), profile,
                intent=strict_json(intent_bytes, MAX_INTENT_BYTES), ready_at_ms=ready_at_ms,
                now_ms=now, min_remaining_ms=MIN_REMAINING_MS)
            conn.commit()
        return ReviewedBundle(intent_bytes, bundle_bytes, digest(profile), ready_at_ms, now, canonical_json(summary))

    def _issue_grant(self, reviewed, *, approval_phrase):
        """Trusted owner-process primitive; CLI requires a live terminal first."""
        if type(reviewed) is not ReviewedBundle:
            fail("APPROVAL_MISMATCH", "Approval requires a frozen reviewed bundle")
        intent = strict_json(reviewed.intent_bytes, MAX_INTENT_BYTES)
        bundle = strict_json(reviewed.bundle_bytes, MAX_BUNDLE_BYTES)
        displayed = reviewed.summary()
        if approval_phrase != displayed.get("approval_phrase"):
            fail("APPROVAL_MISMATCH", "Confirmation does not name the reviewed operation")
        with self._connection() as conn:
            now = self._tick(conn)
            profile = self._profile()
            if digest(profile) != reviewed.profile_sha256 or now < reviewed.reviewed_at_ms:
                fail("APPROVAL_MISMATCH", "Profile or time changed after the displayed review")
            summary = validate_bundle(bundle, profile, intent=intent, ready_at_ms=reviewed.ready_at_ms,
                                      now_ms=now, min_remaining_ms=MIN_REMAINING_MS)
            comparable = {key: value for key, value in summary.items() if key != "remaining_ms"}
            if comparable != {key: value for key, value in displayed.items() if key != "remaining_ms"}:
                fail("APPROVAL_MISMATCH", "The confirmed bundle differs from the displayed review")
            existing = conn.execute("SELECT * FROM grants WHERE operation_id=? OR request_id=?",
                                   (summary["operation_id"], intent["request_id"])).fetchall()
            if existing:
                if len(existing) != 1 or existing[0]["bundle_document"] != reviewed.bundle_bytes.decode() or \
                        existing[0]["intent_document"] != reviewed.intent_bytes.decode():
                    fail("GRANT_CONFLICT", "This operation or reviewed request already has different authority")
                grant = self._decode_grant(existing[0], now)
            else:
                payload = make_grant_payload(bundle["action_challenge"], bundle["assessment"],
                    grant_id=secrets.token_hex(16), issued_at_ms=now, expires_at_ms=summary["expires_at_ms"])
                grant = sign_record(self._key, payload)
                conn.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
                    summary["operation_id"], intent["request_id"], payload["grant_id"],
                    reviewed.intent_bytes.decode(), reviewed.bundle_bytes.decode(), digest(bundle),
                    reviewed.ready_at_ms, reviewed.reviewed_at_ms, now,
                    canonical_json(grant).decode(), digest(grant)))
                final_now = self._tick(conn)
                validate_bundle(bundle, profile, intent=intent, ready_at_ms=reviewed.ready_at_ms,
                                now_ms=final_now, min_remaining_ms=MIN_REMAINING_MS)
            conn.commit()
        return {"status": "GRANT_ISSUED", "operation_id": summary["operation_id"],
                "grant": grant, "effect": "NOT_ESTABLISHED"}

    def _decode_grant(self, row, last_clock):
        try:
            intent = strict_json(row["intent_document"].encode(), MAX_INTENT_BYTES)
            bundle = strict_json(row["bundle_document"].encode(), MAX_BUNDLE_BYTES)
            grant = strict_json(row["grant_document"].encode(), MAX_CHALLENGE_BYTES)
            payload = verify_record(grant, self._public_key)
            bounded_int(row["ready_at_ms"], 0, last_clock, "recorded readiness")
            bounded_int(row["reviewed_at_ms"], row["ready_at_ms"], last_clock, "recorded review")
            bounded_int(row["approved_at_ms"], row["reviewed_at_ms"], last_clock, "recorded approval")
            summary = validate_bundle(bundle, self._profile(), intent=intent,
                ready_at_ms=row["ready_at_ms"], now_ms=row["approved_at_ms"])
            expected = make_grant_payload(bundle["action_challenge"], bundle["assessment"],
                grant_id=row["grant_id"], issued_at_ms=row["approved_at_ms"], expires_at_ms=summary["expires_at_ms"])
            if (payload != expected or row["operation_id"] != summary["operation_id"] or
                    row["request_id"] != intent["request_id"] or row["bundle_sha256"] != digest(bundle) or
                    row["grant_sha256"] != digest(grant) or
                    canonical_json(intent).decode() != row["intent_document"] or
                    canonical_json(bundle).decode() != row["bundle_document"] or
                    canonical_json(grant).decode() != row["grant_document"]):
                fail("STATE_INVALID", "Recorded grant bindings disagree")
            return grant
        except (AdapterError, ValueError, TypeError, KeyError) as exc:
            raise AdapterError("STATE_INVALID", "Owner grant journal is invalid") from exc

    def grant(self, operation_id):
        require_hex(operation_id, 32, "operation id")
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM grants WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None:
                fail("UNKNOWN_OPERATION", "No grant is recorded for this operation")
            last = int(conn.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()[0])
            grant = self._decode_grant(row, last)
            conn.commit()
        return {"status": "GRANT_RECORDED", "operation_id": operation_id, "grant": grant,
                "scope": "RECORDED_GRANT_ONLY", "current_authorization": "NOT_ESTABLISHED",
                "effect": "NOT_ESTABLISHED"}
