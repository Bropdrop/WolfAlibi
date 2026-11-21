"""Read and authenticate one historical Gate 003 admission from a local snapshot."""

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat

from alibi import H, canon, verify_sig
from .clearance_records import _document, _fields, _time
from .finance_records import (
    business_digest, digest, idempotency_key, run_scope, snapshot_packet, validate_peer, validate_scope,
)
from .finance_verify import _EXPECTED, verify_admission
from .solitary_cli import _unique_object
from .stage3_evidence import _hex
from .voidcell002_anchor import _DOMAIN, _MAX_ANCHOR_BYTES, _TYPE, _ledger_state


_ANCHOR_FIELDS = {
    "type", "target_pub", "generation", "previous_anchor_sha256", "ledger_sha256", "policy_sha256",
}
_AUTHORITY_FIELDS = {"profile", "config", "target_pub", "witness_owner", "witness_directory"}
_ISSUER_FIELDS = ("owner_pub", "supervisor_pub", "witness_pub")
_CONFIG_FIELDS = {"scope", "peer", "witness_head_path", *_ISSUER_FIELDS}
_ENTRY_FIELDS = {"business_sha256", "receipt"}
_DECISION_FIELDS = _ENTRY_FIELDS | {
    "outcome", "packet", "observed_peer", "observed_witness_head", "observed_at",
}
_INTENT = "INTENT_RECORDED"
_MAX_ROW_BYTES = 65_536


class HistoryArchiveError(ValueError):
    """The pinned Gate 003 archive cannot substantiate the requested history."""


def _invalid_constant(value):
    raise ValueError(f"invalid JSON constant {value}")


def _canonical_json(raw, fields, label, *, maximum=_MAX_ROW_BYTES):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise HistoryArchiveError(f"invalid {label} size")
    value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    _fields(value, fields, label)
    if raw != canon(value):
        raise HistoryArchiveError(f"noncanonical {label}")
    return value


def _stamp(item):
    if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
        raise HistoryArchiveError("archive requires ordinary single-link files")
    return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def _read_anchor(path, *, anchor_sha256, target_pub):
    expected_digest = _hex(anchor_sha256, 32, "independently retained anchor digest")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        stamp = _stamp(metadata)
        raw = stream.read(_MAX_ANCHOR_BYTES + 1)
    if len(raw) != metadata.st_size or H(raw) != expected_digest or _stamp(path.lstat()) != stamp:
        raise HistoryArchiveError("retained anchor differs from its independent pin or changed during read")
    envelope = _canonical_json(raw, {"payload", "signature"}, "retained anchor", maximum=_MAX_ANCHOR_BYTES)
    payload = envelope["payload"]
    _fields(payload, _ANCHOR_FIELDS, "retained anchor payload")
    if payload["type"] != _TYPE or payload["target_pub"] != target_pub.hex():
        raise HistoryArchiveError("retained anchor names a different target or protocol")
    generation = payload["generation"]
    _time(generation, "retained anchor generation")
    predecessor = payload["previous_anchor_sha256"]
    if generation > 0:
        _hex(predecessor, 32, "retained anchor predecessor")
    elif predecessor is not None:
        raise HistoryArchiveError("genesis anchor has a predecessor")
    for field in ("ledger_sha256", "policy_sha256"):
        _hex(payload[field], 32, field)
    signature = _hex(envelope["signature"], 64, "retained anchor signature")
    if not verify_sig(target_pub, _DOMAIN, canon(payload), signature):
        raise HistoryArchiveError("retained anchor signature is invalid")
    return payload, stamp


def _single(db, sql, values, label):
    rows = db.execute(sql, values).fetchmany(2)
    if len(rows) != 1:
        raise HistoryArchiveError(f"{label} is missing or ambiguous")
    return rows[0]


def _verify_policy(db, expected, anchor):
    raw, checked_at = _single(db, "SELECT pins, checked_at FROM configuration", (), "target policy")
    policy = _canonical_json(raw, _AUTHORITY_FIELDS, "target policy")
    config = policy["config"]
    _fields(config, _CONFIG_FIELDS, "target policy configuration")
    _time(checked_at, "target clock watermark")
    _time(policy["witness_owner"], "target witness file owner")
    directory = policy["witness_directory"]
    if (
        type(directory) is not list or len(directory) != 2
        or any(type(item) is not str or not 1 <= len(item) <= 20
               or not item.isascii() or not item.isdecimal()
               or item != str(int(item)) for item in directory)
    ):
        raise HistoryArchiveError("invalid retained witness directory identity")
    witness = config["witness_head_path"]
    if type(witness) is not str or not os.path.isabs(witness) or os.path.normpath(witness) != witness:
        raise HistoryArchiveError("invalid retained witness path")
    if (
        policy["profile"] != "finance-payment-intent"
        or policy["target_pub"] != expected["target_pub"]
        or canon(config["scope"]) != canon(run_scope(expected["scope"]))
        or validate_peer(config["peer"]) != expected["peer"]
        or any(config[field] != expected[field] for field in _ISSUER_FIELDS)
    ):
        raise HistoryArchiveError("retained finance enrollment differs from external expectations")
    # Gate 003 uses the same canonical bytes in SQL and as the authority-policy input.
    state = _ledger_state(db, integrity=True, authority_policy_digest=H(raw).hex())
    if any(anchor[field] != value for field, value in state.items()):
        raise HistoryArchiveError("committed ledger or policy differs from the pinned checkpoint")
    return checked_at


def _read_intent(db, expected, checked_at):
    scope = expected["scope"]
    key = idempotency_key(scope)
    business = business_digest(scope)
    packet_digest, outcome, raw = _single(
        db, "SELECT dispatch_digest, outcome, receipt FROM effects WHERE operation_id = ?",
        (key,), "original intent",
    )
    if outcome != _INTENT:
        raise HistoryArchiveError("requested intent is fenced or unavailable")
    _hex(packet_digest, 32, "recorded dispatch digest")
    entry = _canonical_json(raw, _ENTRY_FIELDS, "pending intent")
    if entry["business_sha256"] != business:
        raise HistoryArchiveError("historical request ID has different payment instructions")
    decision = _decision_for_intent(db, key, packet_digest)
    _time(decision["observed_at"], "historical target observation time")
    if (
        decision["outcome"] != _INTENT or decision["business_sha256"] != business
        or canon(decision["receipt"]) != canon(entry["receipt"])
        or validate_peer(decision["observed_peer"]) != expected["peer"]
        or decision["observed_witness_head"] != expected["witness_head"]
        or decision["observed_at"] > checked_at
    ):
        raise HistoryArchiveError("original intent and decision evidence disagree")
    evidence = {"packet": decision["packet"], "receipt": entry["receipt"]}
    verified = verify_admission(expected, evidence)
    if (
        verified["outcome"] != "VERIFIED" or verified["authorized_at"] != decision["observed_at"]
        or verified["business_sha256"] != business or verified["idempotency_key"] != key
    ):
        raise HistoryArchiveError("signed original admission disagrees with the retained decision")
    return evidence


def _decision_for_intent(db, key, packet_digest):
    owner_key, = _single(db, "SELECT operation_id FROM effects WHERE dispatch_digest = ?",
                         (packet_digest,), "effect for the original dispatch")
    if owner_key != key:
        raise HistoryArchiveError("original dispatch belongs to a different intent")
    decision = None
    for dispatch_digest, raw in db.execute("SELECT dispatch_digest, receipt FROM decisions ORDER BY id"):
        candidate = _canonical_json(raw, _DECISION_FIELDS, "archived decision evidence")
        packet = snapshot_packet(candidate["packet"])
        if digest(packet) != dispatch_digest:
            raise HistoryArchiveError("archived decision differs from its dispatch digest")
        # Derive the slot from the recorded packet so a second dispatch digest
        # cannot hide another decision for this request ID.
        if idempotency_key(packet["scope"]) != key:
            continue
        if dispatch_digest != packet_digest:
            raise HistoryArchiveError("archived decision conflicts with the requested intent")
        if decision is not None:
            raise HistoryArchiveError("original decision evidence is missing or ambiguous")
        decision = candidate
    if decision is None:
        raise HistoryArchiveError("original decision evidence is missing or ambiguous")
    return decision


def _ledger_stamp(path):
    for suffix in ("-journal", "-wal", "-shm"):
        if os.path.lexists(str(path) + suffix):
            raise HistoryArchiveError("ledger needs a quiescent committed snapshot without sidecars")
    return _stamp(path.lstat())


def read_archive(ledger_path, anchor_path, *, anchor_sha256, expectations):
    """Return the exact signed packet and receipt at an independently pinned checkpoint.

    The caller supplies public finance expectations and the exact retained
    anchor digest from an independent source. This operation verifies past
    admission, with no live inquiry authorization or settlement assertion.
    """
    try:
        expected = _document(expectations, "historical finance expectations")
        _fields(expected, _EXPECTED, "historical finance expectations")
        expected["scope"] = validate_scope(expected["scope"])
        expected["peer"] = validate_peer(expected["peer"])
        for field in ("witness_head", *_ISSUER_FIELDS):
            _hex(expected[field], 32, field)
        target_pub = _hex(expected["target_pub"], 32, "finance target key")
        ledger_path, anchor_path = Path(ledger_path).absolute(), Path(anchor_path).absolute()
        anchor, anchor_stamp = _read_anchor(anchor_path, anchor_sha256=anchor_sha256, target_pub=target_pub)
        ledger_stamp = _ledger_stamp(ledger_path)
        with closing(sqlite3.connect(ledger_path.as_uri() + "?mode=ro", uri=True, timeout=2,
                                     isolation_level=None)) as db:
            db.execute("PRAGMA query_only = ON")
            db.execute("PRAGMA trusted_schema = OFF")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4 * _MAX_ROW_BYTES)
            if db.execute("PRAGMA journal_mode").fetchone() != ("delete",):
                raise HistoryArchiveError("ledger uses an unsupported journal mode")
            db.execute("BEGIN")
            checked_at = _verify_policy(db, expected, anchor)
            evidence = _read_intent(db, expected, checked_at)
            if _ledger_stamp(ledger_path) != ledger_stamp or _stamp(anchor_path.lstat()) != anchor_stamp:
                raise HistoryArchiveError("ledger or retained anchor changed during verification")
        return evidence
    except HistoryArchiveError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError, KeyError, RuntimeError) as exc:
        raise HistoryArchiveError("historical admission could not be authenticated") from exc
