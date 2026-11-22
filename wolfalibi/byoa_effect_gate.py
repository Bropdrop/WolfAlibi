"""Pre-release owner approval for one measured BYOA fixture read.

The target signs a durable admission decision. The broker and witness separately
account for the read. This profile cannot initiate a financial operation.
"""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import resource
import select
import stat
from threading import RLock

from alibi import H, OPS, canon, cp_hash, enc_entry, leaf_hash
from .clearance_records import _fields, _period, _sign, _time, _verify
from .education_target import LEDGER_FILE, _DurableTarget
from .solitary_worker import LIMITS
from .stage3 import FIXTURE_BYTES, FIXTURE_KEY
from .stage3_evidence import _check_anchor, _hex, run_marker, validate_contract
from .stage35_measure import _process_fields, verify_measurement_record
from .voidcell002 import _file_id, _private_directory, _sync_directory
from .voidcell002_anchor import LedgerAnchor


_GRANT = b"quorvane/byoa/read-owner-grant/v1"
_DECISION = b"quorvane/byoa/read-admission/v1"
_ZERO = "00" * 32
_ROLES = {"owner_pub", "target_pub", "broker_pub", "witness_pub", "supervisor_pub"}


def _digest(value):
    return H(canon(value)).hex()


def financial_boundary():
    """Closed financial surface of this read-only profile."""
    return {
        "authorization": {"outcome": "NOT_ISSUED", "operation": "fin.payment.initiate",
                          "live_finance_caller": "NOT_ENROLLED"},
        "effect": {"outcome": "NOT_DISPATCHED", "target_ledger": "NOT_OBSERVED",
                   "settlement": "UNESTABLISHED"},
    }


def _owner_payload(expected):
    _fields(expected, {"schema", "contract", "now", "expected_witness_state_digest", *_ROLES}, "BYOA expectations")
    if expected["schema"] != "quorvane.byoa.expectations.v1":
        raise ValueError("unsupported BYOA expectations")
    contract = expected["contract"]
    validate_contract(contract)
    if (contract["key"] != FIXTURE_KEY or contract["fixture_sha256"] != H(FIXTURE_BYTES).hex()
            or type(contract["profile"].get("byoa")) is not dict):
        raise ValueError("owner grant requires the declared BYOA fixture-read profile")
    keys = {_hex(expected[name], 32, name) for name in _ROLES}
    if len(keys) != len(_ROLES):
        raise ValueError("owner, target, broker, witness and supervisor require distinct keys")
    _hex(expected["expected_witness_state_digest"], 32, "expected witness state")
    _period(expected["now"], contract["expires_at"])
    return {
        "type": "QUORVANE_BYOA_OWNER_READ_GRANT_V1", "budget": 1,
        "expectations_sha256": _digest(expected), "operation": "read", "resource": FIXTURE_KEY,
        "resource_sha256": contract["fixture_sha256"], "target_pub": expected["target_pub"],
        "run_id": contract["run_id"], "challenge": contract["challenge"],
        "not_before": expected["now"], "expires_at": contract["expires_at"],
    }


def issue_read_grant(expected, owner_signer):
    payload = _owner_payload(expected)
    if owner_signer.pub.hex() != expected["owner_pub"]:
        raise ValueError("owner signer differs from the independently selected owner key")
    return _sign(owner_signer, _GRANT, payload)


def _grant(expected, grant, now):
    payload = _owner_payload(expected)
    verified = _verify(grant, bytes.fromhex(expected["owner_pub"]), _GRANT)
    _time(now, "read gate time")
    if canon(verified) != canon(payload) or not payload["not_before"] <= now < payload["expires_at"]:
        raise ValueError("grant differs from the approved read or is outside its validity window")


def _started(expected, anchor):
    """Require the successor of the pinned genesis for this exact Stage 3 run marker."""
    broker = expected["broker_pub"]
    leaf = enc_entry(run_marker(expected["contract"]), OPS["r"], 1, 1)
    checkpoint = {"v": 1, "broker": broker, "epoch": 0, "prev": _ZERO, "size": 1,
                  "root": leaf_hash(leaf).hex(), "events": 1, "seq_lo": 1, "seq_hi": 1}
    heads = {broker: {"epoch": 0, "hash": cp_hash(checkpoint).hex(), "seq_hi": 1}}
    return _check_anchor(anchor, bytes.fromhex(expected["witness_pub"]), 1,
                         expected["expected_witness_state_digest"], heads, [])


def _measurement(expected, snapshot):
    standard = dict(snapshot)
    status = standard.pop("solitary_kernel", None)
    _fields(status, {"launcher_seccomp_filters", "worker_seccomp_filters", "environment_keys"}, "kernel observation")
    before, after = status["launcher_seccomp_filters"], status["worker_seccomp_filters"]
    if (type(before) is not int or type(after) is not int or not 0 <= before < after
            or status["environment_keys"] != ["PWD"] or standard["credentials"]["seccomp_mode"] != 2):
        raise ValueError("required pre-release kernel state missing")
    verify_measurement_record(standard, expected["contract"])


def _live(snapshot, process_fd):
    """Check the measured process and endpoint again using the supervisor's retained pidfd."""
    identity = snapshot["identity"]
    pid = identity["worker_pid"]
    poller = select.poll()
    poller.register(process_fd, select.POLLIN)
    info = Path(f"/proc/self/fdinfo/{process_fd}").read_text().splitlines()
    proc = Path("/proc", str(pid))
    if poller.poll(0) or f"Pid:\t{pid}" not in info:
        raise ValueError("live pidfd differs from measured BYOA worker")
    _, parent, started = _process_fields((proc / "stat").read_text())
    peer = (proc / "fd/0").stat()
    if ((parent, started) != (identity["launcher_pid"], identity["worker_start_ticks"])
            or not stat.S_ISSOCK(peer.st_mode) or peer.st_ino != snapshot["descriptors"]["0"]["expected_inode"]
            or any(list(resource.prlimit(pid, getattr(resource, name))) != pair for name, pair in LIMITS.items())
            or poller.poll(0)):
        raise ValueError("measured worker or its broker endpoint changed")


def _decision_payload(expected, grant, snapshot, signed_head, now):
    return {"type": "QUORVANE_BYOA_READ_ADMISSION_V1", "outcome": "READ_ADMITTED",
            "operation": "read", "resource": FIXTURE_KEY, "expectations_sha256": _digest(expected),
            "grant_sha256": _digest(grant), "snapshot_sha256": _digest(snapshot),
            "witness_state_digest": _started(expected, signed_head), "authorized_at": now}


def verify_read_admission(expected, grant, decision, snapshot):
    """Authenticate historical owner permission, target admission and exact signed witness head."""
    _fields(decision, {"admission", "witness_state"}, "BYOA read decision")
    payload = _verify(decision["admission"], _hex(expected["target_pub"], 32, "target key"), _DECISION)
    now = payload.get("authorized_at")
    _grant(expected, grant, now)
    _measurement(expected, snapshot)
    if canon(payload) != canon(_decision_payload(expected, grant, snapshot, decision["witness_state"], now)):
        raise ValueError("target admission differs from supplied read, witness or measurement")
    return {"outcome": "VERIFIED_HISTORICAL_READ_ADMISSION", "operation": "read",
            "resource": FIXTURE_KEY, "grant_sha256": _digest(grant),
            "decision_sha256": _digest(decision), "authorized_at": now}


class _ReadLedger(_DurableTarget):
    """Use the Gate 002/003 SQLite schema and VOIDCELL signed checkpoint for admission decisions."""
    _effect_outcome = "READ_ADMITTED"
    _count_field = "admission_count"
    _state_error = ValueError

    def __init__(self, root, signer, *, create=False):
        self._blocked = False
        self._lock = RLock()
        self._resources = ExitStack()
        self._signer = signer
        root, _ = _private_directory(root)
        if create:
            (root / "ledger").mkdir(mode=0o700)
            (root / "checkpoint").mkdir(mode=0o700)
            _sync_directory(root)
        self._state, self._lineage = _private_directory(root / "ledger")
        self._anchor_dir, self._anchor_lineage = _private_directory(root / "checkpoint")
        pins = canon({"profile": "quorvane.byoa.read-target.v1", "target_pub": signer.pub.hex()})
        try:
            self._anchor = self._resources.enter_context(LedgerAnchor(self._anchor_dir, signer=signer,
                                                                     authority_policy=pins))
            self._open_ledger(pins, create)
            self._files_unchanged()
            if create:
                self._anchor.initialize(self)
            else:
                self._anchor.verify(self)
        except BaseException:
            self._resources.close()
            raise

    def _files_unchanged(self):
        if (_private_directory(self._state)[1] != self._lineage
                or _private_directory(self._anchor_dir)[1] != self._anchor_lineage
                or _file_id(self._state / LEDGER_FILE) != self._ledger_id):
            raise ValueError("read target state or checkpoint moved")

    def recorded(self, challenge):
        return self._db.execute("SELECT dispatch_digest, receipt FROM effects WHERE operation_id = ?",
                                (challenge,)).fetchone()

    def _enrollment(self):
        return self._db.execute(
            "SELECT receipt FROM decisions WHERE dispatch_digest = ?", ("READ_AUTHORITY_ENROLLMENT_V1",),
        ).fetchall()

    def require_enrollment(self, expected):
        pins = {role: expected[role] for role in _ROLES}
        if self._enrollment() != [(canon(pins),)]:
            raise ValueError("scope differs from the resource target's retained authority enrollment")

    def permitted(self, expected, grant, now, *, fresh):
        self.require_enrollment(expected)
        _grant(expected, grant, now)
        if self._db.execute("SELECT 1 FROM revoked WHERE grant_id = ?", (_digest(grant),)).fetchone():
            raise ValueError("read grant revoked at target")
        if fresh and self.recorded(expected["contract"]["challenge"]) is not None:
            raise ValueError("challenge already admitted")


def initialize_read_target(state_dir, target_signer):
    """Provision once. Opening a gate will never initialize a missing ledger or checkpoint."""
    with _ReadLedger(state_dir, target_signer, create=True) as ledger:
        return ledger.status()


def enroll_read_authorities(state_dir, *, owner_pub, broker_pub, supervisor_pub, witness_pub, target_signer):
    """Create the immutable issuer enrollment as the target administrator."""
    pins = {"owner_pub": owner_pub, "broker_pub": broker_pub, "supervisor_pub": supervisor_pub,
            "witness_pub": witness_pub, "target_pub": target_signer.pub.hex()}
    if len({_hex(value, 32, name) for name, value in pins.items()}) != len(_ROLES):
        raise ValueError("distinct enrolled read authority keys required")
    with _ReadLedger(state_dir, target_signer) as ledger:
        def enroll(now):
            if ledger._enrollment():
                raise ValueError("read target authorities already enrolled")
            ledger._db.execute("INSERT INTO decisions (dispatch_digest, receipt) VALUES (?, ?)",
                               ("READ_AUTHORITY_ENROLLMENT_V1", canon(pins)))
            return {"outcome": "ACCEPTED"}

        _checked(ledger, enroll)
    return {"outcome": "ENROLLED", "roles": pins}


def _require_signer(expected, signer):
    if signer.pub.hex() != expected["target_pub"]:
        raise ValueError("target signing identity differs from independently supplied pin")


def _checked(ledger, operation):
    def validate(now):
        try:
            return {**operation(now), "sampled_at": now}
        except ValueError as error:
            # Commit the observed target clock even when a grant has expired.
            return {"outcome": "DENIED", "reason": str(error)}
    result = ledger._invoke(validate)
    if result.get("outcome") != "ACCEPTED":
        raise ValueError(result.get("reason", "target read transaction was blocked"))
    return result


def revoke_read_grant(state_dir, expected, grant, target_signer):
    """Deny further admissions for the exact genuine grant under the local target lease."""
    _require_signer(expected, target_signer)
    _grant(expected, grant, expected["now"])
    with _ReadLedger(state_dir, target_signer) as ledger:
        def record(now):
            ledger.require_enrollment(expected)
            ledger._db.execute("INSERT OR IGNORE INTO revoked VALUES (?, ?)", (_digest(grant), canon(grant)))
            return {"outcome": "ACCEPTED"}
        _checked(ledger, record)
    return {"outcome": "REVOKED", "grant_sha256": _digest(grant)}


def recover_read_admission(state_dir, expected, grant, target_signer):
    """Read the committed admission from a matching retained checkpoint, without redispatch."""
    _require_signer(expected, target_signer)
    _grant(expected, grant, expected["now"])
    with _ReadLedger(state_dir, target_signer) as ledger:
        ledger.require_enrollment(expected)
        row = ledger.recorded(expected["contract"]["challenge"])
        if row is None:
            return None
        if row[0] != _digest(grant):
            raise ValueError("challenge belongs to a different grant")
        return json.loads(row[1])


class ReadGate:
    """Authenticate and reserve one synthetic read before the broker's durable WAL and release."""
    def __init__(self, state_dir, expected, grant, target_signer, *, witness_state):
        self._state = state_dir
        self._expected = json.loads(canon(expected))
        self._grant = json.loads(canon(grant))
        self._signer = target_signer
        self._witness_state = witness_state
        self._lease = None
        self.decision = None
        self._closed = False
        _require_signer(self._expected, target_signer)
        digest = _check_anchor(witness_state(), _hex(expected["witness_pub"], 32, "witness key"), 0, _ZERO, {}, [])
        if digest != expected["expected_witness_state_digest"]:
            raise ValueError("initial witness differs from independently retained genesis")
        with _ReadLedger(self._state, self._signer) as ledger:
            def before_launch(now):
                ledger.permitted(self._expected, self._grant, now, fresh=True)
                return {"outcome": "ACCEPTED"}
            _checked(ledger, before_launch)

    def __call__(self, contract, snapshot, process_fd):
        if self._closed or self._lease is not None or canon(contract) != canon(self._expected["contract"]):
            raise ValueError("wrong or previously used BYOA read gate")
        try:
            _measurement(self._expected, snapshot)
            _live(snapshot, process_fd)
            ledger = self._lease = _ReadLedger(self._state, self._signer)
            grant, expected = self._grant, self._expected
            challenge = contract["challenge"]

            def admit(now):
                ledger.permitted(expected, grant, now, fresh=True)
                head = self._witness_state()
                payload = _decision_payload(expected, grant, snapshot, head, now)
                decision = {"admission": _sign(self._signer, _DECISION, payload), "witness_state": head}
                ledger._db.execute("INSERT INTO effects VALUES (?, ?, ?, ?)",
                                   (challenge, _digest(grant), "READ_ADMITTED", canon(decision)))
                ledger._db.execute("INSERT INTO decisions (dispatch_digest, receipt) VALUES (?, ?)",
                                   (_digest(grant), canon({"grant": grant, "decision": decision})))
                return {"outcome": "ACCEPTED", "decision": decision}

            decision = _checked(ledger, admit)["decision"]

            def handoff(now):
                ledger.permitted(expected, grant, now, fresh=False)
                if canon(decision["witness_state"]) != canon(self._witness_state()):
                    raise ValueError("witness changed before read handoff")
                _live(snapshot, process_fd)
                return {"outcome": "ACCEPTED"}

            # Persist the last observed target time, then match it after checkpoint publication.
            # Keep the target lease until the broker has released and the trial has closed.
            for _ in range(3):
                sample = _checked(ledger, handoff)["sampled_at"]
                if ledger._checked_now() == sample:
                    break
            else:
                raise ValueError("target handoff clock or permission changed after durable admission")
            self.decision = decision
        except (OSError, RuntimeError) as exc:
            raise ValueError("required live process, target checkpoint or witness state unavailable") from exc

    def close(self):
        self._closed = True
        if self._lease is not None:
            self._lease.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
