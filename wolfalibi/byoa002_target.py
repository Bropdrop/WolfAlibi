"""Resource-owner decisions for disclosure of one fictional record to a live gateway.

The signed receipt describes a committed decision. External retention precedes
handoff to transport. Historical lookup never returns the protected response.
"""

from contextlib import ExitStack
import json
import os
from threading import RLock

from alibi import H, canon
from .byoa_attestation import verify_trial
from .byoa002_enrollment import check_expected, validate_enrollment
from .clearance_records import _fields, _sign, _time, _verify
from .education_records import validate_peer
from .education_target import LEDGER_FILE, _DurableTarget
from .stage3_evidence import _hex
from .voidcell002 import _file_id, _private_directory, _sync_directory
from .voidcell002_anchor import LedgerAnchor


_GRANT = b"quorvane/byoa002/owner-read-grant/v1"
_REQUEST = b"quorvane/byoa002/operator-request/v1"
_RECEIPT = b"quorvane/byoa002/target-commitment/v1"


def _digest(value):
    return H(canon(value)).hex()


def _record():
    return {"record": "fictional-record-002", "review_status": "available"}


def _terms(expected, enrollment, challenge):
    check_expected(enrollment, expected)
    return {
        "operation_id": expected["contract"]["run_id"], "target_id": enrollment["target_id"],
        "operation": enrollment["operation"], "resource": enrollment["resource"],
        "policy_epoch": enrollment["policy_epoch"], "expectations_sha256": _digest(expected),
        "enrollment_sha256": _digest(enrollment), "challenge_sha256": _digest(challenge),
    }


def _challenge(expected, enrollment, challenge, now):
    from .byoa002_verifier import verify_challenge
    return verify_challenge(challenge, expected=expected, enrollment=enrollment, now=now)


def _issued(challenge):
    if not isinstance(challenge, dict) or type(challenge.get("payload")) is not dict:
        raise ValueError("invalid verifier challenge")
    issued = challenge["payload"].get("issued_at")
    _time(issued, "challenge issuance")
    return issued


def _grant_terms(expected, enrollment, challenge, not_before, expires_at):
    q = _challenge(expected, enrollment, challenge, _issued(challenge))
    start = q["issued_at"] if not_before is None else not_before
    end = q["expires_at"] if expires_at is None else expires_at
    _time(start, "owner grant start")
    _time(end, "owner grant expiry")
    if not q["issued_at"] <= start < end <= q["expires_at"]:
        raise ValueError("owner grant must fit within the verifier challenge window")
    return {"type": "QUORVANE_BYOA002_OWNER_GRANT_V1", **_terms(expected, enrollment, challenge),
            "budget": 1, "not_before": start, "expires_at": end}


def issue_owner_grant(expected, enrollment, challenge, owner_signer, *, not_before=None, expires_at=None):
    terms = _grant_terms(expected, enrollment, challenge, not_before, expires_at)
    if owner_signer.pub.hex() != enrollment["owner_pub"]:
        raise ValueError("unrecognized owner signing identity")
    return _sign(owner_signer, _GRANT, terms)


def _check_grant(expected, enrollment, challenge, grant):
    payload = _verify(grant, bytes.fromhex(enrollment["owner_pub"]), _GRANT)
    terms = _grant_terms(expected, enrollment, challenge, payload.get("not_before"), payload.get("expires_at"))
    if canon(payload) != canon(terms):
        raise ValueError("owner grant differs from the enrolled synthetic operation")
    return payload


def _gateway(enrollment, peer, action):
    peer = validate_peer(peer)
    original = enrollment["gateway"]
    flexible = {"pid", "start_ticks"} if action == "reconcile" else set()
    if any(peer[field] != value for field, value in original.items() if field not in flexible):
        raise ValueError("gateway differs from the target-enrolled principal")
    return peer


def _request_terms(action, expected, enrollment, challenge, grant, report, peer):
    if action not in ("dispatch", "reconcile"):
        raise ValueError("unsupported target request")
    return {"type": "QUORVANE_BYOA002_OPERATOR_REQUEST_V1", "action": action,
            **_terms(expected, enrollment, challenge), "grant_sha256": _digest(grant),
            "report_sha256": _digest(report), "gateway": _gateway(enrollment, peer, action)}


def sign_request(action, expected, enrollment, challenge, grant, report, operator_signer, *, recovery_peer=None):
    if action != "reconcile" and recovery_peer is not None:
        raise ValueError("dispatch requires the original enrolled gateway")
    _check_grant(expected, enrollment, challenge, grant)
    if operator_signer.pub.hex() != enrollment["operator_pub"]:
        raise ValueError("unrecognized operator signing identity")
    peer = enrollment["gateway"] if recovery_peer is None else recovery_peer
    return _sign(operator_signer, _REQUEST, _request_terms(action, expected, enrollment, challenge,
                                                          grant, report, peer))


def _check_packet(packet, action, enrollment, peer):
    _fields(packet, {"expected", "challenge", "grant", "report", "request"}, "gateway submission")
    expected, challenge, grant = packet["expected"], packet["challenge"], packet["grant"]
    report, request = packet["report"], packet["request"]
    _check_grant(expected, enrollment, challenge, grant)
    payload = _verify(request, bytes.fromhex(enrollment["operator_pub"]), _REQUEST)
    if canon(payload) != canon(_request_terms(action, expected, enrollment, challenge, grant, report, peer)):
        raise ValueError("operator request differs from packet, live peer or action")
    qualified = verify_trial(report, expected)
    if qualified["outcome"] != "VERIFIED":
        raise ValueError("completed measured agent trial could not be verified")
    measured_at = qualified["authorization"]["read"]["authorized_at"]
    if measured_at < _issued(challenge):
        raise ValueError("qualified worker predates verifier challenge")
    return measured_at


def _receipt_terms(expected, enrollment, challenge, *, grant_hash, request_hash, report_hash, committed_at):
    q = _challenge(expected, enrollment, challenge, committed_at)
    return {"type": "QUORVANE_BYOA002_TARGET_COMMITMENT_V1",
            "decision": "FICTIONAL_READ_COMMITTED", **_terms(expected, enrollment, challenge),
            "gateway": enrollment["gateway"], "previous": q["previous"], "grant_sha256": grant_hash,
            "request_sha256": request_hash, "report_sha256": report_hash,
            "response_sha256": _digest(_record()), "committed_at": committed_at}


def verify_retention_proposal(receipt, *, expected, enrollment, challenge):
    """Authenticate the target's commitment. The verifier does not attest to delivery."""
    check_expected(enrollment, expected)
    payload = _verify(receipt, bytes.fromhex(enrollment["target_pub"]), _RECEIPT)
    hashes = {}
    for label in ("grant", "request", "report"):
        value = payload.get(label + "_sha256")
        _hex(value, 32, label + " digest")
        hashes[label + "_hash"] = value
    committed_at = payload.get("committed_at")
    _time(committed_at, "target commitment time")
    terms = _receipt_terms(expected, enrollment, challenge, **hashes, committed_at=committed_at)
    if canon(terms) != canon(payload):
        raise ValueError("target receipt differs from the exact authorized record")
    return payload


def verify_release(*, expected, enrollment, challenge, grant, request, report, receipt, ack):
    """Verify a past commitment with independently supplied enrollment and trial expectations."""
    from .byoa002_verifier import verify_ack
    packet = {"expected": expected, "challenge": challenge, "grant": grant, "request": request, "report": report}
    measured_at = _check_packet(packet, "dispatch", enrollment, enrollment["gateway"])
    p = verify_retention_proposal(receipt, expected=expected, enrollment=enrollment, challenge=challenge)
    if (p["committed_at"] < measured_at or
            not grant["payload"]["not_before"] <= p["committed_at"] < grant["payload"]["expires_at"] or
            any(p[name + "_sha256"] != _digest(packet[name]) for name in ("grant", "request", "report"))):
        raise ValueError("retained commitment differs from supplied historical evidence")
    verify_ack(ack, expected=expected, enrollment=enrollment, challenge=challenge, receipt=receipt)
    return {"outcome": "VERIFIED", "claim": "HISTORICAL_RETAINED_RELEASE_COMMITMENT",
            "operation_id": p["operation_id"], "receipt_sha256": _digest(receipt),
            "response_sha256": p["response_sha256"], "present_authority": "NOT_ISSUED",
            "recipient_delivery": "NOT_ESTABLISHED"}


class _Ledger(_DurableTarget):
    """Reuse the existing logical checkpoint over all four authoritative SQLite tables."""
    _state_error = ValueError
    _effect_outcome = "FICTIONAL_READ_COMMITTED"
    _count_field = "commitment_count"

    def __init__(self, state_dir, signer, enrollment, *, create=False):
        validate_enrollment(enrollment)
        if enrollment["owner_uid"] != os.geteuid():
            raise ValueError("target service requires the enrolled owner UID")
        if signer.pub.hex() != enrollment["target_pub"]:
            raise ValueError("unrecognized target signing identity")
        root, _ = _private_directory(state_dir)
        self._lock = RLock()
        self._resources = ExitStack()
        self._blocked = False
        self._signer = signer
        if create:
            (root / "ledger").mkdir(mode=0o700)
            (root / "checkpoint").mkdir(mode=0o700)
            _sync_directory(root)
        self._state, self._lineage = _private_directory(root / "ledger")
        self._anchor_dir, self._anchor_lineage = _private_directory(root / "checkpoint")
        pins = canon({"profile": "quorvane.byoa002.release.v1", "enrollment": enrollment})
        try:
            self._anchor = self._resources.enter_context(
                LedgerAnchor(self._anchor_dir, signer=signer, authority_policy=pins))
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
        if (_private_directory(self._state)[1] != self._lineage or
                _private_directory(self._anchor_dir)[1] != self._anchor_lineage or
                _file_id(self._state / LEDGER_FILE) != self._ledger_id):
            raise ValueError("target ledger or retained checkpoint moved")

    def row(self, operation_id):
        return self._db.execute("SELECT dispatch_digest,receipt FROM effects WHERE operation_id=?",
                                (operation_id,)).fetchone()

    def require_previous(self, enrollment, previous):
        from .byoa002_verifier import genesis
        # The signed local checkpoint covers decisions.id, unlike SQLite's implicit rowids.
        rows = self._db.execute("""
            SELECT effects.receipt FROM decisions JOIN effects
                ON effects.dispatch_digest = decisions.dispatch_digest
            ORDER BY decisions.id DESC LIMIT 1
        """).fetchall()
        head = genesis(enrollment)
        if rows:
            prior = json.loads(rows[0][0])
            head = {"generation": prior["payload"]["previous"]["generation"] + 1, "digest": _digest(prior)}
        if canon(head) != canon(previous):
            raise ValueError("verifier predecessor differs from the target ledger head")

    def check_authority(self, expected, enrollment, challenge, grant, now):
        _challenge(expected, enrollment, challenge, now)
        if not grant["payload"]["not_before"] <= now < grant["payload"]["expires_at"]:
            raise ValueError("outside the signed owner grant validity window")
        if self._db.execute("SELECT 1 FROM revoked WHERE grant_id=?", (_digest(grant),)).fetchone():
            raise ValueError("owner grant revoked at resource target")


def initialize_target(state_dir, target_signer, enrollment):
    """Owner provisioning is create-only. Subsequent opens authenticate the complete enrollment."""
    with _Ledger(state_dir, target_signer, enrollment, create=True) as ledger:
        return ledger.status()


def _denied(reason):
    return {"outcome": "DENIED", "reason": str(reason)}


def _blocked(reason):
    return {"outcome": "BLOCKED", "reason": str(reason)}


def _live(live):
    if live() is not True:
        raise ValueError("gateway live identity unavailable")


class Target:
    """The local owner process holds the receipt key. Only dispatch can hand off a body."""
    def __init__(self, state_dir, target_signer, enrollment, *, check_pending, retain, reconcile_head):
        self._enrollment = json.loads(canon(enrollment))
        self._ledger = _Ledger(state_dir, target_signer, self._enrollment)
        self._pending = check_pending
        self._retain = retain
        self._reconcile_head = reconcile_head

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._ledger.close()

    def status(self):
        return self._ledger.status()

    def revoke(self, grant, expected, challenge):
        """Privileged owner-side action. This method is absent from the gateway RPC surface."""
        _check_grant(expected, self._enrollment, challenge, grant)
        def record(_):
            self._ledger._db.execute("INSERT OR IGNORE INTO revoked VALUES (?, ?)", (_digest(grant), canon(grant)))
            return {"outcome": "REVOKED", "grant_sha256": _digest(grant)}
        return self._ledger._invoke(record)

    def _snapshot(self, packet, action, peer):
        # Wire parsers enforce their own input limits and reject duplicate keys.
        data = canon(packet)
        if len(data) > 524288:
            raise ValueError("oversized gateway submission")
        stable = json.loads(data)
        measured_at = _check_packet(stable, action, self._enrollment, peer)
        return stable, measured_at

    def dispatch(self, packet, *, peer, live):
        try:
            packet, measured_at = self._snapshot(packet, "dispatch", peer)
        except (ValueError, KeyError, TypeError, RecursionError) as exc:
            return _denied(exc)
        expected, challenge, grant = packet["expected"], packet["challenge"], packet["grant"]
        refs = (expected, self._enrollment, challenge)
        operation = expected["contract"]["run_id"]
        request_hash = _digest(packet["request"])
        ledger = self._ledger

        def commit(now):
            try:
                if ledger.row(operation) is not None:
                    raise ValueError("operation already committed; use historical reconciliation")
                _live(live)
                ledger.check_authority(*refs, grant, now)
                if now < measured_at:
                    raise ValueError("target time precedes measured agent trial")
                ledger.require_previous(self._enrollment, challenge["payload"]["previous"])
            except ValueError as exc:
                return _denied(exc)
            try:
                pending = self._pending(expected, challenge)
                if canon(pending) != canon(challenge["payload"]):
                    raise ValueError("verifier did not authenticate this exact pending challenge")
            except (ValueError, OSError, RuntimeError) as exc:
                return _blocked("verifier did not confirm pending challenge: " + str(exc))
            # Recheck the clock and peer after the verifier round trip.
            sampled = ledger._checked_now()
            if not ledger._observe_time(sampled):
                return _blocked("TARGET_CLOCK_REGRESSION")
            try:
                ledger.check_authority(*refs, grant, sampled)
                _live(live)
            except ValueError as exc:
                return _denied(exc)
            terms = _receipt_terms(*refs, grant_hash=_digest(grant), request_hash=request_hash,
                                   report_hash=_digest(packet["report"]), committed_at=sampled)
            receipt = _sign(ledger._signer, _RECEIPT, terms)
            ledger._db.execute("INSERT INTO effects VALUES (?, ?, ?, ?)",
                               (operation, request_hash, ledger._effect_outcome, canon(receipt)))
            # Retain the actual signed operator dispatch for exact historical reconstruction.
            ledger._db.execute("INSERT INTO decisions (dispatch_digest,receipt) VALUES (?,?)",
                               (request_hash, canon(packet["request"])))
            return {"outcome": "COMMITTED", "receipt": receipt}

        result = ledger._invoke(commit)
        if result.get("outcome") != "COMMITTED":
            return result
        receipt = result["receipt"]
        try:
            from .byoa002_verifier import verify_ack
            ack = self._retain(expected, challenge, receipt)
            verify_ack(ack, expected=expected, enrollment=self._enrollment, challenge=challenge, receipt=receipt)
        except (ValueError, TypeError, KeyError, OSError, RuntimeError) as exc:
            return _blocked("target committed; verifier retention unconfirmed: " + str(exc))

        def handoff(now):
            try:
                ledger.check_authority(*refs, grant, now)
                if ledger.row(operation) != (request_hash, canon(receipt)):
                    raise ValueError("committed target record changed")
                _live(live)
                return {"outcome": "AUTHORIZED_HANDOFF", "sampled_at": now}
            except ValueError as exc:
                return _denied(exc)

        # The target serializes revocation with final handoff. Socket delivery is outside this transaction.
        with ledger._lock:
            for _ in range(3):
                result = ledger._invoke(handoff)
                if result.get("outcome") != "AUTHORIZED_HANDOFF":
                    return result
                if result["sampled_at"] == ledger._checked_now():
                    try:
                        _live(live)
                    except (OSError, ValueError, RuntimeError) as exc:
                        return _blocked(exc)
                    return {"outcome": "RELEASED", "record": _record(), "receipt": receipt, "ack": ack}
            return _blocked("authorization clock changed during handoff")

    def reconcile(self, packet, *, peer, live):
        try:
            packet, _ = self._snapshot(packet, "reconcile", peer)
        except (ValueError, KeyError, TypeError, RecursionError) as exc:
            return _denied(exc)
        expected, challenge = packet["expected"], packet["challenge"]
        operation = expected["contract"]["run_id"]

        def lookup(_):
            _live(live)
            row = self._ledger.row(operation)
            if row is None:
                return _denied("no committed target record")
            receipt = json.loads(row[1])
            requests = self._ledger._db.execute("SELECT receipt FROM decisions WHERE dispatch_digest=?",
                                                (row[0],)).fetchall()
            if len(requests) != 1:
                return _blocked("historical operator request missing or conflicting")
            return {"outcome": "FOUND", "receipt": receipt, "dispatch": json.loads(requests[0][0])}

        result = self._ledger._invoke(lookup)
        if result.get("outcome") != "FOUND":
            return result
        try:
            receipt = result["receipt"]
            ack = self._reconcile_head(expected, challenge, receipt)
            verify_release(expected=expected, enrollment=self._enrollment, challenge=challenge,
                           grant=packet["grant"], request=result["dispatch"], report=packet["report"],
                           receipt=receipt, ack=ack)
            _live(live)
            return {"outcome": "RECONCILED", "receipt": receipt, "ack": ack}
        except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
            return _blocked("historical confirmation unavailable: " + str(exc))
