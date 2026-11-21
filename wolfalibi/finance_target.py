"""Resource-owned durable ledger for fictional payment intents."""

import json

from alibi import canon
from .education_target import (
    CONFIG_FILE, LEDGER_FILE, EducationTargetError, _Delivery, _DurableTarget,
    _clock_time, _deny, init_key,
)
from .finance_records import (
    business_digest, check_admission_time, check_packet, digest, idempotency_key,
    receipt, snapshot_packet, validate_run_scope,
)


__all__ = ["CONFIG_FILE", "LEDGER_FILE", "FinanceTarget", "FinanceTargetError", "init_key"]


class FinanceTargetError(EducationTargetError):
    """The fictional finance target cannot authenticate its state."""


class FinanceTarget(_DurableTarget):
    """Record one pending intent per request ID in an enrolled synthetic run.

    Only the exact original authenticated packet can recover the receipt.
    An authorized replacement grant cannot change the original evidence.
    """

    _state_error = FinanceTargetError
    _profile = "finance-payment-intent"
    _effect_outcome = "INTENT_RECORDED"
    _count_field = "intent_count"
    _expired_handoff = "BLOCKED"
    _actions = ("initiate", "reconcile")
    _validate_scope = staticmethod(validate_run_scope)
    _snapshot_packet = staticmethod(snapshot_packet)
    _check_packet = staticmethod(check_packet)
    _check_admission_time = staticmethod(check_admission_time)

    def _clock(self):
        return _clock_time()

    def _apply(self, action, packet, peer, authorized_at, deadline, witness_head):
        scope = packet["scope"]
        request_key = idempotency_key(scope)
        request_business = business_digest(scope)
        packet_digest = digest(packet)
        saved = self._db.execute(
            "SELECT dispatch_digest, outcome, receipt FROM effects WHERE operation_id = ?",
            (request_key,),
        ).fetchone()
        if saved is not None:
            original_packet_digest, original_outcome, saved_data = saved
            original = json.loads(saved_data)
            if original["business_sha256"] != request_business:
                return _deny("REQUEST_ID_CONFLICT")
            if original_outcome == "FENCED":
                return _deny("INTENT_FENCED")
            if original_packet_digest != packet_digest:
                return _deny("NONIDENTICAL_PACKET")
            outcome = "RECONCILED" if action == "reconcile" else "HISTORICAL_INTENT"
            result = {"outcome": outcome, "receipt": original["receipt"]}
            return _Delivery(result, authorized_at, deadline, witness_head)

        fenced = action == "reconcile"
        status = "FENCED" if fenced else self._effect_outcome
        signed = None if fenced else receipt(self._signer, scope, packet, authorized_at)
        data = {"business_sha256": request_business, "receipt": signed}
        evidence = {
            **data, "outcome": status, "packet": packet,
            "observed_peer": peer, "observed_witness_head": witness_head.hex(),
            "observed_at": authorized_at,
        }
        self._db.execute("INSERT INTO effects VALUES (?, ?, ?, ?)",
                         (request_key, packet_digest, status, canon(data)))
        self._db.execute("INSERT INTO decisions (dispatch_digest, receipt) VALUES (?, ?)",
                         (packet_digest, canon(evidence)))
        if fenced:
            return _deny("INTENT_FENCED")
        result = {"outcome": self._effect_outcome, "receipt": signed}
        return _Delivery(result, authorized_at, deadline, witness_head)
