"""Fixed synthetic Education and Finance resources for the Quorvane gate.

The gate owns authorization, receipt signing and transaction commit. Domain
helpers operate on its local database and return signed observations through
the supplied factory. Reconciliation reads the ledger without dispatching.
"""

import json

from alibi import H, canon
from .clearance_records import _document, _fields, _id, _time
from .stage3_evidence import _hex


INITIAL_BALANCE_CENTS = 10_000
_PAYEE = "synthetic-library"
_TOPICS = {
    "fractions": "One-half means one of two equal parts.",
}
_PROFILES = {
    "tutor": "education", "student_record": "education",
    "balance": "finance", "initiate_payment": "finance",
}
_REQUEST_FIELDS = {
    "run_id", "challenge", "tenant", "policy_epoch", "operation", "request_id", "parameters",
}
_PARAMETERS = {
    "tutor": {"topic"}, "student_record": {"student_id"}, "balance": set(),
    "initiate_payment": {"payment_id", "payee", "amount_cents"},
}


def operation_profile(operation):
    """Return the qualification profile required by a known operation."""
    if type(operation) is not str or operation not in _PROFILES:
        raise ValueError("unsupported synthetic operation")
    return _PROFILES[operation]


def validate_request(request):
    """Make a bounded copy of a V1 request and check exact parameter shape."""
    frozen = _document(request, "Quorvane request")
    _fields(frozen, _REQUEST_FIELDS, "Quorvane request")
    if type(frozen["run_id"]) is not str or not 1 <= len(frozen["run_id"]) <= 256:
        raise ValueError("invalid run ID")
    _hex(frozen["challenge"], 32, "run challenge")
    _id(frozen["tenant"], "tenant")
    _id(frozen["request_id"], "request ID")
    _time(frozen["policy_epoch"], "policy epoch")
    operation = frozen["operation"]
    operation_profile(operation)
    parameters = frozen["parameters"]
    _fields(parameters, _PARAMETERS[operation], "operation parameters")

    if operation == "tutor":
        topic = parameters["topic"]
        if type(topic) is not str or topic not in _TOPICS:
            raise ValueError("unknown synthetic tutor topic")
    elif operation == "student_record":
        if parameters["student_id"] != "synthetic-student":
            raise ValueError("unknown synthetic student fixture")
    elif operation == "initiate_payment":
        _id(parameters["payment_id"], "payment ID")
        if parameters["payee"] != _PAYEE:
            raise ValueError("unknown synthetic payee")
        amount = parameters["amount_cents"]
        if type(amount) is not int or not 1 <= amount <= INITIAL_BALANCE_CENTS:
            raise ValueError("synthetic payment amount is outside bounds")
    return frozen


def _require_transaction(db):
    if not db.in_transaction:
        raise RuntimeError("domain operations require the gate transaction")


def create_tables(db):
    """Create the Finance ledger within the gate's initialization transaction."""
    _require_transaction(db)
    db.execute("""
        CREATE TABLE quorvane_payments (
            tenant TEXT NOT NULL,
            payment_id TEXT NOT NULL,
            payee TEXT NOT NULL CHECK (payee = 'synthetic-library'),
            amount_cents INTEGER NOT NULL CHECK (amount_cents BETWEEN 1 AND 10000),
            status TEXT NOT NULL CHECK (status IN ('INITIATED', 'SETTLED')),
            initiation_sha256 TEXT NOT NULL,
            initiation_receipt BLOB NOT NULL,
            settlement_receipt BLOB,
            PRIMARY KEY (tenant, payment_id),
            CHECK ((status = 'SETTLED') = (settlement_receipt IS NOT NULL))
        )
    """)


def _decision(receipt_factory, outcome, details, *, data=None):
    result = {"outcome": outcome, "receipt": receipt_factory(outcome, details)}
    if data is not None:
        result["data"] = data
    return result


def _balance(db, tenant):
    reserved, debited = db.execute("""
        SELECT COALESCE(SUM(CASE WHEN status = 'INITIATED' THEN amount_cents ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN status = 'SETTLED' THEN amount_cents ELSE 0 END), 0)
          FROM quorvane_payments WHERE tenant = ?
    """, (tenant,)).fetchone()
    balance = INITIAL_BALANCE_CENTS - debited
    return {
        "balance_cents": balance, "reserved_cents": reserved,
        "available_cents": balance - reserved,
    }


def _initiate_payment(db, tenant, parameters, receipt_factory):
    payment_id, payee, amount = (
        parameters["payment_id"], parameters["payee"], parameters["amount_cents"],
    )
    exists = db.execute("SELECT 1 FROM quorvane_payments WHERE tenant = ? AND payment_id = ?",
                        (tenant, payment_id)).fetchone()
    if exists is not None:
        return _decision(receipt_factory, "DENIED", {
            "reason": "PAYMENT_ID_ALREADY_USED", "payment_id": payment_id,
        })
    if amount > _balance(db, tenant)["available_cents"]:
        return _decision(receipt_factory, "DENIED", {
            "reason": "INSUFFICIENT_SYNTHETIC_BALANCE", "payment_id": payment_id,
        })
    details = {"payment_id": payment_id, "payee": payee, "amount_cents": amount,
               "settlement_status": "PENDING"}
    result = _decision(receipt_factory, "INITIATED", details)
    encoded = canon(result["receipt"])
    digest = H(encoded).hex()
    db.execute("""
        INSERT INTO quorvane_payments
            (tenant, payment_id, payee, amount_cents, status, initiation_sha256, initiation_receipt)
        VALUES (?, ?, ?, ?, 'INITIATED', ?, ?)
    """, (tenant, payment_id, payee, amount, digest, encoded))
    result["data"] = {**details, "initiation_sha256": digest}
    return result


def apply_operation(db, request, *, receipt_factory):
    """Perform a validated resource operation in the caller's transaction."""
    _require_transaction(db)
    request = validate_request(request)
    operation, parameters = request["operation"], request["parameters"]
    if operation == "tutor":
        topic = parameters["topic"]
        return _decision(receipt_factory, "ALLOWED", {"topic": topic},
                         data={"topic": topic, "answer": _TOPICS[topic]})
    if operation == "student_record":
        return _decision(receipt_factory, "DENIED", {"reason": "STUDENT_RECORD_RESTRICTED"})
    if operation == "balance":
        data = _balance(db, request["tenant"])
        return _decision(receipt_factory, "ALLOWED", data, data=data)
    return _initiate_payment(db, request["tenant"], parameters, receipt_factory)


def _settlement_row(db, tenant, payment_id):
    return db.execute("""
        SELECT payee, amount_cents, status, initiation_sha256, initiation_receipt, settlement_receipt
          FROM quorvane_payments WHERE tenant = ? AND payment_id = ?
    """, (tenant, payment_id)).fetchone()


def settle(db, verified_settlement_payload, *, receipt_factory):
    """Apply a separately authenticated settlement to one pending initiation."""
    _require_transaction(db)
    tenant = verified_settlement_payload["tenant"]
    payment_id = verified_settlement_payload["payment_id"]
    supplied_digest = verified_settlement_payload["initiation_sha256"]
    _id(tenant, "tenant")
    _id(payment_id, "payment ID")
    _hex(supplied_digest, 32, "initiation receipt digest")
    row = _settlement_row(db, tenant, payment_id)
    if row is None:
        return _decision(receipt_factory, "DENIED", {
            "reason": "UNKNOWN_PAYMENT", "payment_id": payment_id,
        })
    payee, amount, status, expected_digest, initiation_receipt, stored_settlement = row
    if supplied_digest != expected_digest or H(initiation_receipt).hex() != expected_digest:
        return _decision(receipt_factory, "DENIED", {
            "reason": "INITIATION_RECEIPT_MISMATCH", "payment_id": payment_id,
        })
    if status != "INITIATED":
        return {"outcome": "SETTLED", "receipt": json.loads(stored_settlement), "historical": True}
    details = {
        "payment_id": payment_id, "payee": payee, "amount_cents": amount,
        "initiation_sha256": expected_digest, "settlement_status": "SETTLED",
    }
    result = _decision(receipt_factory, "SETTLED", details, data=details)
    updated = db.execute("""
        UPDATE quorvane_payments SET status = 'SETTLED', settlement_receipt = ?
         WHERE tenant = ? AND payment_id = ? AND status = 'INITIATED' AND initiation_sha256 = ?
    """, (canon(result["receipt"]), tenant, payment_id, expected_digest))
    if updated.rowcount != 1:
        raise RuntimeError("payment ledger changed during settlement")
    return result


def reconcile(db, *, tenant, payment_id):
    """Read the signed resource receipt under trusted local administration."""
    _id(tenant, "tenant")
    _id(payment_id, "payment ID")
    row = _settlement_row(db, tenant, payment_id)
    if row is None:
        return {"outcome": "UNKNOWN_PAYMENT"}
    _, _, status, digest, initiation, settlement = row
    if H(initiation).hex() != digest:
        raise RuntimeError("stored initiation receipt differs from its digest")
    return {
        "outcome": status, "payment_id": payment_id, "initiation_sha256": digest,
        "receipt": json.loads(initiation if status == "INITIATED" else settlement),
    }
