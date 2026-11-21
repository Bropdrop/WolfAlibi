"""Portable, verifier-parameterized negative-access receipts.

This module intentionally makes the verifier supply every security-relevant
reference value.  A receipt can describe itself, but cannot authorize itself:
the verifier must bring its expected keys, challenge, policy, run identifier,
code digest, range, and epoch interval.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from alibi import (AlibiError, DOM_B, DOM_RB, DOM_RW, DOM_W, DurableWitness,
                   H, NotEmpty, canon, cp_hash, verify_alibi, verify_sig)


RECEIPT_TYPE = "NEGATIVE_ACCESS_RECEIPT_V1"
RECEIPT_VERSION = 1
ASSURANCE_BROKER_ONLY = "BROKER_ONLY"
RECORDED_OPERATIONS = ["read", "write", "list", "denied_attempt"]


class ReceiptError(ValueError):
    """A receipt cannot be produced under the requested broker-only scope."""


def policy_digest(policy: Mapping[str, Any]) -> str:
    """Return the deterministic digest a verifier must independently expect."""
    return H(canon(policy)).hex()


def sha256_file(path: Union[str, Path]) -> bytes:
    """Compute a local code artifact digest without asserting it was executed."""
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                return digest.digest()
            digest.update(block)


def _require_bytes(value: Union[bytes, bytearray], name: str,
                   length: Optional[int] = None) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ReceiptError(f"{name} must be bytes")
    value = bytes(value)
    if not value or (length is not None and len(value) != length):
        raise ReceiptError(f"{name} has an invalid length")
    return value


def _failure(reason: str) -> dict[str, str]:
    return {"outcome": "REJECTED", "reason": reason}


class EvidenceRun:
    """Create a receipt around an explicit broker epoch interval.

    ``begin()`` seals prior activity and opens a fresh interval.  ``finish``
    seals completed operations, constructs a Merkle absence proof, and asks the
    existing witness to co-sign a receipt tied to its current checkpoint head.
    It is *not* an execution attestation: ``code_digest`` identifies a local
    artifact supplied by the caller, while the returned assurance remains
    ``BROKER_ONLY`` unless an independently validated confinement layer exists.
    """

    def __init__(self, broker, *, run_id: str, challenge: bytes,
                 policy: Mapping[str, Any], code_digest: bytes):
        if not isinstance(run_id, str) or not run_id or len(run_id) > 256:
            raise ReceiptError("run_id must be a nonempty short string")
        if getattr(broker, "journal", None) is None:
            raise ReceiptError("portable receipts require a durable broker journal")
        if not isinstance(getattr(broker, "witness", None), DurableWitness):
            raise ReceiptError("portable receipts require a DurableWitness")
        self.broker = broker
        self.run_id = run_id
        self.challenge = _require_bytes(challenge, "challenge")
        self.policy = dict(policy)
        self.code_digest = _require_bytes(code_digest, "code_digest", 32)
        # Validate serializability now, before starting a boundary interval.
        canon(self.policy)
        self._started = False
        self._finished = False
        self.start_epoch = None
        self.start_checkpoint_hash = None
        self.start_boundary = None

    def begin(self):
        if self._started:
            raise ReceiptError("run has already begun")
        boundary = self.broker.seal()
        self.start_epoch = boundary["epoch"] + 1
        self.start_checkpoint_hash = cp_hash(boundary)
        boundary_record = self.broker.sealed[boundary["epoch"]]
        self.start_boundary = {
            "cp": boundary_record["cp"],
            "sig": boundary_record["sig"].hex(),
            "wsig": boundary_record["wsig"].hex(),
        }
        self._started = True
        return boundary

    def finish_negative(self, lo: bytes, hi: bytes) -> dict[str, Any]:
        if not self._started or self._finished:
            raise ReceiptError("run is not in a finishable state")
        if not isinstance(lo, bytes) or not isinstance(hi, bytes) or not lo < hi:
            raise ReceiptError("receipt range must be nonempty bytes")
        end = self.broker.seal()
        end_epoch = end["epoch"]
        try:
            evidence = self.broker.prove_empty(lo, hi, self.start_epoch, end_epoch)
        except NotEmpty:
            # The boundary epoch remains valid, but this requested negative
            # receipt cannot honestly be issued.
            raise
        scope = {
            "lo": lo.hex(),
            "hi": hi.hex(),
            "operations": RECORDED_OPERATIONS,
        }
        # Bind the concrete requested range and operation semantics to the
        # externally supplied policy, rather than signing two unrelated blobs.
        effective_policy_digest = policy_digest({"policy": self.policy, "scope": scope})
        payload = {
            "type": RECEIPT_TYPE,
            "v": RECEIPT_VERSION,
            "run_id": self.run_id,
            "challenge": self.challenge.hex(),
            "policy_digest": effective_policy_digest,
            "code_identity": {
                "sha256": self.code_digest.hex(),
                "binding": "DECLARED_LOCAL_ARTIFACT_NOT_EXECUTION_ATTESTATION",
            },
            "scope": scope,
            "broker": self.broker.signer.pub.hex(),
            "witness": self.broker.witness.signer.pub.hex(),
            "assurance": ASSURANCE_BROKER_ONLY,
            "interval": {
                "start_epoch": self.start_epoch,
                "end_epoch": end_epoch,
                "start_checkpoint_hash": self.start_checkpoint_hash.hex(),
                "end_checkpoint_hash": cp_hash(end).hex(),
            },
            "start_boundary": self.start_boundary,
            "evidence": evidence,
            "privacy": (
                "The Merkle adjacency proof may disclose neighboring resource "
                "keys, per-key masks/counts/first sequence values, and event counts."
            ),
        }
        broker_signature = self.broker.signer.sign(DOM_RB, canon(payload))
        witness_signature = self.broker.witness.cosign_receipt(payload, broker_signature)
        self._finished = True
        return {
            "payload": payload,
            "broker_signature": broker_signature.hex(),
            "witness_signature": witness_signature.hex(),
        }


def verify_negative_access_receipt(
        receipt: Mapping[str, Any], *, broker_pub: bytes, witness_pub: bytes,
        challenge: bytes, policy: Mapping[str, Any], lo: bytes, hi: bytes,
        run_id: str, code_digest: bytes, epochs: tuple[int, int],
        assurance: str = ASSURANCE_BROKER_ONLY) -> dict[str, Any]:
    """Verify a receipt against caller-supplied references only.

    Returns ``VERIFIED`` or ``REJECTED``.  Missing/invalid expected inputs are
    ``BLOCKED`` because accepting a receipt-selected key, challenge, policy, or
    range would make a self-authorizing verification API.
    """
    try:
        if (not isinstance(broker_pub, bytes) or len(broker_pub) != 32 or
                not isinstance(witness_pub, bytes) or len(witness_pub) != 32 or
                not isinstance(challenge, bytes) or not challenge or
                not isinstance(lo, bytes) or not isinstance(hi, bytes) or not lo < hi or
                not isinstance(run_id, str) or not run_id or
                not isinstance(code_digest, bytes) or len(code_digest) != 32 or
                not isinstance(epochs, tuple) or len(epochs) != 2):
            return {"outcome": "BLOCKED", "reason": "missing or invalid verifier reference values"}
        payload = receipt["payload"]
        broker_signature = bytes.fromhex(receipt["broker_signature"])
        witness_signature = bytes.fromhex(receipt["witness_signature"])
        if not isinstance(payload, dict):
            return _failure("payload is not an object")
        serialized = canon(payload)
        if not verify_sig(broker_pub, DOM_RB, serialized, broker_signature):
            return _failure("invalid broker receipt signature")
        if not verify_sig(witness_pub, DOM_RW, serialized, witness_signature):
            return _failure("invalid witness receipt signature")
        if payload.get("type") != RECEIPT_TYPE or payload.get("v") != RECEIPT_VERSION:
            return _failure("unsupported receipt version")
        if payload.get("broker") != broker_pub.hex() or payload.get("witness") != witness_pub.hex():
            return _failure("receipt identity does not match expected keys")
        if payload.get("challenge") != challenge.hex():
            return _failure("challenge mismatch")
        if payload.get("run_id") != run_id:
            return _failure("run identifier mismatch")
        if payload.get("assurance") != assurance:
            return _failure("assurance level mismatch")
        code_identity = payload.get("code_identity")
        if not isinstance(code_identity, dict) or code_identity.get("sha256") != code_digest.hex():
            return _failure("code digest mismatch")
        scope = payload.get("scope")
        if (not isinstance(scope, dict) or scope.get("lo") != lo.hex() or
                scope.get("hi") != hi.hex() or scope.get("operations") != RECORDED_OPERATIONS):
            return _failure("query scope mismatch")
        if payload.get("policy_digest") != policy_digest({"policy": dict(policy), "scope": scope}):
            return _failure("policy digest mismatch")
        interval = payload.get("interval")
        if not isinstance(interval, dict):
            return _failure("missing interval")
        if (interval.get("start_epoch"), interval.get("end_epoch")) != epochs:
            return _failure("epoch interval mismatch")
        if not (isinstance(epochs[0], int) and isinstance(epochs[1], int) and 0 <= epochs[0] <= epochs[1]):
            return {"outcome": "BLOCKED", "reason": "invalid expected epoch interval"}
        evidence = payload.get("evidence")
        verified = verify_alibi(evidence, broker_pub, witness_pub, lo, hi, epochs)
        checkpoints = evidence["epochs"]
        if not checkpoints:
            return _failure("receipt has no checkpoint coverage")
        first, last = checkpoints[0]["cp"], checkpoints[-1]["cp"]
        boundary = payload.get("start_boundary")
        if not isinstance(boundary, dict):
            return _failure("missing signed start boundary")
        try:
            boundary_cp = boundary["cp"]
            boundary_sig = bytes.fromhex(boundary["sig"])
            boundary_wsig = bytes.fromhex(boundary["wsig"])
        except (KeyError, TypeError, ValueError):
            return _failure("malformed start boundary")
        if (not isinstance(boundary_cp, dict) or epochs[0] < 1 or
                boundary_cp.get("v") != 1 or boundary_cp.get("epoch") != epochs[0] - 1 or
                boundary_cp.get("broker") != broker_pub.hex() or
                not verify_sig(broker_pub, DOM_B, canon(boundary_cp), boundary_sig) or
                not verify_sig(witness_pub, DOM_W, canon(boundary_cp), boundary_wsig) or
                cp_hash(boundary_cp).hex() != interval.get("start_checkpoint_hash")):
            return _failure("start boundary identity or epoch mismatch")
        if (first.get("prev") != interval.get("start_checkpoint_hash") or
                first.get("seq_lo") != boundary_cp.get("seq_hi", -1) + 1):
            return _failure("start boundary does not link to evidence")
        if cp_hash(last).hex() != interval.get("end_checkpoint_hash"):
            return _failure("end boundary hash mismatch")
        return {
            "outcome": "VERIFIED",
            "run_id": run_id,
            "epochs": epochs,
            "events_covered": verified["events_covered"],
            "assurance": assurance,
        }
    except (AlibiError, KeyError, TypeError, ValueError) as ex:
        return _failure(str(ex) or "malformed receipt")
