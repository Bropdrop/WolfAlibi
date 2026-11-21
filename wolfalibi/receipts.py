"""Portable, verifier-parameterized negative-access receipts.

Receipts never authorize themselves: a verifier brings expected keys,
challenge, policy, run identifier, code digest, scope, and epoch interval.
Version 2 additionally requires externally supplied resource-identity,
execution-boundary, and retained witness-state references. Those bindings make
substitution and local-state rollback detectable to that verifier; they do not
attest execution or make a local witness an independent transparency service.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from alibi import (AlibiError, DOM_B, DOM_RB, DOM_RW, DOM_W, DurableWitness,
                   H, NotEmpty, canon, cp_hash, verify_alibi, verify_sig,
                   verify_witness_state_anchor)


RECEIPT_TYPE_V1 = "NEGATIVE_ACCESS_RECEIPT_V1"
RECEIPT_TYPE_V2 = "NEGATIVE_ACCESS_RECEIPT_V2"
RECEIPT_VERSION_V1 = 1
RECEIPT_VERSION_V2 = 2
# Compatibility aliases retain the Stage 1 construction surface. New callers
# must opt in to v2 explicitly rather than silently changing old receipts.
RECEIPT_TYPE = RECEIPT_TYPE_V1
RECEIPT_VERSION = RECEIPT_VERSION_V1
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


def _canonical_mapping(value: Mapping[str, Any], name: str, *,
                       allow_empty: bool = False) -> dict[str, Any]:
    """Copy a JSON object through canonical encoding before it is signed."""
    if not isinstance(value, Mapping) or (not value and not allow_empty):
        raise ReceiptError(f"{name} must be a nonempty mapping")
    try:
        copied = json.loads(canon(dict(value)))
    except (TypeError, ValueError, json.JSONDecodeError) as ex:
        raise ReceiptError(f"{name} must be canonical JSON data") from ex
    if not isinstance(copied, dict) or (not copied and not allow_empty):
        raise ReceiptError(f"{name} must be a nonempty JSON object")
    return copied


def _failure(reason: str) -> dict[str, str]:
    return {"outcome": "REJECTED", "reason": reason}


def _blocked(reason: str) -> dict[str, str]:
    return {"outcome": "BLOCKED", "reason": reason}


def _state_digest_from_anchor(anchor: Mapping[str, Any]) -> bytes:
    try:
        digest = bytes.fromhex(anchor["state_digest"])
    except (KeyError, TypeError, ValueError) as ex:
        raise ValueError("malformed witness state digest") from ex
    if len(digest) != 32:
        raise ValueError("invalid witness state digest length")
    return digest


def _verify_witness_state_continuity(receipt: Mapping[str, Any], payload: Mapping[str, Any],
                                     witness_pub: bytes,
                                     expected_state_digest: bytes) -> dict[str, Any]:
    """Verify one v2 run's signed witness-state transition chain.

    ``expected_state_digest`` must have been retained outside the local witness
    state before the run. A state rollback branches away from that retained
    digest and is rejected. This is intentionally not a substitute for a
    remote log or a second witness.
    """
    try:
        start = verify_witness_state_anchor(payload["witness_state_start"], witness_pub)
        if _state_digest_from_anchor(start) != expected_state_digest:
            return _failure("witness state start does not match external expectation")
        chain = receipt["witness_state_chain"]
        if not isinstance(chain, list) or len(chain) != 3:
            return _failure("witness state chain must contain begin, end, and receipt anchors")
        previous = start
        for package in chain:
            current = verify_witness_state_anchor(package, witness_pub)
            if (current["generation"] != previous["generation"] + 1 or
                    current["previous_state_digest"] != previous["state_digest"]):
                return _failure("witness state chain is not contiguous")
            previous = current
        if previous["last_receipt_digest"] != H(canon(payload)).hex():
            return _failure("final witness state anchor does not retain receipt digest")
        return {
            "outcome": "VERIFIED",
            "witness_state_digest": previous["state_digest"],
            "witness_state_generation": previous["generation"],
        }
    except (KeyError, TypeError, ValueError) as ex:
        return _failure(str(ex) or "malformed witness state continuity evidence")


class EvidenceRun:
    """Create a receipt around an explicit broker epoch interval.

    ``begin()`` seals prior activity and opens a fresh interval. ``finish``
    seals completed operations, constructs a Merkle absence proof, and asks
    the durable witness to co-sign a receipt tied to its current checkpoint
    head. A v2 receipt additionally binds caller-declared resource identity
    and execution-boundary data, and carries a signed local witness-state
    chain. It remains ``BROKER_ONLY``: declared code and boundary data are not
    execution attestation or complete mediation proof.
    """

    def __init__(self, broker, *, run_id: str, challenge: bytes,
                 policy: Mapping[str, Any], code_digest: bytes,
                 receipt_version: int = RECEIPT_VERSION_V1,
                 resource_identity: Optional[Mapping[str, Any]] = None,
                 execution_boundary: Optional[Mapping[str, Any]] = None):
        if not isinstance(run_id, str) or not run_id or len(run_id) > 256:
            raise ReceiptError("run_id must be a nonempty short string")
        if getattr(broker, "journal", None) is None:
            raise ReceiptError("portable receipts require a durable broker journal")
        if not isinstance(getattr(broker, "witness", None), DurableWitness):
            raise ReceiptError("portable receipts require a DurableWitness")
        if receipt_version not in (RECEIPT_VERSION_V1, RECEIPT_VERSION_V2):
            raise ReceiptError("unsupported receipt version")
        if receipt_version == RECEIPT_VERSION_V1 and (
                resource_identity is not None or execution_boundary is not None):
            raise ReceiptError("resource identity and execution boundary require receipt version 2")
        self.broker = broker
        self.run_id = run_id
        self.challenge = _require_bytes(challenge, "challenge")
        self.policy = _canonical_mapping(policy, "policy", allow_empty=True)
        self.code_digest = _require_bytes(code_digest, "code_digest", 32)
        self.receipt_version = receipt_version
        self.resource_identity = None
        self.execution_boundary = None
        if receipt_version == RECEIPT_VERSION_V2:
            self.resource_identity = _canonical_mapping(resource_identity, "resource_identity")
            self.execution_boundary = _canonical_mapping(execution_boundary, "execution_boundary")
            # This codebase never emits a verified-confinement receipt. Do not
            # let v2's declared boundary field masquerade as an assurance lift.
            if self.execution_boundary.get("assurance") not in (None, "BLOCKED"):
                raise ReceiptError("current receipts only accept BLOCKED execution-boundary assurance")
        self._started = False
        self._finished = False
        self.start_epoch = None
        self.start_checkpoint_hash = None
        self.start_boundary = None
        self._witness_state_start = None
        self._witness_state_after_begin = None

    def begin(self):
        if self._started:
            raise ReceiptError("run has already begun")
        if self.receipt_version == RECEIPT_VERSION_V2:
            self._witness_state_start = self.broker.witness.state_anchor()
        boundary = self.broker.seal()
        self.start_epoch = boundary["epoch"] + 1
        self.start_checkpoint_hash = cp_hash(boundary)
        boundary_record = self.broker.sealed[boundary["epoch"]]
        self.start_boundary = {
            "cp": boundary_record["cp"],
            "sig": boundary_record["sig"].hex(),
            "wsig": boundary_record["wsig"].hex(),
        }
        if self.receipt_version == RECEIPT_VERSION_V2:
            self._witness_state_after_begin = self.broker.witness.state_anchor()
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
        binding: dict[str, Any] = {"policy": self.policy, "scope": scope}
        if self.receipt_version == RECEIPT_VERSION_V2:
            binding.update({
                "resource_identity": self.resource_identity,
                "execution_boundary": self.execution_boundary,
            })
        payload = {
            "type": RECEIPT_TYPE_V2 if self.receipt_version == RECEIPT_VERSION_V2 else RECEIPT_TYPE_V1,
            "v": self.receipt_version,
            "run_id": self.run_id,
            "challenge": self.challenge.hex(),
            "policy_digest": policy_digest(binding),
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
        if self.receipt_version == RECEIPT_VERSION_V2:
            payload.update({
                "resource_identity": self.resource_identity,
                "execution_boundary": self.execution_boundary,
                "witness_state_start": self._witness_state_start,
            })
            witness_state_after_end = self.broker.witness.state_anchor()
        broker_signature = self.broker.signer.sign(DOM_RB, canon(payload))
        witness_signature = self.broker.witness.cosign_receipt(payload, broker_signature)
        self._finished = True
        receipt = {
            "payload": payload,
            "broker_signature": broker_signature.hex(),
            "witness_signature": witness_signature.hex(),
        }
        if self.receipt_version == RECEIPT_VERSION_V2:
            receipt["witness_state_chain"] = [
                self._witness_state_after_begin,
                witness_state_after_end,
                self.broker.witness.state_anchor(),
            ]
        return receipt


def verify_negative_access_receipt(
        receipt: Mapping[str, Any], *, broker_pub: bytes, witness_pub: bytes,
        challenge: bytes, policy: Mapping[str, Any], lo: bytes, hi: bytes,
        run_id: str, code_digest: bytes, epochs: tuple[int, int],
        assurance: str = ASSURANCE_BROKER_ONLY,
        resource_identity: Optional[Mapping[str, Any]] = None,
        execution_boundary: Optional[Mapping[str, Any]] = None,
        expected_witness_state_digest: Optional[bytes] = None) -> dict[str, Any]:
    """Verify a receipt against caller-supplied references only.

    V1 preserves the Stage 1 verifier contract. V2 additionally blocks unless
    the caller independently supplies expected resource identity, boundary
    descriptor, and a witness-state digest retained before this run.
    """
    try:
        if (not isinstance(broker_pub, bytes) or len(broker_pub) != 32 or
                not isinstance(witness_pub, bytes) or len(witness_pub) != 32 or
                not isinstance(challenge, bytes) or not challenge or
                not isinstance(lo, bytes) or not isinstance(hi, bytes) or not lo < hi or
                not isinstance(run_id, str) or not run_id or
                not isinstance(code_digest, bytes) or len(code_digest) != 32 or
                not isinstance(epochs, tuple) or len(epochs) != 2):
            return _blocked("missing or invalid verifier reference values")
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
        receipt_type, version = payload.get("type"), payload.get("v")
        if (receipt_type, version) not in {
                (RECEIPT_TYPE_V1, RECEIPT_VERSION_V1),
                (RECEIPT_TYPE_V2, RECEIPT_VERSION_V2),
        }:
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
        try:
            expected_policy = _canonical_mapping(policy, "policy", allow_empty=True)
        except ReceiptError:
            return _blocked("invalid expected policy")
        binding: dict[str, Any] = {"policy": expected_policy, "scope": scope}
        if version == RECEIPT_VERSION_V2:
            if (resource_identity is None or execution_boundary is None or
                    not isinstance(expected_witness_state_digest, bytes) or
                    len(expected_witness_state_digest) != 32):
                return _blocked("v2 requires external resource, boundary, and witness-state references")
            try:
                expected_resource = _canonical_mapping(resource_identity, "resource_identity")
                expected_boundary = _canonical_mapping(execution_boundary, "execution_boundary")
            except ReceiptError:
                return _blocked("invalid expected v2 reference values")
            if (payload.get("resource_identity") != expected_resource or
                    payload.get("execution_boundary") != expected_boundary):
                return _failure("resource identity or execution boundary mismatch")
            if expected_boundary.get("assurance") not in (None, "BLOCKED"):
                return _failure("unsupported execution-boundary assurance claim")
            binding.update({
                "resource_identity": expected_resource,
                "execution_boundary": expected_boundary,
            })
        elif (resource_identity is not None or execution_boundary is not None or
              expected_witness_state_digest is not None):
            return _blocked("v1 does not bind stage-2 reference values")
        if payload.get("policy_digest") != policy_digest(binding):
            return _failure("policy digest mismatch")
        interval = payload.get("interval")
        if not isinstance(interval, dict):
            return _failure("missing interval")
        if (interval.get("start_epoch"), interval.get("end_epoch")) != epochs:
            return _failure("epoch interval mismatch")
        if not (isinstance(epochs[0], int) and isinstance(epochs[1], int) and 0 <= epochs[0] <= epochs[1]):
            return _blocked("invalid expected epoch interval")
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
        result: dict[str, Any] = {
            "outcome": "VERIFIED",
            "run_id": run_id,
            "epochs": epochs,
            "events_covered": verified["events_covered"],
            "assurance": assurance,
        }
        if version == RECEIPT_VERSION_V2:
            continuity = _verify_witness_state_continuity(
                receipt, payload, witness_pub, expected_witness_state_digest)
            if continuity["outcome"] != "VERIFIED":
                return continuity
            result.update({
                "witness_state_digest": continuity["witness_state_digest"],
                "witness_state_generation": continuity["witness_state_generation"],
            })
        return result
    except (AlibiError, KeyError, TypeError, ValueError) as ex:
        return _failure(str(ex) or "malformed receipt")
