"""Observe fixed Public Lab 002 specimens using the published historical verifiers."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from threading import Barrier

from wolfalibi import finance_records, finance_verify, history_verify


# Canonical JSON digests of PR #35's exact positive outputs. Comparing every
# field includes identity, assurance, historical time and receipt digest.
_RESULT_SHA = {
    "finance": "a16018cba45e68f18288af0d18e29daf5dd2982e105e0aa8c0e3fe5c2f426e79",
    "history": "a372e4ee70e344ad46dc317da56abb75982b784d169ea9c13b6193cd8784ffff",
}
_MANIFEST_SHA = "83c707ef06be9e9f2623f32605c48d4135841300dd694a9f1fe361b99f011fc8"


# The inherited functions signal both domain errors and library faults through
# ValueError. An unfamiliar diagnostic remains inconclusive in this fixed lab.
_HISTORICAL_REFUSALS = {
    "externally supplied run challenge differs from expectations",
    "finance qualification differs from the retained witness digest",
    "historical disclosure differs from external pins or original evidence",
    "history inquiry differs from the expected scope or challenge",
    "inquiry challenge differs from the verifier's expectations",
    "invalid education record signature",
    "invalid finance evidence fields",
    "invalid grant fields",
    "invalid history evidence fields",
    "invalid signed education record fields",
    "noncanonical record signature",
    "receipt differs from the exact payment scope",
    "scope differs from the fixed synthetic payment profile",
}


class WireFormatError(ValueError):
    """A format refusal before a canonical security decision."""


def _fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WireFormatError("duplicate JSON member")
        result[key] = value
    return result


def _forbid_decimal(_):
    raise WireFormatError("profile requires integer JSON numbers")


def _parse(raw):
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WireFormatError("fixture is not UTF-8") from exc
    if text.startswith("\ufeff"):
        raise WireFormatError("UTF-8 byte order mark is outside the wire profile")
    try:
        obj = json.loads(text, object_pairs_hook=_fields, parse_float=_forbid_decimal,
                         parse_constant=_forbid_decimal)
    except json.JSONDecodeError as exc:
        raise WireFormatError("fixture is not complete JSON") from exc
    if type(obj) is not dict:
        raise WireFormatError("fixture must be a JSON object")
    return obj


def _observation(outcome, reason, phase, **details):
    result = {"outcome": outcome, "reason": reason, "phase": phase}
    if details:
        result["details"] = details
    return result


def _verify(profile, pins, evidence, challenge):
    if profile == "history":
        return history_verify.verify_history(pins, evidence, challenge=challenge)
    if profile == "finance":
        if pins["scope"]["challenge"] != challenge:
            raise ValueError("externally supplied run challenge differs from expectations")
        return finance_verify.verify_admission(pins, evidence)
    raise RuntimeError("unknown historical verifier")


def _one(profile, pins, evidence, challenge):
    try:
        result = _verify(profile, pins, evidence, challenge)
    except ValueError as exc:
        # The inherited functions return domain refusals this way. To qualify a
        # fixed negative, the runner also requires its independently specified reason.
        if str(exc) not in _HISTORICAL_REFUSALS:
            raise
        return _observation("REJECTED", str(exc), "historical_verifier")
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if sha256(encoded).hexdigest() != _RESULT_SHA[profile]:
        return _observation("UNEXPECTED_RESULT", "verifier output differs from the published historical result",
                            "historical_verifier", canonical=result)
    return _observation("VERIFIED", result["verified"], "historical_verifier", canonical=result,
                        settlement="UNESTABLISHED", operational_authority="NOT_ISSUED")


def _expired(pins, evidence, historical):
    packet = evidence["packet"]
    expires = packet["grant"]["payload"]["expires_at"]
    details = {**historical["details"], "synthetic_check_time": expires}
    try:
        finance_records.check_packet(
            packet, expected_scope=pins["scope"], owner_pub=bytes.fromhex(pins["owner_pub"]),
            supervisor_pub=bytes.fromhex(pins["supervisor_pub"]),
            witness_pub=bytes.fromhex(pins["witness_pub"]), peer=pins["peer"], now=expires,
            witness_head=pins["witness_head"],
        )
    except ValueError as exc:
        if str(exc) != "education authorization is outside its validity window":
            raise
        return _observation("REJECTED", str(exc), "payment_packet_check_at_expiry", **details)
    return _observation("UNEXPECTED_RESULT", "expired payment packet passed its validity check",
                        "payment_packet_check_at_expiry", **details)


def observe(case, raw, trusted):
    """Report the actual outcome. Never read the case's expected verdict."""
    profile = case["profile"]
    mode = case["mode"]
    if mode == "custody":
        return _observation("UNSUPPORTED", "independent cross-UID custody is outside this profile", "coverage")
    if mode == "joint_rollback":
        return _observation("NOT_ASSESSED", "no independently held later checkpoint is available", "coverage")
    if mode == "manifest":
        if sha256(raw).hexdigest() != _MANIFEST_SHA:
            return _observation("REJECTED", "manifest bytes differ from the pinned PR #35 manifest", "inventory")
        return _observation("VERIFIED", "manifest bytes match the pinned PR #35 manifest", "inventory")

    baseline = trusted[profile]
    pins, challenge, original = baseline["pins"], baseline["challenge"], baseline["genuine"]
    kind = case["input_kind"]
    try:
        if kind == "evidence":
            wrapper = _parse(raw)
            if wrapper.keys() != {"evidence"}:
                raise WireFormatError("expected exactly one evidence wrapper")
            evidence = wrapper["evidence"]
        elif kind == "pins":
            pins = _parse(raw)
            evidence = original["evidence"]
        elif kind == "challenge":
            if len(raw) != 65 or raw[-1:] != b"\n" or any(c not in b"0123456789abcdef" for c in raw[:-1]):
                raise WireFormatError("challenge requires lowercase hex and one line ending")
            challenge = raw[:-1].decode("ascii")
            evidence = original["evidence"]
        else:
            raise RuntimeError("unknown financial challenge input role")
    except WireFormatError as exc:
        return _observation("INPUT_REFUSED", str(exc), "wire_format")

    if mode in ("repeat", "parallel"):
        args = (profile, pins, evidence, challenge)
        if mode == "parallel":
            ready = Barrier(2)

            def check_after_rendezvous():
                ready.wait(timeout=10)
                return _one(*args)

            with ThreadPoolExecutor(max_workers=2) as workers:
                first, second = [workers.submit(check_after_rendezvous) for _ in range(2)]
                results = [first.result(), second.result()]
        else:
            results = [_one(*args), _one(*args)]
        if results[0] != results[1]:
            return _observation("UNEXPECTED_RESULT", "historical observations disagree", "repeat_check",
                                observations=results)
        observed = results[0]
        return {**observed, "details": {**observed.get("details", {}), "verifications": 2, "schedule": mode}}
    if mode not in ("verify", "expired"):
        raise RuntimeError("unknown financial challenge mode")
    result = _one(profile, pins, evidence, challenge)
    if mode == "expired" and result["outcome"] == "VERIFIED":
        return _expired(pins, evidence, result)
    return result
