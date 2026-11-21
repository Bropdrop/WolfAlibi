"""Strict optional observational record for a post-ACK Solitary channel.

This parser accepts one intentionally tiny, unsigned AgentProbe aggregate. It
does not verify Solitary evidence, authorize a broker operation, or establish
that a process actually emitted the record. Its caller must enforce the wire
ordering and framing; only the JSON remainder after the protocol prefix belongs
here.
"""
from __future__ import annotations

import json
import re

from .agent_probe import SCHEMA as AGENT_PROBE_SCHEMA


MAX_PACKET_BYTES = 4096
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_DURATION_BUCKETS = frozenset({"0-9", "10-99", "100-999", "1000+"})
_PRIVACY = "No prompts, arguments, outputs, credentials, file names or error strings collected"
_SUMMARY_FIELDS = frozenset({
    "schema", "run_id", "agent_type", "assurance", "coverage",
    "complete_wrapped_calls", "events", "manual_events", "inflight",
    "counts", "duration_buckets_ms", "privacy", "nonaccess_proof",
    "network_upload",
})
_PACKET_FIELDS = frozenset({"type", "summary"})


class _InvalidObservation(ValueError):
    """The optional aggregate does not match the fixed observational profile."""


def _object_without_duplicates(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise _InvalidObservation("duplicate JSON field")
        result[name] = value
    return result


def _reject_constant(_value):
    raise _InvalidObservation("non-finite JSON value")


def _reject_float(_value):
    raise _InvalidObservation("floating-point JSON value")


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _failure(outcome: str, reason: str) -> dict[str, str]:
    # Reasons are fixed protocol labels: never echo a packet or parser error.
    return {
        "outcome": outcome,
        "assurance": "OBSERVATIONAL_ONLY",
        "reason": reason,
    }


def _normal_summary(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != _SUMMARY_FIELDS:
        raise _InvalidObservation("unexpected summary fields")

    if (type(value["schema"]) is not str or value["schema"] != AGENT_PROBE_SCHEMA or
            type(value["run_id"]) is not str or _RUN_ID.fullmatch(value["run_id"]) is None or
            type(value["agent_type"]) is not str or value["agent_type"] != "custom" or
            type(value["assurance"]) is not str or value["assurance"] != "OBSERVATIONAL_ONLY" or
            type(value["coverage"]) is not str or value["coverage"] != "EXPLICITLY_WRAPPED_CALLS_ONLY" or
            value["complete_wrapped_calls"] is not True or
            type(value["events"]) is not int or value["events"] != 1 or
            type(value["manual_events"]) is not int or value["manual_events"] != 0 or
            type(value["inflight"]) is not int or value["inflight"] != 0 or
            type(value["privacy"]) is not str or value["privacy"] != _PRIVACY or
            value["nonaccess_proof"] is not False or value["network_upload"] is not False):
        raise _InvalidObservation("unsupported summary values")

    counts = value["counts"]
    if type(counts) is not dict or counts != {"filesystem.read.success": 1}:
        raise _InvalidObservation("unexpected aggregate counts")
    # A bool is not an accepted counter even though it compares equal to one.
    if type(counts["filesystem.read.success"]) is not int:
        raise _InvalidObservation("invalid aggregate counter")

    buckets = value["duration_buckets_ms"]
    if type(buckets) is not dict or len(buckets) != 1:
        raise _InvalidObservation("unexpected duration buckets")
    ((bucket, count),) = buckets.items()
    if type(bucket) is not str or bucket not in _DURATION_BUCKETS or type(count) is not int or count != 1:
        raise _InvalidObservation("invalid duration bucket")

    # Construct a fresh, closed object rather than returning parsed input.
    return {
        "schema": AGENT_PROBE_SCHEMA,
        "run_id": value["run_id"],
        "agent_type": "custom",
        "assurance": "OBSERVATIONAL_ONLY",
        "coverage": "EXPLICITLY_WRAPPED_CALLS_ONLY",
        "complete_wrapped_calls": True,
        "events": 1,
        "manual_events": 0,
        "inflight": 0,
        "counts": {"filesystem.read.success": 1},
        "duration_buckets_ms": {bucket: 1},
        "privacy": _PRIVACY,
        "nonaccess_proof": False,
        "network_upload": False,
    }


def parse_observation(packet: bytes) -> dict[str, object]:
    """Parse one optional closed, wrapped-only custom AgentProbe summary.

    Empty bytes mean that no optional observation was supplied. Any other
    malformed, oversized, noncanonical, duplicate, or out-of-profile packet is
    rejected. This function intentionally has no evidence or authorization
    dependencies.
    """
    if type(packet) is not bytes:
        return _failure("REJECTED", "INVALID_OBSERVATION_PACKET")
    if packet == b"":
        return _failure("UNAVAILABLE", "NO_OBSERVATION_PACKET")
    if len(packet) > MAX_PACKET_BYTES:
        return _failure("REJECTED", "INVALID_OBSERVATION_PACKET")
    try:
        decoded = json.loads(
            packet.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
        if type(decoded) is not dict or frozenset(decoded) != _PACKET_FIELDS:
            raise _InvalidObservation("unexpected packet fields")
        if type(decoded["type"]) is not str or decoded["type"] != "agent-observation":
            raise _InvalidObservation("unexpected packet type")
        if _canonical(decoded) != packet:
            raise _InvalidObservation("noncanonical packet")
        summary = _normal_summary(decoded["summary"])
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, OverflowError, RecursionError):
        return _failure("REJECTED", "INVALID_OBSERVATION_PACKET")
    return {
        "outcome": "OBSERVED",
        "assurance": "OBSERVATIONAL_ONLY",
        "summary": summary,
    }


__all__ = ("MAX_PACKET_BYTES", "parse_observation")
