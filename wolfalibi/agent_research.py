"""Consent-gated, local research aggregates for ``AgentProbe`` summaries.

Exports are deliberately unsigned operator reports, never WolfAlibi receipts.
They have no replay protection, perform no network activity, and must not be
read as evidence of non-access, confinement, or complete agent activity.
Only allowlisted coarse aggregates are copied from the source mapping.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import re

from .agent_probe import AGENT_TYPES, OPERATIONS, OUTCOMES, SCHEMA as OBSERVATION_SCHEMA, SURFACES


SCHEMA = "wolfalibi.agent_research_aggregate.v1"
VERSION = 1
OUTCOME_TAGS = frozenset({
    "PASS", "AGENT_ERROR", "TIMEOUT", "INTERRUPTED", "INCOMPLETE",
    "EXPECTATION_FAILED", "BLOCKED", "CANCELLED",
})
_COVERAGE = frozenset({
    "EXPLICITLY_WRAPPED_CALLS_ONLY",
    "EXPLICITLY_WRAPPED_CALLS_AND_DECLARED_MANUAL_EVENTS",
})
_DURATION_BUCKETS = frozenset({"0-9", "10-99", "100-999", "1000+"})
_COUNT_KEYS = frozenset(
    f"{surface}.{operation}.{outcome}"
    for surface in SURFACES
    for operation in OPERATIONS
    for outcome in OUTCOMES
)
_REQUIRED_SUMMARY_FIELDS = frozenset({
    "schema", "run_id", "agent_type", "assurance", "coverage",
    "complete_wrapped_calls", "events", "inflight", "counts",
    "duration_buckets_ms", "privacy", "nonaccess_proof", "network_upload",
})
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_MAX_EVENTS = 1_000_000


class ResearchExportError(ValueError):
    """A proposed local research aggregate is unsafe or malformed."""


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_EVENTS


def _snapshot(summary: Mapping[str, object]) -> dict[str, object]:
    """Copy only known source fields; intentionally discard unknown fields."""
    if not isinstance(summary, Mapping):
        raise ResearchExportError("summary must be an AgentProbe summary mapping")
    if not _REQUIRED_SUMMARY_FIELDS.issubset(summary.keys()):
        raise ResearchExportError("summary is missing required AgentProbe fields")
    try:
        copied = {name: summary[name] for name in _REQUIRED_SUMMARY_FIELDS}
        if not isinstance(copied["counts"], Mapping):
            raise TypeError
        if not isinstance(copied["duration_buckets_ms"], Mapping):
            raise TypeError
        copied["counts"] = dict(copied["counts"])
        copied["duration_buckets_ms"] = dict(copied["duration_buckets_ms"])
        # ``manual_events`` was added after the initial v0 summary.  Accept
        # legacy wrapped-only summaries, but require it when coverage says
        # that manually declared events are present.
        if "manual_events" in summary:
            copied["manual_events"] = summary["manual_events"]
        return copied
    except (KeyError, TypeError, ValueError) as exc:
        raise ResearchExportError("summary has invalid aggregate containers") from exc


def _validate(summary: Mapping[str, object], outcome: str) -> dict[str, object]:
    source = _snapshot(summary)
    if type(outcome) is not str or outcome not in OUTCOME_TAGS:
        raise ResearchExportError("outcome must be a supported coarse research tag")
    if source["schema"] != OBSERVATION_SCHEMA:
        raise ResearchExportError("unsupported AgentProbe summary schema")
    run_id = source["run_id"]
    if type(run_id) is not str or _RUN_ID.fullmatch(run_id) is None:
        raise ResearchExportError("summary is not a valid AgentProbe run snapshot")
    if type(source["agent_type"]) is not str or source["agent_type"] not in AGENT_TYPES:
        raise ResearchExportError("summary has an unsupported agent category")
    if (source["assurance"] != "OBSERVATIONAL_ONLY" or
            type(source["coverage"]) is not str or source["coverage"] not in _COVERAGE or
            source["nonaccess_proof"] is not False or
            source["network_upload"] is not False or
            type(source["privacy"]) is not str):
        raise ResearchExportError("summary does not have AgentProbe observational semantics")
    if type(source["complete_wrapped_calls"]) is not bool:
        raise ResearchExportError("summary completion marker is invalid")
    if not _count(source["events"]) or not _count(source["inflight"]):
        raise ResearchExportError("summary event counters are invalid")
    if source["inflight"] != 0:
        raise ResearchExportError("cannot export an unstable summary with in-flight calls")
    manual_events = source.get("manual_events", 0)
    if not _count(manual_events) or manual_events > source["events"]:
        raise ResearchExportError("summary manual event counter is invalid")
    if source["coverage"] == "EXPLICITLY_WRAPPED_CALLS_ONLY":
        if manual_events != 0:
            raise ResearchExportError("wrapped-only coverage conflicts with manual event count")
    elif "manual_events" not in source or manual_events == 0:
        raise ResearchExportError("manual-event coverage requires a positive manual event count")
    source["manual_events"] = manual_events

    counts = source["counts"]
    buckets = source["duration_buckets_ms"]
    if (not all(type(key) is str and key in _COUNT_KEYS and _count(value) and value > 0
                for key, value in counts.items()) or
            not all(type(key) is str and key in _DURATION_BUCKETS and _count(value) and value > 0
                    for key, value in buckets.items())):
        raise ResearchExportError("summary contains an unsupported aggregate category")
    if sum(counts.values()) != source["events"] or sum(buckets.values()) != source["events"]:
        raise ResearchExportError("summary aggregate totals do not match events")
    if not source["complete_wrapped_calls"] and outcome != "INCOMPLETE":
        raise ResearchExportError("an incomplete summary must use the incomplete outcome")
    return source


def _report(source: dict[str, object], outcome: str) -> dict[str, object]:
    completion = ("COMPLETE_WRAPPED_CALLS" if source["complete_wrapped_calls"]
                  else "INCOMPLETE_WRAPPED_CALLS")
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "outcome": outcome,
        "observation": {
            "agent_type": source["agent_type"],
            "assurance": "OBSERVATIONAL_ONLY",
            "coverage": source["coverage"],
            "completion": completion,
            "events": source["events"],
            "manual_events": source["manual_events"],
            "counts": dict(sorted(source["counts"].items())),
            "duration_buckets_ms": dict(sorted(source["duration_buckets_ms"].items())),
        },
        "reproducibility": {
            "semantics": "SCHEMA_AND_BUCKET_SEMANTICS_ONLY_NO_EXECUTION_CONFIGURATION",
        },
        "provenance": {
            "kind": "UNSIGNED_OPERATOR_LOCAL_RESEARCH_EXPORT",
            "cryptographic_receipt": False,
            "witnessed": False,
            "replay_protection": "NONE",
            "network_upload": False,
            "automatic_sharing": False,
        },
    }


def _write_create_only(path: Path, report: dict[str, object]) -> Path:
    data = (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            try:
                written = os.write(fd, view)
            except InterruptedError:
                continue
            if written <= 0:
                raise OSError("research report write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def export_research(summary: Mapping[str, object], output: str | Path, *, outcome: str,
                    consent: bool = False) -> Path:
    """Create a private create-only research aggregate without uploading it.

    ``outcome`` is a fixed coarse tag.  A summary with incomplete wrapped-call
    coverage can be exported only with ``outcome="INCOMPLETE"``; a complete
    wrapper lifecycle may still have an incomplete agent-run boundary.  No
    signature or replay defence is provided, and the local output path is not
    serialized.
    """
    if consent is not True:
        raise ResearchExportError("explicit consent is required for a local research export")
    source = _validate(summary, outcome)
    try:
        path = Path(output)
    except TypeError as exc:
        raise ResearchExportError("invalid local report destination") from exc
    return _write_create_only(path, _report(source, outcome))
