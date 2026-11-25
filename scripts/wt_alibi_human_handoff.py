#!/usr/bin/env python3
"""Collect one fresh public bundle for the disposable Shirudo counter lab."""

from __future__ import annotations

import argparse
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
import secrets
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shirudo_adapter.action_gate import (
    ADMISSION_MS, CLOCK_SKEW_MS, FRESHNESS_MS, MAX_CHALLENGE_BYTES, MAX_INTEGER,
    _ATTESTATION_KEYS, _action_payload, _times,
)
from shirudo_adapter.model import (
    AdapterError, MAX_EVIDENCE_BYTES, MAX_RECORD_BYTES, bounded_int,
    canonical_json, check_evidence, digest, exact_keys, require_hex, strict_json,
)
from shirudo_adapter.owner import (
    MAX_INTENT_BYTES, MAX_PROFILE_BYTES, MIN_REMAINING_MS,
    validate_bundle, validate_intent, validate_profile,
)
from shirudo_adapter.receipt import verify_receipt, verify_record
from shirudo_adapter.runner import MAX_REPORT_BYTES

READY_LIMIT = 4096
OWNER_BUNDLE_WAIT_MS = 25_000
PIN_SCHEMA = "wolfalibi.shirudo.handoff-pins.v1"
BUNDLE_SCHEMA = "wolfalibi.shirudo.owner-bundle.v1"


class HandoffError(AdapterError):
    """A bounded failure with a public reason code."""


def now_ms():
    return time.time_ns() // 1_000_000


def absolute_path(value):
    path = Path(value)
    if not path.is_absolute() or path.anchor != "/" or not path.name or ".." in path.parts:
        raise HandoffError("PATH", "An absolute file path without traversal is required")
    return path


@contextmanager
def parent_directory(path, *, owner_uid=None):
    """Open a nonreplaceable directory chain without following any symlinks."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        parents = path.parent.parts[1:]
        for index, part in enumerate(parents):
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            sticky = (index < len(parents) - 1 and info.st_uid == 0
                      and info.st_mode & stat.S_ISVTX)
            if (info.st_uid not in {0, os.geteuid(), owner_uid}
                    or (info.st_mode & 0o022 and not sticky)):
                raise HandoffError("DIRECTORY_CUSTODY", "A directory in the path is replaceable")
        info = os.fstat(fd)
        if owner_uid is not None and info.st_uid != owner_uid:
            raise HandoffError("READY_CUSTODY", "READY directory is outside the pinned owner account")
        yield fd
    except OSError as exc:
        raise HandoffError("DIRECTORY_IO", "Cannot open the protected directory chain") from exc
    finally:
        os.close(fd)


def read_public(path, limit):
    """Snapshot a bounded regular file without blocking on a special inode."""
    path = absolute_path(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        with parent_directory(path) as directory:
            fd = os.open(path.name, flags, dir_fd=directory)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                    raise HandoffError("FILE_TYPE_SIZE", "Input must be a bounded, unlinked regular file")
                with os.fdopen(os.dup(fd), "rb") as stream:
                    raw = stream.read(limit + 1)
                after = os.fstat(fd)
            finally:
                os.close(fd)
    except OSError as exc:
        raise HandoffError("FILE_IO", "Cannot read the public input safely") from exc
    if (len(raw) != before.st_size or len(raw) > limit or
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise HandoffError("FILE_CHANGED", "Input changed during the snapshot")
    return raw


def strict_read(path, limit=MAX_EVIDENCE_BYTES):
    try:
        value = strict_json(read_public(path, limit), limit)
        if type(value) is not dict:
            raise HandoffError("INVALID_SCHEMA", "Public document must be an object")
        return value
    except AdapterError as exc:
        raise HandoffError(exc.code, exc.message) from exc


def require_absent(path):
    with parent_directory(path) as directory:
        try:
            os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
    raise HandoffError("OUTPUT_EXISTS", "The destination already exists")


def atomic_new(path, data, *, before_link=None):
    """Publish a complete regular file with a durable, no-replace link."""
    path = absolute_path(path)
    temporary = ".wolfalibi-" + secrets.token_hex(16)
    with parent_directory(path) as directory:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(temporary, flags, 0o600, dir_fd=directory)
        linked = False
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), 0o644)
                os.fsync(stream.fileno())
            if before_link is not None:
                before_link()
            try:
                os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory,
                        follow_symlinks=False)
            except FileExistsError as exc:
                raise HandoffError("OUTPUT_EXISTS", "The destination already exists") from exc
            linked = True
        finally:
            os.unlink(temporary, dir_fd=directory)
        if linked:
            try:
                os.fsync(directory)
            except OSError as exc:
                raise HandoffError("PUBLICATION_UNCERTAIN", "Publication may be visible; retain this request") from exc


def wait_ready(path, owner_uid, *, timeout=300):
    """Read the first line of the original owner's protected stdout file."""
    path = absolute_path(path)
    bounded_int(owner_uid, 1, 2 ** 31 - 1, "owner UID")
    bounded_int(timeout, 1, 900, "READY timeout")
    if owner_uid == os.geteuid():
        raise HandoffError("READY_CUSTODY", "The coordinator and owner require separate accounts")
    deadline = time.monotonic() + timeout
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with parent_directory(path, owner_uid=owner_uid) as directory:
        while time.monotonic() < deadline:
            try:
                fd = os.open(path.name, flags, dir_fd=directory)
            except FileNotFoundError:
                time.sleep(0.025)
                continue
            except OSError as exc:
                raise HandoffError("READY_CUSTODY", "Cannot open the owner's stdout file safely") from exc
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                        or info.st_nlink != 1 or info.st_mode & 0o022):
                    raise HandoffError("READY_CUSTODY", "Owner stdout has unsafe write custody")
                fragment = os.read(fd, READY_LIMIT + 1)
            finally:
                os.close(fd)
            if len(fragment) > READY_LIMIT:
                raise HandoffError("READY_SIZE", "Owner stdout exceeded its READY bound")
            line, separator, tail = fragment.partition(b"\n")
            if separator:
                if tail:
                    raise HandoffError("READY_CLOSED", "The owner has moved beyond this READY event")
                return strict_json(line, READY_LIMIT)
            time.sleep(0.025)
    raise HandoffError("READY_TIMEOUT", "No owner READY arrived before the deadline")


def read_pins(path, expected_sha256):
    require_hex(expected_sha256, 64, "approved pins digest")
    pins = strict_read(path, READY_LIMIT)
    if digest(pins) != expected_sha256:
        raise HandoffError("PINS_DIGEST", "Public pins differ from the approved digest")
    return pins


def pinned_inputs(pins, intent, profile):
    pins = strict_json(canonical_json(pins), READY_LIMIT)
    exact_keys(pins, {"schema", "owner_instance_id", "owner_uid", "profile_sha256",
                      "intent_sha256", "request_id"}, "handoff pins")
    if pins["schema"] != PIN_SCHEMA:
        raise HandoffError("INVALID_SCHEMA", "Unsupported handoff pins")
    require_hex(pins["owner_instance_id"], 32, "owner instance")
    bounded_int(pins["owner_uid"], 1, 2 ** 31 - 1, "owner UID")
    require_hex(pins["request_id"], 32, "expected request")
    require_hex(pins["profile_sha256"], 64, "approved profile digest")
    require_hex(pins["intent_sha256"], 64, "approved intent digest")
    profile = validate_profile(profile)
    intent = validate_intent(intent, profile)
    if (digest(profile) != pins["profile_sha256"] or digest(intent) != pins["intent_sha256"]
            or intent["request_id"] != pins["request_id"]):
        raise HandoffError("PINS_MISMATCH", "Request, intent or profile differs from the independent pins")
    if profile["policy"]["challenge_ttl_seconds"] * 1000 > FRESHNESS_MS:
        raise HandoffError("FRESHNESS_POLICY", "The verifier policy widens the laboratory freshness window")
    return pins, intent, profile


def ready_time(ready, pins, now):
    exact_keys(ready, {"status", "owner_instance_id", "request_id", "intent_sha256",
                       "profile_sha256", "ready_at_ms"}, "READY event")
    if (ready["status"] != "READY" or any(ready[key] != pins[key] for key in
            ("owner_instance_id", "request_id", "intent_sha256", "profile_sha256"))):
        raise HandoffError("READY_BINDING", "READY differs from the pinned owner attempt")
    ready_at = bounded_int(ready["ready_at_ms"], 1, MAX_INTEGER, "READY time")
    if ready_at > now:
        raise HandoffError("CLOCK_SKEW", "Owner READY is ahead of the coordinator's host clock")
    if now - ready_at > FRESHNESS_MS - MIN_REMAINING_MS:
        raise HandoffError("APPROVAL_EXPIRED", "The owner attempt has insufficient lifetime")
    return ready_at


def verified_bundle(intent, profile, bundle, ready, *, pins, at_ms):
    pins, intent, profile = pinned_inputs(pins, intent, profile)
    return validate_bundle(bundle, profile, intent=intent, ready_at_ms=ready_time(ready, pins, at_ms),
                           now_ms=at_ms, min_remaining_ms=MIN_REMAINING_MS)


def checked_challenge(record, profile, *, policy_sha, issued_after_ms, now):
    record = strict_json(canonical_json(record), MAX_CHALLENGE_BYTES)
    payload = verify_record(record, profile["verifier_public_key"])
    exact_keys(payload, _ATTESTATION_KEYS, "verifier challenge")
    if payload["schema"] != "wolfalibi.shirudo.challenge.v1":
        raise HandoffError("INVALID_SCHEMA", "Unsupported verifier challenge")
    require_hex(payload["challenge_id"], 32, "challenge ID")
    require_hex(payload["nonce"], 64, "attestation nonce")
    _times(payload, FRESHNESS_MS)
    if (payload["target_id"] != profile["target_id"] or payload["policy_sha256"] != policy_sha
            or payload["instance_id"] != profile["verifier_instance_id"]
            or payload["expires_at_ms"] - payload["issued_at_ms"] !=
            profile["policy"]["challenge_ttl_seconds"] * 1000):
        raise HandoffError("CHALLENGE_SCOPE_MISMATCH", "Signed challenge differs from independent policy pins")
    issued = payload["issued_at_ms"]
    if issued < issued_after_ms - CLOCK_SKEW_MS or issued > now + CLOCK_SKEW_MS:
        raise HandoffError("CHALLENGE_TIME", "Signed challenge did not originate in the fresh attempt")
    if now - issued > ADMISSION_MS or now >= payload["expires_at_ms"]:
        raise HandoffError("ATTESTATION_STALE", "Verifier challenge missed the admission window")
    return record


def checked_action(record, intent, profile, challenge, now):
    record = strict_json(canonical_json(record), MAX_CHALLENGE_BYTES)
    payload = _action_payload(verify_record(record, profile["gate_public_key"]))
    attestation = challenge["payload"]
    expected = {field: intent[field] for field in (
        "target_id", "gate_instance_id", "policy_sha256", "policy_generation", "action")}
    expected.update(attestation_challenge_sha256=digest(challenge),
                    attestation_challenge_id=attestation["challenge_id"],
                    attestation_nonce=attestation["nonce"])
    if (any(payload[key] != value for key, value in expected.items())
            or not -CLOCK_SKEW_MS <= payload["issued_at_ms"] - attestation["issued_at_ms"] <= ADMISSION_MS
            or payload["expires_at_ms"] != min(payload["issued_at_ms"] + FRESHNESS_MS,
                                                attestation["issued_at_ms"] + FRESHNESS_MS,
                                                attestation["expires_at_ms"])):
        raise HandoffError("ACTION_MISMATCH", "Target challenge differs from the pinned action or timing")
    if payload["issued_at_ms"] > now + CLOCK_SKEW_MS:
        raise HandoffError("CLOCK_SKEW", "Target challenge is too far ahead of the coordinator clock")
    return record


def coordinate(pins, intent, profile, ready, output, transport, record, *, clock=now_ms):
    """Run four fixed public operations after the authenticated READY input.

    The CLI and disposable harness authenticate the owner channel before
    calling this function. The transport accepts only the named lab calls.
    """
    pins, intent, profile = pinned_inputs(pins, intent, profile)
    ready = strict_json(canonical_json(ready), READY_LIMIT)
    started = last = clock()
    ready_at = ready_time(ready, pins, started)
    output = absolute_path(output)
    require_absent(output)
    deadline = ready_at + OWNER_BUNDLE_WAIT_MS

    def budget(until, *, leave=0):
        nonlocal last
        current = clock()
        if current < last:
            raise HandoffError("CLOCK_ROLLBACK", "Coordinator clock moved backwards")
        last = current
        remaining = until - current - leave
        if remaining <= 0:
            raise HandoffError("APPROVAL_EXPIRED", "The attempt has insufficient time for its next step")
        return remaining / 1000

    def write(name, value):
        record(name, canonical_json(value) + b"\n")

    # A durable request marker survives a failed prepare, process exit or lost
    # transport reply. A retry of this request cannot issue another challenge.
    budget(deadline)
    atomic_new(output.parent / f"started-{pins['request_id']}.json", canonical_json(ready) + b"\n")
    write("ready.json", ready)
    challenge = transport.challenge(intent["policy_sha256"], budget(deadline))
    challenge = checked_challenge(challenge, profile, policy_sha=intent["policy_sha256"],
                                  issued_after_ms=started, now=clock())
    write("attestation-challenge.json", challenge)
    attestation = challenge["payload"]
    admission_deadline = min(deadline, attestation["issued_at_ms"] + ADMISSION_MS,
                             attestation["expires_at_ms"])
    action = transport.prepare(challenge, budget(admission_deadline))
    action = checked_action(action, intent, profile, challenge, clock())
    write("action-challenge.json", action)
    operation_deadline = min(deadline, action["payload"]["expires_at_ms"])
    raw = transport.collect(attestation["challenge_id"], attestation["nonce"],
                            budget(operation_deadline, leave=MIN_REMAINING_MS))
    check_evidence(raw, profile["policy"], attestation["nonce"])
    record("evidence.json", raw)
    assessment, upstream_raw = transport.assess(attestation["challenge_id"], raw,
                                                budget(operation_deadline, leave=MIN_REMAINING_MS))
    assessment = strict_json(canonical_json(assessment), MAX_RECORD_BYTES)
    verification = verify_receipt(assessment, profile["verifier_public_key"],
                                  expected_target=profile["target_id"],
                                  expected_policy_sha256=intent["policy_sha256"],
                                  expected_challenge_id=attestation["challenge_id"])
    write("assessment.json", assessment)
    upstream = assessment["payload"]["upstream"]
    if upstream_raw is not None:
        if strict_json(upstream_raw, MAX_REPORT_BYTES) != upstream["report"]:
            raise HandoffError("UPSTREAM_REPORT", "Upstream stdout differs from the signed assessment")
        record("upstream-report.json", upstream_raw)
    elif upstream["report"] is not None:
        raise HandoffError("UPSTREAM_REPORT", "The original upstream stdout is missing")
    if verification["historical_outcome"] != "EVIDENCE_ACCEPTED":
        raise HandoffError(assessment["payload"]["reason_code"], "The pinned verifier declined this evidence")
    if assessment["payload"]["evidence_sha256"] != hashlib.sha256(raw).hexdigest():
        raise HandoffError("EVIDENCE_DIGEST", "The signed assessment names different raw evidence")
    bundle = {"schema": BUNDLE_SCHEMA, "request_id": intent["request_id"],
              "attestation_challenge": challenge, "action_challenge": action, "assessment": assessment}
    budget(deadline)
    review = verified_bundle(intent, profile, bundle, ready, pins=pins, at_ms=last)
    write("bundle.json", bundle)

    def still_fresh():
        budget(deadline)
        budget(review["expires_at_ms"], leave=MIN_REMAINING_MS)

    atomic_new(output, canonical_json(bundle) + b"\n", before_link=still_fresh)
    return {"status": "BUNDLE_PUBLISHED", "request_id": intent["request_id"],
            "operation_id": review["operation_id"], "bundle_sha256": review["bundle_sha256"],
            "actual_human_approval": "NOT_RUN", "effect": "NOT_ESTABLISHED"}


def main(argv=None):
    from scripts.shirudo_prototype_host import Roles
    from scripts.shirudo_real_lab import LabFailure, PublicArtifacts, VERIFIER_SHA256
    from scripts.wt_alibi_human_transport import LabCollection, LabGuest

    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pins-sha256", required=True)
    parser.add_argument("--ready-timeout", type=int, default=300)
    args = parser.parse_args(argv)
    artifacts = None
    try:
        roles = Roles()
        pins = read_pins(roles.exchange / "human-pins.json", args.pins_sha256)
        intent = strict_read(roles.exchange / "human-intent.json", MAX_INTENT_BYTES)
        profile = strict_read(roles.exchange / "owner-profile.json", MAX_PROFILE_BYTES)
        pins, intent, profile = pinned_inputs(pins, intent, profile)
        if profile["policy"]["verifier"]["sha256"] != VERIFIER_SHA256:
            raise HandoffError("VERIFIER_DIGEST", "The disposable lab requires the pinned official verifier")
        guest = LabGuest(args.upstream, args.vm_name)
        artifacts = PublicArtifacts(args.output)
        ready = wait_ready(roles.exchange / "owner-events/events.jsonl", pins["owner_uid"],
                           timeout=args.ready_timeout)
        result = coordinate(pins, intent, profile, ready, roles.exchange / "human-fresh-bundle.json",
                            LabCollection(guest, roles), artifacts.write)
        code = 0
    except (AdapterError, LabFailure, OSError) as exc:
        result = {"status": "BLOCKED", "reason": getattr(exc, "code", "LOCAL_IO"),
                  "actual_human_approval": "NOT_RUN", "effect": "NOT_ESTABLISHED"}
        code = 2
    if artifacts is not None:
        artifacts.json("result.json", result)
        artifacts.json("artifact-manifest.json", {"files": dict(artifacts.files)})
    print(canonical_json(result).decode("ascii"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
