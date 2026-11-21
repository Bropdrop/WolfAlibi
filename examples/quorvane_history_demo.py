"""Disclose one archived synthetic Gate 003 intent through a separate authority.

The demo deliberately lets the original finance caller lose the target response,
then stops both finance processes before the historical authority opens a
read-only authenticated archive.  The original payment grant is allowed to
expire before inquiry.  Consequently the later disclosure proves only a
historical, target-signed pending synthetic intent at its original admission
time; it does not revive payment authority or establish settlement.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from alibi import Signer, canon
from examples.quorvane_education_demo import FixtureError, write_new
from examples.quorvane_finance_demo import fixture
from wolfalibi.finance_records import PENDING, digest, idempotency_key
from wolfalibi.history_authority import HistoryAuthority
from wolfalibi.history_records import inquiry_scope, issue_grant, sign_inquiry
from wolfalibi.history_settlement import (
    SYNTHETIC_SETTLED,
    sign_settlement,
    sign_source,
    verify_settlement,
)
from wolfalibi.history_verify import verify_history
from wolfalibi.stage3_evidence import _hex


_LIMITS = {
    "assurance": "SIMULATED_POLICY_ONLY",
    "cross_uid_custody": "UNSUPPORTED",
    "certification": "NOT_ISSUED",
    "confinement": "BLOCKED",
    "production": "BLOCKED",
}
_EXPIRY_WAIT_SECONDS = 10


def _private_directory(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _digest_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _copy_frozen(source, destination, expected_digest):
    """Copy one stopped archive file without following or retaining a link."""
    source, destination = Path(source), Path(destination)
    source_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    input_fd = os.open(source, source_flags)
    try:
        item = os.fstat(input_fd)
        if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
            raise FixtureError("history archive source must be an ordinary single-link file")
        output_fd = os.open(destination, target_flags, 0o400)
        try:
            os.fchmod(output_fd, 0o400)
            while True:
                block = os.read(input_fd, 65_536)
                if not block:
                    break
                offset = 0
                while offset < len(block):
                    written = os.write(output_fd, block[offset:])
                    if written <= 0:
                        raise OSError("short frozen archive write")
                    offset += written
            os.fsync(output_fd)
        finally:
            os.close(output_fd)
    finally:
        os.close(input_fd)
    copied = destination.lstat()
    if (not stat.S_ISREG(copied.st_mode) or copied.st_nlink != 1
            or stat.S_IMODE(copied.st_mode) != 0o400 or _digest_file(destination) != expected_digest):
        raise FixtureError("frozen history archive differs from the stopped payment snapshot")


def _frozen_archive(root, resource, snapshot):
    """Make a two-file same-UID local copy; it is not an independent escrow."""
    archive = _private_directory(Path(root) / "history-archive")
    ledger = archive / "ledger.sqlite"
    anchor = archive / "ledger-anchor.json"
    _copy_frozen(resource.target_state / "ledger.sqlite", ledger, snapshot["ledger_sha256"])
    _copy_frozen(resource.anchor / "ledger-anchor.json", anchor, snapshot["anchor_sha256"])
    if {entry.name for entry in archive.iterdir()} != {ledger.name, anchor.name}:
        raise FixtureError("history archive contains material beyond the ledger and signed anchor")
    return {"ledger": ledger, "anchor": anchor}


def _finance_snapshot(resource):
    """Take a read-only local snapshot after both payment processes have stopped."""
    if resource.target is not None or resource.caller is not None:
        raise FixtureError("stop the original finance processes before historical inspection")
    ledger = resource.target_state / "ledger.sqlite"
    anchor = resource.anchor / "ledger-anchor.json"
    if any(os.path.lexists(str(ledger) + suffix) for suffix in ("-journal", "-wal", "-shm")):
        raise FixtureError("the historical payment ledger is not quiescent")
    with closing(sqlite3.connect(ledger.as_uri() + "?mode=ro", uri=True, isolation_level=None)) as database:
        database.execute("PRAGMA query_only = ON")
        rows = database.execute(
            "SELECT operation_id, dispatch_digest, outcome, receipt FROM effects ORDER BY operation_id"
        ).fetchall()
    effects = [list(row[:3]) + [hashlib.sha256(row[3]).hexdigest()] for row in rows]
    return {
        "ledger_sha256": _digest_file(ledger),
        "anchor_sha256": _digest_file(anchor),
        "effects": effects,
        "intent_count": sum(effect[2] == "INTENT_RECORDED" for effect in effects),
    }


def _wait_for_expiry(expires_at):
    """Wait briefly for the initial finance grant to become unusable."""
    deadline = time.monotonic() + _EXPIRY_WAIT_SECONDS
    while int(time.time()) < expires_at:
        if time.monotonic() >= deadline:
            raise FixtureError("short original finance grant did not expire")
        time.sleep(0.02)


def _history_expectations(finance, *, history, auditor, anchor_sha256, challenge):
    return {
        "finance": json.loads(canon(finance)),
        "history_pub": history.pub.hex(),
        "auditor_pub": auditor.pub.hex(),
        "anchor_sha256": anchor_sha256,
        "challenge": challenge,
    }


def _experimental_settlement(expected, evidence, *, expectations_out=None):
    """Verify a separate signed synthetic observation; it never calls a target."""
    source, authority = Signer(), Signer()
    original = evidence["original"]
    receipt_time = original["receipt"]["payload"]["authorized_at"]
    source_record = sign_source(
        source,
        finance_receipt=original["receipt"],
        scope=expected["finance"]["scope"],
        reference="fictional-history-settlement-reference",
        settled_at=max(int(time.time()), receipt_time + 1),
        observed_outcome=SYNTHETIC_SETTLED,
    )
    settlement_record = sign_settlement(
        authority, source_record=source_record, source_pub=source.pub,
    )
    pins = {
        "source_pub": source.pub.hex(),
        "authority_pub": authority.pub.hex(),
        "expected_reference": "fictional-history-settlement-reference",
        "expected_source_sha256": digest(source_record),
    }
    settlement_evidence = {"source_record": source_record, "settlement_record": settlement_record}
    if expectations_out is not None:
        write_new(expectations_out, canon(pins) + b"\n")
    result = verify_settlement(
        source_record,
        settlement_record,
        finance_pins=expected["finance"],
        finance_evidence=original,
        source_pub=source.pub,
        authority_pub=authority.pub,
        expected_reference=pins["expected_reference"],
        expected_source_sha256=pins["expected_source_sha256"],
        history_pub=bytes.fromhex(expected["history_pub"]),
        auditor_pub=bytes.fromhex(expected["auditor_pub"]),
    )
    return result, settlement_evidence


def demo(root, *, expectations_out=None, challenge=None, experimental_settlement=False,
         settlement_expectations_out=None):
    """Run a complete synthetic historical-disclosure trial in ``root``.

    ``challenge`` belongs exclusively to the historical inquiry.  The finance
    fixture creates its own distinct run challenge so an old payment-run nonce
    cannot stand in for a fresh historical request.
    """
    if challenge is not None:
        _hex(challenge, 32, "historical controller challenge")
    if settlement_expectations_out is not None and not experimental_settlement:
        raise ValueError("settlement expectations require --experimental-settlement")
    history_challenge = secrets.token_hex(32) if challenge is None else challenge
    root = Path(root)
    finance_challenge = secrets.token_hex(32)
    while finance_challenge == history_challenge:
        finance_challenge = secrets.token_hex(32)
    with fixture(root, challenge=finance_challenge) as resource:
        # Keep the original grant short enough to demonstrate that archive
        # authentication uses the recorded admission time rather than current
        # live finance authority.
        original_start = int(time.time())
        original_end = original_start + 3
        resource.approval = resource.make_grant(start=original_start, end=original_end)
        packet = resource.invoke("sign")["packet"]
        checkpoint = resource.retained_anchor()
        lost = resource.invoke("lost-reply", packet=packet)["result"]
        if lost != {"outcome": "UNKNOWN", "response_read": False}:
            raise FixtureError("the finance caller did not complete the lost-response control")
        resource.wait_for_checkpoint_change(checkpoint)

        # A history authority must not query a live payment target or caller.
        resource.close()
        before = _finance_snapshot(resource)
        expected_effect = [
            idempotency_key(packet["scope"]), digest(packet), "INTENT_RECORDED",
        ]
        if (before["intent_count"] != 1 or len(before["effects"]) != 1
                or before["effects"][0][:3] != expected_effect):
            raise FixtureError("lost finance reply did not leave one matching committed intent")
        frozen = _frozen_archive(root, resource, before)
        if _finance_snapshot(resource) != before:
            raise FixtureError("finance state changed while its historical copy was frozen")
        finance = json.loads(canon(resource.expectations))
        anchor_sha256 = before["anchor_sha256"]
        _wait_for_expiry(original_end)

        history_state = _private_directory(root / "history-state")
        history_heads = _private_directory(root / "history-heads")
        database_path = history_state / "history.sqlite"
        head_path = history_heads / "history-head.sqlite"
        auditor, history = Signer(), Signer()
        scope = inquiry_scope(finance["scope"])
        grant_start = int(time.time())
        grant_id = "fictional-history-grant"
        grant = issue_grant(resource.owner, scope, auditor.pub, grant_id, grant_start, grant_start + 60)
        request = sign_inquiry(auditor, scope, grant, history_challenge)
        expected = _history_expectations(
            finance, history=history, auditor=auditor, anchor_sha256=anchor_sha256,
            challenge=history_challenge,
        )
        # This is intentionally before `inquire`: it represents verifier pins
        # retained outside the authority before the disclosure is requested.
        if expectations_out is not None:
            write_new(expectations_out, canon(expected) + b"\n")

        with HistoryAuthority(
            database_path, head_path,
            ledger_path=frozen["ledger"],
            anchor_path=frozen["anchor"],
            expectations=finance, anchor_sha256=anchor_sha256,
            signer=history, create=True,
        ) as authority:
            disclosed = authority.inquire(request, challenge=history_challenge)
            replayed = authority.inquire(request, challenge=history_challenge)
            revoked = authority.revoke(grant_id)
            new_challenge = secrets.token_hex(32)
            revoked_request = sign_inquiry(auditor, scope, grant, new_challenge)
            revoked_inquiry = authority.inquire(revoked_request, challenge=new_challenge)

    if disclosed.get("outcome") != "DISCLOSED" or set(disclosed) != {"outcome", "evidence"}:
        raise FixtureError("historical authority did not disclose the closed archived intent")
    if replayed != {"outcome": "DENIED", "reason": "CHALLENGE_USED"}:
        raise FixtureError("historical inquiry challenge was not single-use")
    if revoked != {"outcome": "REVOKED"}:
        raise FixtureError("history grant revocation was not retained")
    if revoked_inquiry != {"outcome": "DENIED", "reason": "HISTORY_GRANT_REVOKED"}:
        raise FixtureError("revoked history grant admitted a fresh inquiry")
    verified = verify_history(expected, disclosed["evidence"], challenge=history_challenge)
    if verified.get("outcome") != "VERIFIED" or verified.get("effect") != PENDING:
        raise FixtureError("independent historical verifier rejected the disclosed archive")
    after = _finance_snapshot(resource)
    if after != before:
        raise FixtureError("historical disclosure changed the payment ledger or anchor")
    if (_digest_file(frozen["ledger"]) != before["ledger_sha256"]
            or _digest_file(frozen["anchor"]) != before["anchor_sha256"]):
        raise FixtureError("historical authority changed the frozen local archive")

    observed = {
        "lost_response": lost,
        "original_grant_expired": int(time.time()) >= original_end,
        "historical_disclosure": disclosed["outcome"],
        "challenge_replay": replayed,
        "revocation": revoked,
        "revoked_new_inquiry": revoked_inquiry,
        "finance_snapshot_unchanged": after == before,
        "intent_count": before["intent_count"],
        "historical_verifier": verified["outcome"],
    }
    expected_observed = {
        "lost_response": {"outcome": "UNKNOWN", "response_read": False},
        "original_grant_expired": True,
        "historical_disclosure": "DISCLOSED",
        "challenge_replay": {"outcome": "DENIED", "reason": "CHALLENGE_USED"},
        "revocation": {"outcome": "REVOKED"},
        "revoked_new_inquiry": {"outcome": "DENIED", "reason": "HISTORY_GRANT_REVOKED"},
        "finance_snapshot_unchanged": True,
        "intent_count": 1,
        "historical_verifier": "VERIFIED",
    }
    if observed != expected_observed:
        raise FixtureError("historical disclosure controls did not match")
    result = {
        "schema": "QUORVANE_HISTORY_GATE_004_DEMO_V1",
        "outcome": "PASS",
        **_LIMITS,
        "expected": expected_observed,
        "observed": observed,
        "finance_anchor_sha256": anchor_sha256,
        "evidence": disclosed["evidence"],
    }
    if experimental_settlement:
        settlement, settlement_evidence = _experimental_settlement(
            expected, disclosed["evidence"], expectations_out=settlement_expectations_out,
        )
        result["experimental_settlement"] = settlement
        result["experimental_evidence"] = settlement_evidence
    else:
        result["settlement"] = "UNESTABLISHED"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations-out", type=Path,
                        help="create-only file for history verifier pins retained before inquiry")
    parser.add_argument("--challenge", help="external 32-byte lowercase hex historical inquiry challenge")
    parser.add_argument("--experimental-settlement", action="store_true",
                        help="verify a separate synthetic settlement observation; no target is contacted")
    parser.add_argument("--settlement-expectations-out", type=Path,
                        help="create-only settlement verifier pins; requires --experimental-settlement")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or not hasattr(socket, "SCM_CREDENTIALS") or not hasattr(os, "pidfd_open"):
        result = {"outcome": "UNSUPPORTED", "reason": "LINUX_PEER_AND_PIDFD_REQUIRED"}
    else:
        try:
            with TemporaryDirectory(prefix="wolfalibi-history-") as root:
                result = demo(
                    root,
                    expectations_out=args.expectations_out,
                    challenge=args.challenge,
                    experimental_settlement=args.experimental_settlement,
                    settlement_expectations_out=args.settlement_expectations_out,
                )
        except (KeyError, ValueError, OSError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
            result = {
                "outcome": "BLOCKED",
                "reason": "LOCAL_HISTORY_FIXTURE_UNAVAILABLE",
                "diagnostic": str(error) if isinstance(error, FixtureError) else type(error).__name__,
            }
    print(canon(result).decode("ascii"))
    return 0 if result["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
