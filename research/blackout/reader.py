"""Read-only local recovery. The provisioner supplies exact, verified request bindings."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.wt_alibi_human_oracle import APPLICATION_ID
from shirudo_adapter.action_gate import verify_effect_receipt
from shirudo_adapter.model import AdapterError, canonical_json, digest, strict_json
from shirudo_adapter.receipt import sign_record
from research.blackout.credentials import context

DENIAL = {"outcome": "UNRESOLVED", "reason": "RECOVERY_DENIED"}
LOCATOR = (
    "principal",
    "target_id",
    "gate_instance_id",
    "operation_id",
    "request_sha256",
)
UNKNOWN = {"outcome": "UNRESOLVED", "reason": "TRANSPORT"}
MAX_FRAME = 16384


def locator(binding):
    return {k: binding[k] for k in LOCATOR}


def database(path, factory=sqlite3.Connection):
    con = sqlite3.connect(
        path.as_uri() + "?mode=ro", uri=True, timeout=0.5, isolation_level=None, factory=factory
    )
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    con.execute("PRAGMA trusted_schema=OFF")
    return con


def observation(con, b, profile, guard=None):
    con.execute("BEGIN")
    try:
        if guard is not None:
            guard(con, b)
        meta = dict(con.execute("SELECT key,value FROM metadata"))
        if (
            con.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or con.execute("PRAGMA user_version").fetchone()[0] != 1
            or any(
                meta[k] != v
                for k, v in {
                    "gate_instance_id": b["gate_instance_id"],
                    "policy_sha256": digest(profile["policy"]),
                    "public_key": profile["gate_public_key"],
                }.items()
            )
        ):
            return "UNRESOLVED", "JOURNAL_IDENTITY", None, None
        counter = con.execute("""SELECT value, (SELECT COUNT(*) FROM operations WHERE status='COMMITTED')
                                 FROM counter WHERE id=1""").fetchone()
        if counter is None or counter[0] != counter[1]:
            return "UNRESOLVED", "JOURNAL_BINDING", None, None
        row = con.execute(
            """SELECT status,request_sha256,grant_id,grant_sha256,assessment_sha256,
                          receipt,document FROM operations WHERE id=?""",
            (b["operation_id"],),
        ).fetchone()
        if row is None:
            return "UNRESOLVED", "NO_ROW", None, None
        if digest(json.loads(row["document"])) != b["challenge_sha256"]:
            return "UNRESOLVED", "JOURNAL_BINDING", None, None
        if row["status"] == "COMMITTED":
            if any(
                row[k] != b[k]
                for k in (
                    "request_sha256",
                    "grant_id",
                    "grant_sha256",
                    "assessment_sha256",
                )
            ):
                return "UNRESOLVED", "JOURNAL_BINDING", None, None
            receipt = json.loads(row["receipt"])
            verify_effect_receipt(
                receipt,
                profile["gate_public_key"],
                expected_target=b["target_id"],
                expected_gate_instance_id=b["gate_instance_id"],
                expected_operation_id=b["operation_id"],
                expected_grant_id=b["grant_id"],
                expected_grant_sha256=b["grant_sha256"],
                expected_assessment_sha256=b["assessment_sha256"],
                expected_action_challenge=json.loads(row["document"]),
            )
            return "COMMITTED", "ORIGINAL_RECEIPT", receipt, None
        if row["status"] == "PREPARED" and row["receipt"] is None:
            revoked = con.execute(
                "SELECT revoked_at_ms FROM revoked_grants WHERE id=?", (b["grant_id"],)
            ).fetchone()
            if revoked and type(revoked[0]) is int and revoked[0] > 0:
                return "NOT_COMMITTED", "DURABLE_GRANT_REVOCATION", None, revoked[0]
        return "UNRESOLVED", "NO_TERMINAL_EVIDENCE", None, None
    finally:
        con.rollback()


def response(con, query, peer, config, key, guard=None):
    if not isinstance(query, dict) or set(query) != set(LOCATOR):
        return DENIAL
    if any(type(v) != str for v in query.values()):
        return DENIAL
    binding = config["bindings"].get(query["request_sha256"])
    if binding is None or binding["principal"] != peer or locator(binding) != query:
        return DENIAL
    try:
        outcome, reason, receipt, revoked_at = observation(
            con, binding, config["profile"], guard
        )
    except (sqlite3.Error, OSError, KeyError, AdapterError, TypeError, ValueError):
        outcome, reason, receipt, revoked_at = (
            "UNRESOLVED",
            "JOURNAL_UNAVAILABLE",
            None,
            None,
        )
    payload = dict(
        query,
        schema="wolfalibi.blackout.reconciliation.v1",
        authority="READ_ONLY",
        revoked_at_ms=revoked_at,
        grant_id=binding["grant_id"],
        outcome=outcome,
        reason=reason,
        receipt_sha256=digest(receipt) if receipt else None,
    )
    return {"proof": sign_record(key, payload), "receipt": receipt}


def main(connect=database, guard=None):
    cfg = json.loads(Path("/config.json").read_bytes())
    tls = context(True)
    key = Ed25519PrivateKey.generate()
    limit = threading.BoundedSemaphore(4)
    journal = Path("/journal/journal.sqlite3")

    def handle(raw):
        try:
            with (
                raw,
                tls.wrap_socket(raw, server_side=True) as peer,
                peer.makefile("rb") as stream,
            ):
                principal = hashlib.sha256(
                    peer.getpeercert(binary_form=True)
                ).hexdigest()
                expiry = ssl.cert_time_to_seconds(peer.getpeercert()["notAfter"])
                peer.sendall(b"RECOVERY-READY\n")
                with closing(connect(journal)) as con:
                    for _ in range(512):
                        body = stream.readline(MAX_FRAME + 1)
                        if (
                            not body
                            or len(body) > MAX_FRAME
                            or not body.endswith(b"\n")
                        ):
                            break
                        result = (
                            DENIAL
                            if time.time() >= expiry
                            else response(
                                con, strict_json(body, MAX_FRAME), principal, cfg, key, guard
                            )
                        )
                        peer.sendall(canonical_json(result) + b"\n")
        except ssl.SSLCertVerificationError as exc:
            print(
                json.dumps(
                    {
                        "phase": "tls_rejected",
                        "code": exc.verify_code,
                        "ns": time.monotonic_ns(),
                    }
                ),
                flush=True,
            )
        except (OSError, AdapterError, sqlite3.Error, ValueError):
            pass  # Transport loss has only the unresolved interpretation.
        finally:
            limit.release()

    with (
        socket.socket(socket.AF_UNIX) as listener,
        ThreadPoolExecutor(max_workers=4) as pool,
    ):
        path = "/endpoint/recover.sock"
        listener.bind(path)
        os.chmod(path, 0o600)
        listener.listen(8)
        print(
            json.dumps(
                {
                    "proof_key": key.public_key().public_bytes_raw().hex(),
                    "db_mount_readonly": bool(
                        os.statvfs("/journal").f_flag & os.ST_RDONLY
                    ),
                    "gate_key_visible": Path("/journal/signing.key").stat().st_size
                    != 0,
                    "native_socket_visible": Path("/endpoint/gate.sock").exists(),
                }
            ),
            flush=True,
        )
        while True:
            raw, _ = listener.accept()
            raw.settimeout(5)
            if limit.acquire(timeout=0.25):
                pool.submit(handle, raw)
            else:
                raw.close()


if __name__ == "__main__":
    main()
