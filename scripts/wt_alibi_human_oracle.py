#!/usr/bin/env python3
"""Project the disposable gate's SQLite journal through a read-only connection.

This program also runs as a fixed guest-side command under the trusted lab
administrator. It reads only the selected journal and exports public fields.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import time

SCHEMA = "wolfalibi.shirudo.counter-observation.v1"
LIMIT = 128
APPLICATION_ID = 0x57414731
MAX_RECEIPT_BYTES = 16_384


def observe(journal):
    journal = Path(journal)
    if not journal.is_absolute() or journal.is_symlink() or journal.name != "journal.sqlite3":
        raise ValueError("Expected the approved absolute SQLite journal path")
    with closing(sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True,
                                 timeout=2, isolation_level=None)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN")
        observed_at_ms = time.time_ns() // 1_000_000
        if (connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID or
                connection.execute("PRAGMA user_version").fetchone()[0] != 1):
            raise ValueError("Unexpected action gate journal schema")
        identity = dict(connection.execute(
            "SELECT key,value FROM metadata WHERE key IN ('gate_instance_id','policy_sha256','public_key')"))
        if set(identity) != {"gate_instance_id", "policy_sha256", "public_key"}:
            raise ValueError("Incomplete action gate journal identity")
        counters = connection.execute("SELECT id,value FROM counter LIMIT 2").fetchall()
        if len(counters) != 1 or counters[0]["id"] != 1:
            raise ValueError("Invalid action gate counter")
        counter = counters[0]["value"]
        if type(counter) is not int or not 0 <= counter <= LIMIT:
            raise ValueError("Disposable counter exceeds the observation bound")
        # Check cardinality separately so LIMIT cannot silently hide effects.
        committed = connection.execute(
            "SELECT COUNT(*) FROM operations WHERE status='COMMITTED'").fetchone()[0]
        if counter != committed:
            raise ValueError("Counter disagrees with committed journal rows")
        rows = connection.execute(
            """SELECT id AS operation_id, request_sha256, grant_id, grant_sha256,
               assessment_sha256, counter_before, counter_after,
               CASE WHEN length(receipt) <= ? THEN receipt END AS receipt
               FROM operations WHERE status='COMMITTED' ORDER BY counter_after LIMIT ?""",
            (MAX_RECEIPT_BYTES, LIMIT + 1)).fetchall()
        ledger = []
        for row in rows:
            item = dict(row)
            if type(item["receipt"]) is not str:
                raise ValueError("Missing or oversized committed receipt")
            item["receipt"] = json.loads(item["receipt"])
            ledger.append(item)
        if len(ledger) != counter:
            raise ValueError("Incomplete action gate observation")
        return {"schema": SCHEMA, **identity, "observed_at_ms": observed_at_ms,
                "counter": counter, "committed_operations": committed, "ledger": ledger}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("journal", type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(observe(args.journal), sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (OSError, ValueError, sqlite3.Error, RecursionError):
        print('{"status":"BLOCKED","reason":"JOURNAL_OBSERVATION"}')
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
