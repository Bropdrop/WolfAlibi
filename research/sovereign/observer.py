"""Target-domain SQL probe and separately credentialed reconciliation service."""

import hashlib
import json
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path

from research.sovereign.cluster import read, tls
from research.sovereign.roles import serve
from research.sovereign.review import inspect
from research.sovereign.wire import Session
from shirudo_adapter.model import canonical_json

TABLES = (
    "counter",
    "commands",
    "operations",
    "settlements",
    "revoked_grants",
    "bindings",
    "recovery_acl",
)


def snapshot(command):
    if command != "snapshot":
        raise ValueError("unsupported query")
    with closing(
        sqlite3.connect("file:/volume/journal.sqlite3?mode=ro", uri=True)
    ) as c:
        c.row_factory = sqlite3.Row
        c.execute("BEGIN")
        return {
            t: [dict(r) for r in c.execute(f"SELECT * FROM {t} ORDER BY rowid")]
            for t in TABLES
        }


def audit(config):
    client = tls(Path("/reader"))
    client.endpoint = config["probe_pin"]
    client.member_pins = config["member_pins"]
    client.token = config["token"]
    with Session(config["probe_port"], client) as probe:
        journal = probe.call("snapshot")
    copies = [
        [read(port, client, i + 1) for i in range(len(journal["commands"]))]
        for port in config["members"]
    ]
    evidence = dict(
        enrollment=config["enrollment"], materials=config["materials"], oracle=journal
    )
    evidence["quorum-audit"] = copies
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        pins = {}
        for name, value in evidence.items():
            data = canonical_json(value) + b"\n"
            (root / (name + ".json")).write_bytes(data)
            pins[name] = hashlib.sha256(data).hexdigest()
        counts, _, _ = inspect(root, pins["enrollment"])
    return dict(oracle=journal, copies=copies, pins=pins, counts=counts)


if __name__ == "__main__":
    kind, caller = sys.argv[1:]
    if kind == "probe":
        if Path("/volume/signing.key").stat().st_size != 0:
            raise RuntimeError("native signing key visible")
        serve("read-only SQL probe", snapshot, caller)
    elif kind == "auditor":
        config = json.loads(sys.stdin.readline())

        def collect(command):
            if command != "reconcile":
                raise ValueError("unsupported query")
            return audit(config)

        serve("independent auditor", collect, caller)
