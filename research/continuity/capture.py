"""Trusted local observer reads the final native journal in one attached transaction."""

from contextlib import closing
import json
import sqlite3
from research.schism.storage import attach, guard
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import sign_record
from research.wt_swarm.review import require


def capture(paths, pins, destination, observer, recovery, requests):
    with closing(
        sqlite3.connect(
            paths["target"].as_uri() + "?mode=ro", uri=True, isolation_level=None
        )
    ) as c:
        c.row_factory = sqlite3.Row
        attach(c, paths, pins, "ro", "ro")
        c.execute("BEGIN")
        epoch, head, holder = guard(c, paths, pins)
        require(epoch > 0 and holder is None, "SOURCE_ACTIVE")
        journal = dict(
            metadata=dict(c.execute("SELECT key,value FROM metadata")),
            recovery=recovery,
            recovery_requests=requests,
            counter=c.execute("SELECT value FROM counter").fetchone()[0],
            rows=[dict(r) for r in c.execute("SELECT * FROM operations ORDER BY id")],
            revocations=dict(c.execute("SELECT id,revoked_at_ms FROM revoked_grants")),
            prepared=[
                list(r) for r in c.execute("SELECT * FROM schism_prepared ORDER BY op")
            ],
            clock=c.execute(
                "SELECT value FROM metadata WHERE key='last_clock'"
            ).fetchone()[0],
            policy_active=c.execute(
                "SELECT value FROM metadata WHERE key='policy_active'"
            ).fetchone()[0],
            floor=list(
                c.execute(
                    "SELECT * FROM control.checkpoints ORDER BY epoch DESC LIMIT 1"
                ).fetchone()
            ),
            seal=c.execute("SELECT hash FROM witness.anchor").fetchone()[0],
            permits={
                k: json.loads(v)
                for k, v in c.execute("SELECT op,record FROM control.permits")
            },
            events=[
                dict(seq=s, kind=k, record=json.loads(r))
                for s, k, r in c.execute(
                    "SELECT seq,kind,record FROM witness.events ORDER BY seq"
                )
            ],
        )
        att = sign_record(
            observer,
            dict(
                schema="wolfalibi.continuity.frozen.v1",
                target=pins["target"],
                destination=destination,
                journal=digest(journal),
            ),
        )
        return dict(journal=journal, checkpoint=att)
