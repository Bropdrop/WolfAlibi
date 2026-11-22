"""Local signed checkpoint journal. Its latest contents require separate custody."""
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from alibi import canon
from .byoa002_enrollment import digest
from .clearance_records import _sign, _verify

DOMAIN = b"quorvane/byoa002.1/checkpoint/v1"
EMPTY = digest({"effects": [], "revoked": []})


def inspect_history(records, enrollment, public_key):
    state, parent = EMPTY, "0" * 64
    consumed = set()
    if not records:
        raise ValueError("checkpoint genesis missing")
    for generation, record in enumerate(records):
        p = _verify(record, public_key, DOMAIN)
        expected = {"version": 1, "enrollment": enrollment, "generation": generation,
                    "previous": parent, "before": state}
        if (set(p) != expected.keys() | {"after", "action", "subject"} or
                canon({k: p[k] for k in expected}) != canon(expected)):
            raise ValueError("inconsistent checkpoint history")
        for field in ("subject", "after"):
            if len(bytes.fromhex(p[field])) != 32:
                raise ValueError("invalid checkpoint digest")
        if generation == 0:
            if (p["action"], p["subject"], p["after"]) != ("genesis", enrollment, EMPTY):
                raise ValueError("invalid genesis")
        elif p["action"] == "consume":
            if p["subject"] in consumed:
                raise ValueError("challenge already consumed")
            consumed.add(p["subject"])
        elif p["action"] != "revoke":
            raise ValueError("invalid checkpoint transition")
        parent, state = digest(record), p["after"]
    return {"generation": generation, "digest": parent, "state": state}


def verify_history(records, *, enrollment, public_key, expected_head):
    head = inspect_history(records, enrollment, public_key)
    if canon(head) != canon(expected_head):
        raise ValueError("history differs from retained expectations")
    return {"outcome": "PASS", "historical_head": head, "present_authority": "NOT_ISSUED"}


class Journal:
    def __init__(self, path, signer, enrollment):
        self.path = Path(path).resolve()
        self.signer = signer
        self.enrollment = digest(enrollment)
        if signer.pub.hex() != enrollment["target_pub"]:
            raise ValueError("checkpoint signer differs from enrolled target")

    def initialize(self):
        self.path.touch(mode=0o600, exist_ok=False)
        with closing(self.connect()) as db, db:
            db.execute("CREATE TABLE history (seq INTEGER PRIMARY KEY, record BLOB NOT NULL)")
            db.execute("INSERT INTO history VALUES (0, ?)", (canon(self.record(
                0, "0" * 64, EMPTY, EMPTY, "genesis", self.enrollment)),))

    def connect(self):
        return sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True)

    def record(self, generation, parent, before, after, action, subject):
        return _sign(self.signer, DOMAIN, {"version": 1, "enrollment": self.enrollment,
                     "generation": generation, "previous": parent, "before": before,
                     "after": after, "action": action, "subject": subject})

    def compare(self, before, *, transition=None):
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            records = [json.loads(raw) for raw, in db.execute("SELECT record FROM history ORDER BY seq")]
            head = inspect_history(records, self.enrollment, self.signer.pub)
            if head["state"] != before:
                raise ValueError("current custody reference disagrees with target")
            if transition:
                after, action, subject = transition
                record = self.record(len(records), head["digest"], before, after, action, subject)
                inspect_history([*records, record], self.enrollment, self.signer.pub)
                db.execute("INSERT INTO history VALUES (?, ?)", (len(records), canon(record)))
            return head
