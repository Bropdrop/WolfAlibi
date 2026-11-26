"""One independently provisioned, durable write-ahead witness for a stationary target."""

import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.sovereign.roles import serve
from research.schism.storage import demand
from shirudo_adapter.model import AdapterError, canonical_json, digest
from shirudo_adapter.receipt import sign_record, verify_record

AUTH = "wolfalibi.resurrection.activation.v1"
CHANGE = "wolfalibi.resurrection.reservation.v1"


def authorization(pin, head, auth, boot):
    a = verify_record(auth, pin["owner"])
    demand(
        set(a)
        == {
            "schema",
            "parent",
            "boot",
            "target",
            "gate",
            "volume",
            "snapshot",
            "command",
            "first",
            "last",
            "epoch",
        }
        and (a["schema"], a["parent"], a["boot"], a["target"], a["gate"], a["volume"])
        == (AUTH, digest(head), boot, pin["target"], pin["gate"], pin["volume"]),
        "ACTIVATION_BINDING",
    )
    return a


class Witness:
    def __init__(self, root, genesis):
        self.root = root
        self.pin = genesis["pin"]
        # Commissioning is exclusive. Restart of the witness itself is outside
        # this fixture; losing this store cannot trigger automatic re-enrollment.
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes_raw().hex()
        with (root / "reservations.sqlite3").open("xb"):
            pass
        with closing(self.connect()) as c:
            c.execute(
                "CREATE TABLE reservations(version INTEGER PRIMARY KEY,record TEXT NOT NULL)"
            )
            self.append(
                c,
                dict(
                    version=0,
                    parent=None,
                    boot=genesis["boot"],
                    seal=genesis["seal"],
                    pin=digest(self.pin),
                    auth=None,
                    request=None,
                ),
            )
            c.commit()

    def connect(self):
        c = sqlite3.connect(self.root / "reservations.sqlite3", isolation_level=None)
        c.execute("PRAGMA synchronous=FULL")
        return c

    def append(self, c, value):
        record = sign_record(self.key, value)
        c.execute(
            "INSERT INTO reservations VALUES(?,?)",
            (value["version"], canonical_json(record).decode()),
        )
        return record

    def handle(self, msg):
        try:
            with closing(self.connect()) as c:
                c.execute("BEGIN IMMEDIATE")
                head = json.loads(
                    c.execute(
                        "SELECT record FROM reservations ORDER BY version DESC LIMIT 1"
                    ).fetchone()[0]
                )
                if msg == "head":
                    return head
                current = head["payload"]
                req = msg["request"]
                boot = req["payload"]["boot"]
                p = verify_record(req, boot)
                demand(
                    set(p) == {"schema", "parent", "seal", "boot", "auth"}
                    and p["schema"] == CHANGE
                    and p["parent"] == digest(head),
                    "WITNESS_CAS",
                )
                auth = msg["auth"]
                if boot != current["boot"]:
                    authorization(self.pin, head, auth, boot)
                    demand(p["auth"] == digest(auth), "WITNESS_AUTH")
                else:
                    demand(auth is None and p["auth"] is None, "AUTH_REPLAY")
                record = self.append(
                    c,
                    dict(
                        version=current["version"] + 1,
                        parent=digest(head),
                        boot=boot,
                        seal=p["seal"],
                        pin=digest(self.pin),
                        auth=auth,
                        request=req,
                    ),
                )
                c.commit()
                return record
        except (AdapterError, KeyError, TypeError, ValueError) as exc:
            return {"denied": getattr(exc, "code", "INVALID_REQUEST")}


if __name__ == "__main__":
    w = Witness(Path("/store"), json.loads(sys.stdin.readline()))
    serve(w.public, w.handle, sys.argv[1])
