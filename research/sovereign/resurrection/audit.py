"""Verify historical contexts from retained enrollment, witness reservations and native journal."""

import hashlib, json, tempfile
from pathlib import Path
from research.sovereign.review import inspect
from research.sovereign.resurrection.witness import CHANGE, authorization
from research.schism.storage import demand
from shirudo_adapter.model import canonical_json, digest
from shirudo_adapter.receipt import verify_record


def chain(pin, public, records):
    installers = {}
    old = None
    for i, record in enumerate(records):
        p = verify_record(record, public)
        demand(
            p["version"] == i
            and p["parent"] == (digest(old) if old else None)
            and p["pin"] == digest(pin),
            "WITNESS_CHAIN",
        )
        if i == 0:
            demand(
                p["boot"] == pin["origin"]
                and p["auth"] is None
                and p["seal"] == pin["initial_seal"],
                "GENESIS",
            )
        else:
            req = verify_record(p["request"], p["boot"])
            auth = p["auth"]
            demand(
                req
                == dict(
                    schema=CHANGE,
                    parent=digest(old),
                    boot=p["boot"],
                    seal=p["seal"],
                    auth=digest(auth) if auth else None,
                ),
                "RESERVATION",
            )
            if old["payload"]["boot"] != p["boot"]:
                a = authorization(pin, old, auth, p["boot"])
                demand(
                    a["first"] not in installers and a["last"] >= a["first"], "CUTOVER"
                )
                installers[a["first"]] = p["boot"]
            else:
                demand(auth is None, "REPLAY")
        old = record
    demand(old is not None, "EMPTY_WITNESS")
    return installers


def history(pin, public, records, enrollment, materials, journal, commands):
    installers = chain(pin, public, records)
    demand(digest(enrollment) == pin["enrollment"], "ENROLLMENT")
    superseded = set()
    for record in records:
        auth = record["payload"]["auth"]
        if auth:
            a = auth["payload"]
            last = a["last"]
            first = a["first"]
            demand(0 < first <= last <= len(commands), "CUTOVER_RANGE")
            boundary = journal["commands"][last - 1]
            count = json.loads(boundary["acknowledgement"])["payload"]["counter"]
            for number in range(first, last):
                ack = json.loads(journal["commands"][number - 1]["acknowledgement"])[
                    "payload"
                ]
                demand(ack["counter"] == count, "ATOMIC_CUTOVER")
                if commands[number - 1]["payload"]["kind"] == "activate":
                    superseded.add(number)
            demand(
                0 < last <= len(commands)
                and digest(commands[last - 1]) == a["command"]
                and commands[last - 1]["payload"]["boot"] == a["boot"]
                and commands[last - 1]["payload"]["epoch"] == a["epoch"],
                "ACTIVATION_ORDER",
            )
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        for n, v in (
            ("enrollment", enrollment),
            ("oracle", journal),
            ("materials", materials),
            ("quorum-audit", [commands] * 3),
        ):
            (root / (n + ".json")).write_bytes(canonical_json(v) + b"\n")
        return inspect(
            root,
            hashlib.sha256((root / "enrollment.json").read_bytes()).hexdigest(),
            incarnations=installers,
            superseded=superseded,
        )
