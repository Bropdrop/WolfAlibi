"""Single-host import into a provisioned, unopened native counter."""

from contextlib import closing
import sqlite3
from research.continuity.history import HistoricalDecoder, verify
from research.schism.storage import (
    FencedGate,
    TRANSITION,
    ZERO,
    attach,
    guard,
    check_paths,
    seal,
    append,
    logical_digest,
    demand,
)
from shirudo_adapter.model import canonical_json, digest
from shirudo_adapter.receipt import verify_record


def activate(paths, pins, roots, package, transition, source_paths, before_commit=None):
    """The caller is the enrolled control custodian with write access to control and witness."""
    verified = verify(roots, package)
    data = package["journal"]
    epoch, prior, _ = data["floor"]
    expected = dict(
        schema=TRANSITION,
        epoch=epoch + 1,
        previous=prior,
        gate=pins["gate"],
        target=pins["target"],
        executor=pins["executors"][0],
    )
    demand(
        roots["destination"] == digest(pins)
        and roots["source"]["target"] == pins["target"],
        "DESTINATION_BINDING",
    )
    demand(verify_record(transition, pins["issuer"]) == expected, "ACTIVATION_BINDING")
    with closing(
        sqlite3.connect(
            paths["target"].as_uri() + "?mode=rw", uri=True, isolation_level=None
        )
    ) as c:
        attach(c, paths, pins, "rw")
        source_pins = roots["source"]
        check_paths(source_paths, source_pins)
        for name, mode in (("control", "rw"), ("witness", "ro")):
            c.execute(
                f"ATTACH DATABASE ? AS retired_{name}",
                (source_paths[name].as_uri() + "?mode=" + mode,),
            )
            demand(
                c.execute(f"PRAGMA retired_{name}.journal_mode").fetchone()[0]
                == "delete",
                "STORAGE_MODE",
            )
            c.execute(f"PRAGMA retired_{name}.synchronous=FULL")
        demand(
            paths["target"].stat().st_dev == source_paths["control"].stat().st_dev,
            "STORAGE_FILESYSTEM",
        )
        c.execute("BEGIN IMMEDIATE")
        floor = c.execute(
            "SELECT epoch,head,state_hash FROM retired_control.checkpoints ORDER BY epoch DESC LIMIT 1"
        ).fetchone()
        demand(
            list(floor) == data["floor"]
            and c.execute("SELECT hash FROM retired_witness.anchor").fetchone()[0]
            == data["seal"],
            "RETIREMENT_CHECKPOINT",
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS retired_control.relocations(head TEXT PRIMARY KEY, destination TEXT NOT NULL)"
        )

        demand(
            guard(c, paths, pins) == (0, ZERO, None)
            and not c.execute("SELECT 1 FROM operations").fetchone(),
            "ALREADY_ACTIVATED",
        )
        c.execute(
            "INSERT INTO retired_control.relocations VALUES(?,?)", (prior, digest(pins))
        )
        cols = [r[1] for r in c.execute("PRAGMA table_info(operations)")]
        for row in data["rows"]:
            demand(set(row) == set(cols), "ROW_SCHEMA")
            c.execute(
                "INSERT INTO operations VALUES(" + ",".join("?" for _ in cols) + ")",
                [row[k] for k in cols],
            )
        demand(data["policy_active"] == "1", "RETIRED_POLICY")
        c.executemany(
            "INSERT INTO revoked_grants VALUES(?,?)", data["revocations"].items()
        )
        c.executemany("INSERT INTO schism_prepared VALUES(?,?,?)", data["prepared"])
        c.execute("UPDATE counter SET value=?", (len(verified),))
        c.execute(
            "UPDATE metadata SET value=CAST(MAX(CAST(value AS INTEGER),?) AS TEXT) WHERE key='last_clock'",
            (int(data["clock"]),),
        )
        c.execute("CREATE TABLE control.imported(checkpoint TEXT NOT NULL)")
        c.execute(
            "INSERT INTO control.imported VALUES(?)", (roots["checkpoint_sha256"],)
        )
        head = digest(transition)
        c.execute(
            "INSERT INTO control.transitions VALUES(?,?)",
            (epoch + 1, canonical_json(transition).decode()),
        )
        c.execute("UPDATE schism_head SET epoch=?,head=?", (epoch + 1, head))
        append(c, "transition", transition)
        c.execute(
            "INSERT INTO control.checkpoints VALUES (?,?,?)",
            (epoch + 1, head, logical_digest(c)),
        )
        seal(c)
        if before_commit:
            before_commit()
        check_paths(paths, pins)
        check_paths(source_paths, source_pins)
        c.commit()


class DestinationGate(FencedGate):
    state_schema = "wolfalibi.continuity.state.v1"

    def __init__(self, state, paths, pins, key, roots, package):
        self.historical = verify(roots, package)
        demand(roots["destination"] == digest(pins), "DESTINATION_BINDING")
        self.rows = {row["id"]: dict(row) for row in package["journal"]["rows"]}
        self.decoders = {}
        context, segment = roots, package
        while True:
            decoder = HistoricalDecoder(context["enrollment"])
            self.decoders.update({r["id"]: decoder for r in segment["journal"]["rows"]})
            if "parent" not in context:
                break
            context, segment = context["parent"], segment["parent"]
        self.checkpoint = roots["checkpoint_sha256"]
        super().__init__(state, paths, pins, key)

    def _check_database(self, c):
        anchor = c.execute("SELECT checkpoint FROM control.imported").fetchall()
        demand(
            len(anchor) == 1 and anchor[0][0] == self.checkpoint, "IMPORT_CHECKPOINT"
        )
        super()._check_database(c)

    def _decode_operation(self, row):
        if row["id"] in self.rows:
            demand(dict(row) == self.rows[row["id"]], "HISTORICAL_ROW")
            return self.decoders[row["id"]].decode(row)
        return super()._decode_operation(row)

    def execute(self, request):
        if isinstance(request, dict):
            demand(request.get("operation_id") not in self.rows, "HISTORICAL_READ_ONLY")
        return super().execute(request)
