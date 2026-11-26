"""Single-host fencing. Three durable files on one local SQLite rollback-journal filesystem."""

from contextlib import contextmanager, closing
import hashlib
import json
from pathlib import Path
import sqlite3

from shirudo_adapter.action_gate import Gate, _GateConnection
from shirudo_adapter.model import (
    AdapterError,
    canonical_json,
    digest,
    exact_keys,
    fail,
    require_hex,
)
from shirudo_adapter.receipt import sign_record, verify_record

SCHEMA = "wolfalibi.schism.fenced-state.v1"
TRANSITION = "wolfalibi.schism.transition.v1"
FENCE = "wolfalibi.exodus.source-fence.v1"
PERMIT = "wolfalibi.schism.permit.v1"
STAMP = "wolfalibi.schism.effect.v1"
ZERO = "0" * 64


def demand(test, reason):
    if not test:
        fail(reason, "Disposable authority boundary denied the operation")


def inode(path):
    try:
        s = path.stat()
    except OSError as exc:
        raise AdapterError(
            "CHECKPOINT_UNAVAILABLE", "Required canonical storage is unavailable"
        ) from exc
    return [s.st_dev, s.st_ino]


def check_paths(paths, pins):
    for k, path in paths.items():
        demand(
            inode(path) == pins["files"][k],
            "TARGET_CLONE" if k == "target" else "CHECKPOINT_IDENTITY",
        )


def attach(con, paths, pins, control_mode="ro", seal_mode="rw"):
    check_paths(paths, pins)
    demand(
        con.execute("PRAGMA main.journal_mode").fetchone()[0] == "delete",
        "STORAGE_MODE",
    )
    demand(con.execute("PRAGMA main.synchronous").fetchone()[0] >= 2, "STORAGE_MODE")
    for name, mode in (("control", control_mode), ("witness", seal_mode)):
        con.execute(
            f"ATTACH DATABASE ? AS {name}", (paths[name].as_uri() + "?mode=" + mode,)
        )
        demand(
            con.execute(f"PRAGMA {name}.journal_mode").fetchone()[0] == "delete",
            "STORAGE_MODE",
        )
        con.execute(f"PRAGMA {name}.synchronous=FULL")


def stable_digest(con):
    h = hashlib.sha256()
    for table, order in (
        ("metadata", "key"),
        ("counter", "id"),
        ("operations", "id"),
        ("revoked_grants", "id"),
        ("schism_head", "id"),
        ("schism_prepared", "op"),
    ):
        h.update(table.encode() + b"\n")
        # Fold the final monotonic clock into the seal after this full scan.
        where = "WHERE key != 'last_clock'" if table == "metadata" else ""
        for row in con.execute(f"SELECT * FROM main.{table} {where} ORDER BY {order}"):
            h.update(canonical_json(list(row)) + b"\n")
    return h.hexdigest()


def logical_digest(con, stable=None):
    clock = con.execute(
        "SELECT value FROM main.metadata WHERE key='last_clock'"
    ).fetchone()[0]
    return digest([stable if stable is not None else stable_digest(con), clock])


def seal(con, stable=None):
    value = logical_digest(con, stable)
    con.execute("UPDATE main.schism_tag SET hash=? WHERE id=1", (value,))
    con.execute("UPDATE witness.anchor SET hash=? WHERE id=1", (value,))


def check_fence(payload, pins):
    exact_keys(
        payload,
        {
            "schema",
            "epoch",
            "gate",
            "target",
            "previous",
            "executor",
            "destination",
            "authorization",
        },
        "source retirement",
    )
    authorizer = pins.get("migration_authorizer")
    demand(
        authorizer and authorizer not in [pins["issuer"], *pins["executors"]],
        "MIGRATION_AUTHORITY",
    )
    destination = require_hex(
        payload["destination"], 64, "destination enrollment digest"
    )
    expected = dict(
        schema="wolfalibi.exodus.retire-authority.v1",
        gate=pins["gate"],
        target=pins["target"],
        epoch=payload["epoch"],
        previous=payload["previous"],
        destination=destination,
    )
    demand(
        payload["executor"] is None
        and verify_record(payload["authorization"], authorizer) == expected,
        "MIGRATION_BINDING",
    )


def control_head(con, pins):
    row = con.execute(
        "SELECT epoch,record FROM control.transitions ORDER BY epoch DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return 0, ZERO, None
    record = json.loads(row[1])
    p = verify_record(record, pins["issuer"])
    retiring = p["schema"] == FENCE
    if retiring:
        check_fence(p, pins)
    demand(
        (retiring or p["schema"] == TRANSITION)
        and p["epoch"] == row[0]
        and p["gate"] == pins["gate"]
        and p["target"] == pins["target"]
        and (retiring or p["executor"] in pins["executors"]),
        "TRANSITION_BINDING",
    )
    floor = con.execute(
        "SELECT epoch,head FROM control.checkpoints ORDER BY epoch DESC LIMIT 1"
    ).fetchone()
    demand(
        floor is not None and tuple(floor) == (row[0], digest(record)),
        "CHECKPOINT_FLOOR",
    )
    return row[0], digest(record), p["executor"]


def guard(con, paths, pins, full=True):
    check_paths(paths, pins)
    epoch, head, executor = control_head(con, pins)
    local = tuple(
        con.execute("SELECT epoch,head FROM main.schism_head WHERE id=1").fetchone()
    )
    local_tag = con.execute("SELECT hash FROM main.schism_tag WHERE id=1").fetchone()[0]
    checkpoint = con.execute("SELECT hash FROM witness.anchor WHERE id=1").fetchone()[0]
    demand(
        local == (epoch, head)
        and local_tag == checkpoint
        and (not full or logical_digest(con) == checkpoint),
        "ROLLBACK_DETECTED",
    )
    return epoch, head, executor


def append(con, kind, record):
    con.execute(
        "INSERT INTO witness.events(kind,record,operation) VALUES (?,?,?)",
        (kind, canonical_json(record).decode(), record["payload"].get("op")),
    )


def provision(state, external, issuer, executors, profile):
    paths = {
        "target": state / "journal.sqlite3",
        "control": external / "authority" / "authority.db",
        "witness": external / "checkpoint" / "seal.db",
    }
    for p in (paths["control"], paths["witness"]):
        p.parent.mkdir(mode=0o700)
        p.touch(mode=0o600, exist_ok=False)
    pins = dict(
        files={k: inode(v) for k, v in paths.items()},
        issuer=issuer,
        executors=executors,
        gate=profile["gate_instance_id"],
        target=profile["target_id"],
    )
    demand(len({p.stat().st_dev for p in paths.values()}) == 1, "STORAGE_FILESYSTEM")
    with closing(
        sqlite3.connect(
            paths["target"].as_uri() + "?mode=rw", uri=True, isolation_level=None
        )
    ) as c:
        attach(c, paths, pins, "rw")
        c.execute("BEGIN IMMEDIATE")
        demand(
            c.execute("SELECT count(*) FROM operations").fetchone()[0] == 0,
            "PROVISION_EMPTY",
        )
        for ddl in (
            "CREATE TABLE main.schism_head(id INTEGER PRIMARY KEY,epoch INTEGER,head TEXT)",
            "CREATE TABLE main.schism_prepared(op TEXT PRIMARY KEY,epoch INTEGER,head TEXT)",
            "CREATE TABLE main.schism_tag(id INTEGER PRIMARY KEY,hash TEXT)",
            "CREATE TABLE control.transitions(epoch INTEGER PRIMARY KEY,record TEXT)",
            "CREATE TABLE control.permits(op TEXT PRIMARY KEY,record TEXT)",
            "CREATE TABLE control.checkpoints(epoch INTEGER PRIMARY KEY, head TEXT, state_hash TEXT)",
            "CREATE TABLE witness.anchor(id INTEGER PRIMARY KEY,hash TEXT)",
            "CREATE TABLE witness.events(seq INTEGER PRIMARY KEY,kind TEXT,record TEXT,operation TEXT UNIQUE)",
        ):
            c.execute(ddl)
        c.execute("INSERT INTO main.schism_head VALUES(1,0,?)", (ZERO,))
        c.execute("INSERT INTO main.schism_tag VALUES(1,'')")
        c.execute("INSERT INTO witness.anchor VALUES(1,'')")
        seal(c)
        c.commit()
    # Provision before exposing a socket. The inherited gate rejects this state schema.
    identity = state / "state.json"
    doc = json.loads(identity.read_bytes())
    doc["schema"] = SCHEMA
    identity.write_bytes(canonical_json(doc))
    return paths, pins


def administer(paths, pins, record, barrier=None, on_begin=None):
    p = verify_record(record, pins["issuer"])
    demand(
        p.get("gate") == pins["gate"] and p.get("target") == pins["target"],
        "TRANSITION_BINDING",
    )
    with closing(
        sqlite3.connect(
            paths["target"].as_uri() + "?mode=rw",
            uri=True,
            isolation_level=None,
            timeout=8,
        )
    ) as c:
        attach(c, paths, pins, "rw")
        if on_begin:
            c.set_trace_callback(
                lambda sql: on_begin() if sql == "BEGIN IMMEDIATE" else None
            )
        c.execute("BEGIN IMMEDIATE")
        epoch, head, current = guard(c, paths, pins)
        demand(epoch == 0 or current is not None, "SOURCE_FENCED")
        if p.get("schema") in (TRANSITION, FENCE):
            if p["schema"] == FENCE:
                demand(epoch > 0, "SOURCE_INACTIVE")
                check_fence(p, pins)
            else:
                exact_keys(
                    p,
                    {"schema", "gate", "target", "epoch", "previous", "executor"},
                    "transition",
                )
                demand(p["executor"] in pins["executors"], "UNKNOWN_EXECUTOR")
            demand(
                type(p["epoch"]) is int
                and p["epoch"] == epoch + 1
                and p["previous"] == head,
                "EPOCH_CAS",
            )
            c.execute(
                "INSERT INTO control.transitions VALUES(?,?)",
                (p["epoch"], canonical_json(record).decode()),
            )
            c.execute(
                "UPDATE main.schism_head SET epoch=?,head=? WHERE id=1",
                (p["epoch"], digest(record)),
            )
            append(c, "transition", record)
            c.execute(
                "INSERT INTO control.checkpoints VALUES (?,?,?)",
                (p["epoch"], digest(record), logical_digest(c)),
            )
        else:
            exact_keys(
                p,
                {
                    "schema",
                    "gate",
                    "target",
                    "epoch",
                    "head",
                    "executor",
                    "op",
                    "request",
                    "grant",
                },
                "permit",
            )
            demand(
                p["schema"] == PERMIT
                and (p["epoch"], p["head"], p["executor"]) == (epoch, head, current),
                "STALE_EPOCH",
            )
            demand(type(p["epoch"]) is int, "PERMIT_EPOCH")
            for field, size in (("op", 32), ("request", 64), ("grant", 64)):
                require_hex(p[field], size, field)
            prepared = c.execute(
                "SELECT epoch,head FROM main.schism_prepared WHERE op=?", (p["op"],)
            ).fetchone()
            demand(prepared == (epoch, head), "CROSS_EPOCH_GRANT")
            demand(
                not c.execute(
                    "SELECT 1 FROM control.permits WHERE op=?", (p["op"],)
                ).fetchone(),
                "PERMIT_SPENT",
            )
            c.execute(
                "INSERT INTO control.permits VALUES(?,?)",
                (p["op"], canonical_json(record).decode()),
            )
        seal(c)
        if barrier:
            barrier()
        check_paths(paths, pins)
        c.commit()
    return {"status": "APPLIED", "record": digest(record)}


class SealedConnection(_GateConnection):
    def commit(self):
        check_paths(self.paths, self.pins)
        stable = stable_digest(self)
        if getattr(self, "final_check", None) is not None:
            check = self.final_check
            self.final_check = None
            check()
        seal(self, stable)
        check_paths(self.paths, self.pins)
        return super().commit()


class FencedGate(Gate):
    state_schema = SCHEMA
    connection_factory = SealedConnection

    def __init__(self, state, paths, pins, key):
        self.paths, self.pins, self.executor = (
            dict(paths, target=Path(state) / "journal.sqlite3"),
            pins,
            key,
        )
        self.public = key.public_key().public_bytes_raw().hex()
        super().__init__(state)

    @contextmanager
    def _connection(self):
        with super()._connection() as c:
            c.paths, c.pins = self.paths, self.pins
            attach(c, self.paths, self.pins)
            yield c

    def _check_database(self, c):
        guard(c, self.paths, self.pins)
        super()._check_database(c)

    def _begin(self, c):
        c.execute("BEGIN IMMEDIATE")
        self._check_database(c)
        demand(control_head(c, self.pins)[2] == self.public, "STALE_EXECUTOR")
        return self._tick(c)

    def _commit_prepared(self, c, action):
        epoch, head, executor = control_head(c, self.pins)
        demand(executor == self.public, "STALE_EXECUTOR")
        c.execute(
            "INSERT INTO main.schism_prepared VALUES(?,?,?)",
            (action["payload"]["operation_id"], epoch, head),
        )
        c.commit()

    def _commit_effect(self, c, request, receipt):
        # Native validation and the counter/receipt writes already ran. Both
        # writers must acquire the canonical SQLite transaction before acting.
        check_paths(self.paths, self.pins)
        epoch, head, executor = control_head(c, self.pins)
        demand(executor == self.public, "STALE_EXECUTOR")
        op = request["operation_id"]
        prepared = c.execute(
            "SELECT epoch,head FROM main.schism_prepared WHERE op=?", (op,)
        ).fetchone()
        demand(
            prepared is not None and tuple(prepared) == (epoch, head),
            "CROSS_EPOCH_GRANT",
        )
        row = c.execute(
            "SELECT record FROM control.permits WHERE op=?", (op,)
        ).fetchone()
        demand(row is not None, "EPOCH_PERMIT_REQUIRED")
        permit = json.loads(row[0])
        p = verify_record(permit, self.pins["issuer"])
        expected = dict(
            schema=PERMIT,
            epoch=epoch,
            head=head,
            executor=executor,
            op=op,
            gate=self.instance_id,
            target=self.pins["target"],
            request=digest(request),
            grant=digest(request["grant"]),
        )
        demand(canonical_json(p) == canonical_json(expected), "EPOCH_PERMIT_BINDING")
        endorsement = sign_record(
            self.executor,
            dict(
                expected, schema=STAMP, receipt=digest(receipt), permit=digest(permit)
            ),
        )
        append(c, "effect", endorsement)
        # Recheck native lifetime after any trusted precommit rendezvous.
        row = self._row(c, op)
        action = json.loads(row["document"])["payload"]
        attestation = json.loads(row["attestation_document"])["payload"]

        def final_check():
            now = self._tick(c)
            self._execution_times(
                action,
                attestation,
                request["assessment"]["payload"],
                request["grant"]["payload"],
                now,
            )

        c.final_check = final_check
        c.commit()

    def status(self, operation_id=None):
        demand(operation_id is None, "RECOVERY_AUTH_REQUIRED")
        return super().status()
