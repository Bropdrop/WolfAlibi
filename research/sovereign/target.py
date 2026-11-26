"""Stationary native counter. Effective authority and settlement share only the target's local writer."""

from contextlib import contextmanager, closing
import hashlib, json, sqlite3, threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shirudo_adapter.action_gate import Gate, _GateConnection
from shirudo_adapter.model import canonical_json, digest, AdapterError
from shirudo_adapter.receipt import verify_record, sign_record
from research.schism.storage import demand, ZERO
from research.sovereign.cluster import read

SCHEMA = "wolfalibi.sovereign.stationary.v1"


def stable(c):
    h = hashlib.sha256()
    for table, order in (
        ("metadata", "key"),
        ("counter", "id"),
        ("operations", "id"),
        ("revoked_grants", "id"),
        ("commands", "idx"),
        ("bindings", "op"),
        ("recovery_acl", "op"),
        ("settlements", "seq"),
    ):
        h.update(table.encode() + b"\n")
        where = "WHERE key != 'last_clock'" if table == "metadata" else ""
        for row in c.execute(f"SELECT * FROM {table} {where} ORDER BY {order}"):
            h.update(canonical_json(list(row)) + b"\n")
    return h.hexdigest()


def seal(c, body=None):
    clock = c.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()[0]
    return digest([body or stable(c), clock])


class TargetConnection(_GateConnection):
    def commit(self):
        body = stable(self)
        check = getattr(self, "final_check", None)
        self.final_check = None
        if check:
            check()
        current = seal(self, body)
        super().commit()
        self.target.floor = current


class Stationary(Gate):
    state_schema = SCHEMA
    connection_factory = TargetConnection

    def __init__(self, state, config, client):
        self.config = config
        self.client = client
        self.lock = threading.RLock()
        self.context = threading.local()
        self.boot_key = Ed25519PrivateKey.generate()
        self.boot = self.boot_key.public_key().public_bytes_raw().hex()
        # Dedicated bootstrap, no path for an already-used target to elect itself.
        identity = state / "state.json"
        meta = json.loads(identity.read_bytes())
        demand(
            meta["schema"] == "wolfalibi.shirudo.action-state.v1",
            "TARGET_RESTART_UNRESOLVED",
        )
        with closing(
            sqlite3.connect(
                (state / "journal.sqlite3").as_uri() + "?mode=rw",
                uri=True,
                isolation_level=None,
            )
        ) as c:
            c.execute("PRAGMA synchronous=FULL")
            demand(
                c.execute("PRAGMA journal_mode").fetchone()[0] == "delete",
                "STORAGE_MODE",
            )
            c.execute("BEGIN IMMEDIATE")
            demand(
                c.execute("SELECT COUNT(*) FROM operations").fetchone()[0] == 0,
                "NONEMPTY_BOOT",
            )
            c.execute(
                "CREATE TABLE commands(idx INTEGER PRIMARY KEY, command TEXT UNIQUE, acknowledgement TEXT)"
            )
            c.execute(
                "CREATE TABLE bindings(op TEXT PRIMARY KEY,epoch INTEGER,head TEXT)"
            )
            c.execute(
                "CREATE TABLE recovery_acl(op TEXT PRIMARY KEY, binding TEXT NOT NULL)"
            )
            c.execute(
                "CREATE TABLE settlements(seq INTEGER PRIMARY KEY,op TEXT UNIQUE,endorsement TEXT,permit TEXT,sender TEXT)"
            )
            c.commit()
            self.floor = seal(c)
        identity.write_bytes(canonical_json(dict(meta, schema=SCHEMA)))
        super().__init__(state)

    @contextmanager
    def _connection(self):
        with self.lock, super()._connection() as c:
            c.target = self
            yield c

    def _check_database(self, c):
        demand(seal(c) == self.floor, "TARGET_ROLLBACK")
        super()._check_database(c)

    def head(self, c):
        row = c.execute(
            "SELECT idx,command FROM commands ORDER BY idx DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return 0, ZERO, 0, None
        doc = json.loads(row[1])
        return row[0], digest(doc), doc["payload"]["epoch"], doc["payload"]["holder"]

    def ordered(self, idx):
        for port in self.config["members"]:
            try:
                return read(port, self.client, idx, 0.55)
            except (OSError, RuntimeError, ValueError):
                continue
        raise AdapterError("QUORUM_UNAVAILABLE", "No linearizable directory response")

    def synchronize(self):
        # No distributed transaction. This read fetches a proposed command.
        # The following local transaction decides whether it becomes effective.
        with self._connection() as c:
            c.execute("BEGIN")
            idx, prev, _, _ = self.head(c)
            c.rollback()
        if idx:
            prior = self.ordered(idx)
            demand(prior is not None and digest(prior) == prev, "AUTHORITY_FLOOR")
        command = self.ordered(idx + 1)
        if command is None:
            return {"state": "CURRENT"}
        p = verify_record(command, self._trust["owner_public_key"])
        with self._connection() as c:
            self._begin(c)
            idx, prev, epoch, holder = self.head(c)
            demand(
                p["schema"] == "wolfalibi.sovereign.order.v1"
                and (p["index"], p["previous"]) == (idx + 1, prev)
                and (p["target"], p["gate"], p["boot"])
                == (self._trust["target_id"], self.instance_id, self.boot),
                "COMMAND_BINDING",
            )
            demand(
                set(p)
                == {
                    "schema",
                    "index",
                    "epoch",
                    "target",
                    "gate",
                    "boot",
                    "kind",
                    "holder",
                    "revoked",
                    "previous",
                }
                and type(p["index"]) is int
                and type(p["epoch"]) is int,
                "COMMAND_FIELDS",
            )
            if p["kind"] == "activate":
                demand(
                    p["epoch"] == epoch + 1
                    and p["holder"] in self.config["holders"]
                    and p["revoked"] is None,
                    "SUCCESSION",
                )
            else:
                demand(
                    p["kind"] == "revoke"
                    and holder is not None
                    and p["epoch"] == epoch
                    and p["holder"] == holder
                    and isinstance(p["revoked"], str)
                    and len(p["revoked"]) == 32,
                    "REVOCATION",
                )
                c.execute(
                    "INSERT OR IGNORE INTO revoked_grants VALUES(?,?)",
                    (p["revoked"], c.observed_clock),
                )
            ack = sign_record(
                self.boot_key,
                dict(
                    schema="wolfalibi.sovereign.installed.v1",
                    order=digest(command),
                    epoch=p["epoch"],
                    index=p["index"],
                    counter=c.execute("SELECT value FROM counter").fetchone()[0],
                    target=p["target"],
                ),
            )
            c.execute(
                "INSERT INTO commands VALUES(?,?,?)",
                (
                    idx + 1,
                    canonical_json(command).decode(),
                    canonical_json(ack).decode(),
                ),
            )
            c.commit()
        return {"state": "APPLIED", "ack": ack}

    def _commit_prepared(self, c, action):
        idx, head, epoch, holder = self.head(c)
        demand(holder is not None, "NO_HOLDER")
        c.execute(
            "INSERT INTO bindings VALUES(?,?,?)",
            (action["payload"]["operation_id"], epoch, head),
        )
        c.commit()

    def _begin(self, c):
        now = super()._begin(c)
        frame = getattr(self.context, "frame", None)
        if frame is not None:
            self.validate(c, *frame)
        return now

    def validate(self, c, req, permit, sender, peer):
        _, head, epoch, holder = self.head(c)
        demand(holder and peer == self.config["holders"][holder], "STALE_EXECUTOR")
        b = c.execute(
            "SELECT epoch,head FROM bindings WHERE op=?", (req["operation_id"],)
        ).fetchone()
        demand(b is not None and tuple(b) == (epoch, head), "STALE_GRANT")
        expected = dict(
            schema="wolfalibi.sovereign.permit.v1",
            epoch=epoch,
            head=head,
            holder=holder,
            boot=self.boot,
            target=self._trust["target_id"],
            gate=self.instance_id,
            op=req["operation_id"],
            request=digest(req),
            grant=digest(req["grant"]),
        )
        demand(
            verify_record(permit, self._trust["owner_public_key"]) == expected,
            "PERMIT_BINDING",
        )
        demand(
            verify_record(sender, holder)
            == dict(
                schema="wolfalibi.sovereign.submit.v1",
                permit=digest(permit),
                request=digest(req),
            ),
            "HOLDER_PROOF",
        )
        return expected

    def submit(self, frame, peer):
        require_current = self.synchronize()
        demand(require_current["state"] == "CURRENT", "AUTHORITY_CHANGED_RETRY")
        req, permit, sender = (frame[k] for k in ("request", "permit", "sender"))
        self.context.frame = (req, permit, sender, peer)
        try:
            return super().execute(req)
        finally:
            self.context.frame = None

    def execute(self, request):
        raise AdapterError("HOLDER_PROOF_REQUIRED", "Use authenticated submission")

    def _commit_effect(self, c, request, receipt):
        frame = self.context.frame
        p = self.validate(c, *frame)
        row = self._row(c, p["op"])
        attestation = json.loads(row["attestation_document"])["payload"]
        action = json.loads(row["document"])["payload"]
        stamp = sign_record(
            self.boot_key,
            dict(
                p,
                schema="wolfalibi.sovereign.effect.v1",
                receipt=digest(receipt),
                permit=digest(frame[1]),
            ),
        )
        c.execute(
            "INSERT INTO settlements VALUES(?,?,?,?,?)",
            (
                receipt["payload"]["counter_after"],
                p["op"],
                canonical_json(stamp).decode(),
                canonical_json(frame[1]).decode(),
                canonical_json(frame[2]).decode(),
            ),
        )
        c.final_check = lambda: self._execution_times(
            action,
            attestation,
            request["assessment"]["payload"],
            request["grant"]["payload"],
            self._tick(c),
        )
        c.commit()

    def enroll(self, frame, b):
        req = frame["request"]
        p = verify_record(b, self._trust["owner_public_key"])
        with self._connection() as c:
            now = self._begin(c)
            holder = self.head(c)[3]
            self.validate(
                c, req, frame["permit"], frame["sender"], self.config["holders"][holder]
            )
            row = self._row(c, req["operation_id"])
            action = json.loads(row["document"])
            att = self._attestation(json.loads(row["attestation_document"]))
            self._assessment(req["assessment"], action["payload"], att)
            grant = self._grant(req["grant"], action, req["assessment"])
            self._execution_times(
                action["payload"], att, req["assessment"]["payload"], grant, now
            )
            demand(
                p
                == dict(
                    schema="wolfalibi.sovereign.recover.v1",
                    principal=self.config["principal"],
                    target=self._trust["target_id"],
                    gate=self.instance_id,
                    boot=self.boot,
                    op=req["operation_id"],
                    request=digest(req),
                    grant=grant["grant_id"],
                ),
                "RECOVERY_BINDING",
            )
            c.execute(
                "INSERT INTO recovery_acl VALUES(?,?)",
                (req["operation_id"], canonical_json(b).decode()),
            )
            c.commit()
        return {"state": "ENROLLED"}

    def recovery_boot(self, signed_boot):
        return signed_boot == self.boot

    def recover(self, b, peer):
        # ACL is provisioned with the frozen request via independently signed enrollment.
        grant = verify_record(b, self._trust["owner_public_key"])
        if (
            grant.get("schema") != "wolfalibi.sovereign.recover.v1"
            or grant["principal"] != peer
            or (grant["target"], grant["gate"])
            != (self._trust["target_id"], self.instance_id)
            or not self.recovery_boot(grant["boot"])
        ):
            return {"state": "UNRESOLVED", "reason": "ACCESS_DENIED"}
        with self._connection() as c:
            c.execute("BEGIN")
            demand(seal(c) == self.floor, "TARGET_ROLLBACK")
            acl = c.execute(
                "SELECT binding FROM recovery_acl WHERE op=?", (grant["op"],)
            ).fetchone()
            if acl is None or acl[0] != canonical_json(b).decode():
                return {"state": "UNRESOLVED", "reason": "ACCESS_DENIED"}
            row = c.execute(
                "SELECT status,receipt,request_sha256 FROM operations WHERE id=?",
                (grant["op"],),
            ).fetchone()
            state, receipt = "UNRESOLVED", None
            if row and row[0] == "COMMITTED" and row[2] == grant["request"]:
                receipt = json.loads(row[1])
                state = "COMMITTED"
            elif (
                row
                and row[0] == "PREPARED"
                and c.execute(
                    "SELECT 1 FROM revoked_grants WHERE id=?", (grant["grant"],)
                ).fetchone()
            ):
                state = "NOT_COMMITTED"
            proof = sign_record(
                self.boot_key,
                dict(
                    schema="wolfalibi.sovereign.recovery-proof.v1",
                    binding=digest(b),
                    state=state,
                    receipt=digest(receipt) if receipt else None,
                ),
            )
            return dict(state=state, receipt=receipt, proof=proof)
