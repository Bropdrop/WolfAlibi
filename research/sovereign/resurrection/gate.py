"""Witnessed cold restart of a single enrolled native counter on Linux."""

import fcntl, json, os, sys, threading, time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.schism.storage import demand
from research.sovereign.cluster import tls
from research.sovereign.observer import TABLES
from research.sovereign.target import Stationary, seal
from research.sovereign.wire import Session, serve
from research.sovereign.resurrection.audit import history
from research.sovereign.resurrection.witness import authorization, CHANGE
from shirudo_adapter.action_gate import Gate, _GateConnection
from shirudo_adapter.model import AdapterError, canonical_json, digest
from shirudo_adapter.receipt import sign_record, verify_record


def snapshot(c):
    return {
        t: [dict(row) for row in c.execute(f"SELECT * FROM {t} ORDER BY rowid")]
        for t in TABLES
    }


def schema_hash(c):
    return digest(
        [
            list(row)
            for row in c.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            )
        ]
    )


class WitnessedConnection(_GateConnection):
    def commit(self):
        gate = self.target
        demand(gate.phase in ("ACTIVE", "AUTHORITY_RECONCILED"), "RECOVERY_CLOSED")
        gate.check_volume()
        final = getattr(self, "final_check", None)
        if final:
            final()
        candidate = seal(self)
        try:
            self.finish_witnessed(gate, candidate, final)
        except BaseException:
            gate.phase = "RECOVERY_UNRESOLVED"
            raise

    def finish_witnessed(self, gate, candidate, final):
        gate.reserve(candidate)
        hook = getattr(gate, "reservation_hook", None)
        if hook:
            gate.reservation_hook = None
            hook()
        # Witness latency must not extend a native grant's execution deadline.
        if final:
            req = gate.context.frame[0]
            row = gate._row(self, req["operation_id"])
            now = gate._clock()
            demand(now >= self.observed_clock, "CLOCK_ROLLBACK")
            gate._execution_times(
                json.loads(row["document"])["payload"],
                json.loads(row["attestation_document"])["payload"],
                req["assessment"]["payload"],
                req["grant"]["payload"],
                now,
            )
        super().commit()
        gate.floor = candidate


class Recovered(Stationary):
    connection_factory = WitnessedConnection

    def __init__(self, state, config, client):
        self.config = config
        self.client = client
        self.pin = config["recovery_pin"]
        self.lock = threading.RLock()
        self.context = threading.local()
        self.phase = "RECOVERING"
        self.activation = None
        self.origins = set()
        self.boot_key = Ed25519PrivateKey.generate()
        self.boot = self.boot_key.public_key().public_bytes_raw().hex()
        try:
            self.volume_fd = os.open(
                state / "journal.sqlite3", os.O_RDWR | os.O_NOFOLLOW
            )
        except OSError as e:
            raise AdapterError(
                "STORAGE_UNAVAILABLE", "Canonical volume unavailable"
            ) from e
        self.check_volume()
        try:
            fcntl.flock(self.volume_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise AdapterError("WRITER_HELD", "Enrolled writer still alive") from e
        self.wctx = tls(Path("/identity"))
        self.wctx.endpoint = config["witness_tls"]
        self.anchor = self.contact("head")
        self.floor = self.anchor["payload"]["seal"]
        Gate.__init__(self, state)
        demand(
            self._trust["owner_public_key"] == self.pin["owner"]
            and self._public_key == self.pin["native"]
            and self.instance_id == self.pin["gate"]
            and self._trust["target_id"] == self.pin["target"],
            "NATIVE_ENROLLMENT",
        )

    def check_volume(self):
        s = os.fstat(self.volume_fd)
        demand([s.st_dev, s.st_ino] == self.pin["volume"], "VOLUME_IDENTITY")

    def _check_database(self, c):
        self.check_volume()
        s = (self.path / "journal.sqlite3").stat()
        demand(
            [s.st_dev, s.st_ino] == self.pin["volume"]
            and schema_hash(c) == self.pin["schema_hash"],
            "VOLUME_IDENTITY",
        )
        super()._check_database(c)

    def contact(self, msg):
        try:
            with Session(self.config["witness_port"], self.wctx) as s:
                r = s.call(msg)
        except (OSError, ValueError) as e:
            raise AdapterError("WITNESS_UNAVAILABLE", "Witness unavailable") from e
        demand("denied" not in r, "WITNESS_DENIED")
        p = verify_record(r, self.config["witness_key"])
        demand(p["pin"] == digest(self.pin), "WITNESS_IDENTITY")
        return r

    def reserve(self, value):
        parent = digest(self.anchor)
        auth = self.activation
        req = sign_record(
            self.boot_key,
            dict(
                schema=CHANGE,
                boot=self.boot,
                seal=value,
                parent=parent,
                auth=digest(auth) if auth else None,
            ),
        )
        new = self.contact(dict(request=req, auth=auth))
        demand(
            new["payload"]["request"] == req and new["payload"]["parent"] == parent,
            "RESERVATION",
        )
        self.anchor = new

    def recovery_boot(self, signed_boot):
        return self.phase == "ACTIVE" and signed_boot in self.origins

    def synchronize(self):
        demand(self.phase == "ACTIVE", "RECOVERY_CLOSED")
        return super().synchronize()

    def _begin(self, c):
        demand(self.phase == "ACTIVE", "RECOVERY_CLOSED")
        return super()._begin(c)

    def validate(self, c, *args):
        cmd = c.execute(
            "SELECT command FROM commands ORDER BY idx DESC LIMIT 1"
        ).fetchone()
        demand(
            self.phase == "ACTIVE"
            and cmd
            and json.loads(cmd[0])["payload"]["boot"] == self.boot,
            "INCARNATION_FENCE",
        )
        return super().validate(c, *args)

    def activate(self, msg):
        start = time.monotonic_ns()
        events = ["RECOVERING"]
        with self.lock:
            demand(self.phase != "ACTIVE", "ALREADY_ACTIVE")
            self.phase = "RECOVERING"
            try:
                with self._connection() as c:
                    c.execute("BEGIN IMMEDIATE")
                    self._check_database(c)
                    j = snapshot(c)
                    anchor = self.contact("head")
                    demand(
                        anchor == self.anchor and msg["history"][-1] == anchor,
                        "WITNESS_FLOOR",
                    )
                    idx, prev, epoch, holder = self.head(c)
                    commands = [self.ordered(i) for i in range(1, idx + 1)]
                    history(
                        self.pin,
                        self.config["witness_key"],
                        msg["history"],
                        msg["enrollment"],
                        msg["materials"],
                        j,
                        commands,
                    )
                    self.phase = "STATE_VERIFIED"
                    events.append(self.phase)
                    auth = msg["auth"]
                    a = authorization(self.pin, anchor, auth, self.boot)
                    demand(
                        a["first"] == idx + 1
                        and idx < a["last"] <= idx + 1024
                        and a["snapshot"] == digest(j),
                        "RECOVERY_SCOPE",
                    )
                    old_boot = anchor["payload"]["boot"]
                    installs = []
                    for number in range(idx + 1, a["last"] + 1):
                        doc = self.ordered(number)
                        demand(doc is not None, "DIRECTORY_INCOMPLETE")
                        p = verify_record(doc, self.pin["owner"])
                        expected = dict(
                            schema="wolfalibi.sovereign.order.v1",
                            target=self.pin["target"],
                            gate=self.pin["gate"],
                            previous=prev,
                            index=number,
                        )
                        if p["kind"] == "activate":
                            epoch += 1
                            expected.update(
                                kind="activate",
                                holder=p["holder"],
                                revoked=None,
                                epoch=epoch,
                                boot=p["boot"],
                            )
                            demand(p["holder"] in self.config["holders"], "CANDIDATE")
                            old_boot = p["boot"]
                            holder = p["holder"]
                            if number == a["last"]:
                                demand(
                                    p["boot"] == self.boot
                                    and epoch == a["epoch"]
                                    and digest(doc) == a["command"],
                                    "CANDIDATE",
                                )
                        else:
                            demand(number < a["last"], "ACTIVATION_MISSING")
                            expected.update(
                                kind="revoke",
                                holder=holder,
                                revoked=p["revoked"],
                                epoch=epoch,
                                boot=old_boot,
                            )
                            demand(
                                isinstance(p["revoked"], str)
                                and len(p["revoked"]) == 32,
                                "OFFLINE_REVOCATION",
                            )
                        demand(p == expected, "ORDER_BINDING")
                        prev = digest(doc)
                        installs.append(doc)
                    demand(self.ordered(a["last"] + 1) is None, "DIRECTORY_ADVANCED")
                    self.phase = "AUTHORITY_RECONCILED"
                    events.append(self.phase)
                    now = self._tick(c)
                    for doc in installs:
                        p = doc["payload"]
                        if p["kind"] == "revoke":
                            c.execute(
                                "INSERT OR IGNORE INTO revoked_grants VALUES(?,?)",
                                (p["revoked"], now),
                            )
                        ack = sign_record(
                            self.boot_key,
                            dict(
                                schema="wolfalibi.sovereign.installed.v1",
                                order=digest(doc),
                                epoch=p["epoch"],
                                index=p["index"],
                                counter=j["counter"][0]["value"],
                                target=p["target"],
                            ),
                        )
                        c.execute(
                            "INSERT INTO commands VALUES(?,?,?)",
                            (
                                p["index"],
                                canonical_json(doc).decode(),
                                canonical_json(ack).decode(),
                            ),
                        )
                    self.activation = auth
                    c.commit()
                self.origins = {d["payload"]["boot"] for d in commands + installs}
                self.phase = "ACTIVE"
                events.append(self.phase)
                return dict(
                    state=self.phase,
                    events=events,
                    ns=time.monotonic_ns() - start,
                    anchor=self.anchor,
                )
            except BaseException:
                self.phase = "RECOVERY_UNRESOLVED"
                raise
            finally:
                self.activation = None


if __name__ == "__main__":
    try:
        serve(Recovered)
    except AdapterError as e:
        print(
            json.dumps(dict(startup="RECOVERY_UNRESOLVED", reason=e.code)),
            file=sys.stderr,
        )
        sys.exit(1)
