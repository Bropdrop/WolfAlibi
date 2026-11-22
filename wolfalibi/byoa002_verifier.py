"""Verifier-issued BYOA 002 challenges and durable acceptance of one target receipt.

The verifier owns this state directory. A local checkpoint detects unilateral SQLite
rollback. Restoration of the entire directory needs a separately retained reference.
Historical acknowledgments cannot issue or consume challenges.
"""

from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile
import time

from alibi import H, canon, verify_sig
from .byoa002_enrollment import check_expected, validate_enrollment
from .stage3_evidence import _hex

_Q = "QUORVANE_BYOA002_CHALLENGE_V1"
_A = "QUORVANE_BYOA002_RETENTION_V1"
_SEAL = "QUORVANE_BYOA002_VERIFIER_STATE_V1"
_DB = "verifier.sqlite"
_CHECKPOINT = "checkpoint.json"
_MAX = (1 << 63) - 1


def digest(value):
    return H(canon(value)).hex()


def genesis(enrollment):
    return {"generation": 0, "digest": digest({"type": "QUORVANE_BYOA002_GENESIS_V1",
                                               "enrollment_sha256": digest(enrollment)})}


def _time(value):
    if type(value) is not int or not 0 <= value <= _MAX:
        raise ValueError("invalid verifier time")
    return value


def _now(override):
    return _time(int(time.time()) if override is None else override)


def _head(value):
    if type(value) is not dict or value.keys() != {"generation", "digest"}:
        raise ValueError("invalid retained head fields")
    if type(value["generation"]) is not int or not 0 <= value["generation"] < _MAX:
        raise ValueError("invalid retained generation")
    _hex(value["digest"], 32, "retained head digest")
    return value


def _signed(signer, domain, payload):
    return {"payload": payload, "signature": signer.sign(domain.encode("ascii"), canon(payload)).hex()}


def _authenticate(record, domain, enrollment):
    if type(record) is not dict or record.keys() != {"payload", "signature"} or type(record["payload"]) is not dict:
        raise ValueError("invalid verifier record")
    if not verify_sig(_hex(enrollment["verifier_pub"], 32, "enrolled verifier"), domain.encode("ascii"),
                      canon(record["payload"]), _hex(record["signature"], 64, "verifier signature")):
        raise ValueError("invalid verifier signature")
    return record["payload"]


def _challenge_payload(expected, enrollment, previous, issued_at):
    contract = expected["contract"]
    return {"type": _Q, "expectations_sha256": digest(expected), "enrollment_sha256": digest(enrollment),
            "run_id": contract["run_id"], "challenge": contract["challenge"], "issued_at": issued_at,
            "expires_at": contract["expires_at"], "previous": previous}


def verify_challenge(challenge, *, expected, enrollment, now):
    """Check an exact signed issuance at an explicitly chosen time, without spending it."""
    check_expected(enrollment, expected)
    p = _authenticate(challenge, _Q, enrollment)
    previous = _head(p.get("previous"))
    issued_at = _time(p.get("issued_at"))
    if previous["generation"] == 0 and previous != genesis(enrollment):
        raise ValueError("wrong verifier genesis")
    if canon(p) != canon(_challenge_payload(expected, enrollment, previous, issued_at)):
        raise ValueError("signed challenge differs from independently approved inputs")
    if not expected["now"] <= issued_at <= _time(now) < p["expires_at"]:
        raise ValueError("challenge outside its validity interval")
    return p


def _ack_payload(challenge, receipt, retained_at):
    previous = challenge["payload"]["previous"]
    committed = digest(receipt)
    return {"type": _A, "challenge_sha256": digest(challenge), "receipt_sha256": committed,
            "previous": previous, "head": {"generation": previous["generation"] + 1, "digest": committed},
            "retained_at": retained_at}


def _target_commitment(expected, enrollment, challenge, receipt, stamp):
    from .byoa002_target import verify_retention_proposal

    committed = verify_retention_proposal(receipt, expected=expected, enrollment=enrollment, challenge=challenge)
    if committed["committed_at"] > stamp:
        raise ValueError("verifier retention predates target commitment")


def verify_ack(ack, *, expected, enrollment, challenge, receipt):
    """Verify the historical verifier endorsement of these exact target receipt bytes."""
    p = _authenticate(ack, _A, enrollment)
    stamp = _time(p.get("retained_at"))
    verify_challenge(challenge, expected=expected, enrollment=enrollment, now=stamp)
    _target_commitment(expected, enrollment, challenge, receipt, stamp)
    if canon(p) != canon(_ack_payload(challenge, receipt, stamp)):
        raise ValueError("retention acknowledgment differs from the submitted receipt or history")
    return p


def _directory(state_dir):
    path = Path(state_dir).absolute()
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError("verifier needs its own mode-0700 state directory")
    return path


def _private_file(path):
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1):
        raise ValueError("invalid verifier state file")


def _durable_write(directory, value, *, initialize=False):
    path = directory / _CHECKPOINT
    with tempfile.NamedTemporaryFile(mode="wb", dir=directory, delete=False) as stream:
        scratch = Path(stream.name)
        try:
            stream.write(canon(value))
            stream.flush()
            os.fsync(stream.fileno())
            if initialize:
                os.link(scratch, path)
                scratch.unlink()
            else:
                os.replace(scratch, path)
            fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            scratch.unlink(missing_ok=True)


def _configuration(db):
    row = db.execute("SELECT generation,head,watermark FROM configuration WHERE id=1").fetchone()
    if row is None:
        raise ValueError("missing verifier configuration")
    return _head({"generation": row[0], "digest": row[1]}), _time(row[2])


def _ledger_digest(db):
    h = hashlib.sha256(b"quorvane/verifier/sqlite/v1\0")
    for query in ("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name",
                  "SELECT id,enrollment,generation,head,watermark FROM configuration ORDER BY id",
                  "SELECT nonce,run,used FROM reservations ORDER BY nonce",
                  "SELECT nonce,run,issue,receipt,ack FROM challenges ORDER BY nonce"):
        for row in db.execute(query):
            h.update(canon(list(row)) + b"\n")
    return h.hexdigest()


def initialize_verifier(state_dir, *, enrollment):
    """Create a pristine verifier store. Never bootstrap over an earlier store."""
    validate_enrollment(enrollment)
    path = _directory(state_dir)
    dbfile = path / _DB
    os.close(os.open(dbfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    os.close(os.open(path / "verifier.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    with closing(sqlite3.connect(dbfile)) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        db.execute("""CREATE TABLE configuration (
            id INTEGER PRIMARY KEY CHECK (id=1), enrollment TEXT NOT NULL,
            generation INTEGER NOT NULL, head TEXT NOT NULL, watermark INTEGER NOT NULL)""")
        db.execute("""CREATE TABLE reservations (
            nonce TEXT PRIMARY KEY NOT NULL, run TEXT UNIQUE NOT NULL,
            used INTEGER NOT NULL CHECK (used IN (0,1)))""")
        db.execute("""CREATE TABLE challenges (
            nonce TEXT PRIMARY KEY NOT NULL, run TEXT UNIQUE NOT NULL, issue TEXT NOT NULL,
            receipt TEXT, ack TEXT, CHECK ((ack IS NULL)=(receipt IS NULL)))""")
        db.execute("INSERT INTO configuration VALUES(1,?,0,?,0)", (digest(enrollment), genesis(enrollment)["digest"]))
        db.commit()
        _durable_write(path, {"genesis": _ledger_digest(db)}, initialize=True)
    return genesis(enrollment)


class VerifierPrincipal:
    def __init__(self, state_dir, signer, enrollment, *, expected_head=None):
        validate_enrollment(enrollment)
        self.path = _directory(state_dir)
        self.enrollment = json.loads(canon(enrollment))
        self.signer = signer
        self.closed = False
        self.observed_head = None
        if signer.pub.hex() != enrollment["verifier_pub"]:
            raise ValueError("verifier identity differs from enrollment")
        current = self.head()
        if expected_head is not None and current != _head(expected_head):
            raise ValueError("verifier state differs from externally retained head")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    @contextmanager
    def _open(self):
        try:
            with self._connection() as db:
                yield db
        except (OSError, sqlite3.Error) as exc:
            raise ValueError("verifier state or checkpoint unavailable") from exc

    @contextmanager
    def _connection(self):
        import fcntl

        if self.closed:
            raise ValueError("verifier principal is closed")
        for name in (_DB, _CHECKPOINT, "verifier.lock"):
            _private_file(self.path / name)
        with (self.path / "verifier.lock").open("rb") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            with closing(sqlite3.connect((self.path / _DB).as_uri() + "?mode=rw", uri=True)) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                sealed = json.loads((self.path / _CHECKPOINT).read_bytes())
                ledger = _ledger_digest(db)
                enrolled, = db.execute("SELECT enrollment FROM configuration WHERE id=1").fetchone()
                if enrolled != digest(self.enrollment):
                    raise ValueError("verifier database belongs to another enrollment")
                if "genesis" in sealed:
                    clean = (_configuration(db) == (genesis(self.enrollment), 0)
                             and db.execute("SELECT count(*) FROM challenges").fetchone() == (0,)
                             and db.execute("SELECT count(*) FROM reservations").fetchone() == (0,))
                    if not clean or sealed != {"genesis": ledger}:
                        raise ValueError("verifier genesis differs from its ledger")
                elif _authenticate(sealed, _SEAL, self.enrollment) != {"enrollment": enrolled, "ledger": ledger}:
                    raise ValueError("verifier checkpoint differs from its ledger")
                self._observe_head(db)
                yield db

    def _observe_head(self, db):
        current, _ = _configuration(db)
        previous = self.observed_head
        if previous is not None and previous != current:
            if current["generation"] <= previous["generation"]:
                raise ValueError("verifier history conflicts with the last observed head")
            if previous["generation"]:
                row = db.execute("SELECT ack FROM challenges WHERE receipt=?", (previous["digest"],)).fetchone()
                if row is None or json.loads(row[0])["payload"]["head"] != previous:
                    raise ValueError("verifier history is missing the last observed head")
        self.observed_head = current

    def head(self):
        with self._open() as db:
            return _configuration(db)[0]

    def _apply(self, now, action, expires_at):
        # The lease spans COMMIT, checkpoint replacement and the outgoing response.
        # A denied request still records a later clock observation.
        with self._open() as db:
            _, watermark = _configuration(db)
            start = _now(now)
            if start < watermark:
                raise ValueError("verifier clock moved backwards")
            failure = None
            end = start
            db.execute("SAVEPOINT decision")
            try:
                result = action(db, start)
                end = _now(now)
                if not start <= end < expires_at:
                    raise ValueError("verifier time changed before commitment")
            except (ValueError, sqlite3.IntegrityError) as exc:
                db.execute("ROLLBACK TO decision")
                failure = ValueError(str(exc))
            db.execute("RELEASE decision")
            if failure is None or max(start, end) > watermark:
                db.execute("UPDATE configuration SET watermark=? WHERE id=1", (max(start, end),))
                seal = {"enrollment": digest(self.enrollment), "ledger": _ledger_digest(db)}
                package = _signed(self.signer, _SEAL, seal)
                db.commit()
                _durable_write(self.path, package)
                self._observe_head(db)
            if failure is not None:
                raise failure
            return result

    def fresh(self, *, now=None):
        """Reserve a new verifier-generated run and challenge before either value leaves storage."""
        def reserve(db, _stamp):
            nonce, run = secrets.token_hex(32), secrets.token_hex(16)
            db.execute("INSERT INTO reservations VALUES(?,?,0)", (nonce, run))
            return {"run_id": run, "challenge": nonce}

        return self._apply(now, reserve, _MAX)

    def issue(self, expected, *, now=None):
        expected = json.loads(canon(expected))
        check_expected(self.enrollment, expected)

        def record(db, stamp):
            head, _ = _configuration(db)
            p = _challenge_payload(expected, self.enrollment, head, stamp)
            q = _signed(self.signer, _Q, p)
            verify_challenge(q, expected=expected, enrollment=self.enrollment, now=stamp)
            claimed = db.execute("UPDATE reservations SET used=1 WHERE nonce=? AND run=? AND used=0",
                                 (p["challenge"], p["run_id"]))
            if claimed.rowcount != 1:
                raise ValueError("run and nonce must be an unused verifier-generated pair")
            db.execute("INSERT INTO challenges(nonce,run,issue) VALUES(?,?,?)",
                       (p["challenge"], p["run_id"], canon(q).decode("ascii")))
            return q

        return self._apply(now, record, expected["contract"]["expires_at"])

    def _pending(self, db, expected, challenge, stamp):
        p = verify_challenge(challenge, expected=expected, enrollment=self.enrollment, now=stamp)
        row = db.execute("SELECT issue,ack FROM challenges WHERE nonce=?", (p["challenge"],)).fetchone()
        if not row or row[0] != canon(challenge).decode("ascii"):
            raise ValueError("unknown verifier challenge")
        if row[1] is not None:
            raise ValueError("challenge already consumed")
        if p["previous"] != _configuration(db)[0]:
            raise ValueError("challenge was issued against a stale head")
        return p

    def check_pending(self, expected, challenge, *, now=None):
        expected, challenge = json.loads(canon([expected, challenge]))
        return self._apply(now, lambda db, stamp: self._pending(db, expected, challenge, stamp),
                           expected["contract"]["expires_at"])

    def retain(self, expected, challenge, receipt, *, now=None):
        expected, challenge, receipt = json.loads(canon([expected, challenge, receipt]))

        def accept(db, stamp):
            p = self._pending(db, expected, challenge, stamp)
            _target_commitment(expected, self.enrollment, challenge, receipt, stamp)
            a = _ack_payload(challenge, receipt, stamp)
            ack = _signed(self.signer, _A, a)
            db.execute("UPDATE challenges SET receipt=?,ack=? WHERE nonce=?",
                       (a["receipt_sha256"], canon(ack).decode("ascii"), p["challenge"]))
            db.execute("UPDATE configuration SET generation=?,head=? WHERE id=1",
                       (a["head"]["generation"], a["head"]["digest"]))
            return ack

        return self._apply(now, accept, expected["contract"]["expires_at"])

    def reconcile(self, expected, challenge, receipt):
        """Recover a previously committed ACK only. Perform no dispatch or signing."""
        expected, challenge, receipt = json.loads(canon([expected, challenge, receipt]))
        with self._open() as db:
            row = db.execute("SELECT issue,receipt,ack FROM challenges WHERE nonce=?",
                             (expected["contract"]["challenge"],)).fetchone()
            if not row or row[0] != canon(challenge).decode("ascii") or row[1] != digest(receipt) or not row[2]:
                raise ValueError("no matching retained receipt acknowledgment")
            ack = json.loads(row[2])
            verify_ack(ack, expected=expected, enrollment=self.enrollment, challenge=challenge, receipt=receipt)
            return ack
