#!/usr/bin/env python3
"""
ALIBI - verifiable NEGATIVE claims about what an AI agent touched.

CLAIM PROVEN (to anyone holding two public keys and ~1-2 KB of proof):
    "During witnessed epochs a..b, the broker mediated ZERO operations
     (read / write / list / denied attempt) on any key in [lo, hi)."
    e.g. "nothing under finance/ was touched while the agent ran."

HOW:
  * The agent's only door to the filesystem is a Broker. It records every
    operation (write-ahead, fsync'd, fail-closed) BEFORE releasing any data.
  * Each epoch the Broker seals the SET of touched keys into a sorted RFC-6962
    style Merkle tree and signs a checkpoint (hash-chained to the previous one).
  * An independent Witness (e.g. your second device) receives the full leaf
    list, re-derives the root, checks strict key ordering, contiguous sequence
    numbers and chain linkage, and only then co-signs. It refuses equivocation.
  * "Nothing in [lo,hi)" is proven by two ADJACENT leaves that straddle the
    range (or one boundary leaf at either end). The verifier never sees the
    other leaves, so it learns nothing about what WAS touched.

TRUST MODEL (read this):
  Trusted:   Broker code + key, Witness code + key (independent of each other).
  Untrusted: the agent, whoever stores/relays/presents the proof, the network.
  NOT proven: that the agent had no OTHER channel to the resource. Alibi is
  only as strong as the confinement that forces all access through the Broker
  (container / seccomp / no ambient credentials) - which this prototype does
  not implement.  Untouched-by-Broker != untouched-by-universe.

Requires: Python 3.9+, `cryptography` (Ed25519), and Linux `openat2(2)` for
the hardened filesystem broker.  Durable journal/witness leases use POSIX
`fcntl`; unsupported hosts fail closed rather than using path-string fallback.
"""
import bisect
import ctypes
import errno
import hashlib
import json
import os
import platform
import stat
import struct
import sys
import tempfile
import threading
from contextlib import contextmanager

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --------------------------------------------------------------------------
# Hashing / Merkle tree (RFC 6962 shape: 0x00 leaf prefix, 0x01 node prefix,
# split at largest power of two < n -> no duplicate-node (CVE-2012-2459) trick)
# --------------------------------------------------------------------------
def H(b): return hashlib.sha256(b).digest()
EMPTY = H(b"")
def leaf_hash(d): return H(b"\x00" + d)
def node_hash(l, r): return H(b"\x01" + l + r)

def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k

def mth(hs, lo, hi):
    """Merkle tree hash over already-hashed leaves hs[lo:hi]."""
    n = hi - lo
    if n == 0:
        return EMPTY
    if n == 1:
        return hs[lo]
    k = _split(n)
    return node_hash(mth(hs, lo, lo + k), mth(hs, lo + k, hi))

def audit_path(hs, idx, lo=0, hi=None):
    hi = len(hs) if hi is None else hi
    n = hi - lo
    if n == 1:
        return []
    k = _split(n)
    if idx < lo + k:
        return audit_path(hs, idx, lo, lo + k) + [mth(hs, lo + k, hi)]
    return audit_path(hs, idx, lo + k, hi) + [mth(hs, lo, lo + k)]

def root_from_path(idx, size, lh, path):
    """Recompute root from (leaf hash, index, tree size, path). None if malformed."""
    if size <= 0 or not (0 <= idx < size):
        return None
    if size == 1:
        return lh if not path else None
    if not path:
        return None
    k = _split(size)
    sib, rest = path[-1], path[:-1]
    if idx < k:
        sub = root_from_path(idx, k, lh, rest)
        return None if sub is None else node_hash(sub, sib)
    sub = root_from_path(idx - k, size - k, lh, rest)
    return None if sub is None else node_hash(sib, sub)

# --------------------------------------------------------------------------
# Encoding, signing
# --------------------------------------------------------------------------
OPS = {"r": 1, "w": 2, "l": 4}
DENIED = 8          # attempt blocked by policy / sandbox / race detection
OUTSIDE = b"!outside"
DOM_B, DOM_W, DOM_C = b"alibi/broker/v1", b"alibi/witness/v1", b"alibi/cp/v1"
DOM_RB, DOM_RW = b"alibi/receipt/broker/v1", b"alibi/receipt/witness/v1"
# A durable witness state anchor is separately signed so a verifier can retain
# one digest outside the witness host and detect a later rollback to an older
# local state.  It is not a transparency log or a substitute for an
# independently operated witness service.
DOM_WS, DOM_WSA = b"alibi/witness-state/v1", b"alibi/witness-state-anchor/v1"

# Journal v2 is deliberately framed.  A record becomes eligible to release an
# effect only after its complete frame has been written and fsync() has
# returned.  This lets recovery distinguish an incomplete final write from a
# complete record; old newline-delimited journals do not have that property.
JOURNAL_MAGIC = b"WALBJ2\0"
JOURNAL_DIGEST_LEN = 32
JOURNAL_MAX_RECORD = 16 * 1024 * 1024


class JournalError(OSError):
    """A journal cannot safely support further evidence production."""


class BrokerClosed(RuntimeError):
    """The broker has failed closed or was explicitly closed."""


# Linux openat2(2) lets the broker anchor resolution to its directory handle.
# All currently supported Linux architectures use syscall number 437.  Keeping
# this small ctypes wrapper avoids adding a dependency merely for a syscall.
_OPENAT2_SYSCALLS = {
    "x86_64": 437, "amd64": 437, "aarch64": 437, "arm64": 437,
    "riscv64": 437, "ppc64le": 437, "s390x": 437,
}
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_IN_ROOT = 0x10


class _OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_ulonglong),
                ("mode", ctypes.c_ulonglong),
                ("resolve", ctypes.c_ulonglong)]


def _openat2(dirfd, rel, flags, mode, resolve):
    """Open ``rel`` beneath ``dirfd`` or fail without path escape.

    The caller has already rejected lexical attempts to escape the root.  The
    kernel additionally prevents racing symlinks, magic links, and absolute
    symlink targets from escaping the held root directory descriptor.
    """
    number = _OPENAT2_SYSCALLS.get(platform.machine().lower())
    if not sys.platform.startswith("linux") or number is None:
        raise OSError(errno.ENOSYS, "secure path resolution requires Linux openat2")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    how = _OpenHow(flags, mode, resolve)
    result = libc.syscall(ctypes.c_long(number), ctypes.c_int(dirfd),
                          ctypes.c_char_p(os.fsencode(rel)), ctypes.byref(how),
                          ctypes.c_size_t(ctypes.sizeof(how)))
    if result == -1:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), rel)
    return int(result)

def enc_entry(path, mask, count, first_seq):
    return struct.pack(">I", len(path)) + path + struct.pack(">BIQ", mask, count, first_seq)

def dec_entry(d):
    (n,) = struct.unpack_from(">I", d, 0)
    if len(d) != 4 + n + 13:
        raise ValueError("bad entry length")
    return d[4:4 + n], struct.unpack_from(">BIQ", d, 4 + n)

def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()

def cp_hash(cp):
    return H(DOM_C + b"\0" + canon(cp))

class Signer:
    def __init__(self, seed=None):
        self.sk = Ed25519PrivateKey.from_private_bytes(seed) if seed else Ed25519PrivateKey.generate()
        self.pub = self.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    def sign(self, dom, msg):
        return self.sk.sign(dom + b"\0" + msg)

def verify_sig(pub, dom, msg, sig):
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, dom + b"\0" + msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

# --------------------------------------------------------------------------
# Witness: the independent second party
# --------------------------------------------------------------------------
class WitnessRefused(Exception):
    pass


_LIVE_WITNESS_STATES = set()
_LIVE_WITNESS_STATES_LOCK = threading.Lock()


class Witness:
    def __init__(self, signer=None):
        self.signer = signer or Signer()
        self.heads = {}                 # broker pub hex -> (epoch, cp_hash, seq_hi)
        self._lock = threading.Lock()

    def _store_head(self, broker, head):
        """Persist a head before any outward signature in durable subclasses."""
        self.heads[broker] = head

    def cosign(self, cp, sig, leaves):
        cpb = canon(cp)
        if not verify_sig(bytes.fromhex(cp["broker"]), DOM_B, cpb, sig):
            raise WitnessRefused("bad broker signature")
        h = cp_hash(cp)
        with self._lock:
            head = self.heads.get(cp["broker"])
            if head and head[0] == cp["epoch"]:
                if head[1] == h:        # idempotent re-seal after a crash
                    return self.signer.sign(DOM_W, cpb)
                raise WitnessRefused("equivocation: different checkpoint for same epoch")
            exp_epoch = 0 if head is None else head[0] + 1
            exp_prev = b"\0" * 32 if head is None else head[1]
            exp_seq = 1 if head is None else head[2] + 1
            if cp["epoch"] != exp_epoch:
                raise WitnessRefused("epoch gap or rollback")
            if bytes.fromhex(cp["prev"]) != exp_prev:
                raise WitnessRefused("broken hash chain")
            if cp["seq_lo"] != exp_seq:
                raise WitnessRefused("sequence gap")
            hs, total, last = [], 0, None
            for l in leaves:
                try:
                    k, (m, c, f) = dec_entry(l)
                except Exception:
                    raise WitnessRefused("malformed leaf")
                if last is not None and not (last < k):
                    raise WitnessRefused("leaves not strictly sorted")
                if c < 1 or m == 0 or (m & ~15) or f < cp["seq_lo"] or f > cp["seq_hi"]:
                    raise WitnessRefused("bad leaf fields")
                last, total = k, total + c
                hs.append(leaf_hash(l))
            if len(leaves) != cp["size"] or total != cp["events"]:
                raise WitnessRefused("size/event count mismatch")
            if cp["seq_hi"] - cp["seq_lo"] + 1 != cp["events"]:
                raise WitnessRefused("sequence numbers not contiguous")
            if mth(hs, 0, len(hs)).hex() != cp["root"]:
                raise WitnessRefused("root does not match leaves")
            self._store_head(cp["broker"], (cp["epoch"], h, cp["seq_hi"]))
            return self.signer.sign(DOM_W, cpb)

    def cosign_receipt(self, receipt, broker_sig):
        """Co-sign a run receipt only when it names this witness's head.

        This adds a run-bound signature; it does not turn an in-memory witness
        into durable anti-equivocation evidence.  ``DurableWitness`` should be
        used when a receipt claims a persisted witness history.
        """
        try:
            broker = receipt["broker"]
            interval = receipt["interval"]
            end_epoch = interval["end_epoch"]
            end_hash = bytes.fromhex(interval["end_checkpoint_hash"])
        except (KeyError, TypeError, ValueError) as ex:
            raise WitnessRefused("malformed receipt") from ex
        payload = canon(receipt)
        if not verify_sig(bytes.fromhex(broker), DOM_RB, payload, broker_sig):
            raise WitnessRefused("bad receipt broker signature")
        with self._lock:
            head = self.heads.get(broker)
            if head is None or head[0] != end_epoch or head[1] != end_hash:
                raise WitnessRefused("receipt is not bound to the current witness head")
            return self.signer.sign(DOM_RW, payload)


class DurableWitness(Witness):
    """A witness whose checkpoint heads survive restart before it signs.

    The caller owns the state location and signing key.  The state is protected
    by an exclusive POSIX lease and atomically replaced with fsync ordering:
    temporary file -> fsync(file) -> rename -> fsync(parent directory).
    This protects one local witness process from forgetting a previously
    co-signed head; it is not an external transparency log or a second trust
    domain by itself.
    """

    # Version 2 adds a signed, hash-linked state anchor.  A state anchor is
    # useful only when its digest is retained independently of this state
    # file; a local attacker who can roll back both copies is still in scope.
    STATE_VERSION = 2
    LEGACY_STATE_VERSION = 1
    RECEIPT_HISTORY_LIMIT = 4096

    def __init__(self, state_path, signer=None, *, expected_state_digest=None):
        self.state_path = os.path.abspath(state_path)
        self._state_fd = None
        self._state_lease_key = None
        self.receipt_hashes = []
        self._state_generation = None
        self._state_digest = None
        self._state_anchor = None
        self._state_anchor_signature = None
        if expected_state_digest is not None:
            if (not isinstance(expected_state_digest, bytes) or
                    len(expected_state_digest) != 32):
                raise JournalError("expected witness state digest must be 32 bytes")
        super().__init__(signer)
        try:
            self._acquire_state_lease()
            self._load_state()
            if self._state_digest is None:
                if expected_state_digest is not None:
                    raise JournalError(
                        "witness state has no signed continuity anchor for the expected digest")
                # Persist a signed genesis anchor at construction time, rather
                # than waiting for the first checkpoint.  This gives an
                # external operator something concrete to retain before a run.
                self._persist(self.heads, self.receipt_hashes)
            elif (expected_state_digest is not None and
                  self._state_digest != expected_state_digest):
                raise JournalError("witness state digest does not match the external expectation")
        except BaseException:
            self.close()
            raise

    def _acquire_state_lease(self):
        try:
            import fcntl
        except ImportError as ex:
            raise JournalError("durable witness state requires POSIX fcntl") from ex
        directory = os.path.dirname(self.state_path) or "."
        os.makedirs(directory, mode=0o700, exist_ok=True)
        lock_path = self.state_path + ".lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as ex:
            os.close(fd)
            raise JournalError("durable witness state already has a live writer") from ex
        try:
            st = os.fstat(fd)
            key = (st.st_dev, st.st_ino)
            with _LIVE_WITNESS_STATES_LOCK:
                if key in _LIVE_WITNESS_STATES:
                    raise JournalError("durable witness state already has a live writer")
                _LIVE_WITNESS_STATES.add(key)
            self._state_fd, self._state_lease_key = fd, key
        except BaseException:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
            raise

    @staticmethod
    def _decode_hex(value, length, label):
        if type(value) is not str:
            raise ValueError(f"{label} must be hexadecimal text")
        decoded = bytes.fromhex(value)
        if len(decoded) != length:
            raise ValueError(f"{label} has an invalid length")
        return decoded

    def _parse_heads(self, heads):
        if not isinstance(heads, dict):
            raise ValueError("witness heads must be an object")
        parsed = {}
        for broker, item in heads.items():
            if not isinstance(item, dict):
                raise ValueError("invalid witness head")
            epoch, seq_hi = item.get("epoch"), item.get("seq_hi")
            checkpoint_hash = self._decode_hex(item.get("hash"), 32, "witness head hash")
            if (type(broker) is not str or len(self._decode_hex(broker, 32, "broker identity")) != 32 or
                    type(epoch) is not int or epoch < 0 or
                    type(seq_hi) is not int or seq_hi < 0):
                raise ValueError("invalid witness head")
            parsed[broker] = (epoch, checkpoint_hash, seq_hi)
        return parsed

    def _parse_receipt_hashes(self, receipt_hashes):
        if (not isinstance(receipt_hashes, list) or
                len(receipt_hashes) > self.RECEIPT_HISTORY_LIMIT):
            raise ValueError("invalid durable receipt history")
        for item in receipt_hashes:
            self._decode_hex(item, 32, "receipt digest")
        return list(receipt_hashes)

    def _state_core(self, heads, receipt_hashes, generation, previous_state_digest):
        if type(generation) is not int or generation < 0:
            raise ValueError("invalid witness state generation")
        if not isinstance(previous_state_digest, bytes) or len(previous_state_digest) != 32:
            raise ValueError("invalid previous witness state digest")
        heads = self.heads if heads is None else heads
        receipt_hashes = self.receipt_hashes if receipt_hashes is None else receipt_hashes
        return {
            "v": self.STATE_VERSION,
            "witness": self.signer.pub.hex(),
            "heads": {
                broker: {"epoch": epoch, "hash": checkpoint_hash.hex(), "seq_hi": seq_hi}
                for broker, (epoch, checkpoint_hash, seq_hi) in heads.items()
            },
            "receipt_hashes": list(receipt_hashes),
            "generation": generation,
            "previous_state_digest": previous_state_digest.hex(),
        }

    def _anchor_for_core(self, core):
        state_digest = H(DOM_WS + b"\0" + canon(core))
        receipt_hashes = core["receipt_hashes"]
        anchor = {
            "v": 1,
            "type": "WITNESS_STATE_ANCHOR_V1",
            "witness": self.signer.pub.hex(),
            "generation": core["generation"],
            "state_digest": state_digest.hex(),
            "previous_state_digest": core["previous_state_digest"],
            "heads_digest": H(canon(core["heads"])).hex(),
            "receipt_history_digest": H(canon(receipt_hashes)).hex(),
            "last_receipt_digest": receipt_hashes[-1] if receipt_hashes else None,
        }
        return anchor, self.signer.sign(DOM_WSA, canon(anchor)), state_digest

    @classmethod
    def _parse_anchor_package(cls, value, witness_pub):
        if (not isinstance(value, dict) or not isinstance(value.get("anchor"), dict) or
                type(value.get("signature")) is not str or
                not isinstance(witness_pub, bytes) or len(witness_pub) != 32):
            raise ValueError("malformed witness state anchor")
        anchor = value["anchor"]
        signature = cls._decode_hex(value["signature"], 64, "witness state anchor signature")
        if (anchor.get("v") != 1 or anchor.get("type") != "WITNESS_STATE_ANCHOR_V1" or
                anchor.get("witness") != witness_pub.hex() or
                type(anchor.get("generation")) is not int or anchor["generation"] < 0):
            raise ValueError("invalid witness state anchor identity")
        cls._decode_hex(anchor.get("state_digest"), 32, "witness state digest")
        cls._decode_hex(anchor.get("previous_state_digest"), 32, "previous witness state digest")
        cls._decode_hex(anchor.get("heads_digest"), 32, "witness heads digest")
        cls._decode_hex(anchor.get("receipt_history_digest"), 32, "receipt history digest")
        last_receipt = anchor.get("last_receipt_digest")
        if last_receipt is not None:
            cls._decode_hex(last_receipt, 32, "last receipt digest")
        if not verify_sig(witness_pub, DOM_WSA, canon(anchor), signature):
            raise ValueError("invalid witness state anchor signature")
        return dict(anchor), signature

    def _state_anchor_package(self):
        if self._state_anchor is None or self._state_anchor_signature is None:
            raise JournalError("durable witness has no persisted state anchor")
        # Canonical round-tripping prevents a caller from mutating the live
        # in-memory anchor through the returned object.
        return {
            "anchor": json.loads(canon(self._state_anchor)),
            "signature": self._state_anchor_signature.hex(),
        }

    def state_anchor(self):
        """Return the latest signed state anchor for external retention."""
        with self._lock:
            return self._state_anchor_package()

    @property
    def state_digest(self):
        """Latest signed state digest; retain it outside this host for rollback detection."""
        with self._lock:
            if self._state_digest is None:
                raise JournalError("durable witness has no persisted state digest")
            return bytes(self._state_digest)

    def _load_state(self):
        if not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "rb") as state_file:
                raw = state_file.read()
            obj = json.loads(raw)
            if canon(obj) != raw:
                raise ValueError("state is not canonical")
            if obj.get("witness") != self.signer.pub.hex():
                raise ValueError("wrong witness identity")
            parsed = self._parse_heads(obj.get("heads"))
            receipt_hashes = self._parse_receipt_hashes(obj.get("receipt_hashes", []))
            if obj.get("v") == self.LEGACY_STATE_VERSION:
                # A v1 state has no signed continuity anchor.  It can be
                # migrated, but cannot satisfy an externally supplied anchor
                # expectation from before this version.
                self.heads, self.receipt_hashes = parsed, receipt_hashes
                return
            if obj.get("v") != self.STATE_VERSION:
                raise ValueError("wrong state version")
            required = {
                "v", "witness", "heads", "receipt_hashes", "generation",
                "previous_state_digest", "anchor", "anchor_signature",
            }
            if set(obj) != required:
                raise ValueError("unexpected witness state fields")
            generation = obj["generation"]
            if type(generation) is not int or generation < 0:
                raise ValueError("invalid witness state generation")
            previous = self._decode_hex(obj["previous_state_digest"], 32,
                                        "previous witness state digest")
            core = self._state_core(parsed, receipt_hashes, generation, previous)
            anchor, signature = self._parse_anchor_package(
                {"anchor": obj["anchor"], "signature": obj["anchor_signature"]}, self.signer.pub)
            state_digest = H(DOM_WS + b"\0" + canon(core))
            if (anchor["generation"] != generation or
                    anchor["state_digest"] != state_digest.hex() or
                    anchor["previous_state_digest"] != previous.hex() or
                    anchor["heads_digest"] != H(canon(core["heads"])).hex() or
                    anchor["receipt_history_digest"] != H(canon(receipt_hashes)).hex() or
                    anchor["last_receipt_digest"] != (receipt_hashes[-1] if receipt_hashes else None)):
                raise ValueError("witness state anchor does not bind state")
            self.heads = parsed
            self.receipt_hashes = receipt_hashes
            self._state_generation = generation
            self._state_digest = state_digest
            self._state_anchor = anchor
            self._state_anchor_signature = signature
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as ex:
            raise JournalError("durable witness state is malformed") from ex

    @staticmethod
    def _write_all_bytes(fd, data):
        view = memoryview(data)
        while view:
            try:
                count = os.write(fd, view)
            except OSError as ex:
                if ex.errno == errno.EINTR:
                    continue
                raise
            if not isinstance(count, int) or count <= 0:
                raise OSError(errno.EIO, "witness state write made no progress")
            view = view[count:]

    def _persist(self, heads, receipt_hashes=None):
        receipt_hashes = self.receipt_hashes if receipt_hashes is None else receipt_hashes
        generation = 0 if self._state_generation is None else self._state_generation + 1
        previous = b"\0" * 32 if self._state_digest is None else self._state_digest
        core = self._state_core(heads, receipt_hashes, generation, previous)
        anchor, signature, state_digest = self._anchor_for_core(core)
        state_object = dict(core, anchor=anchor, anchor_signature=signature.hex())
        directory = os.path.dirname(self.state_path) or "."
        payload = canon(state_object)
        fd, temporary = tempfile.mkstemp(prefix=".wolfalibi-witness-", dir=directory)
        try:
            os.fchmod(fd, 0o600)
            self._write_all_bytes(fd, payload)
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(temporary, self.state_path)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        self._state_generation = generation
        self._state_digest = state_digest
        self._state_anchor = anchor
        self._state_anchor_signature = signature
        return self._state_anchor_package()

    def _store_head(self, broker, head):
        new_heads = dict(self.heads)
        new_heads[broker] = head
        # This is deliberately before Witness.cosign returns a signature.
        self._persist(new_heads, self.receipt_hashes)
        self.heads = new_heads

    def cosign_receipt(self, receipt, broker_sig):
        """Persist the exact receipt digest before its witness signature escapes."""
        try:
            broker = receipt["broker"]
            interval = receipt["interval"]
            end_epoch = interval["end_epoch"]
            end_hash = bytes.fromhex(interval["end_checkpoint_hash"])
        except (KeyError, TypeError, ValueError) as ex:
            raise WitnessRefused("malformed receipt") from ex
        payload = canon(receipt)
        if not verify_sig(bytes.fromhex(broker), DOM_RB, payload, broker_sig):
            raise WitnessRefused("bad receipt broker signature")
        with self._lock:
            head = self.heads.get(broker)
            if head is None or head[0] != end_epoch or head[1] != end_hash:
                raise WitnessRefused("receipt is not bound to the current witness head")
            receipt_hash = H(payload).hex()
            if receipt_hash not in self.receipt_hashes:
                if len(self.receipt_hashes) >= self.RECEIPT_HISTORY_LIMIT:
                    raise WitnessRefused("durable receipt history is full")
                updated = self.receipt_hashes + [receipt_hash]
                self._persist(self.heads, updated)
                self.receipt_hashes = updated
            return self.signer.sign(DOM_RW, payload)

    def close(self):
        fd, key = self._state_fd, self._state_lease_key
        self._state_fd, self._state_lease_key = None, None
        if key is not None:
            with _LIVE_WITNESS_STATES_LOCK:
                _LIVE_WITNESS_STATES.discard(key)
        if fd is not None:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def verify_witness_state_anchor(value, witness_pub):
    """Validate a signed DurableWitness state anchor without its state file.

    The returned anchor can be retained by an independent verifier.  It proves
    only that this witness key signed a local state transition; it does not
    itself make the state externally durable or independently observed.
    """
    anchor, _signature = DurableWitness._parse_anchor_package(value, witness_pub)
    return anchor

# --------------------------------------------------------------------------
# Broker: the only door
# --------------------------------------------------------------------------
class NotEmpty(Exception):
    def __init__(self, epoch, key):
        super().__init__(f"epoch {epoch}: key {key!r} lies inside the queried range")
        self.epoch, self.key = epoch, key

def subtree(prefix):
    """Range covering everything under a directory (incl. its listing key 'dir/')."""
    p = prefix.strip("/").encode()
    return p + b"/", p + b"0"           # '0' is the byte after '/'

def exact(path):
    b = path.encode()
    return b, b + b"\0"

_LIVE_JOURNALS = set()
_LIVE_JOURNALS_LOCK = threading.Lock()
_LIVE_BROKER_IDENTITIES = set()
_LIVE_BROKER_IDENTITIES_LOCK = threading.Lock()


class Broker:
    """The mediated filesystem boundary.

    An epoch covers *completed* broker operations.  ``seal()`` first closes
    an admission gate, waits for every admitted operation to finish (including
    reads, listings, and durable writes), then commits the resulting epoch.
    A request admitted after that gate reopens belongs to the next epoch.

    This is deliberately a broker-level guarantee only.  It says nothing
    about direct host access or other unmediated resource channels.
    """

    def __init__(self, root, signer, witness, deny=(), journal=None):
        self.root = os.path.realpath(root)
        self.signer, self.witness = signer, witness
        self.deny = tuple(d.encode() for d in deny)
        self.journal = os.path.abspath(journal) if journal else None
        self._state_lock = threading.RLock()
        self._barrier = threading.Condition(threading.Lock())
        self._resource_lock = threading.Lock()
        self._active_ops = 0
        self._sealing = False
        self._closed = False
        self._fatal_reason = None
        self.epoch, self.prev, self.seq, self.epoch_start = 0, b"\0" * 32, 0, 0
        self.cur, self.sealed = {}, {}
        self._pre_open_hook = None       # test-only: inject races
        self._jfd = None
        self._journal_lease_key = None
        self._identity_lease_key = None
        self._root_fd = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            self._root_fd = os.open(self.root, flags)
            if not stat.S_ISDIR(os.fstat(self._root_fd).st_mode):
                raise NotADirectoryError(self.root)
            self._require_secure_resolver()
            self._acquire_identity_lease()
            if self.journal:
                self._open_journal()
        except BaseException:
            self._release_journal()
            self._release_identity_lease()
            self._close_root_fd()
            raise

    # ---- lifecycle / operation boundary ---------------------------------
    def _assert_live(self, allow_closed=False):
        if self._fatal_reason is not None:
            raise BrokerClosed(f"broker is fail-closed: {self._fatal_reason}")
        if self._closed and not allow_closed:
            raise BrokerClosed("broker is closed")

    @contextmanager
    def _operation(self):
        """Admit one operation into the current epoch's quiescence barrier."""
        with self._barrier:
            while self._sealing and self._fatal_reason is None and not self._closed:
                self._barrier.wait()
            self._assert_live()
            self._active_ops += 1
        try:
            yield
        finally:
            with self._barrier:
                self._active_ops -= 1
                if self._active_ops == 0:
                    self._barrier.notify_all()

    @contextmanager
    def _seal_window(self):
        """Exclude new operations and wait for current effects to quiesce."""
        with self._barrier:
            while self._sealing and self._fatal_reason is None and not self._closed:
                self._barrier.wait()
            self._assert_live()
            self._sealing = True
            while self._active_ops:
                self._barrier.wait()
            self._assert_live()
        try:
            yield
        finally:
            with self._barrier:
                self._sealing = False
                self._barrier.notify_all()

    def _fail_closed(self, reason):
        """Prevent future effects and relinquish a broken writer lease."""
        with self._barrier:
            if self._fatal_reason is None:
                self._fatal_reason = str(reason)
            self._barrier.notify_all()
        # A failed append must not be followed by another append in the same
        # process: it could turn a partial frame into ambiguous journal bytes.
        self._release_journal()
        self._release_identity_lease()

    def _close_root_fd(self):
        if self._root_fd is not None:
            try:
                os.close(self._root_fd)
            except OSError:
                pass
            self._root_fd = None

    def _require_secure_resolver(self):
        """Reject hosts that cannot enforce the advertised rooted resolution."""
        try:
            probe = _openat2(self._root_fd, ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                             0, _RESOLVE_IN_ROOT | _RESOLVE_NO_MAGICLINKS)
        except OSError as ex:
            raise JournalError("Linux openat2 rooted resolution is required") from ex
        else:
            os.close(probe)

    def _acquire_identity_lease(self):
        """Reject two live broker objects using one signing identity in-process."""
        key = self.signer.pub.hex()
        with _LIVE_BROKER_IDENTITIES_LOCK:
            if key in _LIVE_BROKER_IDENTITIES:
                raise JournalError("broker signing identity already has a live writer")
            _LIVE_BROKER_IDENTITIES.add(key)
        self._identity_lease_key = key

    def _release_identity_lease(self):
        key, self._identity_lease_key = self._identity_lease_key, None
        if key is not None:
            with _LIVE_BROKER_IDENTITIES_LOCK:
                _LIVE_BROKER_IDENTITIES.discard(key)

    def close(self):
        """Stop admitting effects and release held descriptors/leases."""
        with self._barrier:
            self._closed = True
            self._barrier.notify_all()
            while self._active_ops or self._sealing:
                self._barrier.wait()
        self._release_journal()
        self._release_identity_lease()
        self._close_root_fd()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        # Best effort only; callers that need timely lease release should use
        # close() or a context manager.
        try:
            self._release_journal()
            self._release_identity_lease()
            self._close_root_fd()
        except Exception:
            pass

    # ---- durable single-writer journal ----------------------------------
    def _open_journal(self):
        try:
            import fcntl
        except ImportError as ex:
            raise JournalError("exclusive journal leases require POSIX fcntl") from ex
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.journal, flags, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as ex:
                raise JournalError("journal already has a live broker writer") from ex
            st = os.fstat(fd)
            key = (st.st_dev, st.st_ino)
            with _LIVE_JOURNALS_LOCK:
                if key in _LIVE_JOURNALS:
                    raise JournalError("journal already has a live broker writer")
                _LIVE_JOURNALS.add(key)
            self._jfd, self._journal_lease_key = fd, key
            self._recover()
        except BaseException:
            if self._journal_lease_key is not None:
                with _LIVE_JOURNALS_LOCK:
                    _LIVE_JOURNALS.discard(self._journal_lease_key)
                self._journal_lease_key = None
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
            self._jfd = None
            raise

    def _release_journal(self):
        with self._resource_lock:
            fd, key = self._jfd, self._journal_lease_key
            self._jfd, self._journal_lease_key = None, None
        if key is not None:
            with _LIVE_JOURNALS_LOCK:
                _LIVE_JOURNALS.discard(key)
        if fd is not None:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
            try:
                os.close(fd)
            except OSError:
                pass

    def _read_journal(self):
        if self._jfd is None:
            return b""
        os.lseek(self._jfd, 0, os.SEEK_SET)
        chunks = []
        while True:
            block = os.read(self._jfd, 65536)
            if not block:
                break
            chunks.append(block)
        os.lseek(self._jfd, 0, os.SEEK_END)
        return b"".join(chunks)

    def _truncate_journal(self, size):
        os.ftruncate(self._jfd, size)
        os.fsync(self._jfd)
        os.lseek(self._jfd, 0, os.SEEK_END)

    @staticmethod
    def _frame(obj):
        payload = canon(obj)
        if len(payload) > JOURNAL_MAX_RECORD:
            raise JournalError("journal record exceeds configured limit")
        return (JOURNAL_MAGIC + struct.pack(">I", len(payload)) + payload +
                H(payload))

    @staticmethod
    def _write_all(fd, data):
        view = memoryview(data)
        while view:
            try:
                written = os.write(fd, view)
            except OSError as ex:
                if ex.errno == errno.EINTR:
                    continue
                raise
            if not isinstance(written, int) or written <= 0:
                raise OSError(errno.EIO, "journal write made no progress")
            view = view[written:]

    def _jwrite(self, obj):
        if self._jfd is None:
            return
        self._write_all(self._jfd, self._frame(obj))
        os.fsync(self._jfd)

    def _recover(self):
        """Replay complete v2 frames and discard only an incomplete final frame."""
        data = self._read_journal()
        if not data:
            return
        if not data.startswith(JOURNAL_MAGIC):
            if JOURNAL_MAGIC.startswith(data):
                # A crash before the first complete frame cannot have released
                # an effect, because release follows the full write + fsync.
                self._truncate_journal(0)
                return
            raise JournalError("legacy or malformed journal is not safe to recover")

        records, offset = [], 0
        header_len = len(JOURNAL_MAGIC) + 4
        while offset < len(data):
            start = offset
            if len(data) - offset < header_len:
                break
            if data[offset:offset + len(JOURNAL_MAGIC)] != JOURNAL_MAGIC:
                # Accept only an *incomplete* non-frame suffix for compatibility
                # with the historical torn-tail reproducer.  A complete legacy
                # line/object could represent an effect from an unsafe writer,
                # so recovery must refuse it rather than silently omit it.
                tail = data[start:]
                if b"\n" in tail:
                    raise JournalError("unexpected complete non-frame journal data")
                try:
                    json.loads(tail)
                except (TypeError, ValueError, UnicodeDecodeError):
                    pass
                else:
                    raise JournalError("unexpected complete non-frame journal data")
                break
            offset += len(JOURNAL_MAGIC)
            (length,) = struct.unpack_from(">I", data, offset)
            offset += 4
            if length > JOURNAL_MAX_RECORD:
                raise JournalError("impossible journal frame length")
            end = offset + length + JOURNAL_DIGEST_LEN
            if end > len(data):
                offset = start
                break
            payload, digest = data[offset:offset + length], data[offset + length:end]
            if H(payload) != digest:
                raise JournalError("journal frame digest mismatch")
            try:
                obj = json.loads(payload)
            except (TypeError, ValueError, UnicodeDecodeError) as ex:
                raise JournalError("journal frame is not canonical JSON") from ex
            if not isinstance(obj, dict) or canon(obj) != payload:
                raise JournalError("journal frame is not an object")
            records.append(obj)
            offset = end
        if offset != len(data):
            self._truncate_journal(offset)
        for obj in records:
            self._replay(obj)

    def _replay(self, obj):
        try:
            kind = obj["t"]
        except (KeyError, TypeError) as ex:
            raise JournalError("journal record has no type") from ex
        if kind == "e":
            try:
                seq, key, mask = obj["seq"], bytes.fromhex(obj["k"]), obj["m"]
            except (KeyError, TypeError, ValueError) as ex:
                raise JournalError("malformed event record") from ex
            if (type(seq) is not int or seq != self.seq + 1 or
                    type(mask) is not int or mask <= 0 or mask & ~15):
                raise JournalError("non-contiguous or invalid event record")
            self._apply(key, mask, seq)
            return
        if kind != "s":
            raise JournalError("unknown journal record type")
        try:
            epoch, cp = obj["epoch"], obj["cp"]
            sig, wsig = bytes.fromhex(obj["sig"]), bytes.fromhex(obj["wsig"])
            leaves = [bytes.fromhex(item) for item in obj["leaves"]]
        except (KeyError, TypeError, ValueError) as ex:
            raise JournalError("malformed seal record") from ex
        if type(epoch) is not int or epoch != self.epoch:
            raise JournalError("journal seal has an unexpected epoch")
        items = sorted(self.cur.items())
        expected_leaves = [enc_entry(k, m, c, f) for k, (m, c, f) in items]
        expected_cp = self._checkpoint(items)
        if (leaves != expected_leaves or cp != expected_cp or
                not verify_sig(self.signer.pub, DOM_B, canon(cp), sig)):
            raise JournalError("journal seal does not commit the recovered events")
        self.sealed[epoch] = dict(cp=cp, sig=sig, wsig=wsig, leaves=leaves,
                                  hs=[leaf_hash(leaf) for leaf in leaves])
        self.epoch, self.prev = epoch + 1, cp_hash(cp)
        self.epoch_start, self.cur = self.seq, {}

    def _apply(self, key, mask, seq):
        self.seq = seq
        entry = self.cur.get(key)
        if entry is None:
            self.cur[key] = [mask, 1, seq]
        else:
            entry[0] |= mask
            entry[1] += 1

    def _record(self, key, mask):
        """Write-ahead record. Raises -> caller must NOT release data/effects."""
        with self._state_lock:
            self._assert_live()
            seq = self.seq + 1
            try:
                self._jwrite({"t": "e", "seq": seq, "k": key.hex(), "m": mask})
            except Exception as ex:
                self._fail_closed(f"event journal append failed: {ex}")
                raise
            self._apply(key, mask, seq)

    # ---- guarded access --------------------------------------------------
    def _candidate_path(self, rel):
        """Return a diagnostic resolved path, or None for lexical root escape."""
        if not isinstance(rel, str):
            raise TypeError("broker paths must be text")
        if "\0" in rel or os.path.isabs(rel):
            return None
        depth = 0
        for part in rel.split(os.sep):
            if part in ("", "."):
                continue
            if part == "..":
                depth -= 1
                if depth < 0:
                    return None
            else:
                depth += 1
        return os.path.realpath(os.path.join(self.root, rel))

    def _key_for(self, p, is_dir):
        if p is None or (p != self.root and not p.startswith(self.root + os.sep)):
            return OUTSIDE
        rel = os.path.relpath(p, self.root).replace(os.sep, "/")
        rel = "" if rel == "." else rel
        return (rel + "/" if is_dir else rel).encode()

    def _safe_open(self, rel, flags, is_dir, is_write):
        resolve = _RESOLVE_IN_ROOT | _RESOLVE_NO_MAGICLINKS
        # Creation follows only non-symlink components.  This prevents a
        # swapped parent from directing O_CREAT outside the held root before a
        # post-open check could notice it.
        if is_write:
            resolve |= _RESOLVE_NO_SYMLINKS
        flags |= os.O_CLOEXEC | (os.O_DIRECTORY if is_dir else 0)
        return _openat2(self._root_fd, rel, flags, 0o600 if is_write else 0, resolve)

    def _record_unsafe_resolution(self, op):
        self._record(OUTSIDE, OPS[op] | DENIED)

    def _guarded_open(self, rel, flags, op, is_dir):
        p = self._candidate_path(rel)
        key = self._key_for(p, is_dir)
        denied = key == OUTSIDE or any(key.startswith(d) for d in self.deny)
        self._record(key, OPS[op] | (DENIED if denied else 0))  # BEFORE any release
        if denied:
            raise PermissionError("blocked: " + ("outside sandbox" if key == OUTSIDE else "policy"))
        if self._pre_open_hook:
            self._pre_open_hook(p)
        # This is a diagnostic race check, not the boundary enforcement (that
        # is openat2 below).  It retains the actual resolved in-root target in
        # the evidence as a denied attempt, while refusing before any data is
        # released or an O_CREAT call can create a file.
        actual = os.path.realpath(os.path.join(self.root, rel))
        if actual != p:
            self._record(self._key_for(actual, is_dir), OPS[op] | DENIED)
            raise PermissionError("path changed during resolution (race detected)")
        try:
            fd = self._safe_open(rel, flags, is_dir, op == "w")
        except OSError as ex:
            if ex.errno in (errno.EXDEV, errno.ELOOP, errno.EPERM, errno.EACCES):
                self._record_unsafe_resolution(op)
                raise PermissionError("blocked: unsafe path resolution") from ex
            if ex.errno in (errno.ENOSYS, errno.EINVAL):
                raise BrokerClosed("secure path resolution is unsupported on this host") from ex
            raise
        try:
            actual = os.path.realpath(f"/proc/self/fd/{fd}")
            if actual != p:              # raced: log what we REALLY opened, release nothing
                self._record(self._key_for(actual, is_dir), OPS[op] | DENIED)
                raise PermissionError("path changed during open (race detected)")
            # A hard link has more than one filesystem path for one object.
            # The v0.1 range proof is path-scoped, so it cannot honestly map
            # every such alias back into every requested path interval.  Do
            # not release bytes (or truncate an existing file) through an
            # ambiguous regular-file alias.  This is deliberately a refusal,
            # not a claim that inode identity has been solved.
            opened = os.fstat(fd)
            if (not is_dir and stat.S_ISREG(opened.st_mode) and opened.st_nlink > 1):
                self._record(key, OPS[op] | DENIED)
                raise PermissionError("blocked: hard-link resource aliases are unsupported")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def read(self, rel):
        with self._operation():
            fd = self._guarded_open(rel, os.O_RDONLY, "r", False)
            with os.fdopen(fd, "rb") as f:
                return f.read()

    def listdir(self, rel="."):
        with self._operation():
            fd = self._guarded_open(rel, os.O_RDONLY, "l", True)
            try:
                return sorted(os.listdir(fd))
            finally:
                os.close(fd)

    def write(self, rel, data):
        # Validate/copy caller data before opening or truncating any target.
        # An invalid buffer must not turn into an empty-file side effect.
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("broker writes require bytes-like data")
        payload = bytes(data)
        with self._operation():
            fd = self._guarded_open(rel, os.O_WRONLY | os.O_CREAT, "w", False)
            try:
                os.ftruncate(fd, 0)      # only after secure resolution + logging
                self._write_all(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)

    # ---- sealing & proving ----------------------------------------------
    def _checkpoint(self, items):
        leaves = [enc_entry(k, m, c, f) for k, (m, c, f) in items]
        hs = [leaf_hash(leaf) for leaf in leaves]
        cp = {"v": 1, "broker": self.signer.pub.hex(), "epoch": self.epoch,
              "prev": self.prev.hex(), "size": len(leaves),
              "root": mth(hs, 0, len(hs)).hex(),
              "events": sum(c for _, (m, c, f) in items),
              "seq_lo": self.epoch_start + 1, "seq_hi": self.seq}
        return cp

    def seal(self):
        with self._seal_window():
            with self._state_lock:
                self._assert_live()
                items = sorted(self.cur.items())
                leaves = [enc_entry(k, m, c, f) for k, (m, c, f) in items]
                hs = [leaf_hash(leaf) for leaf in leaves]
                cp = self._checkpoint(items)
                sig = self.signer.sign(DOM_B, canon(cp))
                wsig = self.witness.cosign(cp, sig, leaves)     # may refuse safely
                try:
                    self._jwrite({"t": "s", "epoch": self.epoch, "cp": cp,
                                  "sig": sig.hex(), "wsig": wsig.hex(),
                                  "leaves": [leaf.hex() for leaf in leaves]})
                except Exception as ex:
                    self._fail_closed(f"seal journal append failed: {ex}")
                    raise
                self.sealed[self.epoch] = dict(cp=cp, sig=sig, wsig=wsig,
                                               leaves=leaves, hs=hs)
                self.epoch, self.prev = self.epoch + 1, cp_hash(cp)
                self.epoch_start, self.cur = self.seq, {}
                return cp

    def prove_empty(self, lo, hi, e_from, e_to):
        with self._state_lock:
            self._assert_live(allow_closed=True)
            records = [self.sealed[e] for e in range(e_from, e_to + 1)]
        out = []
        for e, rec in zip(range(e_from, e_to + 1), records):
            hs = rec.get("hs") or [leaf_hash(leaf) for leaf in rec["leaves"]]
            keys = [dec_entry(leaf)[0] for leaf in rec["leaves"]]
            i = bisect.bisect_left(keys, lo)
            if i < len(keys) and keys[i] < hi:
                raise NotEmpty(e, keys[i])
            def node(j):
                return {"idx": j, "leaf": rec["leaves"][j].hex(),
                        "path": [item.hex() for item in audit_path(hs, j)]}
            out.append({"cp": rec["cp"], "sig": rec["sig"].hex(),
                        "wsig": rec["wsig"].hex(),
                        "proof": {"pred": node(i - 1) if i > 0 else None,
                                  "succ": node(i) if i < len(keys) else None}})
        return {"query": {"lo": lo.hex(), "hi": hi.hex()}, "epochs": out}

# --------------------------------------------------------------------------
# Verifier: needs only (bundle, broker_pub, witness_pub, query, epoch range)
# --------------------------------------------------------------------------
class AlibiError(Exception):
    pass

def check_empty(size, root, proof, lo, hi):
    """True iff proof shows no leaf key k with lo <= k < hi in the committed tree."""
    try:
        if not (lo < hi):
            return False
        pred, succ = proof["pred"], proof["succ"]
        if size == 0:
            return root == EMPTY and pred is None and succ is None
        if pred is None and succ is None:
            return False
        def chk(node):
            idx, leaf = node["idx"], bytes.fromhex(node["leaf"])
            if type(idx) is not int or not (0 <= idx < size):
                return None
            r = root_from_path(idx, size, leaf_hash(leaf), [bytes.fromhex(x) for x in node["path"]])
            return (idx, dec_entry(leaf)[0]) if r == root else None
        ip = ks = None
        if pred is not None:
            p = chk(pred)
            if p is None or not (p[1] < lo):
                return False
            ip = p[0]
        if succ is not None:
            s = chk(succ)
            if s is None or not (s[1] >= hi):
                return False
            ks = s[0]
        if pred is not None and succ is not None:
            return ks == ip + 1
        if pred is not None:
            return ip == size - 1
        return ks == 0
    except Exception:
        return False

def verify_alibi(bundle, broker_pub, witness_pub, lo, hi, epochs):
    try:
        return _verify(bundle, broker_pub, witness_pub, lo, hi, epochs)
    except AlibiError:
        raise
    except Exception as ex:
        raise AlibiError(f"malformed bundle: {ex!r}")

def _verify(bundle, broker_pub, witness_pub, lo, hi, epochs):
    a, b = epochs
    if not (lo < hi and 0 <= a <= b):
        raise AlibiError("bad query")
    q = bundle["query"]
    if bytes.fromhex(q["lo"]) != lo or bytes.fromhex(q["hi"]) != hi:
        raise AlibiError("bundle answers a different query")
    eps = bundle["epochs"]
    if [e["cp"]["epoch"] for e in eps] != list(range(a, b + 1)):
        raise AlibiError("epoch coverage mismatch")
    prev, events = None, 0
    for e in eps:
        cp = e["cp"]
        cpb = canon(cp)
        if cp["v"] != 1 or bytes.fromhex(cp["broker"]) != broker_pub:
            raise AlibiError(f"epoch {cp['epoch']}: wrong broker")
        if not verify_sig(broker_pub, DOM_B, cpb, bytes.fromhex(e["sig"])):
            raise AlibiError(f"epoch {cp['epoch']}: bad broker signature")
        if not verify_sig(witness_pub, DOM_W, cpb, bytes.fromhex(e["wsig"])):
            raise AlibiError(f"epoch {cp['epoch']}: missing/invalid witness co-signature")
        if cp["epoch"] == 0 and cp["prev"] != "00" * 32:
            raise AlibiError("bad genesis")
        if prev is not None and cp["prev"] != prev.hex():
            raise AlibiError(f"epoch {cp['epoch']}: hash chain broken")
        prev = cp_hash(cp)
        if not check_empty(cp["size"], bytes.fromhex(cp["root"]), e["proof"], lo, hi):
            raise AlibiError(f"epoch {cp['epoch']}: emptiness proof invalid")
        events += cp["events"]
    return {"epochs": (a, b), "events_covered": events, "queried": (lo, hi)}

# --------------------------------------------------------------------------
# Demo + benchmark
# --------------------------------------------------------------------------
def _sandbox(tmp):
    files = {"docs/notes.txt": b"meeting notes", "docs/todo.md": b"- ship it",
             "src/main.py": b"print('hi')", "finance/q3.xlsx": b"REVENUE ...",
             "finance/tax/2025.pdf": b"TAX ...", "secrets/.env": b"API_KEY=..."}
    for rel, data in files.items():
        p = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
    os.makedirs(os.path.join(tmp, "out"), exist_ok=True)

def demo():
    import tempfile
    tmp = tempfile.mkdtemp()
    _sandbox(tmp)
    bs, ws = Signer(), Witness()
    br = Broker(tmp, bs, ws, deny=["secrets/"])
    print("== Run 1: scripted agent (NOT an LLM - a fixed script) behaves ==")
    br.listdir("docs"); br.read("docs/notes.txt"); br.read("src/main.py")
    br.write("out/summary.md", b"summary")
    cp = br.seal()
    print(f"sealed epoch {cp['epoch']}: {cp['events']} events, {cp['size']} distinct keys, root {cp['root'][:16]}...")
    for name in ("finance", "secrets"):
        lo, hi = subtree(name)
        bundle = br.prove_empty(lo, hi, 0, 0)
        blob = json.dumps(bundle).encode()
        info = verify_alibi(json.loads(blob), bs.pub, ws.signer.pub, lo, hi, (0, 0))
        print(f"  ALIBI '{name}/': proof {len(blob)} B  -> VERIFIED ({info['events_covered']} events, none in range)")
    print("\n== Run 2: agent is 'hijacked' and reads finance via a symlink in docs/ ==")
    os.symlink("../finance/tax/2025.pdf", os.path.join(tmp, "docs", "innocent.txt"))
    br.read("docs/innocent.txt")
    try:
        br.read("secrets/.env")
    except PermissionError as ex:
        print("  secrets/.env ->", ex)
    br.seal()
    lo, hi = subtree("finance")
    try:
        br.prove_empty(lo, hi, 1, 1)
    except NotEmpty as ex:
        print("  prover refuses:", ex)
    print("  (symlink did not hide it: the broker logs the RESOLVED path)")
    bundle = br.prove_empty(*subtree("finance"), 0, 0)
    try:
        verify_alibi(bundle, bs.pub, ws.signer.pub, *subtree("finance"), (0, 1))
    except AlibiError as ex:
        print("  replaying run-1 proof for epochs 0..1 ->", ex)

def bench(n):
    import time
    keys = sorted({f"proj{(i * 7919) % 100003:06d}/file{i:07d}".encode() for i in range(n)})
    leaves = [enc_entry(k, 1, 1, i + 1) for i, k in enumerate(keys)]
    t = time.time(); hs = [leaf_hash(l) for l in leaves]; root = mth(hs, 0, len(hs)); tb = time.time() - t
    m = len(keys) // 2
    lo, hi = keys[m] + b"\0", keys[m + 1]
    sk, wk = Signer(), Signer()
    cp = {"v": 1, "broker": sk.pub.hex(), "epoch": 0, "prev": "00" * 32, "size": len(leaves),
          "root": root.hex(), "events": len(leaves), "seq_lo": 1, "seq_hi": len(leaves)}
    cb = canon(cp)
    t = time.time()
    node = lambda j: {"idx": j, "leaf": leaves[j].hex(), "path": [x.hex() for x in audit_path(hs, j)]}
    bundle = {"query": {"lo": lo.hex(), "hi": hi.hex()},
              "epochs": [{"cp": cp, "sig": sk.sign(DOM_B, cb).hex(), "wsig": wk.sign(DOM_W, cb).hex(),
                          "proof": {"pred": node(m), "succ": node(m + 1)}}]}
    tp = time.time() - t
    blob = json.dumps(bundle).encode()
    t = time.time()
    for _ in range(200):
        verify_alibi(bundle, sk.pub, wk.pub, lo, hi, (0, 0))
    tv = (time.time() - t) / 200
    print(f"n={len(keys):>9,} keys | build {tb:6.2f}s | prove {tp:5.2f}s | proof {len(blob):5d} B JSON | verify {tv*1000:5.2f} ms")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "demo"
    if cmd == "bench":
        for n in (1_000, 100_000, int(sys.argv[2]) if len(sys.argv) > 2 else 1_000_000):
            bench(n)
    else:
        demo()
