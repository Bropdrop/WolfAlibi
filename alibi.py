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

Requires: Python 3.9+, `cryptography` (Ed25519).  Everything else is stdlib.
"""
import bisect
import hashlib
import json
import os
import struct
import sys
import threading

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

class Witness:
    def __init__(self, signer=None):
        self.signer = signer or Signer()
        self.heads = {}                 # broker pub hex -> (epoch, cp_hash, seq_hi)
        self._lock = threading.Lock()

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
            self.heads[cp["broker"]] = (cp["epoch"], h, cp["seq_hi"])
            return self.signer.sign(DOM_W, cpb)

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

class Broker:
    def __init__(self, root, signer, witness, deny=(), journal=None):
        self.root = os.path.realpath(root)
        self.signer, self.witness = signer, witness
        self.deny = tuple(d.encode() for d in deny)
        self.journal = journal
        self._lock = threading.Lock()
        self.epoch, self.prev, self.seq, self.epoch_start = 0, b"\0" * 32, 0, 0
        self.cur, self.sealed = {}, {}
        self._pre_open_hook = None       # test-only: inject races
        self._jfd = None
        if journal:
            self._recover()
            self._jfd = os.open(journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)

    # ---- durability ------------------------------------------------------
    def _jwrite(self, obj):
        if self._jfd is None:
            return
        os.write(self._jfd, json.dumps(obj, separators=(",", ":")).encode() + b"\n")
        os.fsync(self._jfd)

    def _recover(self):
        if not os.path.exists(self.journal):
            return
        with open(self.journal, "rb") as f:
            lines = f.read().split(b"\n")
        lines = lines[:-1]               # drop torn tail (event never released)
        os.truncate(self.journal, sum(len(l) + 1 for l in lines))
        for ln in lines:
            o = json.loads(ln)
            if o["t"] == "e":
                self._apply(bytes.fromhex(o["k"]), o["m"], o["seq"])
            else:
                cp = o["cp"]
                self.sealed[o["epoch"]] = dict(
                    cp=cp, sig=bytes.fromhex(o["sig"]), wsig=bytes.fromhex(o["wsig"]),
                    leaves=[bytes.fromhex(x) for x in o["leaves"]])
                self.epoch, self.prev = o["epoch"] + 1, cp_hash(cp)
                self.epoch_start, self.cur = cp["seq_hi"], {}

    def _apply(self, key, mask, seq):
        self.seq = max(self.seq, seq)
        e = self.cur.get(key)
        if e is None:
            self.cur[key] = [mask, 1, seq]
        else:
            e[0] |= mask
            e[1] += 1

    def _record(self, key, mask):
        """Write-ahead record. Raises -> caller must NOT release data (fail closed)."""
        with self._lock:
            seq = self.seq + 1
            self._jwrite({"t": "e", "seq": seq, "k": key.hex(), "m": mask})
            self._apply(key, mask, seq)

    # ---- guarded access --------------------------------------------------
    def _key_for(self, p, is_dir):
        if p != self.root and not p.startswith(self.root + os.sep):
            return OUTSIDE
        rel = os.path.relpath(p, self.root).replace(os.sep, "/")
        rel = "" if rel == "." else rel
        return (rel + "/" if is_dir else rel).encode()

    def _guarded_open(self, rel, flags, op, is_dir):
        p = os.path.realpath(os.path.join(self.root, rel))     # resolves symlinks / ..
        key = self._key_for(p, is_dir)
        denied = key == OUTSIDE or any(key.startswith(d) for d in self.deny)
        self._record(key, OPS[op] | (DENIED if denied else 0))  # BEFORE any release
        if denied:
            raise PermissionError("blocked: " + ("outside sandbox" if key == OUTSIDE else "policy"))
        if self._pre_open_hook:
            self._pre_open_hook(p)
        fd = os.open(p, flags | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if is_dir else 0), 0o600)
        try:
            actual = os.path.realpath(f"/proc/self/fd/{fd}")
            if actual != p:              # raced: log what we REALLY opened, release nothing
                self._record(self._key_for(actual, is_dir), OPS[op] | DENIED)
                raise PermissionError("path changed during open (race detected)")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def read(self, rel):
        fd = self._guarded_open(rel, os.O_RDONLY, "r", False)
        with os.fdopen(fd, "rb") as f:
            return f.read()

    def listdir(self, rel="."):
        fd = self._guarded_open(rel, os.O_RDONLY, "l", True)
        try:
            return sorted(os.listdir(fd))
        finally:
            os.close(fd)

    def write(self, rel, data):
        fd = self._guarded_open(rel, os.O_WRONLY | os.O_CREAT, "w", False)
        try:
            os.ftruncate(fd, 0)          # truncate only AFTER the path check passed
            os.write(fd, data)
        finally:
            os.close(fd)

    # ---- sealing & proving ----------------------------------------------
    def seal(self):
        with self._lock:
            items = sorted(self.cur.items())
            leaves = [enc_entry(k, m, c, f) for k, (m, c, f) in items]
            hs = [leaf_hash(l) for l in leaves]
            cp = {"v": 1, "broker": self.signer.pub.hex(), "epoch": self.epoch,
                  "prev": self.prev.hex(), "size": len(leaves),
                  "root": mth(hs, 0, len(hs)).hex(),
                  "events": sum(c for _, (m, c, f) in items),
                  "seq_lo": self.epoch_start + 1, "seq_hi": self.seq}
            sig = self.signer.sign(DOM_B, canon(cp))
            wsig = self.witness.cosign(cp, sig, leaves)         # may raise
            rec = dict(cp=cp, sig=sig, wsig=wsig, leaves=leaves, hs=hs)
            self.sealed[self.epoch] = rec
            self._jwrite({"t": "s", "epoch": self.epoch, "cp": cp, "sig": sig.hex(),
                          "wsig": wsig.hex(), "leaves": [l.hex() for l in leaves]})
            self.epoch, self.prev = self.epoch + 1, cp_hash(cp)
            self.epoch_start, self.cur = self.seq, {}
            return cp

    def prove_empty(self, lo, hi, e_from, e_to):
        out = []
        for e in range(e_from, e_to + 1):
            rec = self.sealed[e]
            hs = rec.get("hs") or [leaf_hash(l) for l in rec["leaves"]]
            keys = [dec_entry(l)[0] for l in rec["leaves"]]
            i = bisect.bisect_left(keys, lo)
            if i < len(keys) and keys[i] < hi:
                raise NotEmpty(e, keys[i])
            def node(j):
                return {"idx": j, "leaf": rec["leaves"][j].hex(),
                        "path": [x.hex() for x in audit_path(hs, j)]}
            out.append({"cp": rec["cp"], "sig": rec["sig"].hex(), "wsig": rec["wsig"].hex(),
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