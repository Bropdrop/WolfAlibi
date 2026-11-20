import json, os, pathlib, random, subprocess, sys, tempfile, threading, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from alibi import *
import alibi

HERE = os.path.dirname(os.path.abspath(__file__))
STATS = {}

def mk(deny=("secrets/",), journal=None, seed=None):
    tmp = tempfile.mkdtemp()
    alibi._sandbox(tmp)
    bs, ws = Signer(seed), Witness()
    return tmp, bs, ws, Broker(tmp, bs, ws, deny=deny, journal=journal)

class Crypto(unittest.TestCase):
    def test_known_merkle_vectors(self):
        # RFC 6962 / CT reference vectors (recalled from memory; matching = strong evidence)
        self.assertEqual(mth([], 0, 0).hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        hs = [leaf_hash(b"")]
        self.assertEqual(mth(hs, 0, 1).hex(), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
        hs = [leaf_hash(b""), leaf_hash(b"\x00")]
        self.assertEqual(mth(hs, 0, 2).hex(), "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125")

    def test_inclusion_paths_all_sizes(self):
        for n in range(1, 70):
            hs = [leaf_hash(bytes([i])) for i in range(n)]
            root = mth(hs, 0, n)
            for i in range(n):
                self.assertEqual(root_from_path(i, n, hs[i], audit_path(hs, i)), root)

    def test_second_preimage_domain_separation(self):
        hs = [leaf_hash(bytes([i])) for i in range(4)]
        inner = node_hash(hs[0], hs[1])
        fake_leaf = hs[0] + hs[1]                       # attacker presents an inner node as a "leaf"
        self.assertNotEqual(leaf_hash(fake_leaf), inner)
        root = mth(hs, 0, 4)
        self.assertNotEqual(root_from_path(0, 2, leaf_hash(fake_leaf), [mth(hs, 2, 4)]), root)

class Honest(unittest.TestCase):
    def test_alibi_roundtrip_and_privacy(self):
        tmp, bs, ws, br = mk()
        br.listdir("docs"); br.read("docs/notes.txt"); br.read("src/main.py"); br.write("out/s.md", b"x")
        br.seal()
        lo, hi = subtree("finance")
        b = br.prove_empty(lo, hi, 0, 0)
        info = verify_alibi(json.loads(json.dumps(b)), bs.pub, ws.signer.pub, lo, hi, (0, 0))
        self.assertEqual(info["events_covered"], 4)
        blob = json.dumps(b)
        # privacy: the proof reveals exactly the two neighbouring touched keys, and no others
        self.assertIn(b"docs/notes.txt".hex(), blob)
        self.assertIn(b"out/s.md".hex(), blob)
        self.assertNotIn(b"src/main.py".hex(), blob)
        with self.assertRaises(NotEmpty):
            br.prove_empty(*subtree("docs"), 0, 0)

    def test_empty_epoch_and_multi_epoch(self):
        tmp, bs, ws, br = mk()
        br.seal()                                       # empty epoch 0
        br.read("docs/notes.txt"); br.seal()
        br.seal()
        lo, hi = subtree("finance")
        info = verify_alibi(br.prove_empty(lo, hi, 0, 2), bs.pub, ws.signer.pub, lo, hi, (0, 2))
        self.assertEqual(info["events_covered"], 1)

class Forgery(unittest.TestCase):
    def test_exhaustive_forgery_search(self):
        """For small trees, try EVERY (pred, succ) pairing of authentic leaves/indices/paths
        against EVERY non-empty range. Zero may verify. Every empty range must verify honestly."""
        pool = [b"a", b"b", b"c/d", b"c/e", b"fin/x", b"fin/y/z", b"m", b"zz", b"docs/", b"src/main.py"]
        rnd = random.Random(7)
        attempts = honest = 0
        for n in range(1, 7):
            for trial in range(1 if n < 3 else 2):
                keys = sorted(rnd.sample(pool, n))
                leaves = [enc_entry(k, 1, 1, i + 1) for i, k in enumerate(keys)]
                hs = [leaf_hash(l) for l in leaves]
                root = mth(hs, 0, n)
                paths = [[x.hex() for x in audit_path(hs, i)] for i in range(n)]
                opts = [None]
                seen = set()
                for j in range(n):
                    for idx in range(n):
                        for src in {j, idx}:
                            key = (j, idx, src)
                            if key not in seen:
                                seen.add(key)
                                opts.append({"idx": idx, "leaf": leaves[j].hex(), "path": paths[src]})
                bounds = sorted(set(keys + [k + b"\0" for k in keys] + [b"", b"~"]))
                for lo in bounds:
                    for hi in bounds:
                        if not lo < hi:
                            continue
                        nonempty = any(lo <= k < hi for k in keys)
                        if nonempty:
                            for p in opts:
                                for s in opts:
                                    attempts += 1
                                    if check_empty(n, root, {"pred": p, "succ": s}, lo, hi):
                                        self.fail(f"FORGERY ACCEPTED n={n} range={lo!r}..{hi!r} pred={p} succ={s}")
                        else:
                            i = bisect.bisect_left(keys, lo)
                            pr = {"idx": i - 1, "leaf": leaves[i - 1].hex(), "path": paths[i - 1]} if i > 0 else None
                            su = {"idx": i, "leaf": leaves[i].hex(), "path": paths[i]} if i < n else None
                            self.assertTrue(check_empty(n, root, {"pred": pr, "succ": su}, lo, hi))
                            honest += 1
        STATS["forgery_attempts"], STATS["honest_proofs_verified"] = attempts, honest
        self.assertGreater(attempts, 100000)

    def test_bitflip_fuzz(self):
        tmp, bs, ws, br = mk()
        br.read("docs/notes.txt"); br.seal(); br.read("src/main.py"); br.seal()
        lo, hi = subtree("finance")
        raw = json.dumps(br.prove_empty(lo, hi, 0, 1), sort_keys=True, separators=(",", ":")).encode()
        def norm(o):
            if isinstance(o, str): return o.lower()
            if isinstance(o, dict): return {k: norm(v) for k, v in o.items()}
            if isinstance(o, list): return [norm(v) for v in o]
            return o
        base = norm(json.loads(raw))
        total = rejected = benign = 0
        bad = []
        for pos in range(len(raw)):
            for bit in range(8):
                m = bytearray(raw); m[pos] ^= 1 << bit; total += 1
                try:
                    obj = json.loads(bytes(m).decode())
                    verify_alibi(obj, bs.pub, ws.signer.pub, lo, hi, (0, 1))
                except (AlibiError, ValueError, UnicodeDecodeError):
                    rejected += 1; continue
                if norm(obj) == base: benign += 1          # hex upper/lower-case: identical bytes
                else: bad.append((pos, bit))
        STATS["fuzz"] = (len(raw), total, rejected, benign, len(bad))
        self.assertEqual(bad, [])

    def test_wrong_keys_queries_coverage(self):
        tmp, bs, ws, br = mk()
        br.read("docs/notes.txt"); br.seal(); br.seal()
        lo, hi = subtree("finance")
        b = br.prove_empty(lo, hi, 0, 1)
        ok = lambda **k: verify_alibi(k.get("b", b), k.get("bp", bs.pub), k.get("wp", ws.signer.pub),
                                      k.get("lo", lo), k.get("hi", hi), k.get("ep", (0, 1)))
        ok()
        with self.assertRaises(AlibiError): ok(bp=Signer().pub)            # wrong broker
        with self.assertRaises(AlibiError): ok(wp=Signer().pub)            # wrong witness
        with self.assertRaises(AlibiError): ok(lo=subtree("secrets")[0], hi=subtree("secrets")[1])  # other query
        with self.assertRaises(AlibiError): ok(ep=(0, 2))                  # claims more epochs than proven
        with self.assertRaises(AlibiError): ok(ep=(1, 1))                  # coverage mismatch
        b2 = json.loads(json.dumps(b)); b2["epochs"].pop(0)
        with self.assertRaises(AlibiError): ok(b=b2, ep=(0, 1))            # dropped epoch
        b3 = json.loads(json.dumps(b)); b3["epochs"][1]["cp"]["prev"] = "11" * 32
        with self.assertRaises(AlibiError): ok(b=b3)                       # broken chain

class Witnessing(unittest.TestCase):
    def _cp(self, bs, leaves, **kw):
        hs = [leaf_hash(l) for l in leaves]
        cp = {"v": 1, "broker": bs.pub.hex(), "epoch": 0, "prev": "00" * 32, "size": len(leaves),
              "root": mth(hs, 0, len(hs)).hex(), "events": len(leaves), "seq_lo": 1, "seq_hi": len(leaves)}
        cp.update(kw)
        return cp, bs.sign(DOM_B, canon(cp))

    def test_unsorted_tree_refused(self):
        """A broker that builds an unsorted tree could hide a key behind a fake adjacency."""
        bs, ws = Signer(), Witness()
        L = [enc_entry(b"zzz", 1, 1, 1), enc_entry(b"finance/x", 1, 1, 2)]   # not sorted
        cp, sig = self._cp(bs, L)
        with self.assertRaises(WitnessRefused): ws.cosign(cp, sig, L)

    def test_equivocation_refused(self):
        tmp, bs, ws, br = mk()
        br.read("finance/q3.xlsx"); cp = br.seal()
        alt, sig = self._cp(bs, [], seq_lo=1, seq_hi=0, events=0)            # same epoch, "nothing happened"
        with self.assertRaises(WitnessRefused): ws.cosign(alt, sig, [])
        # presenting the alt checkpoint with the real witness signature fails verification
        b = br.sealed[0]
        fake = {"query": {"lo": subtree("finance")[0].hex(), "hi": subtree("finance")[1].hex()},
                "epochs": [{"cp": alt, "sig": sig.hex(), "wsig": b["wsig"].hex(),
                            "proof": {"pred": None, "succ": None}}]}
        with self.assertRaises(AlibiError):
            verify_alibi(fake, bs.pub, ws.signer.pub, *subtree("finance"), (0, 0))

    def test_gap_rollback_and_seq_gap_refused(self):
        tmp, bs, ws, br = mk()
        br.seal()
        cp, sig = self._cp(bs, [], epoch=5, prev="00" * 32, seq_lo=1, seq_hi=0, events=0)
        with self.assertRaises(WitnessRefused): ws.cosign(cp, sig, [])        # epoch gap
        cp, sig = self._cp(bs, [], epoch=1, prev=cp_hash(br.sealed[0]["cp"]).hex(), seq_lo=9, seq_hi=8, events=0)
        with self.assertRaises(WitnessRefused): ws.cosign(cp, sig, [])        # sequence gap

    def test_spliced_histories_rejected_despite_valid_signatures(self):
        """Witness amnesia: same witness key, wiped state -> it signs a forked history.
        Attacker splices a CLEAN epoch 0 over the incriminating one. Every signature is
        valid; only the hash-chain linkage exposes the splice."""
        seed, wseed = bytes(range(32)), bytes(range(1, 33))
        def history(touch_finance):
            tmp = tempfile.mkdtemp(); alibi._sandbox(tmp)
            bs, ws = Signer(seed), Witness(Signer(wseed))
            br = Broker(tmp, bs, ws)
            br.read("finance/q3.xlsx" if touch_finance else "docs/notes.txt"); br.seal()
            br.read("docs/notes.txt"); br.seal()
            return br, bs, ws
        A, B = history(False), history(True)
        lo, hi = subtree("finance")
        with self.assertRaises(NotEmpty):
            B[0].prove_empty(lo, hi, 0, 1)                       # truth: finance WAS touched
        a, b = A[0].prove_empty(lo, hi, 0, 1), B[0].prove_empty(lo, hi, 1, 1)
        spliced = {"query": a["query"], "epochs": [a["epochs"][0], b["epochs"][0]]}
        with self.assertRaises(AlibiError):
            verify_alibi(spliced, A[1].pub, A[2].signer.pub, lo, hi, (0, 1))

    def test_KNOWN_LIMIT_lying_broker(self):
        """Documents what Alibi does NOT stop: a broker that simply never logs an access."""
        tmp, bs, ws, br = mk()
        br._record = lambda key, mask: None            # malicious/buggy broker silently skips logging
        br.read("finance/q3.xlsx"); br.seal()
        lo, hi = subtree("finance")
        info = verify_alibi(br.prove_empty(lo, hi, 0, 0), bs.pub, ws.signer.pub, lo, hi, (0, 0))
        self.assertEqual(info["events_covered"], 0)    # verifies falsely -> broker must be trusted/attested

class Hostile(unittest.TestCase):
    def test_symlink_traversal_outside(self):
        tmp, bs, ws, br = mk()
        os.symlink("../finance/tax/2025.pdf", os.path.join(tmp, "docs", "innocent.txt"))
        self.assertEqual(br.read("docs/innocent.txt"), b"TAX ...")
        for p in ("../../etc/hostname", "/etc/hostname", "docs/../../x"):
            with self.assertRaises(PermissionError): br.read(p)
        br.seal()
        with self.assertRaises(NotEmpty): br.prove_empty(*subtree("finance"), 0, 0)
        keys = [dec_entry(l)[0] for l in br.sealed[0]["leaves"]]
        self.assertIn(b"finance/tax/2025.pdf", keys)
        self.assertIn(OUTSIDE, keys)

    def test_toctou_race_detected(self):
        tmp, bs, ws, br = mk()
        os.makedirs(os.path.join(tmp, "pub")); pathlib.Path(tmp, "pub", "file.txt").write_bytes(b"harmless")
        pathlib.Path(tmp, "finance", "file.txt").write_bytes(b"SECRET")
        def swap(p):
            os.rename(os.path.join(tmp, "pub"), os.path.join(tmp, "pub_real"))
            os.symlink(os.path.join(tmp, "finance"), os.path.join(tmp, "pub"))
        br._pre_open_hook = swap
        with self.assertRaises(PermissionError):
            br.read("pub/file.txt")                     # data must NOT be released
        br.seal()
        keys = [dec_entry(l)[0] for l in br.sealed[0]["leaves"]]
        self.assertIn(b"finance/file.txt", keys)        # what was REALLY opened is on record
        with self.assertRaises(NotEmpty): br.prove_empty(*subtree("finance"), 0, 0)

    def test_fail_closed_when_log_unwritable(self):
        tmp = tempfile.mkdtemp(); alibi._sandbox(tmp)
        jp = os.path.join(tmp, "j.log")
        br = Broker(tmp, Signer(), Witness(), journal=jp)
        os.close(br._jfd)                               # disk "fails"
        with self.assertRaises(OSError): br.read("docs/notes.txt")
        self.assertEqual(br.cur, {})
        self.assertEqual(br.seq, 0)

    def test_concurrency_completeness(self):
        tmp = tempfile.mkdtemp(); alibi._sandbox(tmp)
        bs, ws = Signer(), Witness()
        br = Broker(tmp, bs, ws, deny=["secrets/"], journal=os.path.join(tmp, "j.log"))
        targets = [("r", "docs/notes.txt"), ("r", "src/main.py"), ("r", "finance/q3.xlsx"), ("r", "nope/missing.txt"),
                   ("r", "secrets/.env"), ("l", "docs"), ("l", "."), ("r", "../escape"), ("l", "src")]
        lock, attempted, count, errs, stop = threading.Lock(), set(), [0], [], threading.Event()
        def gt(op, rel):
            if rel.startswith(".."): return OUTSIDE
            if op == "l": return (b"" if rel == "." else rel.encode()) + b"/"
            return rel.encode()
        def worker(seed):
            r = random.Random(seed)
            for _ in range(120):
                op, rel = r.choice(targets + [("w", f"out/w{seed}.txt")])
                try:
                    (br.read(rel) if op == "r" else br.listdir(rel) if op == "l" else br.write(rel, b"x"))
                except (PermissionError, FileNotFoundError, IsADirectoryError, NotADirectoryError):
                    pass
                with lock:
                    attempted.add(gt(op, rel)); count[0] += 1
        def sealer():
            while not stop.is_set():
                try: br.seal()
                except Exception as e: errs.append(e)
                stop.wait(0.02)
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        st = threading.Thread(target=sealer); st.start()
        [t.start() for t in ts]; [t.join() for t in ts]
        stop.set(); st.join(); br.seal()
        self.assertEqual(errs, [])
        committed, events, prev_hi = set(), 0, 0
        for e in sorted(br.sealed):
            cp = br.sealed[e]["cp"]
            self.assertEqual(cp["seq_lo"], prev_hi + 1); prev_hi = cp["seq_hi"]
            events += cp["events"]
            committed |= {dec_entry(l)[0] for l in br.sealed[e]["leaves"]}
        # every attempt is committed (denied/blocked ones too, plus extra records from none here)
        self.assertEqual(events, count[0])
        self.assertEqual(committed, attempted)
        STATS["concurrency"] = (len(br.sealed), count[0])
        lo, hi = subtree("finance")
        with self.assertRaises(NotEmpty): br.prove_empty(lo, hi, 0, max(br.sealed))

class Crash(unittest.TestCase):
    SEED = bytes(range(32))
    def _run(self, tmp, jp, body):
        code = (f"import os,sys\nsys.path.insert(0,{HERE!r})\nfrom alibi import *\n"
                f"br=Broker({tmp!r},Signer({self.SEED!r}),Witness(),journal={jp!r})\n{body}\n")
        return subprocess.run([sys.executable, "-c", code], capture_output=True).returncode

    def test_crash_after_release_is_recorded(self):
        tmp = tempfile.mkdtemp(); alibi._sandbox(tmp); jp = os.path.join(tmp, "j.log")
        self.assertEqual(self._run(tmp, jp, "d=br.read('finance/q3.xlsx')\nos._exit(7)"), 7)
        br2 = Broker(tmp, Signer(self.SEED), Witness(), journal=jp); br2.seal()
        self.assertIn(b"finance/q3.xlsx", [dec_entry(l)[0] for l in br2.sealed[0]["leaves"]])

    def test_crash_between_record_and_release(self):
        tmp = tempfile.mkdtemp(); alibi._sandbox(tmp); jp = os.path.join(tmp, "j.log")
        rc = self._run(tmp, jp, "br._pre_open_hook=lambda p: os._exit(9)\nbr.read('finance/q3.xlsx')")
        self.assertEqual(rc, 9)
        br2 = Broker(tmp, Signer(self.SEED), Witness(), journal=jp); br2.seal()
        self.assertIn(b"finance/q3.xlsx", [dec_entry(l)[0] for l in br2.sealed[0]["leaves"]])

    def test_torn_journal_tail_survives(self):
        tmp = tempfile.mkdtemp(); alibi._sandbox(tmp); jp = os.path.join(tmp, "j.log")
        self.assertEqual(self._run(tmp, jp, "br.read('docs/notes.txt')\nos._exit(3)"), 3)
        with open(jp, "ab") as f: f.write(b'{"t":"e","seq":2,"k":"66')           # torn write
        br2 = Broker(tmp, Signer(self.SEED), Witness(), journal=jp)
        br2.read("src/main.py"); br2.seal()                                        # journal still appendable
        keys = [dec_entry(l)[0] for l in br2.sealed[0]["leaves"]]
        self.assertEqual(keys, [b"docs/notes.txt", b"src/main.py"])
        br3 = Broker(tmp, Signer(self.SEED), Witness(), journal=jp)               # second recovery is clean
        self.assertEqual(br3.epoch, 1)

    def test_crash_after_witness_before_journal_is_idempotent(self):
        tmp = tempfile.mkdtemp(); alibi._sandbox(tmp); jp = os.path.join(tmp, "j.log")
        ws = Witness()
        b1 = Broker(tmp, Signer(self.SEED), ws, journal=jp)
        b1.read("docs/notes.txt")
        orig = b1._jwrite
        def boom(o):
            if o["t"] == "s": raise OSError("crash")
            orig(o)
        b1._jwrite = boom
        with self.assertRaises(OSError): b1.seal()                                # witness already co-signed epoch 0
        self.assertEqual(ws.heads[b1.signer.pub.hex()][0], 0)
        b2 = Broker(tmp, Signer(self.SEED), ws, journal=jp)                        # same witness remembers
        cp = b2.seal()                                                             # deterministic re-seal
        self.assertEqual(cp["epoch"], 0)

if __name__ == "__main__":
    res = unittest.main(exit=False, verbosity=2)
    print("\nMEASURED:", json.dumps(STATS, default=str))
    sys.exit(0 if res.result.wasSuccessful() else 1)