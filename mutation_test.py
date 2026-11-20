"""Sabotage alibi.py in 8 security-critical ways; the test suite must fail on every one."""
import os, re, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "alibi.py")).read()
M = {
 "M1 drop adjacency check (succ == pred+1)": ("return ks == ip + 1", "return True"),
 "M2 drop succ >= hi boundary check": ("if s is None or not (s[1] >= hi):", "if s is None:"),
 "M3 drop Merkle domain separation": ('def leaf_hash(d): return H(b"\\x00" + d)\ndef node_hash(l, r): return H(b"\\x01" + l + r)', 'def leaf_hash(d): return H(d)\ndef node_hash(l, r): return H(l + r)'),
 "M4 witness skips sortedness check": ("if last is not None and not (last < k):", "if False:"),
 "M5 verifier skips witness co-signature": ('if not verify_sig(witness_pub, DOM_W, cpb, bytes.fromhex(e["wsig"])):', "if False:"),
 "M6 verifier skips epoch-coverage check": ('if [e["cp"]["epoch"] for e in eps] != list(range(a, b + 1)):', "if False:"),
 "M7 broker skips post-open race check": ("if actual != p:", "if False:"),
 "M8 verifier skips hash-chain linkage": ('if prev is not None and cp["prev"] != prev.hex():', "if False:"),
}
caught = 0
for name, (old, new) in M.items():
    assert old in src, name
    d = tempfile.mkdtemp()
    open(f"{d}/alibi.py", "w").write(src.replace(old, new, 1))
    shutil.copy(os.path.join(HERE, "test_alibi.py"), d)
    r = subprocess.run([sys.executable, "test_alibi.py"], cwd=d, capture_output=True, text=True)
    failed = sorted(set(re.findall(r"^(?:FAIL|ERROR): (\w+)", r.stderr + r.stdout, re.M)))
    caught += bool(r.returncode)
    print(f"{'CAUGHT  ' if r.returncode else 'SURVIVED'} {name} -> {', '.join(failed) or '-'}")
print(f"\n{caught}/{len(M)} mutants caught")