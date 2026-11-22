"""Sabotage alibi.py in 8 security-critical ways; the test suite must fail on every one."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
src = (Path(HERE) / "alibi.py").read_text()
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
# Expected assertions are pinned to the original regression source and archived observations.
ORACLES = {
    "M1": ("test_exhaustive_forgery_search", "AssertionError: FORGERY ACCEPTED"),
    "M2": ("test_exhaustive_forgery_search", "AssertionError: FORGERY ACCEPTED"),
    "M3": ("test_known_merkle_vectors", "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
    "M4": ("test_unsorted_tree_refused", "WitnessRefused not raised"),
    "M5": ("test_wrong_keys_queries_coverage", "ok(wp=Signer().pub)"),
    "M6": ("test_wrong_keys_queries_coverage", "ok(ep=(0, 2))"),
    "M7": ("test_toctou_race_detected", "PermissionError not raised"),
    "M8": ("test_spliced_histories_rejected_despite_valid_signatures", "AlibiError not raised"),
}


def designated_failure(result, case, count):
    test, marker = ORACLES[case]
    log = result.stderr
    if (result.returncode != 1 or f"Ran {count} test" not in log or
            not re.search(r"^FAILED \(failures=\d+\)$", log, re.M)):
        return False
    for section in log.split("=" * 70):
        if (section.startswith("\nFAIL: " + test + " (") and marker in section
                and "\nAssertionError:" in section):
            return True
    return False


def run(source, args):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "alibi.py"
        path.write_text(source)
        shutil.copyfile(Path(HERE) / "test_alibi.py", path.with_name("test_alibi.py"))
        result = subprocess.run([sys.executable, "-B", *args], cwd=directory, capture_output=True,
                                text=True, timeout=180)
        return result, hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    vector_only = sys.argv[1:] == ["--known-vector"]
    if sys.argv[1:] and not vector_only:
        raise SystemExit("unrecognized arguments")
    args = ["-m", "unittest", "-v", "test_alibi.Crypto.test_known_merkle_vectors"] if vector_only else ["test_alibi.py"]
    count = 1 if vector_only else 21
    baseline, original = run(src, args)
    if baseline.returncode or f"Ran {count} test" not in baseline.stderr or not baseline.stderr.rstrip().endswith("\nOK"):
        print(baseline.stderr)
        return 2
    caught = attempted = 0
    for name, (old, new) in M.items():
        case = name.split()[0]
        if vector_only and case != "M3":
            continue
        attempted += 1
        if src.count(old) != 1:
            raise ValueError(f"mutation site changed for {case}")
        result, modified = run(src.replace(old, new, 1), args)
        detected = modified != original and designated_failure(result, case, count)
        caught += int(detected)
        print(json.dumps({"case": case, "original_sha256": original, "modified_sha256": modified,
                          "baseline": vars(baseline), "mutant": vars(result), "expected": ORACLES[case],
                          "detected": detected}))
        print(f"{'CAUGHT  ' if detected else 'UNCONFIRMED'} {name} -> {ORACLES[case][0]}")
    print(f"{caught}/{attempted} mutants caught")
    return int(caught != attempted)


if __name__ == "__main__":
    sys.exit(main())
