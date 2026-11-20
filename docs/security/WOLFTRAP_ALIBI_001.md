# WOLFTRAP-ALIBI-001 — Independent Local Security Review

**Date:** 2026-11-20  
**Scope:** User-supplied `alibi.py`, `test_alibi.py`, `mutation_test.py`, `RESULTS.txt`  
**Method:** Source review, original test reproduction, independent synthetic-directory hostile tests; no real data or external systems accessed.

## Decision

**PASS for a limited educational cryptographic prototype; BLOCK for operational claims of complete filesystem nonaccess or trustworthy agent confinement.** The Merkle exclusion and witness signature machinery passed the supplied tests, but four independently reproduced boundary defects allow false nonaccess evidence or unauthorized file creation under the stated test conditions.

## Original tests, independently reproduced

- `python3 alibi.py demo`: expected behavior reproduced; symlink-mediated finance read prevents an epoch 1 nonaccess proof.
- `python3 test_alibi.py`: **21/21 pass**, including 1,088,244 exhaustive small-tree forgery attempts, 11,504 bit-flip attempts, and 960 concurrent API operations in this run. Counts for benign bit flips and sealed epochs vary between runs.
- `python3 mutation_test.py`: **8/8 deliberately introduced mutants detected**. This tests eight chosen weaknesses, not completeness against all attack classes.
- `python3 alibi.py bench 1000000`: 1M-key Merkle build **1.13 seconds**, proof **1.46 seconds**, proof JSON **3,721 bytes**, verify **~0.35 ms** in the independent local execution. The implementation benchmarks proof construction with a linear-time Merkle recomputation; short proofs do not imply constant-time proof generation.

## Additional hostile tests: 4 failures on the uploaded implementation

Run `python3 -m unittest -v test_wolftrap_alibi.py` from the directory containing `alibi.py` and the new test file. **All four fail on the unchanged implementation, as intended.** They are acceptance tests for future hardening, and use only temporary synthetic directories.

### WT-A01 — Epoch boundary false negative

**Impact:** A signed epoch can prove `finance/` empty even though a finance-file read releases data after that epoch begins.

**Root cause:** `Broker._record` holds `self._lock` only for journal logging. `Broker._guarded_open` then opens the file and releases its contents *after* the lock is released (`alibi.py` around lines 253–305). Concurrent `Broker.seal()` can sign epoch 0 after the record is created but before the file is opened/read. Epoch 1 contains no finance record even though the read completes within it.

**Reproduction:** Pause the reader after `_record`, let a separate sealer thread seal epoch 0, resume the reader, seal epoch 1, then verify a `finance/` nonaccess proof for epoch 1. Verification **succeeds falsely** under data-release semantics.

**Repair:** Specify a precise temporal predicate, implement an operation-in-flight quiescence barrier at the seal boundary, and bind the evidence interval to an actual agent run. Alternatively record overlapping in-flight effects in all affected epochs. Preserve pre-release logging and fail-closed behavior.

### WT-A02 — Shared signer/journal identity hides broker access

**Impact:** Two independent broker instances with the same signer and journal can generate a valid checkpoint that excludes an access by one instance.

**Root cause:** Each `Broker` maintains private `cur`, `seq`, and `epoch`, while sharing a single append-only journal and signing identity. There is no cross-process/same-process exclusive writer lease or witness reconciliation of the journal (`alibi.py` around lines 203–258, 309–327). The witness validates the leaf set it was *given*, not the full set in the shared journal.

**Reproduction:** Instance A reads `docs/notes.txt`, instance B reads `finance/q3.xlsx`, and instance A seals epoch 0. A's signed `finance/` nonaccess proof **verifies** even though B read the file. The journal shows both events with duplicate sequence number 1.

**Qualification:** The design describes a single trusted broker. This test exposes a high-risk integration condition **not prevented by the implementation**; fail-fast rejection of a second writer would close this test without supporting multiwriter deployment.

**Repair:** Enforce one live broker per signing key/session/journal (exclusive durable lease and fail-closed recovery) or introduce a central sequencer with transactional event aggregation. The independent witness should anchor a consistent event-log digest and reject concurrent competing sources.

### WT-A03 — Write path race creates an unauthorized outside file

**Impact:** A rejected write can still create a file outside the broker's root before the post-open check notices the change.

**Root cause:** `Broker._guarded_open` uses a `realpath()` check, but later calls `os.open(p, O_CREAT | ...)` on a path whose **parent directory** can be swapped to a symlink. `O_NOFOLLOW` protects only the final component. The subsequent `/proc/self/fd` check catches the escape but occurs after `O_CREAT` has created the target (`alibi.py` around lines 268–285, 300–306).

**Reproduction:** Replace `root/pub` with a symlink to an unrelated temporary directory immediately before `os.open`. `br.write('pub/new.txt', b'SECRET')` raises `PermissionError` but still leaves `outside/new.txt` as an **empty unauthorized file**. The payload bytes were not written in this test.

**Repair:** Anchor traversal to trusted directory handles, use suitable Linux path-resolution controls and OS-level confinement, and guarantee that path-validation and creation cannot cross the boundary. Regression-test side effects, not only return values.

### WT-A04 — Partial journal write followed by restart yields false negative

**Impact:** If `os.write` returns a positive short write, the broker fsyncs and releases finance data even though the event was not fully journaled. On restart, recovery drops the truncated line; a witness then signs an empty epoch and a false `finance/` nonaccess proof verifies.

**Root cause:** `_jwrite` performs one `os.write()` without checking the returned byte count or retrying (`alibi.py` around lines 219–223). `_recover` unconditionally discards a final unterminated line (`alibi.py` around lines 225–241). These two behaviors combine into silent event loss on a legitimate short-write return.

**Reproduction:** Fault-inject an `os.write` that writes and reports 15 bytes without an exception. `br.read('finance/q3.xlsx')` returns the file contents; reconstruct the broker, seal, and verify `finance/` empty for epoch 0. The proof **verifies falsely**. This is a fault-injection test, not a claim that the local filesystem spontaneously produced a short write in the ordinary runs.

**Repair:** Write full records in a checked loop, retry interrupted writes, reject zero-progress and errors, fsync before effects, and recover only from complete authenticated journal records. Add repeated crash/fault-injection at each write offset.

## Pre-existing limits openly acknowledged by the uploaded implementation

1. The real AI process is not confined to the broker. Direct filesystem access or ambient credentials bypass the proof entirely. The demo uses a scripted agent, not an LLM.
2. The witness is in-memory; its `heads` state is not durable, and resetting it can permit forked history until an independently anchored head is consulted.
3. Proof verification depends on caller-supplied expected epoch range and trusted keys; there is no built-in freshness challenge or attested binding between a checkpoint and a specific user-requested run.
4. The proof reveals adjacency leaf metadata and aggregate event counts; it is not a blanket zero-knowledge claim.

## Release acceptance gates

1. Formalize **what nonaccess means**: which actor, objects, operations (including denial and side effects), and start/end time boundaries are covered.
2. Enforce real confinement, credential isolation and a sole mediated filesystem route. The broker alone is insufficient.
3. Make event recording durable, verify write lengths and recovery, close the in-flight epoch race, and prevent multiple writers sharing one identity from producing partial seals.
4. Make protected writes side-effect-free when blocked, even under mutable-directory path races.
5. Persist witness state independently and bind root/epoch history to an attested fresh run.
6. Keep **21/21 original tests green**, **8/8 target mutants caught**, and get **4/4 new WolfTrap tests green**. Add real process-level contention and power-loss simulations before any production use.

**Summary:** The innovation is promising: privacy-preserving *negative provenance* for mediated accesses. The existing implementation demonstrates the cryptographic proof technique, but its operational safety claim is not yet sound. The four attached hostile regression failures show where to harden it next.