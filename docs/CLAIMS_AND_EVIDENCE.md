# WolfAlibi — claims, evidence, and limits

**Last reviewed:** 2026-11-20  
**Verdict for security-sensitive deployment:** **BLOCKED**  
**Scope:** the baseline code in `alibi.py` and the evidence checked into the `feat/wolfalibi-v0-1` history. Update this matrix whenever the implementation changes.

## Claim ladder

| Claim | Current status | Supporting evidence / limitation |
|---|---|---|
| A witness can cosign a sorted Merkle commitment containing the keys supplied by the broker | **Demonstrated in synthetic unit tests** | `test_alibi.py`; witness recomputes the tree and checks sort order |
| A verifier can check the non-membership of a queried range in that signed committed set | **Demonstrated in synthetic unit tests** | Adjacency and boundary verification; limited to the signed set |
| The supplied baseline passed 21 original tests and caught eight chosen mutants | **Reported and independently reproduced on 2026-11-20** | See `docs/evidence/ORIGINAL_RESULTS.txt` and the WolfTrap review; rerun on your platform |
| All actual filesystem accesses by an AI are captured by the broker | **NOT DEMONSTRATED** | No operational process confinement in the baseline; bypass routes exist |
| An epoch can truthfully certify absence of all data releases/effects that occurred within its time interval | **BROKEN IN BASELINE** | WT-A01 demonstrates in-flight boundary mismatch |
| Two broker instances sharing a journal/signing identity cannot omit each other's operations | **BROKEN IN BASELINE** | WT-A02 demonstrates an omitted financial-file access |
| A forbidden file creation has no outside effects even under parent-directory substitution | **BROKEN IN BASELINE** | WT-A03 demonstrates creation of an empty outside file |
| A released file read remains recorded across a positive short journal write and restart | **BROKEN IN BASELINE** | WT-A04 demonstrates record loss and a false nonaccess proof |
| Witness memory survives loss of process state and prevents persistent signing forks | **NOT DEMONSTRATED** | Baseline witness heads are in process memory |
| An issued receipt is fresh and belongs to a particular user-authorized task | **NOT IMPLEMENTED** | No externally checked challenge, run identity, or execution attestation |
| A signed statement proves the AI did not access a resource by *any means* | **NOT SUPPORTED** | Even a flawless Merkle proof over an incomplete event set cannot prove this |

## A precise, modest prototype statement

> Given externally trusted broker and witness public keys, a specified key interval and a specified set of epochs, the verifier checks signatures, sequential checkpoint linkage, and Merkle exclusion of keys from the broker-supplied, witness-cosigned commitment.

This is **not** equivalent to saying that every access was recorded, that the broker itself was honest, or that the AI had no other capability to reach the resource. A witness checking a list supplied by the broker is independent as a signer, **not necessarily independent as an observer**.

## Honest failure words

- `VERIFIED`: the specified claim was checked under an explicitly supported, satisfied assurance level and externally supplied expectations.
- `REJECTED`: evidence contradicts or fails validation.
- `BLOCKED`: required assurance (for example trusted confinement, journal completeness, freshness or witness state) could not be established.
- `UNKNOWN`: information required to judge the claim is unavailable; never map to a clean certificate.

These are **target** receipt outcomes, not an assertion that the current CLI implements them.

## Evidence index

- `alibi.py`, `test_alibi.py`, `mutation_test.py` — baseline engine and authored tests.
- `test_wolftrap_alibi.py` — four new red-team regression tests.
- `docs/security/WOLFTRAP_ALIBI_001.md` — independent local analysis, reproduction, proposed repairs.
- `docs/evidence/ORIGINAL_RESULTS.txt` — reported baseline output.
- `docs/evidence/WOLFTRAP_ALIBI_TEST_RESULTS.txt` — reproduced hostile failures.

## Updating this page

Every promoted claim needs: exact commit, exact commands, test environment (OS, Python, kernel and dependencies), independently inspectable proof artifacts, adversary/coverage assumptions, and negative counterexamples. **No green badge based on a test being skipped.** Performance claims require a specified dataset and measurement method.

**Security rule:** signatures authenticate statements; they do not make incomplete statements true.
