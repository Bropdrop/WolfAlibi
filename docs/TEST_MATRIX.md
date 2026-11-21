# WolfAlibi test and challenge matrix

**Scope:** research baseline and proposed qualifications. Counts in earlier evidence files are not current head status.

| ID | Test family | Baseline evidence | Necessary before elevated assurance |
|---|---|---|---|
| B-01 | Merkle RFC-6962 vectors and inclusion paths | Authored tests passed | Preserve known vectors across refactor |
| B-02 | Exhaustive small-tree predecessor/successor forgery search | Authored tests passed; >1 million combinations in independent review | Additional adversarial malformed proofs |
| B-03 | Witness signature, epoch-coverage and chain linkage | Authored tests passed | External challenge/run binding and persistent witness checks |
| B-04 | Eight mutation-injected security defects | 8/8 caught in supplied baseline review | Expand mutants targeting new primitives |
| WT-A01 | Epoch straddling a data release | **Failing baseline** | Data release is counted in every affected verified interval |
| WT-A02 | Duplicate brokers sharing a signing identity and journal | **Failing baseline** | Refuse duplicate writer or independently establish complete combined order |
| WT-A03 | Parent-directory substitution on file creation | **Failing baseline** | Forbidden side effects never occur |
| WT-A04 | Partial journal write + restart | **Failing baseline** | Released accesses remain recoverable |
| C-01 | Direct system call bypass of broker | Not implemented | Process-level confinement demonstrated |
| C-02 | Inherited fd, subprocess, bind mount, hard-link and symlink aliases | Not comprehensively tested | Bypass matrix with results for supported Linux kernel |
| W-01 | Witness restart, fork/rollback, reset, key reuse | In-memory baseline only | Durable witness and independent state verification |
| R-01 | Wrong challenge, run, policy, expected keys, scope, interval | No portable receipt yet | Offline verifier rejects substitutions |
| R-02 | Privacy leakage in neighbor proofs / event counts | Known by design | Disclosure contract and verified optional privacy upgrades |
| E-01 | Crash at each release/logging/witness/checkpoint boundary | Partial authored coverage | Deterministic fault injection and proof semantics |
| P-01 | Performance across event cardinality / epoch count / key distribution | Baseline benchmark reported, environment-specific | Reproducible method and independent measurements |

## Reproduce before promoting a claim

```bash
python3 -m unittest -v test_alibi.py
python3 -m unittest -v test_wolftrap_alibi.py
python3 mutation_test.py
python3 alibi.py demo
```

All results must include exact commit SHA and environment. The correct outcome for unsupported features is `BLOCKED` / `NOT IMPLEMENTED`, not pass by test omission.

## What makes a useful contribution

A new test is strongest when it demonstrates a specific violated invariant on the parent commit, isolates the effect with synthetic resources, and then succeeds after a focused repair. Test both **data released** and **side effects performed** rather than just raised exceptions.

See [claims and evidence](CLAIMS_AND_EVIDENCE.md) for public assertions that cannot be made yet.
