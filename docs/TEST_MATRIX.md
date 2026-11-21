# WolfAlibi qualification matrix

**Baseline:** `dd7c5c76cadc49ab464f14abdbf77269ca735291` (Stage 1).  
**Published Stage 2:** `37b277521041d68fa81748d41824e4c8bb66a592`.

| ID | Property | Evidence at Stage 2 | Next required evidence |
|---|---|---|---|
| WT-A01 | Closing an epoch doesn't omit in-flight data releases | Reported regression PASS | Independent concurrency/race scheduling audit |
| WT-A02 | No live split-brain journal writer | Reported regression PASS | Cross-process and recovery stress on supported filesystems |
| WT-A03 | Denied path-swap creation has no outside effect | Reported regression PASS | Mount/alias/TOCTOU expansion with local synthetic fixtures |
| WT-A04 | Positive short journal writes do not lose released accesses | Reported regression PASS | Crash/failpoint matrix, storage error recovery |
| M1–M8 | Historical selected mutations are caught | Reported 8/8 caught | Expanded mutation operators for new v2 features |
| CRYPTO | RFC-6962-style proof, adjacency, chain, signatures | Authored unit tests passing | Independent verifier and malformed-input/property test |
| RECEIPT_V1 | Broker-only bounded negative receipt | Implemented | Third-party verification using independent input values |
| RECEIPT_V2 | Signed run, challenge, boundary, resource identity, expected retained witness digest | Reported adversarial tests PASS | External anchor issuance and verification service |
| WITNESS_V2 | Signed local state anchor and expected-digest rollback check | Reported local tests PASS | Independently operated/verifiably retained anchor |
| ISOLATION | Bubblewrap synthetic host marker and FD probes | Limited `DEMONSTRATED` or `BLOCKED` results; always `assurance: BLOCKED` | Sole broker IPC path and full declared capability inventory |
| HARDLINK | Multiple-hardlink regular files refused | Reported local tests PASS | Object identity across mounts and hostile concurrent aliases |
| STAGE3_IPC | Confined worker can only access protected fixtures through broker | Not implemented | Minimal audited broker socket and deny-direct-read tests |
| STAGE3_ID | Actual launched program and end-of-run closure bound to receipt | Not implemented | Trustworthy supervisor measurements and lifecycle proof |
| STAGE3_ANCHOR | Independent verifier sees monotonic witness history | Not implemented | Separate custody and fork/rollback tests |

### Local rerun

```bash
python3 -m unittest discover -v
python3 -m unittest -v test_wolftrap_alibi.py
python3 -u mutation_test.py
python3 alibi.py demo
python3 alibi.py bench 1000000
python3 wolfalibi_cli.py isolation-status
```

Reported Stage 2: 51/51 unit tests, four original WolfTrap cases included, eight of eight selected mutants detected. These observations are not proofs of a universal security property. Add the exact host environment, working-tree state and command logs to independent reproductions.

### Reviewer success criteria

Any accepted negative-access evidence must state **which accesses**, **which resource identities**, **which time interval**, **whose signing keys**, **who retained the expected witness head**, **which code/launcher identity is actually attested**, and **which surfaces are not monitored**.

If any essential field is unknown, the corresponding assurance claim remains `BLOCKED`.
