# Stage 3.5 execution evidence and verifier storage

**Engineering verdict is CONDITIONAL for the fixed synthetic worker.** A supervisor checks the live worker before allowing one broker read. The offline verifier checks the broker transcript and a separately signed snapshot against pinned references. A verifier-owned store accepts a transaction against its current head once. Assurance remains `BROKER_ONLY` and confinement qualification remains `BLOCKED`.

The work addresses the distinction between worker assertions and supervisor measurements raised in Issue #9. The Stage 3 worker still reports its direct-open and canary checks in the broker exchange. Stage 3.5 requires a separate supervisor snapshot before the broker can read the fixture. The verifier blocks absent snapshot evidence and rejects invalid signatures, mismatched profiles and inconsistent snapshot values. [Stage 3 qualification plan](STAGE3_QUALIFICATION_PLAN.md) · [Issue #7](https://github.com/Bropdrop/WolfAlibi/issues/7) · [Issue #9](https://github.com/Bropdrop/WolfAlibi/issues/9)

## Expected and observed behavior

| Property | Expected behavior | Observed local result and evidence |
| --- | --- | --- |
| Executable and process identity | Pinned live worker, expected executable digest, contract-matched argv and namespace PID 1 | Supervisor checked Linux proc records using proc directory handles and pidfds. The signed record includes the kernel-observed executable digest, the source digest observed in argv and the measured run arguments. |
| Mounts, permissions and descriptors | A private tmpfs root, exactly the declared read-only runtime mounts, no protected root, distinct namespaces, expected credentials and exactly the broker socket and null output descriptors | Both fixed fixtures completed with two signatures on the broker transcript, a separate supervisor signature, and a verified snapshot. Missing measurement blocked before any response. Inconsistent executable, privilege or descriptor observations failed the validator. |
| Declared fixture and broker operations | Allow one catalog key per run. Refuse unexpected layout or permissions and release no protected bytes before a durable read record. | `protected.txt` and `reports/summary.txt` each passed in a separate sandbox. Alias and permission controls failed before layout approval. Malformed, truncated and ancillary-data requests got no response. A synthetic WAL sync failure prevented file open, response and terminal sealing. A witnessed in-range denial refuted absence over that range. |
| Verifier acceptance | Pin the contract and keys and verify the required supervisor record. Commit the canonical envelope digest, challenge consumption and witness-head advance in one transaction. | The verifier rejected missing or invalid supervisor records for a measured challenge and passed restart, expiry, replay, concurrent duplicate and competing-history tests. An independently retained newer digest rejected a restored database. A transaction failure left both state changes unapplied. |

The live profile works on Linux x86_64 with the fixed Stage 3 Bubblewrap and system CPython layout, `pidfd_open` and supervisor access to the relevant process records. The local run used Linux 6.18.57, Bubblewrap 0.12.0, supervisor CPython 3.12.14, worker CPython 3.13.5 and cryptography 50.0.0. Host policy may block inspection or launch. The command reports the missing evidence and exits with a nonzero status.

## Reproduce

```bash
python3 scripts/qualify_stage35.py > /tmp/wolfalibi-stage35-qualification.json
```

The JSON captures exact commit and tree, environment, test counts and output, mutation results, and the signed transcripts and snapshots for both fixture paths. A skipped required test, dirty tree or changed revision makes exact-tree qualification `BLOCKED`. Read `stage35_tests`, `full_suite`, `mutation_suite` and `trials` for the exact commands and outputs. The tests use synthetic fixtures and local temporary directories.

To run just one measured trial, give it a new private state directory and a fresh nonce.

```bash
state=$(mktemp -d)
challenge=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
python3 -m wolfalibi.stage35 --state-dir "$state" --run-id measured-demo \
  --challenge "$challenge" --key reports/summary.txt
```

The result contains `evidence` for the existing broker transcript, `supervisor_record` for the detached signature, and `measurement_verification` and `fresh_acceptance` for their respective outcomes. `demo_references` permits offline reproduction of this synthetic case. An independent verifier instead obtains the expected contract, keys, prior witness digest and verification time through its own trusted inputs. Supply those inputs to `verify_measured_trial`. [Supervisor and detached record](../wolfalibi/stage35.py) · [Measurement fields and validator](../wolfalibi/stage35_measure.py)

For the transactional path, create `VerifierStore` with `bootstrap_heads` pinned by the verifier, call `issue` with the expected `supervisor_pub`, and call `accept` with the broker transcript and its `supervisor_record`. A measured challenge requires both components. The recorded digest covers the accepted envelope. Issuance without a supervisor key supports the original broker transcript. Retain `head` outside the database, then reopen using `expected_heads`. The default acceptance clock is the verifier host clock. Tests supply explicit time for reproducibility. [Verifier store and transaction](../wolfalibi/stage35_verifier.py) · [Verifier tests](../test_stage35_verifier.py)

## Remaining qualification gates

- The supervisor collects the snapshot in the pre-read gate and signs it with the finished transcript afterward. Ordering relies on the trusted supervisor code path and kernel, without an external timing witness. Argv source is an observation. Continuous execution identity, effective syscall rules, complete descendant closure and a measured process scope need further evidence.
- The fixed corpus covers two paths in separate runs under private, stable directories. The broker policy and snapshot checks cover the declared fixture layout and the measured mounts. Complete mediation over the entire run, alternate copies, concurrent host changes and resource routes outside this test profile remain open.
- The single-store transaction rejects a competing history relative to its retained head. The Stage 3 schema starts each run at fresh witness genesis. Retained heads detect rollback across accepted transitions. A snapshot with only pending-issuance changes can have the same head. Independent custody, multirun continuation, rollback of all retained copies and equivocation across disconnected verifier stores remain open.
- Existing Stage 3 and V1/V2 receipt checks remain valid. This increment preserves the distinction between a broker event, response send, worker acknowledgement and actual byte consumption.
