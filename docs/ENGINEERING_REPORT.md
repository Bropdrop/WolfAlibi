# WolfAlibi v0.1 engineering report

## Scope and verdict

This work was performed on `feat/wolfalibi-v0-1` using only local temporary directories and synthetic fixture data.

**Verdict: BLOCKED for operational security deployment.**

The Stage 1 implementation and its local regression suite pass, but an absence receipt remains `BROKER_ONLY`: no complete real-agent confinement, execution attestation, external witness anchoring, or comprehensive multi-resource mediation is established. Passing these tests must not be treated as authorization to protect secrets or trigger effects.

## Reproduced baseline

Baseline revision: `d930bfd1a319bcee7ec252eb89d74293f038bbfa` (`feat/wolfalibi-v0-1` before this work).

Environment used for baseline and final validation:

- Linux `6.18.57` on `x86_64`
- Python `3.12.14`
- `cryptography 50.0.0`
- Bubblewrap `0.12.0` was present for the optional launcher test

Commands and observed baseline results:

```bash
python3 -m unittest -v test_alibi.py        # 21/21 pass
python3 -m unittest -v test_wolftrap_alibi.py # 4/4 fail, as documented
python3 mutation_test.py                    # 8/8 chosen mutants caught
python3 alibi.py demo                       # completed
python3 alibi.py bench 1000000              # completed
```

The four baseline failures were WT-A01 epoch boundary, WT-A02 shared writer identity, WT-A03 `O_CREAT` directory swap, and WT-A04 short journal write/recovery.

## Implemented changes

| Component | Implemented change |
| --- | --- |
| `alibi.py` broker | Completed-operation admission/quiescence barrier; `openat2` rooted resolution; write symlink rejection; held root descriptor; fail-closed errors. |
| `alibi.py` journal | v2 framed canonical WAL with payload digest, full-write loop, `EINTR` retry, zero-progress rejection, fsync, strict recovery, and exclusive writer leases. |
| `alibi.py` witness | `DurableWitness` with an exclusive state lease, atomic fsynced persistence of checkpoint heads and receipt digests before signatures. |
| `wolfalibi/receipts.py` | Versioned `NEGATIVE_ACCESS_RECEIPT_V1`, requiring a framed broker journal plus `DurableWitness`; explicit run boundaries, signed start boundary, policy/scope/challenge/run/code bindings, and caller-parameterized offline verification. |
| `wolfalibi/isolation.py` | Optional Bubblewrap namespace launcher that intentionally never reports verified confinement. |
| `wolfalibi/adapters.py` | Explicit proposal-only event/adapter/registry interfaces; no API/database adapter is active. |
| `wolfalibi_cli.py` | Synthetic receipt generation, explicit-input verification, and isolation capability status commands. |
| Tests and documentation | Nine new Stage 1 hardening tests, receipt/durable witness tests, extension/CLI/isolation contract tests, architecture, threat model, and updated user/security documentation. |

The original torn-tail recovery test now explicitly closes its recovered broker before constructing a second broker, because the new single-writer lease correctly rejects two live writers.

## Final validation commands

Run from the repository root:

```bash
python3 -m unittest -v test_alibi.py
python3 -m unittest -v test_wolftrap_alibi.py
python3 -m unittest -v test_stage1_hardening.py
python3 -m unittest -v test_receipts.py
python3 -m unittest -v test_extensions.py
python3 -m unittest discover -v
python3 mutation_test.py
python3 alibi.py demo
python3 alibi.py bench 1000000
python3 wolfalibi_cli.py isolation-status
```

Final local results recorded during this implementation:

- Original suite: **21/21 pass**.
- WolfTrap acceptance regressions: **4/4 pass**.
- New Stage 1 hardening regressions: **9/9 pass**.
- Durable witness / receipt regressions: **6/6 pass**.
- Extension, CLI, and isolation-contract regressions: **4/4 pass**.
- Discovery suite: **44/44 pass in 6.894 s**.
- Original mutation harness: **8/8 selected mutants caught**.
- `alibi.py demo` completed; its synthetic symlinked finance read was recorded and refused a negative proof.
- `alibi.py bench 1000000` completed locally: 1,000 keys `0.28 ms` verify, 100,000 keys `0.45 ms`, and 1,000,000 keys: build `1.13 s`, proof `1.39 s`, JSON `3,721 B`, verify `0.32 ms`; these are environment-specific measurements, not a performance claim.
- `wolfalibi_cli.py isolation-status` reported Bubblewrap `READY` with assurance `BLOCKED`; the launcher did not upgrade evidence assurance.

## Remaining work and limitations

- A Bubblewrap child is not yet connected to the broker by an audited sole IPC route; it is never granted `CONFINED_LINUX_VERIFIED` assurance.
- There is no authoritative multiwriter sequencer, remote witness transparency log, independent witness quorum, key rollover protocol, or external checkpoint anchoring.
- A declared code digest is not proof of execution. Fresh challenge issuance/expiration policy is the verifier's responsibility.
- Filesystem proofs remain scoped to this broker API and its configured root/operations; they do not cover direct host access, APIs, databases, memory-mapped resources, inherited handles outside the launcher policy, or a compromised trusted component.
- Adapters for local tools, APIs, and databases are architecture interfaces only and must not be represented as implemented integrations.

The final committed revision is reported by `git rev-parse HEAD` in the implementation handoff, rather than embedded self-referentially in this source document.
