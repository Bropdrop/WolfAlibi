# WolfAlibi BYOA SOLITARY — qualification profile v1

> **Design proposal, not implemented or independently qualified.** This profile is deliberately narrower than a general sandbox for hostile code. Follow [Issue #15](https://github.com/Bropdrop/WolfAlibi/issues/15) for the synthetic acceptance matrix.

## Product contract

An engineer brings an **authorized**, user-owned agent and synthetic test corpus. BYOA asks for explicit execution permission, inventories the declared resource and tool surfaces, starts a constrained worker, and reports:

- What **agent hooks** observed (`OBSERVATIONAL_ONLY`).
- What the **broker journal** records and a witnessed proof verifies (`BROKER_ONLY`).
- What **actual supervisor/kernel enforcement** has been measured (a separate qualification result).
- What was **not** monitored or has no adequate evidence (`UNKNOWN` or `BLOCKED`).

These are **separate evidence planes**. Never convert partial observations into a universal claim that the agent did not touch any resource.

## Planned developer commands (not yet available)

```text
wolfalibi byoa doctor
wolfalibi byoa inspect --manifest agent.json
wolfalibi byoa test --manifest agent.json --profile solitary-synthetic
wolfalibi byoa verify --evidence ./local-evidence.json --expect ./expected-run.json
```

`doctor` reports platform prerequisites without executing agent code. `inspect` reports what modules/tools/capabilities were *declared* and should not import them. The test command must require explicit consent, and a *separate* agreement to execute operator-supplied code; consent to run does not imply consent to upload data. Verification takes independent expectations, not a self-authorizing receipt.

## Execution architecture

```text
Operator-approved test manifest + synthetic corpus
    |
    v
Preflight: kernel capabilities / launcher profile / resource limits
    |
    v
Trusted supervisor --------> independent verifier expectations
    |                                    |
    +---- fresh run challenge ----------+
    |
    +--- pinned worker code / process scope / measured controls
    |       |
    |       v
    |   isolated agent --ONLY declared mediated requests--> broker socket
    |                                                      |
    |                                                      v
    |                                     WAL before data/effect release
    |                                                      |
    +------ terminal scope closure ------------------------+
                                 |
                         durable witness record
                                 |
                         offline verifier + evidence
```

### Required cell properties

1. **No ambient secrets or sensitive mounts.** No host home, credential store, SSH agent, cloud metadata endpoint, private source or unexpected file descriptor. Runtime artifacts pinned/read-only; new isolated scratch. Network disabled by default, including inherited connected sockets.
2. **Kernel enforcement for declared resources.** Explicit Linux mount/user/PID/net/IPC/UTS namespaces and capability reduction, appropriately scoped Landlock/seccomp where actually installed, fd-anchored broker resolution. Record **effective** controls, not just requested CLI flags. Unsupported host -> `UNSUPPORTED` / `BLOCKED`.
3. **Only declared broker interactions.** Per-run, length-bounded IPC with strict operations, sequence, identity, anti-replay, denial semantics and no ancillary descriptor passing; no unaccounted protected releases or write side effects.
4. **Controlled lifecycle.** Resource-limited worker/process scope (CPU, memory, PID, file size, time). No successful terminal result until process scope empty, sockets closed, requests drained and all witness checkpoints durable. Mere parent exit or EOF is insufficient for general agents.
5. **Independent expectation and witness custody.** Verifier-controlled issued challenge and transactional consumption; expected signing keys/policy/scope retained separately; witness history continuation validated from an independently held authenticated head.
6. **Hostile arbitrary-code boundary.** A namespace/Bubblewrap profile is not a sufficient blanket promise for hostile third-party code. Evaluate stronger microVM/hypervisor separation before shipping an `UNTRUSTED_AGENT_CELL` profile.

### Assurance vocabulary

`OBSERVE_ONLY` = explicitly wrapped tool observations; no confinement claim.

`SYNTHETIC_CELL_CANDIDATE` = preliminary measured Linux synthetic test results. **Not** a security assurance upgrade.

`BROKER_ONLY` = cryptographic verification of specified mediated broker events under its explicit trusted-component assumptions.

`CONFINED_DECLARED_SCOPE` = reserved future assurance; only after complete declared-resource mediation, effective kernel controls, closed-run lifecycle, separate verifier expectations and independent hostile qualification are reproduced. **Not currently emitted.**

`BLOCKED` = any mandatory evidence absent, stale, contradictory or unsupported. A blocked result is a correct security outcome.

## Minimum adversarial test suite

| Group | Positive test | Negative/hostile test |
|---|---|---|
| Broker IPC | authorized synthetic read is WAL-recorded and delivered | wrong run, replay, duplicate, malformed packet, FD ancillary message, timeout |
| Direct filesystem | permitted scratch read | direct protected open, alias, symlink, hardlink, `/proc/self/fd`, inherited canary FD |
| Network and secrets | local stub via explicitly mediated adapter | no outbound socket or inherited token/env; synthetic local endpoint only |
| Process and quotas | fixed agent runs and all processes exit | fork/exec after measurement, descendant escapes, busy loop, memory/PID exhaustion |
| Journal and witness | durable record, signed checkpoint, offline proof | WAL failure before release, witness unavailable, crash, spliced/rolled-back head |
| Timing and attestation | supervisor and kernel observations bound to nonce | swap program, change mount/descriptor after sample, falsely self-report denial |
| Verifier | accept fresh challenge, advance independent head | replay, concurrent duplicate, expired challenge, stale anchor, incomplete close |
| Claim semantics | disjoint exclusion proof verifies under declared scope | in-range read or denied attempt prevents negative proof if attempts included |

Tests are limited to **owned local synthetic resources**. No scanning external systems or testing unrelated security targets. Record exact commit/tree, OS/kernel, Bubblewrap, dependencies, control profile, expected/observed resource effects and any skipped/unsupported cases.

## Privacy and optional research intelligence

The AgentProbe branch already records only categorical outcomes and coarse timing when explicitly enabled. Raw prompts, tool arguments, contents, credentials, customer data, filesystem paths and exception messages are excluded from the observer report. This design does **not** add automatic telemetry or remote collection. Sharing anonymized summaries requires a separate per-report opt-in and a published retention/deletion policy.

**Product promise:** bring your agent, test a declared synthetic boundary, receive an honest verdict and evidence. Not an unqualified promise that every possible attack or access has been prevented.
