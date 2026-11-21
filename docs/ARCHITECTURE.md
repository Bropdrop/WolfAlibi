# WolfAlibi architecture: from signed sets to credible nonaccess receipts

**Maturity:** current prototype + proposed upgrade path, not a description of completed isolation.

## One-sentence system goal

Provide independently checkable evidence of the absence of **specified, fully mediated** resource operations during a **fresh, bounded, authorized** software execution, without disclosing the full event log.

## Baseline implemented today

```text
scripted agent
  |
  v
Broker.read/write/listdir()
  |              |
  |              +--> local write-ahead event journal (optional in current code)
  v
epoch's sorted distinct touched keys
  |
  v
RFC-6962-style Merkle root + broker-signed checkpoint
  |
  v
Witness checks supplied leaves, ordering, root, seq and chain; cosigns
  |
  v
predecessor/successor exclusion proof
  |
  v
External verifier checks signatures + continuity + non-membership
```

The existing demonstration is not a real confined LLM execution. The witness knows that the **supplied** list is consistent, but not whether a broker omitted events. Current witness heads live in memory. The epoch, file-creation and journaling boundary bugs documented in WT-A01..A04 are release blockers.

## Target architecture (not yet implemented)

```text
User / policy authority
  | expected run id + fresh challenge + policy digest
  v
Trusted launch / confinement setup --------> measured environment evidence
  |
  v
Untrusted agent (isolated child)
  |
  +---- ONLY specified mediated resource/tool routes ----+
                                                        |
                                                        v
                                 Broker enforcing policy + bounded capabilities
                                      |                    |
                                      |                    +--> no unauthorized side effects
                                      v
                            Durable ordered event journal
                                      |
                                      +--> independent witness evidence/anchor
                                      |
                                      v
                       Quiescent, closed-run commitment
                                      |
                                      v
                   Signed negative-access receipt package
                                      |
                                      v
                  Offline verifier with external expectations
                                      |
                         VERIFIED / REJECTED / BLOCKED
```

At every arrow, explicitly state who is trusted and what observation proves that the arrow is complete. Merely adding a second signature to the same broker assertion does not create an independent observer.

## Suggested components and ownership

| Component | Responsibility | Critical correctness property |
|---|---|---|
| Launcher | Identify actual program, constrain capabilities, establish run start and end | No unexpected open process, credential, file descriptor or network bypass for the claimed surfaces |
| Policy compiler | Resolve human-readable resource scope to canonical enforceable identifiers | No ambiguity between path, inode, alias, mounted filesystem and API object |
| Broker | Mediate requests and stage effects | No data release before durable record; denied operation has no protected side effect |
| Ordered journal | Preserve complete mediated events and sequence identity | One coherent writer/transaction order; crash-safe authenticated recovery |
| Barrier/closer | Establish closed run interval | No in-flight operation falls out of the claimed observation interval |
| Checkpoint builder | Commit event set (sorted leaves + Merkle root) and timeline | Canonical serialization; no omitted, reordered or conflicting events |
| Witness | Independently validate commitment and remember highest signed state | Durable state; detect divergence, rollback and equivocation |
| Receipt packager | Bind run, policy, challenge, epoch coverage, environment and proofs | All relevant material authenticated together |
| Offline verifier | Validate caller's expectations and failure modes | Never infer expected challenge, keys, policy or scope solely from untrusted receipt |

## Security-focused state transitions (proposed)

`CREATED → CONFINEMENT_ESTABLISHED → RUNNING → QUIESCING → SEALED → VERIFIABLE`

Any impossible or ambiguous transition must end in `BLOCKED`. A seal is valid for release semantics only after all affected operations have terminated or have been correctly attributed across boundaries. Signing after an ambiguous event/journal failure is not acceptable.

## Privacy model

Current neighbor proofs expose **up to two leaf records** and their Merkle audit paths. Checkpoints also expose event count, distinct key count, sequence fields and timing inferred from context. Such a proof is selective disclosure, **not zero knowledge**. Future schemes can research hiding neighboring key names, but must preserve correctness and simple independent verification.

## Compatibility and expansion

Define adapters rather than leaking companion-project code:
- Filesystem: resolved resource identity, attempted and completed effects.
- Tool/API: normalized operation and resource identity, external request-id/replay effects and response disposition.
- Database: query shape and actual authorized rows/tables accessed (beware query-planner, cache and trigger effects).
- Governed compute: what was authorized, independently verified, then executed, with clear separation between authorization and execution.

Each adapter needs its own completeness contract and hostile tests; a filesystem receipt cannot silently authorize statements about all API traffic.

## Design-review questions

1. What is the minimal trusted computing base?
2. Can a compromised but correctly signed broker omit evidence?
3. Is the trusted witness observing the full event stream or trusting a summary?
4. How do we prove all child tasks and inherited descriptors are finished?
5. How are races and system crashes distinguished from harmless denials?
6. Can the verifier reject an authentic receipt for the wrong run or policy?
7. Which data leaks through the negative proof?

**Desired outcome:** the design refuses false confidence rather than inventing completeness.
