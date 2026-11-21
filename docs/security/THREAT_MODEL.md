# WolfAlibi v0.1 threat model

## Verdict

**Operational deployment remains BLOCKED.** The implementation improves the reliability of a trusted, mediated filesystem broker. It does not establish that an AI process or host had no alternative resource route.

## Claim under evaluation

For a verifier that independently supplies expected keys, challenge, policy, resource interval, run ID, code digest, and epoch range, a verified `BROKER_ONLY` receipt means:

1. the named broker and witness keys signed the listed contiguous checkpoints;
2. the verifier's Merkle checks found no committed key in the named interval;
3. the broker's documented operation barrier covered completed broker-mediated filesystem operations in those epochs.

It does **not** mean “the agent did not access this resource anywhere.”

For an opt-in receipt v2, the verifier additionally supplies expected resource
identity, execution-boundary metadata, and a witness-state digest retained
before the run. Those fields make receipt substitution and a local
state-and-journal rollback detectable to that verifier. They do not turn a
declared boundary into execution attestation or universal nonaccess evidence.

## Actors and assets

| Actor / asset | Trusted for the narrow claim | Not established |
| --- | --- | --- |
| Broker implementation and private key | Accurate event mediation, write-ahead ordering, epoch barrier, and path policy | Resistance to a compromised/malicious broker or key holder |
| Witness implementation and key | Checkpoint validation, non-equivocation while state is retained | Independent observation of actual broker completeness |
| Durable witness storage | Local restart continuity of heads/receipt digests and signed state-anchor chain | Remote anchoring, availability, multi-site durability |
| Externally retained witness-state digest | Detecting a rollback branch relative to that retained digest | Safety if the external copy, witness key, and local state are jointly compromised |
| Linux kernel and `openat2` | Rooted path resolution for the stated API calls | Whole-host or kernel compromise resistance |
| Optional Bubblewrap launcher | Exact declared mount/namespace policy plus two narrow synthetic exclusion probes | Complete confinement, broker-only IPC, code attestation, seccomp/Landlock coverage, or workdir ownership/mode validation |
| External verifier | Correct expected values and freshness challenge | Authorization to take an effect based on a receipt |

## Attacker model and treatment

| Threat | v0.1 treatment | Residual limitation |
| --- | --- | --- |
| Forge an absence proof by changing an adjacent leaf/path | RFC-6962-shaped hashes, signatures, strict adjacency and chain checks | SHA-256/Ed25519 assumptions remain trusted |
| Seal between event log and data release | Admission gate plus quiescence barrier waits for completed effects | Only broker API operations are covered |
| Concurrent broker objects omit events | Exclusive journal writer lease; second live writer fails | No multiwriter aggregation protocol |
| Short/partial journal write loses an event after restart | Framed checked WAL, full-write loop, `EINTR` retry, zero-progress failure, fail-closed broker | Storage/hardware lies or privileged tampering are out of scope |
| Directory/symlink swap creates outside file | Held root descriptor and Linux `openat2`; writes reject symlink components | Trusted root initialization and kernel behavior are assumed |
| Witness restart signs a checkpoint fork | Durable head state is atomically persisted before signing | State deletion/rollback by a privileged attacker and external equivocation remain possible |
| State and journal rollback after a later receipt | v2 chain is rejected when the verifier retained a later state digest outside the rolled-back state | No protection if all external anchors are rolled back/deleted or the witness key is malicious |
| Receipt replay/substitution | Signatures bind values; verifier must require its own fresh challenge and expected references | Challenge freshness policy is owned by verifier/application |
| Resource aliases | Symlinks use resolved target paths; hard-linked regular files are refused before bytes/truncation | No inode-wide object identity across mounts, hard links, or direct host paths |
| Launcher claim inflation | Manifest/boundary metadata remains `BLOCKED`; synthetic probe only reports exact observed exclusions | Namespace request and marker absence do not prove every route was mediated |
| Direct filesystem/network/API access by agent | Not solved by broker-only evidence | This is the principal reason assurance remains `BROKER_ONLY`/`BLOCKED` |
| Privacy leakage from proof | Receipt calls out adjacency/count leakage | No zero-knowledge construction is implemented |

## Fail-closed conditions

The broker or verifier must not issue/accept a positive claim when any of these are true:

- journal append, recovery, exclusive lease, or root-resolution security prerequisites fail;
- a requested path escapes the root, crosses a rejected symlink on write, or races to a different target;
- witness checkpoint state rejects a chain, sequence, leaf ordering, or durable-state write;
- the verifier lacks an expected key, challenge, policy, scope, run ID, code digest, or epoch range;
- a v2 verifier lacks expected resource identity, execution-boundary metadata, or a retained pre-run witness-state digest;
- a requested isolation prerequisite is absent or a caller asks for an assurance level this implementation does not produce.

The expected typed response is `BLOCKED` or `REJECTED`, not an optimistic verification badge.

## Testing boundary

All repository tests use temporary directories and synthetic strings/files. They do not probe third-party systems, live credentials, real records, or hosted services. The Bubblewrap check demonstrates only that a synthetic marker is absent from one explicitly constructed mount view; it is not a completeness proof for all escape paths.
