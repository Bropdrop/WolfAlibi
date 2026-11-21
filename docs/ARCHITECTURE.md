# WolfAlibi v0.1 architecture

WolfAlibi is an experimental negative-provenance system. Its strongest implemented statement is deliberately narrow:

> A trusted broker and witness recorded no mediated filesystem event whose canonical key lies in a specified interval during a contiguous, sealed epoch interval.

That statement is not evidence that an arbitrary AI, host process, API client, or person had no other route to the resource.

## Evidence flow

```text
caller / agent
      |
      v
Broker --write-ahead journal--> framed local WAL --exclusive live-writer lease
  |       |                                      |
  |       +-- Linux openat2(root fd)              v
  |                                      checkpoint recovery / refusal
  v
completed mediated operation
      |
      v
epoch quiescence barrier --> broker checkpoint --> Witness checkpoint head
                                                     |
                                                     +--> DurableWitness state
                                                           (persisted before signature)
      |
      v
Merkle adjacency proof + bound receipt --> independent verifier with expected references
```

## Implemented components

### Broker and Stage 1 reliability boundary

`alibi.Broker` records every broker-mediated read, write, list, and denied attempt before data is returned or a write is truncated. Its operation admission gate and quiescence barrier give epochs this precise meaning:

- An operation admitted before `seal()` closes the gate remains in that epoch until its read/list data has been returned or its write has completed/fsynced.
- `seal()` waits for admitted operations to finish before signing the checkpoint.
- An operation admitted after the gate reopens belongs to the next epoch.

This closes the former record/seal/release boundary race. It does not bind an epoch to a real agent process by itself.

The v1 leaf mask is deliberately conservative: it records an operation attempt before release and marks known denials, so a failed/partial operation still prevents a negative claim for that key. It does **not** yet expose separate committed event types for authorization, successful open, payload return, partial write, and completed effect. That richer event model is future work; consumers must not infer it from a v1 `r`/`w`/`l` bit.

When a journal is configured, records use the v2 frame format `magic | length | canonical JSON | SHA-256(payload)`. The broker loops on short writes, retries `EINTR`, rejects zero progress, calls `fsync`, and enters a fail-closed state on append failure. Recovery replays only complete checked frames; it can truncate an incomplete final v2 frame because no effect is released until that frame is fully durable. Legacy newline journals are rejected rather than treated as equivalent durable evidence.

One live broker owns a journal through a POSIX `flock` lease plus an in-process identity guard. A second broker using that journal fails closed; the in-process signing-identity guard also rejects split-brain brokers without a journal. Cross-process evidence needs a journal lease—memory-only brokers are compatibility/demo mode, not a durable multi-process deployment. Multiwriter aggregation is not implemented.

### Filesystem resolution

On supported Linux hosts, the broker retains a root directory descriptor and uses `openat2(2)` with `RESOLVE_IN_ROOT` and `RESOLVE_NO_MAGICLINKS`. Writes additionally use `RESOLVE_NO_SYMLINKS`, so a symlinked or swapped parent cannot direct `O_CREAT` outside the anchored root. The broker compares diagnostic pre/post targets and records a denied target if a read/list race resolves to a different in-root resource.

This feature needs Linux `openat2`; an unsupported kernel or architecture fails closed rather than falling back to a path-string check. Root setup, the kernel, the broker process, and its signing key remain trusted computing-base components.

### Witnesses and receipts

`Witness` checks sorted leaves, contiguous sequence numbers, checkpoint chain links, and a broker signature before signing a checkpoint. `DurableWitness` adds:

- a POSIX live-writer lock for one local state owner;
- canonical state stored atomically with file and parent-directory `fsync`;
- persisted checkpoint heads before checkpoint signatures leave the process;
- a bounded, persisted history of receipt payload digests before receipt signatures leave the process.

`wolfalibi.receipts.EvidenceRun` requires both a configured durable broker journal and `DurableWitness`, seals a pre-run boundary, seals a completed interval, creates a Merkle absence proof, and produces `NEGATIVE_ACCESS_RECEIPT_V1`. A receipt binds the run ID, fresh challenge, concrete scope, policy-plus-scope digest, declared local artifact digest, signed start/end checkpoint boundaries, broker/witness identities, proof, and signatures.

The offline verifier requires expected broker and witness public keys, challenge, policy, range, run ID, code digest, and epoch range from its caller. It returns `VERIFIED`, `REJECTED`, or `BLOCKED`; it never obtains those references from the receipt as authorization.

Receipt assurance is currently **`BROKER_ONLY`**. The code digest is a declared local artifact digest, not proof that that code executed. Durable local witness state is useful anti-amnesia evidence, but it is not an external transparency log or independent governance service.

### Optional Linux launcher

`wolfalibi.isolation` can launch a command with Bubblewrap in new user, PID, network, IPC, and UTS namespaces. It supplies a writable `/work`, a temporary `/tmp`, selected read-only runtime library mounts, no stdin, `close_fds=True`, and a cleared environment. It returns `UNSUPPORTED` or `BLOCKED` when prerequisites are absent.

It intentionally does **not** expose a broker IPC route, attest executable identity, prove all file-descriptor or kernel escape avenues closed, or upgrade a receipt to `CONFINED_LINUX_VERIFIED`. Its reported assurance is always `BLOCKED` in v0.1. It is a process-level demonstration and a base for future review, not a general sandbox promise.

## Extensibility boundary

`wolfalibi.adapters` defines `ResourceEvent`, `ResourceAdapter`, and `AdapterRegistry`. These are proposal-oriented interfaces only. No API, database, local-tool, or remote service adapter is active. A future adapter must specify canonical identity, attempted/authorized/opened/completed semantics, durable event ordering, failure behavior, policy binding, and its confinement assumptions before it can share a receipt format with filesystem evidence.

## Assurance levels

| Level | Meaning in v0.1 |
| --- | --- |
| `BROKER_ONLY` | Implemented: checked broker/witness evidence for the named mediated interval; direct/unmonitored access remains possible. |
| `CONFINED_LINUX_VERIFIED` | Reserved; not emitted by this repository. It needs an audited broker-only route, code/run attestation, and tested confinement coverage. |
| `BLOCKED` | Required evidence or platform support is missing, invalid, or outside the declared scope. |

## Required local prerequisites

- Python 3.9+ and `cryptography` for the base prototype.
- Linux kernel and a supported architecture with `openat2(2)` for broker filesystem access hardening.
- POSIX `fcntl` for journal and durable-witness exclusive leases.
- Bubblewrap (`bwrap`) only for the optional launcher demonstration; it is never auto-installed.

## Non-goals and remaining limitations

- No complete agent confinement, direct-access detection, or universal nonaccess proof.
- No multiwriter sequencer, externally anchored witness history, replicated witness quorum, key rollover protocol, or formal verification.
- No guarantee that local `fsync` survives arbitrary hardware/controller failure beyond the host/filesystem contract.
- No protection from a compromised trusted broker, witness key, privileged launcher, kernel, or host administrator.
- No privacy guarantee beyond the existing adjacency proof; neighboring keys, masks, counts, first sequence values, and aggregate event counts can leak.
- No production authorization, compliance, financial, or regulatory use.
