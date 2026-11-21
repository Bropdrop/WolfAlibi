# Stage 2 foundations: confined-process and continuity experiments

## Status

This is a research foundation, not an operational security boundary. All
receipts emitted by this repository remain **`BROKER_ONLY`** and production
deployment remains **BLOCKED**.

The Stage 1 delivery was qualified at commit
`dd7c5c76cadc49ab464f14abdbf77269ca735291`; the machine-readable result is
in [stage1-qualification-dd7c5c76.json](evidence/stage1-qualification-dd7c5c76.json).
The work below belongs to the separate `feat/wolfalibi-stage2-foundations`
development branch. It does not merge or alter draft community PR #1.

## Implemented foundation

### Narrow Linux Bubblewrap policy

`wolfalibi.isolation` now produces a versioned JSON manifest and SHA-256 policy
digest for one intentionally limited Linux/Bubblewrap configuration:

- separate user, PID, network, IPC, and UTS namespaces;
- empty inherited environment, `stdin=/dev/null`, and `close_fds=True`;
- only the supplied host directory mounted writable at `/work`, plus an
  isolated writable tmpfs at `/tmp`;
- `/usr`, `/lib`, and `/lib64` mounted read-only for the runtime;
- new `/proc`, minimal `/dev`, temporary `/tmp`, and dropped capabilities.

`isolation-status` gives a typed `UNSUPPORTED`, `BLOCKED`, or `READY` result
for platform, `bwrap`, user-namespace policy, and runtime prerequisites.
`confinement-probe` uses only caller-owned synthetic files and reports
`DEMONSTRATED` only when a designated host marker path and parent marker file
descriptor are both absent from two launched children. A demonstration still
has `assurance: BLOCKED`.

The launcher has no broker IPC, executable allowlist, seccomp/Landlock policy,
code-execution attestation, remote witness, or proof that all kernel/host
escape routes are closed. It must not be described as a general agent sandbox.
Its resolved host workdir is a declared bind source, not an ownership or mode
verification mechanism; root/workdir initialization and concurrent host writers
remain part of the trusted deployment setup.

```bash
python3 wolfalibi_cli.py isolation-status

# Use directories and a marker created solely for this synthetic experiment.
python3 wolfalibi_cli.py confinement-probe \
  --workdir /tmp/wolfalibi-work \
  --synthetic-marker /tmp/wolfalibi-protected/synthetic-marker.txt
```

The probe intentionally performs no real network test and never makes an
outbound request.

### Durable witness-state continuity anchors

`DurableWitness` state format v2 stores an atomically persisted, witness-signed
state anchor on every state transition. Each anchor has a generation, previous
state digest, state digest, heads digest, receipt-history digest, and final
receipt digest (when one exists). State files retain the existing lease,
temporary-file, file-`fsync`, rename, and parent-directory-`fsync` ordering.

An operator or verifier can retain `witness.state_digest` outside the witness
host and later pass it as `expected_state_digest=` at startup. A mismatch fails
closed. This detects a rollback only when the expected digest survived outside
the rolled-back state. It does not defend against a privileged party that can
change both the witness key and every external copy, nor does it create an
independent log.

Legacy v1 state is accepted and migrated to a new v2 genesis anchor, but it
cannot satisfy a pre-existing v2 anchor expectation. There is no invented
retroactive continuity claim.

### Receipt v2: explicit external bindings

Stage 1 `NEGATIVE_ACCESS_RECEIPT_V1` remains supported for compatibility.
`EvidenceRun(..., receipt_version=2, ...)` produces
`NEGATIVE_ACCESS_RECEIPT_V2`, which additionally signs and verifies:

- a caller-supplied resource-identity descriptor;
- a caller-supplied execution-boundary descriptor;
- the existing fresh challenge, run ID, policy, exact path range, operations,
  declared code digest, signed start/end boundaries, and epoch interval;
- a three-step witness-state anchor chain for start boundary, end boundary, and
  persisted receipt digest.

V2 verification blocks unless the verifier independently provides expected
resource identity, execution boundary, and the witness-state digest retained
before the run. The boundary descriptor must still carry `assurance: BLOCKED`
in this implementation. It binds an expectation to evidence; it does not prove
that a launched process was complete, confined, or the source of the events.

The CLI demo defaults to v2 and writes synthetic verification inputs so it can
be reproduced. Those emitted inputs are deliberately **not** an independent
anchor workflow; a real verifier must retain the pre-run digest elsewhere.

```bash
python3 wolfalibi_cli.py demo-receipt \
  --output /tmp/wolfalibi-receipt.json \
  --inputs /tmp/wolfalibi-inputs.json \
  --state-dir /tmp/wolfalibi-witness-state
```

### Alias refusal

Path interval proofs are path-scoped. An in-root symlink is resolved before
its key is recorded, so a `docs/` alias into `finance/` is committed under the
resolved `finance/` target. Regular files with more than one hard link are now
refused before bytes are returned or an existing target is truncated. That
refusal is conservative and is checked after an open: it is not inode-wide
identity, it is TOCTOU-sensitive under hostile concurrent root mutation, and
a denied alias is still recorded under its alias path. It therefore cannot be
used to claim object-level nonaccess for every hard-link alias.

## Adversarial coverage

`test_stage2_adversarial.py` adds synthetic regressions for:

- restart plus state-and-journal rollback, caught by an externally retained
  later state anchor;
- v2 receipt replay/substitution of challenge and execution-boundary inputs;
- symlink resolution into a protected path range;
- hard-link alias refusal before data release or truncation;
- host-marker and inherited-FD exclusion probes under Bubblewrap, including
  typed unsupported/blocked outcomes.

## Reproducibility

To reproduce the immutable Stage 1 qualification, first check out exactly the
pushed revision and use:

```bash
bash scripts/qualify_stage1.sh dd7c5c76cadc49ab464f14abdbf77269ca735291
```

The script intentionally refuses a dirty tree or a different HEAD. It runs the
44-test discovery suite, WolfTrap regressions, eight selected mutation checks,
the ALIBI demo, and the one-million-key benchmark.

## Still proposed, not implemented

- An audited broker-only IPC route between a confined agent and the broker.
- Enforceable code/run identity attestation and executable policy.
- Seccomp/Landlock policy, cgroup/resource limits, side-channel analysis, and
  complete mediation of filesystem, API, database, credential, and network
  resources.
- Remote witness transparency, quorum, anchoring, key rollover, or durable
  external challenge issuance/consumption.
- Portable inode/object identity across hard links, bind mounts, mounts, and
  filesystems.

The next milestone should prototype a broker IPC protocol within a narrowly
audited launcher, then have an independently operated verifier validate its
launch and witness anchors before any assurance label is reconsidered.
