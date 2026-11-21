# WolfAlibi Stage 1 delivery and Stage 2 foundations report

## Delivery status

Stage 1 was delivered without a force push, merge, release, deployment, or CI
change. The Bropdrop remote development ref was fetched after the push and
verified as follows.

| Item | Value |
| --- | --- |
| Remote | `https://github.com/Bropdrop/WolfAlibi.git` |
| Branch | `feat/wolfalibi-v0-1` |
| Pushed commit | `dd7c5c76cadc49ab464f14abdbf77269ca735291` |
| Git tree | `ebfbf4e2dcf70fbcf1d919fef277f9cbf371eac9` |
| Pre-push remote head | `d930bfd1a319bcee7ec252eb89d74293f038bbfa` |
| Update relation | verified fast-forward |

Draft community documentation PR #1 was reviewed read-only. It remains an open,
unmerged documentation-only draft on `docs/community-onramp-v1`; no files,
comments, commits, or merge state were changed.

Stage 2 work is on the separate local development branch
`feat/wolfalibi-stage2-foundations`. It has not been merged to `main`, released,
deployed, or pushed as part of this report.

## Independent qualification of the pushed revision

The exact pushed revision was qualified before Stage 2 edits. Environment:
Linux `6.18.57` x86_64, glibc `2.41`, CPython `3.12.14`, `cryptography 50.0.0`,
and Git `2.56.1`. The tree was clean before and after the run.

| Command | Result |
| --- | --- |
| `python3 -m unittest discover -v` | **44/44 passed** in 6.064 s, including all four WolfTrap regressions |
| `python3 -u mutation_test.py` | **8/8 selected mutants caught** (M1–M8), approximately 35.55 s |
| `python3 alibi.py demo` | completed; synthetic symlink hijack and replay were refused |
| `python3 alibi.py bench 1000000` | 1M: build 1.11 s, proof 1.14 s, 3,721 B JSON, verify 0.28 ms |

The complete machine-readable record is
[stage1-qualification-dd7c5c76.json](evidence/stage1-qualification-dd7c5c76.json).
Use `bash scripts/qualify_stage1.sh dd7c5c76cadc49ab464f14abdbf77269ca735291`
only after checking out that immutable commit; it intentionally rejects a dirty
tree or a different HEAD.

## Stage 2 foundation implementation

| Area | Implemented now | Explicitly not claimed |
| --- | --- | --- |
| Linux isolation | Versioned Bubblewrap manifest/digest, prerequisite detection, direct-argv launcher, dropped capabilities, empty environment, closed descriptors, narrow synthetic marker/FD probe | General sandboxing, broker-only IPC, code attestation, seccomp/Landlock, complete mediation, or `CONFINED_LINUX_VERIFIED` |
| Witness continuity | Atomic signed v2 state anchors, generation/previous digest linkage, startup expectation check, receipt-persisted digest binding | Remote transparency, quorum, independent operation, protection if all external anchors or witness key are compromised |
| Portable receipts | Opt-in v2 binds externally supplied resource identity, boundary descriptor, challenge, run, policy, scope, code digest, epoch boundaries, and retained state digest | That declared code ran, the boundary confined it, or every resource channel was observed |
| Alias defense | Resolved symlink paths are committed; hard-linked regular files are refused before bytes/truncation | Global inode/object identity over mounts, aliases, APIs, or direct host paths |
| Developer usability | CLI v2 synthetic demo, isolation status/probe commands, reproducibility script, Stage 2 design document | Production workflow or durable external challenge service |

## Stage 2 automated validation

On this branch after the implementation:

| Command | Result |
| --- | --- |
| `python3 -m unittest discover -v` | **51/51 passed** in 6.494 s |
| `python3 -u mutation_test.py` | **8/8 selected mutants caught** |
| `python3 alibi.py demo` | completed with expected symlink and replay refusal |
| `python3 alibi.py bench 1000000` | 1M: build 1.11 s, proof 1.13 s, 3,721 B JSON, verify 0.28 ms |

The added adversarial coverage includes external-anchor rollback detection,
challenge/boundary replay, restart recovery, symlink and hard-link aliases,
unsupported launcher detection, and narrow marker/FD exclusion probes. Timing
is a single-host observation, not a performance promise.

## Components changed for Stage 2

- `alibi.py` — durable-witness v2 signed state anchors and hard-link refusal.
- `wolfalibi/receipts.py` — compatible v1 plus opt-in v2 receipt construction
  and independent-state/boundary verification.
- `wolfalibi/isolation.py` — explicit policy, typed support detection, launch
  manifest, boundary descriptor, and synthetic probe.
- `wolfalibi_cli.py` and `wolfalibi/__init__.py` — v2 and confinement UX.
- `test_stage2_adversarial.py`, `test_extensions.py`, `test_receipts.py` — new
  synthetic regressions.
- `docs/STAGE2_FOUNDATIONS.md`, architecture/threat-model/README updates,
  `scripts/qualify_stage1.sh`, and machine-readable qualification evidence.

## Known security limitations and blockers

Operational production remains **BLOCKED**. In particular:

1. A Bubblewrap child has no audited sole broker IPC route, so direct/unrecorded
   access is not ruled out.
2. The isolation probe establishes only two synthetic negative observations;
   it does not test every filesystem, credential, namespace, kernel, or network
   escape route. The workdir's ownership/mode and concurrent host writers are
   trusted setup, not verified controls.
3. V2 boundary and code fields are signed bindings, not execution attestation.
4. Witness-state rollback detection requires an independently retained expected
   digest; a local-only state file is not an independent anchor.
5. There is no remote witness quorum, transparency log, sequencer, key rollover,
   API/database adapter, challenge service, or proof of multi-resource
   completeness.
6. Hard-link refusal is deliberately conservative, occurs after open, and does
   not solve object identity across mounts or hostile concurrent root mutation.

## Suggested next milestone

Prototype a broker IPC protocol inside a minimal, independently inspectable
Linux launcher. Bind a verifier-issued challenge to a concrete child identity,
record its lifecycle and permitted descriptors, and have a separately operated
witness or append-only service retain the resulting state anchors. Only after
that design has adversarial review should the project consider any assurance
label beyond `BROKER_ONLY`.
