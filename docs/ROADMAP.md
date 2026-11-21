# WolfAlibi development roadmap

**Public research prototype.** These are milestones and engineering acceptance gates, not shipped capability claims.

## P0 — Fix the four reproduced defects

Owner: current implementation workstream / Codex. Independent reviewers should inspect and propose **additional** counterexamples rather than altering its branch without coordination.

| Case | Repair target | Exit evidence |
|---|---|---|
| WT-A01: epoch overlap | Closed-run/operation barrier or equivalent correct cross-epoch semantics | Original hostile reproducer green and new scheduling stress tests |
| WT-A02: duplicate broker owner | Single-writer lease or audited central sequencer | Two instances cannot silently seal an incomplete log |
| WT-A03: creation-side race | OS and fd-relative guard preventing outside side effects | Zero unauthorized file creations across deterministic race injection |
| WT-A04: partial journal | Checked writes + unambiguous recovery | No released event can disappear across write faults or restart |

In addition: 21 original tests remain green, all eight historical mutants remain caught, added hostile regressions green. Passing these **does not** imply production-ready confinement.

## P1 — Process-level confinement demonstration

- Linux local launcher with documented kernel feature requirements and unsupported environments returning `BLOCKED`.
- Prove the child cannot reach protected resources outside the declared broker path, including inherited file descriptors, aliases and subprocess behavior.
- Verify the launcher under synthetic adversarial tests; separate confined and unconfined modes in every result.
- Independently inspect kernel/Landlock/namespace/openat2 interactions and their actual coverage.

**Exit:** a reproducible confined process test, with explicit negative bypass results and no claim of universal host containment.

## P2 — Independent portable receipt

- Versioned canonical schema for externally challenge-bound run, policy, scope, effects and epoch interval.
- Offline verifier with supplied expected keys, run challenge, policy and minimum assurance.
- Authenticated chain and witness freshness; reject altered or stale transcripts.
- Typed outcomes `VERIFIED`, `REJECTED`, `BLOCKED`.

**Exit:** independently verifiable synthetic receipts, including hostile replay/substitution tests.

## P3 — Durable independent witness

- Persistent anti-equivocation heads, restart tests and rollback detection.
- Verify event-stream completeness independently or state the actual witness trust assumptions.
- Optional independent anchor/witness with genuinely separate trust roots.
- Explicit key-rotation and recovery protocols.

**Exit:** malicious restart/fork scenarios cannot produce accepted contradictory histories under documented assumptions.

## P4 — Portable adapters and public ecosystem

- Tool/API/database mediation contracts, each with independent resource/effect semantics.
- Interfaces for future governed execution systems without importing proprietary code.
- Versioned protocol documentation and interop fixtures.
- Public threat-model challenges, contribution docs, and optional audited packages.

**Exit:** a third-party team can verify and challenge receipts without access to the issuer's full log or private implementation.

## Research rather than promises

Privacy-improved non-membership protocols, third-party attested execution, cross-host continuity and multi-observer evidence should be investigated only after fundamental mediation, semantics and durability are sound. Do not confuse research hypotheses with tested features.

## Maintainer release gate

A public demo can be published as an **educational prototype** with warnings. A security-sensitive release requires: complete declared confinement, all known high-severity hostile tests passing, unambiguous durability, documented independent witness assumptions, replay-safe external verification, an explicit license, and external review.

**Never turn a `BLOCKED` claim green by suppressing or skipping a hostile test.**
