# WolfAlibi roadmap: evidenced claims first

This roadmap is for the public research program, **not a production release schedule**. Current authoritative implementation: Stage 2 at `37b277521041d68fa81748d41824e4c8bb66a592`.

## Completed experimental foundations

**Stage 1 — Broker integrity:** operation/epoch barrier, framed journal recovery, exclusive journal writer, kernel-anchored `openat2` resolution, durable local witness state, V1 `BROKER_ONLY` receipt, and offline verification.

**Stage 2 — Evidence continuity:** signed v2 witness-state anchors and expected digest checks, opt-in V2 receipt bindings, narrow Bubblewrap policy/probes, hard-link refusal, and an additional synthetic adversarial test suite.

All features remain **research grade**. A host-level claim of complete agent nonaccess is not yet supported. See the [Stage 2 report](ENGINEERING_REPORT_STAGE2.md).

## Stage 3 — Close the actual mediation gap

**3A. Audited broker IPC.** Design a bounded, typed, per-run communication channel between a constrained worker and a broker outside that worker's capability boundary. Ensure the child can receive approved data only through this channel. A local synthetic test must demonstrate that a direct read is denied while the same fixture through the authorized broker succeeds and is durably recorded. Challenge the design with inherited descriptors, process ancestry, symlink/hard-link aliases, and interrupted or duplicated messages.

**3B. Execution identity and run closure.** Identify the launched executable and exact confinement manifest. Record the supervisor lifecycle, child process and descendants, admission/complete boundaries, and post-run quiescence. Show how the verifier distinguishes a declared digest from evidence about what actually executed. Demonstrate refusal of receipts for an early-exited, timed-out, still-running, or unmeasured child.

**3C. Independently retained witness heads.** Define a separate durable custody boundary for witness state and checkpoints. Test stale anchor, fork, rollback, restart, compromised local state, and failure to contact the external observer. Require a verifier-controlled expected head and freshness challenge. The first implementation may be a second isolated local process or independently stored file used as a test fixture, but must clearly identify where separation is and is not achieved.

**3D. Receipt and verifier protocol.** Specify how the attested boundary and witness custody are bound cryptographically to one authorized run, policy, resource-identity scheme, expected keys, operations, and interval. Preserve V1/V2 compatibility; no silent assurance promotion. Return `BLOCKED` whenever a stage prerequisite cannot be established.

**3E. Independent hostile qualification.** Publish a typed matrix of positive/negative controls, exact commands, OS/kernel features and expected results. Retest all historical WT-A01..A04 and selected mutants. Tests using only synthetic fixtures. Capture failpoints at every release/journal/witness boundary.

## Stage 4 — External review and interoperability

- Small, stable verifier API and neutral sample receipts.
- Independent alternative verifier, property/fuzz tests, documented cryptographic assumptions.
- Explicit tool/API/database adapter semantics, each requiring its own capture and completeness contract.
- Optional integration interfaces for governed execution platforms without sharing private source or secrets.
- Privacy review of neighboring keys, counts, stable identifiers and timing.

## Release gates

A **developer preview** should be clearly labeled experimental and include reproducible demos, contribution instructions, provenance/rights clearance and an explicit license. A future **security-sensitive release** requires documented complete mediation for its claimed scope, credible execution identity and run closure, genuinely independent witness state, verified failure recovery, external review, and no known critical false-proof findings.

No public claims of universal nonaccess, certification, or production-ready sandboxing without evidence. A system that refuses a proof when evidence is missing is behaving correctly.
