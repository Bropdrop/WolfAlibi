# Stage 3 review protocol — draft acceptance specification

**Source boundary:** this page translates the *reported* local Stage 3 direction into reviewable requirements. The actual Stage 3 design commit `a812679a6d6f636eaa5bb767e04bb94efcfb37a2` has **not** yet been published, read, or adopted here. Reconcile this page against that design once its exact tree is available.

The target is not a universal sandbox. The target is a *precisely bounded, demonstrably exclusive* path for a **specific set of protected resources** in a synthetic local test.

## Stage 3A — Per-run broker IPC

A supervisor creates a fresh channel for one run. The broker, not the untrusted child, opens the protected host resource. The child receives no ambient access path to the protected fixture except a deliberately scoped request. The broker checks per-request identity, policy and resource keys, writes a durable event before releasing requested data, and records the observed outcome. Repeated/late/altered requests must not cause unauthorized effects.

**Acceptance controls:** authorized synthetic read succeeds and appears in committed evidence; direct protected read is denied; a forbidden write changes no file; requesting another run's channel is denied; closed-run channels refuse further data; broker crash before durable record releases nothing. Do not equate a returned exception with a verified lack of side effects.

## Stage 3B — Supervisor measurement

The supervisor binds an externally supplied fresh challenge, policy/manifest digest, code/executable identity, and a precise lifecycle interval to run evidence. It must distinguish a **declared artifact digest** from an OS-observed executable/launch identity, and explain what the measurement cannot prove. End-of-run evidence requires all relevant in-flight operations and child/descendant work complete, or an explicit fail-closed verdict.

**Acceptance controls:** swap the executable, modify the manifest after measurement, replay an old run challenge, retain an open broker descriptor beyond declared closure, kill a child midoperation, and force a launcher feature to be unavailable. All out-of-contract cases return `REJECTED` or `BLOCKED`; nothing silently upgrades to `CONFINED_LINUX_VERIFIED`.

## Stage 3C — Witness custody

A verifier retains an expected witness head under custody genuinely separate from the local witness instance. Candidate protocols must show who can alter state, how key rotation is authorized, whether a witness can sign forks after amnesia, and what a stale/missing anchor implies.

**Acceptance controls:** mutate local state or journal while retaining an external head; restore an older snapshot; request contradictory signatures for an epoch; splice proof intervals from distinct histories; remove the external head; simulate delayed or unavailable witness publication. For cases without sufficient evidence, emit `BLOCKED` instead of assuming continuity.

## Stage 3D — Proof binding

The verifier must require **external expectations** for trusted public keys, task challenge and freshness, run identity, covered operations, resource scope, expected confinement manifest, checkpoint range and witness head. A receipt cannot choose all the criteria against which it will be verified. Distinguish `BROKER_ONLY` from an experimental confinement-evidence profile and never silently promote an unsupported level.

## Evidence standards

For every claim: exact commit/tree, environment, commands, data fixtures, expected and actual output, signed transcript schema, positive control, negative controls, and source-visible reproduction. New tests must first fail against an implementation that lacks the corresponding security property. If real confinement depends on kernel facilities unavailable on the test host, record `UNSUPPORTED` / `BLOCKED`, not PASS.

No third-party services, live credentials, host privilege escalation, paid CI, deployment, or release operations.

## Review questions

- What observation makes omission of events impossible for the **declared** protected resources?
- Who controls the worker, broker, supervisor, witness and key material?
- What if a worker races run closure or forks descendants?
- What proves a witness observed enough to validate completeness versus merely the supplied commitment?
- Can a verifier reject authentic evidence from the wrong session without contacting the issuer?
- Can neighboring proofs expose private resource names, counts or timings?

**Graduation criterion:** stronger receipt assurance is earned by auditable, independently reproduced evidence, not by naming a new assurance level.
