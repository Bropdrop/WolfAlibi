# VOIDCELL v1 — Zero-Route Execution, Resource-Side Effect Vault

**Status: architecture proposal only; no independent implementation or qualification.** Issue [#19](https://github.com/Bropdrop/WolfAlibi/issues/19) holds the complete hostile acceptance matrix. The word "absolute" describes the ambition, **not an achieved or achievable universal security guarantee**.

## One-sentence thesis

Do not make access to protected infrastructure depend solely on whether an AI agent stays inside its sandbox. **Move protected credentials and the final enforcement point outside the agent's trust domain**, prevent the target service from accepting any other route, and require current, independently validated evidence plus owner authorization for *every* protected effect.

## Reference architecture

```text
Owner-controlled policy + verified, short-lived challenge
                      │
                      ▼
        External ALIBI Clearance authority
          │ qualification │ owner grant
          └──────┬────────┘
                 │ authenticated, scoped, expiring lease
                 ▼
BYOA / untrusted agent ── one bounded protocol ──> effect gateway
     inside VOIDCELL                           (separate owner domain)
     ┌──────────────────┐                            │
     │ no target keys   │                            ├─ resource policy + revocation
     │ no target mounts │                            ├─ durable intent + replay fence
     │ no direct egress │                            ├─ ambiguous effect reconciliation
     │ bounded runtime  │                            ▼
     └──────────────────┘                     protected synthetic resource
                 │                                  │
                 └── observation only               ├─ owner-side decision record
                                                    └─ signed acceptance/denial
                                                             │
                                                independent evidence verifier
```

For a genuine production deployment, the cell and effect vault must be **different administrative/security trust domains**. A local process pretending to be another independent party is only a protocol test.

## The enforceable predicate

For protected resource `S` over declared time interval `I`, define `Accepted(S,I)` as operations the **resource itself** accepted, not the agent's stated intent, callback result or broker dispatch.

**Target invariant:**

`Accepted(e) => QualifiedAtEffect(e) AND OwnerAuthorizedAtEffect(e) AND ExactScope(e) AND DurableEffectRecord(e)`

It additionally requires an independently controlled target-side enforcement route that rejects bypasses. Treat a violation of any assumption as a failure to qualify the invariant. This is a **future proof obligation**, not an assertion that the current code already establishes it.

### Independent checks at the moment of effect

- **Agent/build:** bound to run ID, measured artifact digest, execution profile, pinned verifier challenge, current authority epoch and policy version. Never trust an agent-provided badge alone.
- **Owner grant:** audience, tenant, resource, operation, expiry, request budget, idempotency key and revocation state checked by the owner's gate. User-approved testing is not an owner grant for real infrastructure.
- **Transport:** per-run authenticated IPC from cell to gateway, strict type/length/sequence/nonce, with no unmediated network path to the target. The target rejects direct requests from the cell or any bearer of unsanctioned credentials.
- **Effect boundary:** accept/reject decision enforced at the target. Gateway-held credentials never enter worker memory, environment, logs, filesystem, prompts or model context.
- **Evidence:** record intent before release, then separately reconcile the resource's own accepted-effect receipt. A lost response is `AMBIGUOUS`, not evidence of no effect, and must not trigger an unsafe repeat.

No signed hash of worker self-report is sufficient to qualify any of the above without an independently observed binding.

## Three candidate cells (do not mix their guarantees)

| Cell | Purpose | Essential limitation |
| --- | --- | --- |
| `DECLARED_WASM` | Agents/tool modules portable to a Wasm component with explicit host-call imports and finite execution fuel | Not general Python; host function interface, WASI permissions and Wasm runtime itself are part of the trusted computing base |
| `NARROW_LINUX` | Existing Stage 3.5-style fixed synthetic Python worker using measured namespaces, pidfds, reduced capabilities, Landlock/seccomp when supported | Not arbitrary hostile-code confinement. Missing writable cgroup delegation prevents strong general resource/process accounting; no stronger claim |
| `UNTRUSTED_MICROVM` | Potential future arbitrary-code execution boundary with a dedicated hypervisor and tightly constrained devices / vsock transport | Host prerequisites, hypervisor bugs, cgroup/DoS controls and separate networking remain open. No claim that Firecracker is enabled here |

**Do not bypass a cloud host's lack of writable cgroup delegation.** Test on available supported profiles or return `UNSUPPORTED`/`BLOCKED`; test general process containment on an operator-controlled host with proper delegation or microVM resources. Cgroups are useful for resource/DoS containment, but the effect-vault authority decision can be tested separately with synthetic resources even when cgroup delegation is absent.

## No back door to the target

The resource OWNER, not the agent or worker-host firewall, must control these conditions:

1. Target has no public or agent-reachable path that bypasses gateway enforcement.
2. Target rejects unauthenticated and non-gateway-origin requests **even if the worker escapes its sandbox or acquires arbitrary network connectivity on its own host**.
3. No reusable target credential is provisioned in the cell or its model-provider environment.
4. Every permitted operation receives a fresh or replay-fenced bound request identity, checked by a current owner grant at the target-side decision point.
5. Model inference is a separate capability through a model relay; model outputs never directly become infrastructure authority.

If the target has other valid integrations, its authorization boundary must cover **all** those routes for any claim about total accepted effects. Otherwise narrow the claim to the gateway route only.

## Evidence state machine

```text
UNASSESSED -> QUALIFIED_SCOPE -> OWNER_GRANTED
                                  │
                                  v
                        REQUEST_PREPARED
                          │           │
                     deny/revoke      v
                          │      EFFECT_DISPATCHED
                          v           │
                        DENIED     resource acknowledgement?
                                      │
                              ┌───────┴─────────┐
                              v                 v
                       ACCEPTED_EVIDENCED    AMBIGUOUS
                              │                 │
                              v                 v
                     CLOSED / RECEIPT     RECONCILIATION
```

A broker's committed request is **not** proof the remote effect was accepted. An accepted resource receipt is **not** proof bytes were consumed by an external human or process. Never silently convert `AMBIGUOUS` to success, failure, or authorization for retry.

On revocation, future effects are fenced at the resource side. Previously dispatched ambiguous effects require reconciliation; do not claim retroactive prevention.

## What would make this composition interesting

This combines known primitives—Linux isolation, WebAssembly capabilities, Zero Trust enforcement, short-lived workload identity, transactional admission, negative broker provenance, and independent evidence—around a falsifiable theorem about **protected-resource acceptance**, instead of claiming to see all of an AI's internal behavior.

We do **not** claim we invented these underlying components or that VOIDCELL is the first architecture to combine them. Establish distinct novelty or patentability only with a dedicated prior-art review.

## First offline qualification (no production access)

Use two separately provisioned **synthetic** services or processes: a worker that cannot hold the target credential, and a target-side gate that stores its own credential/authority state. At least one hostile synthetic worker should be allowed to lie about its AgentProbe logs.

Qualify, with independent expected values:

- Authorized read and unauthorized write, grant revoked at dispatch, expired qualification, wrong audience/tenant/scope, program digest substitution.
- Direct-to-resource attempt from outside gateway; prove target rejects with no accepted effect (not just no worker callback).
- Replay/duplicate/cross-run requests; resource idempotency check prevents double effect.
- Journal short write, fsync failure, witness outage and resource disconnect; outcome `BLOCKED` or `AMBIGUOUS`, never false clean receipt.
- Effective policy change after preflight and before dispatch; fresh resource-side check required.
- Malicious host/worker with fake measurements; missing trusted supervisor or verifier reference prevents admission.
- A missing or writable cgroup delegation must never be labeled qualified process confinement; show it as a separate failure dimension.
- Honest matrix for all four assurance planes: `OBSERVATIONAL_ONLY`, `BROKER_ONLY`, `RESOURCE_SIDE_EFFECT_GATE` (future test result only), `INDEPENDENT_CUSTODY` (future).

## Graduation conditions

Produce exact Git commit/tree, all trust assumptions, owner-controlled route inventory, measured restrictions (where used), signed resource-acceptance or denial receipts, durable journal recovery, negative hostile controls, independent reproduction, and separate `CONDITIONAL/BLOCKED` verdicts for each assurance plane. Only after this evidence can a narrower claim such as "this protected service accepted no effect outside its qualified gate during the witnessed interval" be considered.

No main merge, release, paid CI, real provider credentials, real sensitive resources, or deploy until explicitly approved.

**Links:** [Stage 4 BYOA PR #18](https://github.com/Bropdrop/WolfAlibi/pull/18) · [SOLITARY Issue #15](https://github.com/Bropdrop/WolfAlibi/issues/15) · [ALIBI CLEARANCE Issue #17](https://github.com/Bropdrop/WolfAlibi/issues/17) · [VOIDCELL Issue #19](https://github.com/Bropdrop/WolfAlibi/issues/19).

**External context:** [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) · [Linux Landlock](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html) · [Firecracker production guidance](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md) · [Wasmtime interruption/fuel](https://docs.wasmtime.dev/examples-interrupting-wasm.html).
