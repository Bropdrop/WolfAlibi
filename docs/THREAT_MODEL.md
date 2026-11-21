# WolfAlibi threat model — working specification

**Document maturity:** research design; not proof of operational confinement.

## Protected statement

The goal is to demonstrate a scoped negative predicate:

> For an externally identified run `R`, policy `P`, resource set `S`, operation set `O`, and fully covered run interval `I`, no operation or protected effect matching `(S,O)` occurred over the mediated surfaces declared by `P`.

A receipt must not silently claim an entirely different interval, operation category or set of surfaces. A broker-only receipt cannot imply no read via direct syscalls, another process, an inherited file descriptor, a network mount, a remote API, a database query, or another tool.

### Roles and trust boundaries

1. **Requesting verifier:** supplies expected run challenge, allowed policy and resource interval, trusted key identifiers and minimum assurance.
2. **Agent/child process:** potentially adversarial; may choose arguments, file paths, timing and process behavior.
3. **Broker/launcher:** enforces access restrictions and records attempted/completed actions; *currently a required trusted component*.
4. **Journal and sequencer:** durable event order and exclusive-writer or explicitly correct multiwriter ownership.
5. **Witness:** validates checkpoint structure, ordering, continuity and commitments; must persist anti-equivocation state independently. A witness solely consuming broker-provided entries cannot detect hidden broker events.
6. **Operating system:** must enforce the confinement contract if the receipt claims process-level exclusion.
7. **Receipt verifier:** receives untrusted bytes and must reject malformed, stale, substituted or incomplete evidence.

### What must be protected

- Protected file contents and metadata, including existence, listing and aliases.
- Integrity of ordinary files and effects; denied write must be side-effect-free.
- Completeness and order of mediated event records; no append/flush ambiguity.
- Signing key identity and independence, witness durability, run freshness and replay protection.
- Privacy of unrelated accessed resources leaked through proofs, logs, timestamps or counts.

### Relevant attacker strategies

| Attack surface | Representative strategy | Required defense / evidence |
|---|---|---|
| Path resolution | Symlink/hard-link aliases; dot-dot; parent replacement; bind mounts | Kernel-enforced resource boundary and fd-anchored traversal; no outside effects |
| Event capture | Bypass broker via direct syscall, subprocess or inherited descriptor | Actual child-process confinement; coverage of every claimed surface |
| Logging | Partial writes, torn tails, disk full, fsync failure, process crash | Full checked writes; crash-consistent recovery; no release after uncertain durability |
| Concurrency | Seal during in-flight read; competing brokers share identity | Quiescence barrier or formally defined cross-epoch accounting; exclusive writer or central sequencer |
| Witness | Reset memory; reuse same key after restart; conflicting checkpoints | Durable transactional heads, integrity/rollback controls, independent anchoring |
| Merkle proof | False neighbors, unsorted leaves, path mutation, fabricated boundaries | Full root/order validation and correctly verified adjacent authenticated leaves |
| Receipt substitution | Swap run, policy, epoch, prefix, key, agent or sandbox identity | Canonical signed transcript and external verifier expectations |
| Privacy | Neighbor keys disclose unrelated names; correlation between runs | Minimize disclosures, document leakage, optionally research stronger private protocols |
| Availability | Kill broker, revoke key, fill disk, withhold proof | Fail closed and produce `BLOCKED`; do not manufacture a clean receipt |

### Boundary semantics to decide before implementation

- Is `read` defined at authorization, open, byte release, or data consumption? Does metadata access count?
- Does `write` mean attempt, file creation, truncation, changed contents or completed durable effect?
- How is an operation that begins in one epoch and completes in the next accounted for?
- What constitutes a *closed* run when children, threads, async tasks or open descriptors remain alive?
- Are denied attempts considered `touched`? Current baseline records denied operations: name this when making claims.
- Are directory listings and path aliases mapped to one canonical resource identity?

Implementers must choose precise events and defend them with tests. Undefined semantics must never be papered over by a signature.

## Assurance levels (proposals)

- `BROKER_ONLY`: only the integrity of the committed broker-mediated event set is claimed; no proof of process confinement.
- `CONFINED_LINUX_VERIFIED`: a measured, explicitly specified Linux confinement setup and complete mediation evidence are validated for the run and selected surfaces.
- `BLOCKED`: evidence is missing, unsupported, inconsistent, or invalid for the requested assurance.

No level covers all possible out-of-band human or physical access. Deployment-grade guarantees require independent hostile review of the implementation, kernel assumptions and launch environment.

## Known baseline failures

**WT-A01:** in-flight operation straddles a sealed epoch.  
**WT-A02:** competing broker objects omit each other's shared-journal events.  
**WT-A03:** parent-directory race causes an unauthorized empty file to be created.  
**WT-A04:** partial journal write followed by recovery erases a released access.

Full reproductions: [WOLFTRAP-ALIBI-001](security/WOLFTRAP_ALIBI_001.md).

## Explicit non-goals for the first iteration

- Formal proof that no human/operator/system has ever read a resource.
- Operating-system-independent confinement claims.
- Production compliance certifications, automatic legal assertions, token payouts, or protected execution outside synthetic local test environments.
- A blanket guarantee against malicious administrators, kernel compromise or side channels.

**North star:** no proof is safer than a convincing false proof.
