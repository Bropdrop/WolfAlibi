# CODEX MISSION — WOLFALIBI V0.1: PROVE THE ABSENCE, NOT THE STORY

> **Status:** Engineering assignment. The repository is an experimental prototype, **not a production security system**.
>
> **Owner's instruction:** Keep this public and quiet for now. Do not publish a release, announce the project, merge into `main`, or deploy anything. Work only on `feat/wolfalibi-v0-1` or a child feature branch. Keep GitHub Actions disabled unless the owner explicitly approves spending.
>
> **Prime directive:** Every security claim must be no stronger than its independently reproducible evidence.

## 0. Why this exists

An AI was challenged to invent something that sounds improbable but can be built with today's technology. It returned **ALIBI**, a proof-of-negative-provenance prototype: an access broker logs mediated filesystem operations; each epoch commits a sorted Merkle set of touched keys; an independent Ed25519 witness checks and co-signs the checkpoint; a compact adjacency proof lets an external verifier check that a specified key interval was untouched *through the broker*, without seeing the full touched-key list.

The original prototype is the **starting point, not the finished invention**. It passed the author's 21 tests and detected 8 chosen code mutations; a separate WolfTrap review reproduced **four failures** affecting false nonaccess claims or prohibited side effects. All source, harnesses, original results, and findings have been copied into this branch.

## 1. Read these files first, in this order

1. `alibi.py` — original full implementation (Python 3.9+, `cryptography`).
2. `test_alibi.py` — original 21 tests, including exhaustive small-tree forgery search.
3. `mutation_test.py` — eight intentional security degradations to catch.
4. `test_wolftrap_alibi.py` — four additional **failing** hostile regressions. They must become green.
5. `docs/security/WOLFTRAP_ALIBI_001.md` — analysis, proofs of reproduction, limits, acceptance gates.
6. `docs/evidence/ORIGINAL_RESULTS.txt` — author's reported outputs (not independent verification).
7. `docs/evidence/WOLFTRAP_ALIBI_TEST_RESULTS.txt` — independent 4-failure trace.

Reproduce baseline before changing code:

```bash
python3 -m unittest -v test_alibi.py
python3 -m unittest -v test_wolftrap_alibi.py
python3 mutation_test.py
python3 alibi.py demo
python3 alibi.py bench 1000000
```

Expect **21/21 original passing, 4/4 WolfTrap failing, 8/8 target mutations caught** on the unchanged prototype. If actual results differ, report the exact versions, commands, errors, and environment. Never present baseline results as proof that the operational system is secure.

## 2. Security invariants (nonnegotiable)

- **NO COMPLETE CONFINEMENT EVIDENCE -> NO UNIVERSAL NONACCESS CLAIM.**
- **NO DURABLE PRE-RELEASE RECORD -> NO DATA RELEASE OR PROTECTED EFFECT.**
- **NO TRUSTWORTHY, CONTIGUOUS INTERVAL -> NO NEGATIVE PROOF.**
- **NO AUTHORITATIVE SINGLE WRITER OR CONSISTENT MULTIWRITER SEQUENCER -> NO SEAL.**
- **NO FRESH RUN BINDING -> NO STATEMENT ABOUT THAT RUN.**
- **NO INDEPENDENTLY PERSISTED WITNESS HISTORY -> NO STRONG ANTI-EQUIVOCATION CLAIM.**
- **DENIED WRITE -> NO UNAUTHORIZED FILESYSTEM SIDE EFFECT**, including empty files.
- **VALID SIGNATURE != COMPLETE LOG; VALID CHECKPOINT != ACTUAL SANDBOX CONFINEMENT.**
- **VERIFIED PROOF != AUTHORIZATION TO EXECUTE AN EFFECT.**
- If required security properties cannot be established, stop with a machine-readable `BLOCKED` result; do not lower the bar to satisfy tests.

Be explicit about the trusted computing base: the broker implementation, witness and keys, host kernel and confinement, and any privileged launcher. For an adversarial or compromised broker, witness co-signing a broker-supplied leaf list **alone** does not guarantee log completeness.

## 3. First milestone — fix the four reproduced breaks (P0)

| ID | Failure | Minimum acceptable behavior |
| --- | --- | --- |
| WT-A01 | Epoch boundary: a pre-seal logged operation releases finance data after the seal; the next epoch falsely proves nonaccess | Define precise run/epoch semantics; use an in-flight operation barrier or equivalent complete accounting; do not claim nonaccess across uncovered effects |
| WT-A02 | Two broker objects share signer and journal but only one object's events enter the witnessed root | Fail closed on a second live writer, or use real serialization and witness-verifiable aggregation; reject duplicate or ambiguous sequence identities |
| WT-A03 | A directory swap redirects `O_CREAT` outside the root; an empty prohibited file appears even though the API raises | Anchor traversal to safe directory handles with appropriate OS path constraints; no outside side effects even in fault injection |
| WT-A04 | A positive short `os.write` permits release after an incomplete journal record; recovery discards it, yielding false proof | Check full write progress; handle EINTR and zero writes; add safe framing and recovery; ensure released accesses cannot vanish |

Do not patch the tests merely to turn red into green. A fix must address the violated invariant and add/retain a test that fails on the old revision. Preserve the ability to reproduce each exploit. Use synthetic temporary directories only.

## 4. Second milestone — confinement that means something (P1)

Build a Linux **process-level demonstration**, not a pretend LLM simulation:

- Child process under an intentionally restricted identity and filesystem view with no ambient file descriptors, no unrestricted shell escapes, no inherited credentials, and no ambient network path that can reach protected data.
- Broker is the *only mediated access route* for precisely specified resources. Use kernel facilities where available (Landlock, namespace isolation, seccomp, openat2 / safe fd-relative traversal), but report the exact kernel/prerequisite/coverage of each guarantee. Landlock alone is not an attestation of total confinement.
- Block or flag symlink, hard-link, parent-replacement, bind mount, `/proc` and file-descriptor escape attempts; scrutinize `openat`, `rename`, `link`, `mmap`, directory handles, subprocess inheritance, executable/working-directory access, and network/API routes. Do not claim a defense against an untested pathway.
- Explicitly distinguish attempts, authorizations, actual opens, successful reads, writes, and completed effects in event semantics.
- Provide an honest `UNSUPPORTED` or `BLOCKED` result on hosts that cannot enforce the declared confinement. No 'test passed' from a skipped confinement test.

Important: a confined worker may need deliberate access to binaries, libraries, and scratch data. Document what is and is not inside the policy boundary; do not confuse a broad host compromise with a project-specific claim.

## 5. Third milestone — the receipt I actually want (P2)

Design `NEGATIVE_ACCESS_RECEIPT_V1`, a versioned, canonical, independently verifiable record binding:

- Fresh challenge/nonce and `run_id`; launched agent code identity or digest (what was actually run, not asserted).
- Scope: root, resource identity model, explicit protected prefix/range, operations, allowed aliases and expected event semantics.
- Start/end boundary and proof of quiescence, a contiguous broker sequence/epoch interval, and complete chain of checkpoint hashes.
- Broker identity, independent witness identity, key identifiers, signed policy digest, and durable witness head/freshness evidence.
- Merkle absence proof with an explicit privacy disclosure note; record that adjacent paths and counts may leak.
- A clear **assurance level**: `BROKER_ONLY`, `CONFINED_LINUX_VERIFIED`, or `BLOCKED` (names provisional). Do not silently promote one level into another.
- Offline `verify` CLI accepting external expected keys, challenge, policy, range, epoch/run, and typed outcome: `VERIFIED`, `REJECTED`, `BLOCKED`. The verifier must never infer the reference values from an untrusted receipt alone.

Provide deterministic serialization, negative tests for replay/substitution/splicing/fork/rollback/expired challenge, and public reproducible sample receipts generated with **synthetic** data. A valid receipt must be self-describing but not self-authorizing.

## 6. Fourth milestone — durable witnesses, privacy, and governance (P3)

- Persist witness state transactionally *before signing outward-facing claims*; test crash points, power-loss simulation, replay, fork across restarts, log rotation, identity reuse and key rollover.
- Consider two independent witnessing processes with disjoint trust roots and optional external checkpoint anchoring. Do not present 'two signatures' as independent observers if they merely sign the same unverified broker assertion.
- Investigate privacy-preserving proof variants, append-only audit extraction, verifier freshness requests, and policy-bound selective disclosure. Preserve the simplest correct version; avoid gratuitous ZK complexity.
- Future optional integration points: WolfTrap hostile test packs, Ground Truth authority grants, HERCULES effect admission, MobiPute/TruthPute computation receipts. **Do not import, copy, or expose private code, secrets, links, or credentials from those systems**. Define adapter interfaces and synthetic fixtures only.
- Reserve broader 'AI did not access X anywhere' claims until the adversary model, every possible resource path, and confinement evidence support them.

## 7. Wild direction (research track, *not* an MVP feature promise)

**An AI should be able to produce a portable, privacy-preserving, independently checkable 'I did NOT do X' receipt—anchored to a specific authorized run, with fail-closed effects—across filesystem, API/tool calls, database queries, and eventually governed devices.** Consumers could set policies such as 'prove no contact with customer secrets before releasing this analysis.' These are planned extensions, not accomplished implementations.

Think in terms of a **negative provenance plane** next to a positive provenance plane: one accounts for every mediated effect; the other proves the absence of specified effects in a closed, attested interval. Authorization governs whether the next effect may happen. Where completeness cannot be established, the honest answer is `UNKNOWN/BLOCKED`, never 'PROVEN CLEAN'.

Challenge the design before coding. Consider whether another architecture is simpler or more sound. Keep proofs precise and approachable, not magical.

## 8. Engineering and cost discipline

- Work on a **dedicated feature branch**, not `main`. Open a **draft PR** only after a coherent tested commit; **do not merge**.
- Do not install/enable GitHub Actions, paid CI, external APIs, hosted services, or release automation without owner approval. Prefer local unit, integration, mutation, property and fault-injection tests.
- Preserve original baseline files in Git history; refactor carefully and keep reproducibility.
- Prefer Python stdlib + audited `cryptography`. Every added dependency needs a reason and pinned version.
- Never use actual personal documents, real banking data, provider credentials, or external security targets in test fixtures.
- Maintain `SECURITY.md`, an explicit threat model, and deterministic test reports with commands, platform/kernel, commit SHA and outcome.
- Report measured performance only with environment and methodology, and distinguish signing/computation cost from proof transfer/verification.
- No guarantees of priority/patentability/originality without prior-art research; 'never built before' is aspiration, not evidence.

## 9. Definition of done for the FIRST Codex delivery

1. P0 defects addressed at the underlying trust boundary, not masked.
2. All 21 original tests green; all four WolfTrap tests green or a documented incompatibility with an *equivalent, stronger reproducer*; all eight original mutation faults still caught.
3. Expanded hostile tests for multiwriter, partial writes, checkpoint crash windows, concurrent epochs and path races.
4. `README.md` accurately tells a newcomer what the product *can* and *cannot* prove.
5. Document which P1/P2/P3 features are implemented, partial, or still blocked; do not conflate them.
6. Submit a concise evidence-backed design review, changed-file summary, test commands, exact revision SHA, and clear `PASS`/`CONDITIONAL`/`BLOCKED` verdict.
7. No merge, no deployment, no publication of a release, no live system claims.

**Your challenge is not to make the demo look convincing. It is to make a false proof harder than refusing the proof.**
