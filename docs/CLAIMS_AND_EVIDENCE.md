# WolfAlibi — claims and evidence register

**Reviewed against pushed Stage 2 commit:** `37b277521041d68fa81748d41824e4c8bb66a592`.

Status words:
- **IMPLEMENTED**: the code for this narrow property exists, with synthetic tests.
- **REPORTED PASS**: recorded local results; not an independent external audit.
- **BLOCKED**: the property is not established for security-sensitive operational use.
- **PROPOSED**: not yet implemented.
- **NOT ESTABLISHED**: evidence is insufficient for the requested claim.

| Statement | Evidence and limit | Status |
|---|---|---|
| Verify exclusion of a queried key range in a signed, ordered broker-supplied Merkle commitment | Authored tests, Ed25519 signatures, contiguous checkpoint chain; only the submitted committed set | IMPLEMENTED |
| Repair the four reproduced historical WolfTrap defects | Stage 1 source and regression tests; local 44-test report; tests retained at Stage 2 | REPORTED PASS |
| Stage 2 unit tests and chosen mutation harness | Codex reports 51/51 and 8/8 locally on exact Stage 2 commit; independently repeat on a second host | REPORTED PASS |
| Journal durability, single live writer and rooted path handling | Stage 1 framed WAL, `flock`, `openat2`, hostile tests | IMPLEMENTED, scoped to broker |
| Durable local witness checkpoint heads and receipts | Stage 1 `DurableWitness`; Stage 2 signed v2 state anchors | IMPLEMENTED, local state only |
| Detect rollback of a witness state snapshot | Requires a separately retained expected state digest; test covers that assumption | IMPLEMENTED under a critical external-reference assumption |
| V2 binds declared resource/boundary descriptions and externally supplied expectations | Opt-in V2 signature and verification plus local adversarial tests | IMPLEMENTED; not execution attestation |
| Linux process isolation marker and inherited FD probes | Bubblewrap synthetic probes only; `assurance: BLOCKED` even when demonstrated | IMPLEMENTED as limited demo |
| Hard-linked regular file alias cannot be read through broker | Conservative post-open refusal; not inode-wide resolution and potentially racy | IMPLEMENTED with explicit limits |
| The child has **no** unmonitored route to protected resources | No audited sole broker IPC; no complete Linux confinement qualification | BLOCKED |
| Witness has an independently operated remote retained-head/transparency service | External retention is caller-managed; remote independent service absent | PROPOSED |
| The signed code digest proves what actually executed | Digest is declared; no attestation/measurement chain | BLOCKED |
| All tools, databases, APIs and network requests are mediated | Adapter interfaces only | NOT ESTABLISHED |
| A valid receipt can authorize a downstream protected effect | No governed effect protocol; a receipt is evidence, not authority | NOT ESTABLISHED |
| 'AI never accessed X anywhere' | Direct paths, kernel, compromised broker and other out-of-scope channels remain | **NOT A VALID CLAIM** |

## Evidence anchor

Stage 1 [engineering report](ENGINEERING_REPORT.md) and [machine-readable qualification](evidence/stage1-qualification-dd7c5c76.json); Stage 2 [report](ENGINEERING_REPORT_STAGE2.md), [design](STAGE2_FOUNDATIONS.md) and [adversarial tests](../test_stage2_adversarial.py). The evidence JSON was produced by the implementation team; it is not an external certification.

A witness authenticating a broker-supplied event list checks its consistency, **not whether the broker omitted events**. Even a fully valid signature does not establish whole-agent confinement.

## Before promoting a claim

Provide exact commit, test commands, observed outcomes, environment (OS/kernel/Python/crypto), independent verifier expectations, effect/side-effect analysis, adversarial coverage, and a threat-model statement. Unsupported platform or skipped test: **BLOCKED**, not green.

**Current operational security verdict: BLOCKED.** No enterprise or compliance guarantees.
