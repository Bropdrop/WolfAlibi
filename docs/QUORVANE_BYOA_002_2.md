# Custody closure review

## Verdicts

| Gate | Verdict | Basis |
|---|---|---|
| A. Full regression completeness | BLOCKED | The selected local run covers all 002.1 custody tests and both inherited focused cases. The complete 605-test and 14-mutation reproduction remains outstanding. |
| B. Checkpoint consistency | CONDITIONAL | A separately preserved journal, signed local anchor, honest target and authentic verifier are required. The target compares the generation, signed record digest and materialized state digest. |
| C. Revocation continuity | CONDITIONAL | The target checks the revoked grant ledger before commitment and handoff. Repeated identical revocations advance signed history. Both the exact predecessor and authorization state must agree. |
| D. Recovery after interruption | CONDITIONAL | Retained matching target and verifier records support historical inquiry. One-sided commits can require retirement of the enrollment. |
| E. Cross-account isolation | UNSUPPORTED | Only UID 1000 was authorized. |
| F. Independent witness custody | UNSUPPORTED | All local roles and example public pins share one administrator. |
| G. Independent readiness | BLOCKED | Full regression and independently administered evidence remain outstanding. |

## Protocol review and crash boundaries

Row zero in the anchor-covered decisions table holds the exact journal head. The reserved non-hex label cannot match an operation digest. The target initializes the row only against signed genesis and updates it with the effect or revocation inside the target transaction. A 002.1 store lacking this record can still supply historical inquiry. New live operations require fresh provisioning or an independently reviewed migration. The code does not derive a missing historical pin from the supplied journal.

| Boundary | Durable observation or basis | Disposition |
|---|---|---|
| Before authenticated pending acceptance | Missing pending control inspects zero committed effects. | Withhold. |
| After pending approval, before journal COMMIT | Child terminated at journal COMMIT. On reopen there were zero target rows, only genesis and verifier generation zero. | A fresh live check allowed one commitment. |
| After journal COMMIT, before target COMMIT | Child terminated at target COMMIT. Signed history had two entries, target had zero effects and verifier generation was zero. | Restart refused dispatch. The journal records a prepared transition, insufficient evidence of an effect. |
| After target COMMIT, before local anchor publication | Child terminated before local anchor advance. One effect, two journal entries, verifier generation zero. | Reopen detected divergence. |
| During anchor file publication | SQLite state and local anchor are separate durability domains. Exact filesystem replacement and power-loss cut points were not injected. | A torn or inconsistent anchor cannot establish authority. |
| After local publication, before verifier retention | Retention interrupted. One target row survived. Historical inquiry lacked the matching ACK. | Withhold and preserve evidence. |
| After verifier commit, before retain reply | Callback interrupted after actual verifier retention. Reopen returned the original ACK. Counts were one target row and verifier generation one. | Historical reconciliation only. |
| After ACK, before protected handoff | Live re-read of the retained ACK and journal plus grant, peer and time checks. Restoring verifier state in this window withheld the body despite one durable target row. Revocation during retention also withheld the body. | Withhold on disagreement. |
| Response delivery and subsequent inquiry | Lost-reply simulation reopened the target, compared the signed receipt and ACK, and counted one effect. | Delivery to a recipient remains unknown. |
| Revocation publication | Restart and restoration tests cover committed revocation. Journal and target share the same publication ordering as effect commitment. | Mid-revocation power loss was not separately measured. |

The isolated restoration tests compare target-only, verifier-only and joint snapshots with surviving state. The fork control orders two genuine revocations differently to produce distinct signed heads with the same generation and state digest. The stale-generation control uses consecutive valid signatures over identical authorization state. Both tests observe a blocked dispatch and zero effects on the restored test target. The original duplicate-disclosure reproducer remains in inherited history.

## Administrative recovery and reviewer custody

Quiesce the affected enrollment. Preserve immutable copies of the journal, target database and anchor, verifier database and anchor, and the previously retained public expectations. Record file hashes and the last confirmed generation through the independent reviewer. Verify the signed journal against that reviewer's enrollment, target key and exact head. Use the historical package verifier to compare the original request, owner grant, target receipt and verifier ACK. A matching authenticated pair establishes one historical decision. Neither artifact establishes recipient delivery.

If the stores disagree, preserve the original records and classify the operation as unresolved. If a unique outcome cannot be authenticated, retire the enrollment and close its grants. Resuming new work requires separately authorized fresh identities, epoch, genesis and challenge. Reissuing the unresolved request or rewinding a checkpoint risks another disclosure.

Use the [two-account procedure](QUORVANE_BYOA_002.md) with the [custody profile](QUORVANE_BYOA_002_1.md) on a separately authorized host. The reviewer supplies the enrollment digest and key obtained at enrollment, retains each accepted successor separately and selects the final expected head from that store. Same-run producer-generated expectations support a format/cryptography regression only. Local processes, filesystem ownership and distinct keys do not establish separate administration.

The journal, local anchor and verifier remain separate transactions. Availability depends on their survival and trusted SQLite/filesystem durability. Joint rewind of all trust inputs, key compromise, hostile administration and changes after the final live check remain outside the claim. Production and arbitrary-agent confinement remain blocked. No certificate was issued.

## Reproduction

Create a private virtual environment and install the five direct package pins listed in pyproject.toml under dependencies and agent-all. From the exact checkout run `PYTHON=/path/to/venv/bin/python scripts/qualify_byoa0022.sh /new/output/directory`. The runner captures Git objects, platform, package versions, commands, unittest output, three selected inherited mutants, both original custody mutants, two decision-state mutants and historical verification. The original wording-only detection is recorded separately and receives no custody-control credit. The two closure controls check the actual consumed challenge digest and the committed successor of a revocation.
