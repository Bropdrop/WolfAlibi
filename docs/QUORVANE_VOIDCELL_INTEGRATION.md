# Proposed Quorvane integration with VOIDCELL

The sector lab currently evaluates Python values and records a payment intent in memory. VOIDCELL 003 currently serves one resource-owned synthetic counter. The proposed adapter would place sector admission and the corresponding synthetic effect in the target process. A sector decision today carries `SIMULATED_POLICY_ONLY`, `qualification=NOT_ASSESSED` and `certification=NOT_ISSUED`. Cross-UID custody is `UNSUPPORTED` on this builder. [Sector profiles](QUORVANE_SECTOR_PROFILES_001.md) · [VOIDCELL 003 procedure](VOIDCELL_EXPERIMENT_003.md)

## Actors and inputs

| Actor | Proposed responsibility |
| --- | --- |
| Resource owner | Select the tenant, resource, enabled profile and policy version. Pin the permitted authorizer keys and roles for each operation. The school controls record-read grants. The account authority controls balance and payment grants. |
| Gateway | Persist the exact dispatch before transmission. Sign its envelope and present it over the per-run socket from the enrolled gateway UID. Keep only its own private key and intent journal. |
| Target | Keep its signing key, resource data, ledger, revocations and authoritative decisions under the resource owner's identity. Use the kernel peer credentials on the request connection and independently configured policy and verification pins. |
| Runtime supervisor and witness | Bind the qualified worker and its live gateway route to an externally supplied challenge and run ID. Supply current execution evidence and a retained witness head. The sector request's agent public key alone cannot establish who sent it. |
| Settlement authority | If settlement research is added later, authenticate the separate system that observes a completed synthetic settlement. Pin its verification key independently of the gateway and initiation target. |

Start with the existing VOIDCELL roles and journal pattern. Keep its counter scope, receipt types and verifier compatible. Introduce separate versioned sector record types and signature domains for dispatch, owner grant, target decision, reconciliation and any future settlement record. The sector lab's V1 grant omits live-run and target bindings. Enroll a new grant for the integrated protocol. [Target authority](../wolfalibi/voidcell002.py) · [Gateway journal](../wolfalibi/voidcell_gateway.py) · [003 trial runner](../wolfalibi/voidcell003_gateway.py)

## Admission at the resource

1. At provisioning, give both parties authenticated public pins for the target, gateway, authorizer, supervisor and witness. Pin the source revision, policy epoch, exact allowed target resource and expected run. The gateway checks the socket peer and signed target inventory. The target checks the gateway UID on the connection and the signed dispatch.
2. Revalidate the operation using the closed sector request grammar. Bind the owner signature to the audience, target identity, policy epoch, tenant, agent, operation, request ID and canonical argument digest. Bind dispatch to that grant, the live run ID and verifier challenge. Verify qualification freshness, witness continuity, the grant interval on the target clock, and durable revocation state.
3. Route tutoring only to the declared lesson fixture. For a record read, bind the exact student and purpose and require the school grant. For a balance read, bind the account. For an initiation, bind the account, payee, integer amount and currency and require explicit payment authority. Commit the read authorization and evidence before releasing a synthetic result.
4. For payment, key the target's durable uniqueness constraint by target, tenant, operation and request ID. Store a separate digest of the immutable business request so that a changed amount or payee conflicts, even across restarts. Keep the grant and run digests as authorization evidence. A renewed grant for an identical request must never open another payment slot.
5. Serialize revocation and admission at the target. In one resource transaction, record the decision, any new intent and the signed receipt. Advance the retained checkpoint before returning the receipt. A duplicate with current authority can retrieve the original intent. A conflicting request or revoked grant receives a denial.

## Ambiguity, privacy and settlement

After a lost reply, the gateway reopens its original journal and reconciles by exact dispatch digest. The target returns the committed receipt or durably fences a missing dispatch before answering. A mismatch between committed SQL state and the retained checkpoint blocks service for owner review. Protecting against coordinated restoration of both stores requires an independently held latest checkpoint.

The lab's `PENDING_EXTERNAL_SETTLEMENT` currently describes a volatile synthetic intent. A future initiation receipt would establish only the target-local disposition. A settlement verifier would need an independently pinned authority's signed event referencing the exact initiation receipt, tenant, account, amount, currency and unique settlement ID. It would reject a replay, conflicting history or message from the gateway purporting to settle the operation.

Public handoffs should disclose the minimum public pins, commitments and typed outcomes. Keep sensitive arguments and the evidence needed to open their commitments in owner-controlled storage. Student references and small amounts can be guessed from unsalted hashes. Define the commitment scheme, selective disclosure, retention and access rules before independent review.

## Qualification before enabling the adapter

Begin with one synthetic protected read, then qualify the synthetic payment intent separately. Require distinct unprivileged accounts, a successful authorized dispatch, wrong-UID rejection, and actual denied opens of the key and ledger. Exercise cross-tenant and cross-profile substitution, forged or expired grants, concurrent conflicting IDs, revocation ordering, restart, lost requests and replies, and checkpoint divergence. Require independent reproduction from external run and key pins. Live runtime qualification, independent witness custody, settlement and formal certification each require their own evidence and review. Production remains `BLOCKED`.
