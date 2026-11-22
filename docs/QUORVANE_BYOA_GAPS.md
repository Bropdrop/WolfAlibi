# Independent qualification and untrusted-agent execution


This host ran the review as UID/GID 1000, with matching real, effective, saved and filesystem IDs and zero effective, permitted and ambient capabilities. Passing its actual owner/gateway identity pair to the VOIDCELL split-role preflight yielded `UNSUPPORTED`. A service-account entry or a UID remapped inside a namespace cannot establish a separately administered resource-owner account. No second authorized operator, live independently enrolled target or external witness custodian was supplied.

A third-party untrusted-code experiment would need a separately authorized disposable runtime. A candidate is a measured microVM with a pinned guest image, no guest NIC, no host directory sharing, an explicit narrow broker channel, bounded resources and independently observed teardown. Verify the image and dependency closure, runtime updates, denial/availability behavior and process accounting on that environment before admitting external code. No such runtime is qualified by this profile.

Independent qualification additionally needs authenticated key and expectation provisioning, separated signer administration, a verifier-owned challenge and witness state retained across restarts, an authenticated clock/rollback policy and a genuine two-account target trial. Testing an older ledger against a newer retained copy covers one-store rollback under that trust assumption. Joint restoration of the references and ledger by the host operator remains unassessed. Formal certification would also require a published scope, independent assessment and decision authority, versioned criteria, renewal and revocation procedures, and externally reproducible evidence. Confinement and production remain `BLOCKED`. Certification is `NOT_ISSUED`.

## Evidence required to change the current verdicts

| Open question | Evidence an independent reviewer would need |
| --- | --- |
| Separate control of identities and keys | An authorized host with independently provisioned unprivileged owner and gateway users, successful enrolled cross-account dispatch, actual kernel denials for owner key and ledger access, and a separate operator verifying the original signed outcome after restart. |
| Whole-run execution and isolation | A pinned runtime and dependency closure, measured boot or equivalent external trust anchor, authenticated pre-execution policy, complete descendant/resource accounting through teardown, and explicit coverage of every declared communication and effect route. |
| Agent-originated protected requests | A separately reviewed protocol that starts the selected framework and agent inside the measured environment, attributes an exact request to the live selected entrypoint, checks current owner authority at that boundary, and returns target evidence for the resulting effect. |
| Durable independent history | Verifier-controlled challenge issuance across runs and separately administered witness checkpoints that survive local rollback. Test conflicting histories, compromised local storage, unavailable witnesses and recovery under that custody model. |
| Third-party assessment | Public, versioned criteria, repeatable assessment by an independent party, a defined scope and exclusions, procedures for revocation and reassessment, and a responsible issuer. |

A historical report can be independently checked under the supplied public pins today. For this experiment the fixture operator controlled all roles. The three verdicts therefore distinguish reproducible observation, conditional execution evidence and the blocked decision on independent qualification.

[Operator guide](QUORVANE_BYOA_001.md) · [Measured trust boundary](QUORVANE_BYOA_BOUNDARY.md)
