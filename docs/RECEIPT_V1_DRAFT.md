# NEGATIVE_ACCESS_RECEIPT_V1 — discussion draft

**Status:** not implemented; schema proposal only. This file is not a certification protocol or a valid sample receipt.

## Claim semantics

`NO_MEDIATED_OPERATION` means *no matching event in a complete, externally anchored, policy-bound observation of specified mediated surfaces during one closed run*. It does **not** imply the unmonitored universe was untouched.

A verifier needs trusted expectations **outside** the receipt. No self-issued receipt may choose its own verification criteria after the fact.

## Logical fields (names provisional)

```text
version = NEGATIVE_ACCESS_RECEIPT_V1
issuer:
  broker_key_id
  broker_pubkey
  witness_key_id(s)
run:
  run_id
  challenge_nonce
  challenge_expiry
  measured_executable_digest
  agent_identity_claim (optional, separately attested)
policy:
  policy_digest
  resource_identifier_scheme
  resource_scope
  operation_set
  denied_attempts_count_as_touch
  claimed_mediated_surfaces
environment:
  assurance_level
  kernel/confinement feature report
  evidence_digest
coverage:
  start_boundary
  end_boundary
  quiescence_evidence
  first_epoch / last_epoch
  first_seq / last_seq
  checkpoint_chain
proof:
  canonical merkle nonmembership witness(es) for each relevant epoch
  co-signatures
  commitment anchoring / freshness evidence
verification:
  algorithm_and_schema_versions
  informational_privacy_disclosures
```

Do **not** put actual customer filenames or secret payloads in published test receipts. Use synthetic names and deterministic test keys where appropriate.

## Cryptographic binding

Define an unambiguous canonical byte representation with domain-separated signatures. Bind challenge, policy, run, resource scope, statement type, effects definition, coverage, environment assurance and checkpoint-chain roots into the signed transcript. Do not rely on ordinary JSON object key ordering or a merely descriptive string. Require strict validation of numeric range, tree size, path length and type; reject duplicates, unknown critical fields, impossible epoch/sequence intervals and trailing data. Decide and document key-rotation semantics.

## Verification algorithm outline

1. Check caller-supplied trusted public keys, expected challenge, expected run, expected policy/scope and minimum assurance.
2. Parse the receipt under exact protocol/version rules; reject malformed or ambiguous encodings.
3. Authenticate the complete transcript and expected signing identities.
4. Verify policy and measured execution environment; if the claimed confinement lacks required evidence, output `BLOCKED`.
5. Verify fresh run closing/quiescence, contiguous event/epoch coverage, durability and witness-head proof; if evidence is incomplete, `BLOCKED`.
6. Check nonmembership proofs against authenticated checkpoints. Invalid proof/signature/expected-value mismatch is `REJECTED`.
7. Output `VERIFIED` only for the **exact** declared predicate and assurance level, including what is not covered.

## Required hostile fixtures

- Authentic receipt for wrong challenge, wrong run or wrong verifier expectation.
- Authentic evidence with a broader claimed interval than checkpoints cover.
- Valid signature but no confinement evidence, or unsupported kernel features.
- Valid witness signature on an incomplete broker log.
- Authentic epoch history spliced with another fork or reset witness state.
- Duplicate sequence numbers, partial journal recovery, overlapping operations.
- Alias of protected resource by hard link, symlink, bind mount or inherited descriptor.
- Scope confusion between `finance/` and `finance-other/`, canonical Unicode/byte/path cases, directory list vs file read.
- Signature substitution, key-rollover ambiguity and use of an expired challenge.
- Count/timing/neighbor privacy disclosure tests.

## Protocol evolution

Build a testable minimal `BROKER_ONLY` proof first; mark it limited. Extend to a `CONFINED_LINUX_VERIFIED` assurance profile **only** after real confinement evidence exists. Do not version-bump a format merely to make a failing security test disappear.

Review questions and changes should be contributed through a small pull request with a counterexample or verifier test.
