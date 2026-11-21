# Quorvane Sector Profiles 001 — Offline Education & Finance Policy Lab

**Status: experimental synthetic policy test pack. NOT a certificate, admission credential, legal compliance assessment, production service, or demonstrated agent confinement.**

This isolated feature branch proposes the first two **sector-specific agentic qualification test profiles** without expanding a claim VOIDCELL 003 cannot substantiate. The published cross-UID target/gateway qualification in [draft PR #29](https://github.com/Bropdrop/WolfAlibi/pull/29) remains **UNSUPPORTED**, and production/independent custody remain **BLOCKED**.

## Try the synthetic demo

From the WolfAlibi checkout, with the existing \`cryptography\` dependency installed:

\`\`\`bash
python -m unittest -v test_sector_profiles.py
python examples/quorvane_sector_profiles_demo.py
\`\`\`

The demo creates temporary Ed25519 test keys **in process**. It simulates policy decisions; it does not read student records, open bank accounts, initiate payments, connect to external infrastructure, start agents, issue a certificate, write a ledger to disk or upload telemetry.

The module \`wolfalibi/sector_profiles.py\` supports strictly shaped local request objects and **exact request-bound** owner-signed test grants with a maximum 300-second interval. Requests are pinned to an expected owner signing key, agent public key and tenant.

It issues outputs under the schema \`quorvane.sector_lab.v1\`, always declaring:

\`\`\`json
{
  "assurance": "SIMULATED_POLICY_ONLY",
  "qualification": "NOT_ASSESSED",
  "confinement": "BLOCKED",
  "certification": "NOT_ISSUED",
  "production": "BLOCKED"
}
\`\`\`

## Education profile: EDU_STUDENT_DATA_READ_V0

| Synthetic operation | Expected decision | Control |
| --- | --- | --- |
| Tutoring on \`synthetic-lessons\` | \`ALLOWED_SYNTHETIC\` | Only a fixed math/reading lesson category, not a student record |
| Access to \`synthetic-student-records\` without a current grant | \`DENIED\` | School authority is separate from the agent's ability to tutor |
| Exact student-record read with current school-officer grant | \`ALLOWED_SYNTHETIC\` | Owner signature binds student, tenant, agent, request, purpose and resource |
| Change student, tenant or protected resource | \`DENIED\` | Grant cannot be reused for a different target |

The role and consent models here are **toy policy fixtures**, not legal authorization for child/student information. A real educational institution must define access rights, guardian/learner privacy, record retention, safeguarding and relevant jurisdictional requirements with qualified professionals.

## Finance profile: FIN_PAYMENT_INITIATION_V0

| Synthetic operation | Expected decision | Control |
| --- | --- | --- |
| Balance read without a signed owner grant | \`DENIED\` | Read access is not assumed |
| Exact owner-granted balance read | \`ALLOWED_SYNTHETIC\` | Read capability only |
| Use balance grant for payment | \`DENIED\` | Operation classes and effects are separate |
| Exact signed test payment instruction | \`PENDING_EXTERNAL_SETTLEMENT\` | One in-memory **intent**, not a sent/settled payment |
| Exact duplicate test payment request | Historical intent, \`repeat=true\` | No additional synthetic intent |
| Same request ID with different amount or changed payee | \`DENIED\` | Exact digest, payee/amount/currency binding |
| Expired/revoked/foreign-owner grant | \`DENIED\` | Current local owner authorization required |

The \`SyntheticSectorGate.intents\` mapping is **in-memory only**. It is not a durable ledger, bank-integrated idempotency control, settlement verifier, or recovery mechanism. \`PENDING_EXTERNAL_SETTLEMENT\` intentionally never means \`SETTLED\`.

## Focused qualification coverage

The new \`test_sector_profiles.py\` contains **24 offline synthetic tests** covering education route separation, authorization, cross-student/tenant substitution, balance-to-payment privilege escalation, payee and amount substitution, duplicate request identity, invalid currency/amount, expired grants, revocation, forged owner signature, wrong agent key, malformed scope, and assertion of non-certification.

In an isolated local Python environment, these **24 focused tests passed**. The **252 inherited tests and 8 inherited mutation controls have not been rerun on this GitHub feature branch**, so the entire stacked branch is *not yet qualified*. Do not merge until its exact-tree parent and new tests pass together, with visible skipped/unsupported counts.

## Next necessary integrations

1. A policy adapter for the existing Stage 4 BYOA framework hooks: no automatic assumption that hook observation proves a qualified runtime.
2. A resource-owner enforcement adapter for VOIDCELL 002/003 that retains authoritative effect state outside the agent; don't substitute this in-memory lab for its SQLite target.
3. Re-run the sector test matrix under a separately operated target/gateway identity, once an authorized two-UID host is available.
4. An independent assessor and evidence schema: independently pinned issuer and subject, measured deployment tuple, sector scope, expiry, revocation and published criteria.
5. Separate settlement reconciliation for any real financial effect, and domain-specific legal/privacy review before educational or financial deployments.

Quorvane is the **working product-facing identity** in this design; the existing WolfAlibi repository and security source remain unchanged. No trademark or formal accreditation rights are asserted.

**Research invariant:** a passed synthetic policy test is neither an ALIBI CLEARANCE credential nor permission for a protected real-world effect.

Related: [Agentic Certification issue #22](https://github.com/Bropdrop/WolfAlibi/issues/22) · [VOIDCELL 003 PR #29](https://github.com/Bropdrop/WolfAlibi/pull/29) · [VOIDCELL 002 issue #26](https://github.com/Bropdrop/WolfAlibi/issues/26).
