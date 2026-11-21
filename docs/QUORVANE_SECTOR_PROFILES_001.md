# Quorvane Sector Profiles 001 — Offline Education & Finance Policy Lab

**Status: experimental synthetic policy test pack. NOT a certificate, admission credential, legal compliance assessment, production service, or demonstrated agent confinement.**

This isolated feature branch proposes the first two **sector-specific agentic qualification test profiles** without expanding a claim VOIDCELL 003 cannot substantiate. The published cross-UID target/gateway qualification in [draft PR #29](https://github.com/Bropdrop/WolfAlibi/pull/29) remains **UNSUPPORTED**, and production/independent custody remain **BLOCKED**.

## Try the synthetic demo

From the WolfAlibi checkout, with the existing `cryptography` dependency installed:

```bash
python -m unittest -v test_sector_profiles.py
python -m examples.quorvane_sector_profiles_demo
```

The demo creates temporary Ed25519 test keys **in process**. It simulates policy decisions; it does not read student records, open bank accounts, initiate payments, connect to external infrastructure, start agents, issue a certificate, write a ledger to disk or upload telemetry.

The module `wolfalibi/sector_profiles.py` supports strictly shaped local request objects and **exact request-bound** owner-signed test grants with a maximum 300-second interval. Requests are pinned to an expected owner signing key, agent public key and tenant.

It issues outputs under the schema `quorvane.sector_lab.v1`, always declaring:

```json
{
  "assurance": "SIMULATED_POLICY_ONLY",
  "qualification": "NOT_ASSESSED",
  "confinement": "BLOCKED",
  "certification": "NOT_ISSUED",
  "production": "BLOCKED"
}
```

## Education profile: EDU_STUDENT_DATA_READ_V0

| Synthetic operation | Expected decision | Control |
| --- | --- | --- |
| Tutoring on `synthetic-lessons` | `ALLOWED_SYNTHETIC` | Only a fixed math/reading lesson category, not a student record |
| Access to `synthetic-student-records` without a current grant | `DENIED` | School authority is separate from the agent's ability to tutor |
| Exact student-record read with current school-officer grant | `ALLOWED_SYNTHETIC` | Owner signature binds student, tenant, agent, request, purpose and resource |
| Change student, tenant or protected resource | `DENIED` | Grant cannot be reused for a different target |

The role and consent models here are **toy policy fixtures**, not legal authorization for child/student information. A real educational institution must define access rights, guardian/learner privacy, record retention, safeguarding and relevant jurisdictional requirements with qualified professionals.

## Finance profile: FIN_PAYMENT_INITIATION_V0

| Synthetic operation | Expected decision | Control |
| --- | --- | --- |
| Balance read without a signed owner grant | `DENIED` | Read access is not assumed |
| Exact owner-granted balance read | `ALLOWED_SYNTHETIC` | Read capability only |
| Use balance grant for payment | `DENIED` | Operation classes and effects are separate |
| Exact signed test payment instruction | `PENDING_EXTERNAL_SETTLEMENT` | One in-memory **intent**, not a sent/settled payment |
| Exact duplicate test payment request with current authority | Historical intent, `repeat=true` | Concurrent copies create one in-memory intent |
| Same request ID with different amount or changed payee | `DENIED` | Exact digest, payee/amount/currency binding |
| Expired/revoked/foreign-owner grant | `DENIED` | Current local owner authorization required |
| Claimed settlement action or caller-supplied settlement field | `DENIED` | The existing intent and its pending status are preserved |

The `SyntheticSectorGate.intents` mapping is **in-memory only**. It is not a durable ledger, bank-integrated idempotency control, settlement verifier, or recovery mechanism. `PENDING_EXTERNAL_SETTLEMENT` intentionally never means `SETTLED`.

## Qualification Gate 001 review

PR #30 added four files above VOIDCELL 003 commit `83dcecb9301f998a25352b2825527db7d153019a`. Its submitted head `afe9b5b0bc9415a3900fc2596ee0dbbe2aa473a4` passed 276 tests with zero skips and detected all eight inherited ALIBI mutations before repairs.

| Finding in the submitted code | Repair and qualification control |
| --- | --- |
| Request validation and signature checking read caller-owned dictionaries more than once. A later edit could change the returned request or authenticated grant ID. | Validate detached fields and arguments. Verify the exact signed payload and use the ID from that snapshot for revocation. The grant helpers reject tutoring grants and require the operation's specified role. |
| Payment lookup and insertion, revocation checks and updates, and inspection of bookkeeping were unsynchronized. | Order admission, revocation and intent insertion under one per-gate lock. Concurrent identical requests return one new and one historical intent. A conflicting request cannot replace the winner. Public inspection returns snapshots. |
| A gate accepted earlier supplied time samples after observing expiry. | Record the latest sample in the gate and recheck it when admitting an operation. A stale sample returns `BLOCKED`. A fresh evaluation at or after the grant's expiry is denied. A newly authorized identical request can retrieve the prior intent without creating another. |

The fixture trusts its configured owner to issue grants for the relevant resources and roles. It matches a request's agent label to a pin. There is no proof of possession by a live agent, and the grant's role field carries no independent institutional credential. The initial absolute time and subsequent samples come from the trusted fixture caller. Restart discards the time history, revocations and simulated intents. These limits apply to every sector result.

## Focused qualification coverage

The new `test_sector_profiles.py` contains **24 offline synthetic tests** covering education route separation, authorization, cross-student/tenant substitution, balance-to-payment privilege escalation, payee and amount substitution, duplicate request identity, invalid currency/amount, expired grants, revocation, forged owner signature, wrong agent key, malformed scope, and assertion of non-certification.

Qualification Gate 001 runs the inherited VOIDCELL suite, these 24 tests, the review regressions, the eight original ALIBI mutation checks and the synthetic demo. Run the following command from a clean checkout with the optional agent integrations installed. Choose an output file outside the checkout.

```sh
python scripts/qualify_sector_profiles.py > "$evidence_dir/qualification.json"
```

The JSON identifies the reviewed PR, its VOIDCELL parent and the tree under test. A policy pass applies only to the recorded in-process cases. The trusted caller supplies time and expected keys. An agent key in a request identifies the intended subject. The lab does not authenticate a running agent. The target-side authorization, custody, replay and settlement requirements are specified in the [VOIDCELL integration design](QUORVANE_VOIDCELL_INTEGRATION.md).

Quorvane is the **working product-facing identity** in this design; the existing WolfAlibi repository and security source remain unchanged. No trademark or formal accreditation rights are asserted.

**Research invariant:** a passed synthetic policy test is neither an ALIBI CLEARANCE credential nor permission for a protected real-world effect.

Related: [Agentic Certification issue #22](https://github.com/Bropdrop/WolfAlibi/issues/22) · [VOIDCELL 003 PR #29](https://github.com/Bropdrop/WolfAlibi/pull/29) · [VOIDCELL 002 issue #26](https://github.com/Bropdrop/WolfAlibi/issues/26).
