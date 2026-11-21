# Quorvane Gate V1 — synthetic sector resource gate

Quorvane is a local research fixture for the narrow sector direction in
[Issue #22](https://github.com/Bropdrop/WolfAlibi/issues/22), informed by the
resource-side boundary in [Issue #19](https://github.com/Bropdrop/WolfAlibi/issues/19)
and the live-caller gaps identified in the [PR #23 review](https://github.com/Bropdrop/WolfAlibi/pull/23).
It is neither a certification nor an authorization system for real education
or financial services.

This branch retains the exact PR #23 ancestor and all 214 tests from its
VOIDCELL descendant in PR #25. Quorvane issues its own live qualification for
the synthetic resource.

## Active local qualification

The resource owner runs a private SQLite `synchronous=FULL` parent/server
fixture and issues an exact short-lived run containing the resource challenge,
tenant, sector profile, and active policy epoch.  A separate fixed Python
process echoes fixed, local test requests over a private Linux
`SOCK_SEQPACKET` endpoint. The target checks kernel `SO_PASSCRED` metadata for
each received record. It retains a pidfd, rejects unexpected queued data at
the transport checks, and measures the executable, argv, start time, UID,
exec environment and descriptors of the live process. After committing the
signed effect, the target rechecks authority and sends the result to the same
peer. A second credentialed echo acknowledges the result frame. That tests
delivery to the fixed fixture. Agent intent, result use and continuous
process liveness remain outside the claim.

The trusted local qualifier and witness roles use distinct keys to sign the
exact measured identity and run. The gate checks them against the
externally retained witness head at enrollment and at each effect.
Enrollment requires a live measured peer on the target-issued challenge.

This establishes only a same-host local protocol boundary.  The server,
parent, authorities, and caller run under the trusted harness and same UID;
they are not independently administered trust domains.

## Fixed synthetic operations

| Profile | Resource behavior |
| --- | --- |
| Education | A fixed tutor answer is allowed only under an exact owner grant. Synthetic student-record requests are always denied. |
| Finance | A synthetic balance read requires an exact owner grant. Payment initiation requires an exact grant from a distinct payment-owner key that binds payee, amount, payment ID, tenant, run and policy epoch. |

For payment initiation, the target durably reserves one tenant-wide
idempotency key and records a signed initiation receipt in the same atomic
transaction.  A separate trusted settlement authority must sign that exact
initiation-receipt hash before settlement, which commits atomically. The
expiry, policy change or revocation of a caller's grant blocks new
initiations. Existing reservations can settle with separate authority.
Reconciliation is read-only and returns the stored historical target receipt.
A lost reply stays `UNKNOWN` until reconciliation supplies evidence. An exact
settlement replay returns the original receipt without a second debit.

## Local use and qualification

With the active `agent-all` extras installed, use an empty private directory:

```bash
state=$(mktemp -d)
python -m wolfalibi.quorvane_demo demo --consent --state-dir "$state"
python -m wolfalibi.quorvane_demo verify \
  --report "$state/report.json" \
  --expect "$state/expected.json"

python scripts/qualify_quorvane.py
```

The demo uses only synthetic fixtures. Offline verification checks historical
qualification and witness records, owner grants, target receipts and linked
settlement authority against separately supplied expectations. The demo
generates the expectations locally. Current liveness, revocations and policy
state must be checked at the resource.

## Explicit limits

The gate does not establish arbitrary-process confinement, descendant-process
tracking, host-level denial-of-service containment, independent witness/key
custody, or route completeness outside the declared fixture.  It does not
provide a real student-record service, banking service, payment rail,
compliance approval, production deployment, or formal certification.  All of
those claims remain **BLOCKED**.
