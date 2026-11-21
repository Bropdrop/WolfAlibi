# VOIDCELL Experiment 001 — synthetic resource-side effect gate

This experiment tests one offline effect, a single increment of
`synthetic-counter`. It builds on Stage 5 commit
`114e2447ef00bd36127f75a44e5042f83b6fef97`. [Issue #19](https://github.com/Bropdrop/WolfAlibi/issues/19) ·
[VOIDCELL design](https://github.com/Bropdrop/WolfAlibi/pull/20) ·
[Stage 5 baseline](https://github.com/Bropdrop/WolfAlibi/pull/24)

## Narrow enforcement walkthrough

1. A fixed Stage 5 Solitary envelope is pinned to the request, including its
   current contract, challenge, profile, and expected witness-state digest.
2. A separately signed owner grant authorizes exactly one synthetic
   `synthetic-counter` / `increment` operation.
3. The independent gateway signs the exact scoped dispatch, durably records
   its intent before sending it, and never automatically retries an uncertain
   dispatch.
4. The resource-side target independently re-verifies the current Solitary
   envelope, owner grant, operation scope, expiry/revocation state, and an
   externally supplied current witness head immediately before the effect.
5. Its owner-controlled SQLite ledger uses `synchronous=FULL` and one
   transaction to persist the decision, a single accepted counter-increment
   row when allowed, and a signed target receipt.  Denials and revocations are
   durable too.
6. A missing or unverified reply leaves the gateway intent `AMBIGUOUS`.
   Reconciliation returns the stored signed result. When the ledger has no
   result, the target commits a `FENCED` receipt and a rejection of late
   dispatch together. A denial binds the exact dispatch digest and remains
   denied on replay. The gateway lease and delivery lock prevent reconciliation
   from fencing a dispatch while the live gateway is still delivering it.

The target therefore treats a self-reported AgentProbe result, a direct agent
request, a forged gateway record, or a stale/mismatched qualification as no
authority.  The fixture gives the agent no service-admin interface or target
credential.

## Local topology and its limit

The hostile fixture and target run in separate subprocesses. The trusted
harness relays the fixture packet to the target without adding a gateway
signature. The target serves one RPC per subprocess over offline pipes. The
harness holds the test signing roles and configures the target's private
bootstrap. Both subprocesses share the host and UID. The model assumes the
fixture cannot modify trusted code, the authority file, or the private ledgers.
Exposure to arbitrary same-UID code and independent administrative custody
remain unqualified.

An agent may send direct packets or fabricate its own reports.  Such data is
dropped unless it passes the target's pinned signatures and current checks.
This is resource-side enforcement for the named synthetic target, not proof
that the agent cannot access other resources.

## Synthetic CLI and verification

Use an empty private directory created locally:

```bash
state=$(mktemp -d)
python -m wolfalibi.voidcell_demo demo --consent --state-dir "$state"
python -m wolfalibi.voidcell_demo verify \
  --receipt "$state/receipt.json" \
  --expect "$state/expected.json"
```

The verifier checks the historical target signature and the externally
supplied scope, target key and dispatch digest. Its result is
`TARGET_RECEIPT_ONLY`. Live policy state and revocation history are outside
that verification. The demo generates matching
expectations locally. Retain your own references for independent review.
`dispatch.json` holds the signed route and the exact owner grant and Solitary
envelope the target evaluated. An independently supplied Solitary expectation
file can be used with `wolfalibi byoa verify`.

Install the `agent-all` extra to cover the inherited framework tests, then
reproduce the exact-tree result.

```bash
python -m pip install -e '.[agent-all]'
python scripts/qualify_voidcell.py
```

It runs the inherited 198-test suite and focused hostile tests, recording the
exact local result rather than enabling hosted CI or contacting an external
service.

## Remaining blocked claims

`RESOURCE_SIDE_EFFECT_GATE` covers the one SQLite counter under the trusted
target, signing keys, resource clock, retained witness reference and
transactional ledger. Owner-signed revocations delivered to the target
serialize with dispatch inside the database. The receipt time is the target's
decision time. This experiment
assumes one intact database per provisioned run. Coordinated rollback,
independent witness administration, cancellation of a committed effect,
external services, alternate routes, process confinement and
denial-of-service containment remain **BLOCKED**.
