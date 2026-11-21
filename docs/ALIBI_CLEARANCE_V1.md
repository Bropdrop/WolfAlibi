# ALIBI Clearance V1

**Local synthetic research demonstration. Production use is blocked.**

Clearance V1 combines a newly issued, completed Solitary qualification with a
separate owner-approved, one-shot read of a fixed local service. It is a narrow
admission experiment based on the Solitary implementation in [PR #21](https://github.com/Bropdrop/WolfAlibi/pull/21)
and the requirements in [Issue #17](https://github.com/Bropdrop/WolfAlibi/issues/17) and
[the Solitary design draft](https://github.com/Bropdrop/WolfAlibi/pull/16).

The gateway uses this fixed scope.

| Field | Fixed value |
| --- | --- |
| Audience | `wolfalibi.clearance.synthetic.v1` |
| Resource / operation | `synthetic-records` / `read` |
| Qualification fixture | `protected.txt` |
| Profile | `solitary-synthetic` |
| Effect | One local synthetic service callback, with a response digest |

The demonstration runs offline with local synthetic data. The upstream
credential stays in trusted gateway and stub process memory. The Solitary
worker receives its existing fixed environment and broker endpoint.

## Qualification scope

The admission predicate requires **completion of a newly issued Solitary
trial**. A fresh challenge, run contract, fixed qualification fixture, expected witness
head, and pinned identities must all match. It is valid only for the exact
synthetic scope and short window described here.

The later request comes from a trusted local Python fixture with its own
subject signing key. The gateway re-hashes the on-disk runtime profile before
admission and effect. This is a point-in-time file identity check. The
qualification envelope covers the earlier Solitary worker. Confinement and
runtime identity of the later client remain unverified.

A terminal Solitary receipt serves as a build-and-scope prerequisite for this
one synthetic admission. Live process confinement and production authorization
remain blocked.

## Two deliberately separate phases

1. **Qualification.** The gateway creates a fresh Solitary contract and a
   120-second qualification window. `VerifierStore` issues and consumes the
   challenge against pinned broker, witness, and supervisor keys. It verifies
   the completed Solitary envelope and supervisor record while checking an
   independently retained, live witness-state head. The fixed `protected.txt`
    read exercises the qualification fixture. The stub read is a distinct effect.

2. **Admission and local effect.** A separately pinned owner signs one exact
   grant for the issued scope. The grant binds the run, challenge, fixed key
   and fixture hash, contract hash, agent and gateway keys, expected witness
   state, and executable/worker/profile/policy digests. A separate local
   subject key signs one request. Only then may the trusted local gateway call
   its fixed synthetic service once.

The gateway emits signed decisions whose condition axes remain distinct:

| Axis | Meaning |
| --- | --- |
| Qualification | `SYNTHETIC_CURRENT` only while the exact live qualification checks hold; otherwise `BLOCKED` or denied. |
| Owner authorization | Exact signed grant is `CURRENT`, `DENIED`, or `REVOKED`. |
| Effect | `NONE`, gateway-observed `OBSERVED`, or `UNKNOWN`; an unknown effect is never retried automatically. |

`OBSERVED` means that the trusted local gateway observed its fixed callback
return. It is not independently witnessed byte consumption or a claim about a
real upstream service.

## Grants, expiry, and revocation

An owner grant has an exact scope, gateway target, subject key, `budget: 1`,
and a validity window of at most 300 seconds. Admission creates an unexported
capability valid until the earliest of the owner-grant expiry, qualification
expiry, and 30 seconds after admission. The request is bound to the hash of
that capability and is rejected if signed by another key or reused.

The owner may submit a separately signed revocation for the exact grant and
gateway. The private gateway serializes revocation and effect checks under its
single lease. A revocation recorded before the effect gate blocks the effect;
a concurrent revocation has the local serialized order in which it is committed
and cannot undo a completed callback. Time is the gateway's trusted local wall
clock, which refuses to move backward within persisted state.

## Persistence and recovery boundary

The demo starts in a new, owner-controlled private state directory. It uses
a single non-blocking file lease and a SQLite store with `synchronous=FULL`.
Its verifier store is separate and the expected witness head must also be
observed outside that database. This detects a changed/restored local witness
history only to the extent that the retained external head and trusted host are
actually protected.

Before calling the synthetic service, the gateway durably marks the one use as
`PENDING` with the signed request identity. It writes a terminal signed result
after a normal callback return and final predicate checks. A timeout or
interruption may leave the entry `PENDING` or `INCOMPLETE`. Subsequent calls
report an `UNKNOWN` effect and `NO_AUTOMATIC_RETRY`. Reconciliation is manual.
SQLite cannot make an external effect transactional. At-most-once local
dispatch depends on the one gateway ledger remaining intact.

Reports contain bounded signed records and constrained hashes, not capability
tokens, private keys, credentials, or raw response bytes. They are local audit
artifacts, not portable credentials.

## Verification boundary

Live admission requires the current `VerifierStore` state, live retained
witness head, owner grant/revocation state, and profile re-hash callback.
Offline `verify` checks the historical positive chain against supplied public
keys, contract, and pre-run witness digest. It deliberately cannot query
current revocation, current witness availability, current process identity, or
confinement.

The demo writes `expected.json` for reproducibility. Because the demo also
creates its own local keys and expectation file, that file alone is not
independent custody. A party seeking independent verification must retain and
supply the expected pins and witness anchor before the run, outside the
report-producing process.

Trusted assumptions include the local host/kernel, gateway, SQLite durability,
clock, owner key, verifier and witness key custody, externally retained witness
head, fixed local service, and profile callback. Not provided are arbitrary
agent mediation, complete resource mediation, real API/database authorization,
independent timing or host attestation, recovery of an external side effect, or
any guarantee after the qualification process has ended.

## Reproduce locally

Install the local checkout, then use a fresh private directory for every trial:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[agent-all]'
umask 077
state=$(mktemp -d)
```

`--consent` permits the fixed local Solitary execution only. Without the
separate owner-approval flag, the demonstration deliberately signs no owner
grant, returns a signed `DENIED` result, and reports `upstream_reads: 0`:

```bash
wolfalibi byoa clearance demo --consent --state-dir "$state"
```

For the one positive synthetic read, create another fresh private state
directory and explicitly approve the demo owner's grant:

```bash
state=$(mktemp -d)
wolfalibi byoa clearance demo --consent --approve-synthetic-read --state-dir "$state"
wolfalibi byoa clearance verify --report "$state/report.json" --expect "$state/expected.json"
```

The second command verifies historical signatures and bindings. It does not
turn the locally generated `expected.json` into independent third-party
evidence.

Run the broad local qualification suite on the exact tree being reviewed:

```bash
python -m unittest discover -v
python -u mutation_test.py
python scripts/qualify_clearance.py
```

The qualification script records the exact revision and tree, environment,
commands, outputs, demonstration report, and verification result.
Unsupported Linux prerequisites, a dirty/changing tree, a skipped required
test, a failed mutation check, or a failed trial must block qualification rather
than be reported as a production-ready result.
