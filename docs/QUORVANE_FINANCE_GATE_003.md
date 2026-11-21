# Quorvane Gate 003 — a target-owned synthetic payment intent

A local Linux target records one fictional payment intent per request ID and returns a signed receipt. The example requests 4,500 CAD minor units from `fictional-checking` to `fictional-supplier` under tenant `fictional-bank`. The only signed financial outcome is `PENDING_EXTERNAL_SETTLEMENT`. The experiment has no balances, clearing network or settlement authority.

## Run and verify one trial

Use an unprivileged Linux account with procfs, pidfds and Unix sequence-packet sockets with peer and message credentials. Use Python 3.11+ with the repository's pinned dependencies. The full inherited suite also exercises the `agent-all` extras and the earlier Linux fixture dependencies.

```sh
evidence_dir=$(mktemp -d)
challenge=$(python -c 'import secrets; print(secrets.token_hex(32))')
python -m examples.quorvane_finance_demo --challenge "$challenge" \
  --expectations-out "$evidence_dir/expectations.json" > "$evidence_dir/finance-demo.json"
python -m wolfalibi.finance_verify --challenge "$challenge" \
  --expectations "$evidence_dir/expectations.json" --evidence "$evidence_dir/finance-demo.json"
```

The controller pins the expected payment, authority keys, live process measurements and local witness reference before dispatch. An independent reviewer needs an authentic copy of the pins and the challenge. The demo retains the exact signed packet, sends it once, and closes the socket without reading the reply. It restarts the target and reconciles the retained packet. The verifier authenticates the original receipt and checks the underlying authorization at the target's signed time.

For exact-tree qualification, run the following from a clean checkout. The JSON records the Git objects, environment, commands, test results, mutation detections and verifier output.

```sh
python scripts/qualify_finance_gate.py --evidence-dir "$evidence_dir/full-run" \
  > "$evidence_dir/qualification.json"
```

## What the target checks

- **Live caller and qualification.** The target checks Unix peer and per-message credentials, holds a pidfd, and samples the PID, UID, GID, boot ID, start ticks, interpreter, arguments and caller source. The supervisor signs the measured identity and run scope. The witness countersigns it. The target checks both signatures, their validity window and a witness reference supplied outside the request.
- **Account-owner authorization.** A distinct owner key signs the tenant, account, payee, integer minor-unit amount, currency, operation, target public key, policy epoch, caller, run ID, challenge and request ID. A qualification can cover several requests for the enrolled account. Each payment needs an exact owner grant. The maximum grant duration is 300 seconds and the maximum qualification duration is 120 seconds. A payment must fall within both validity windows. The caller's signature covers the scope and both authorization records. The target clock and durable revocation table govern admission and retries.
- **Atomic recording.** The target writes the pending intent, its signed receipt and the decision evidence in one SQLite transaction. Its retained signed checkpoint must agree with the committed ledger before the target can return a receipt. The target checks the clock and witness again before handoff.

## Request identity and recovery

The uniqueness key covers target, tenant, operation and request ID. A separate digest binds the account, payee, amount and currency to that slot. The ledger retains the original dispatch digest. A fresh signature or a different grant cannot create a second intent under the same ID.

| Target condition | API result |
| --- | --- |
| First qualified, owner-approved initiation | `INTENT_RECORDED` with the signed pending-intent receipt |
| Identical initiation with current authority | `HISTORICAL_INTENT` with the same receipt |
| Exact reconciliation with current authority | `RECONCILED` with the original receipt |
| Correctly authorized different amount or payee using the same ID | `DENIED` with `REQUEST_ID_CONFLICT` |
| Same business request with a different signed packet | `DENIED` with `NONIDENTICAL_PACKET` |
| Authorized reconciliation arrives before initiation | The target records a durable fence and denies later dispatch to that slot |
| Reply lost after sending | The caller reports `UNKNOWN` and reconciles the original packet |
| Ledger and retained checkpoint diverge | Service blocks pending owner investigation |

An intent can exist even when a crash, expiry or witness change prevents a receipt from reaching the caller. A timeout or blocked handoff leaves the ledger outcome unknown to the caller. Retrieval requires the original eligible live caller, current authorization and matching witness state. Refusing reconciliation after revocation or expiry leaves the past intent count undisclosed. The ledger is provisioned for one run and policy epoch. The key derivation is stable across epochs, but live enrollment rollover, cross-run or cross-host deduplication, and post-expiry operator recovery remain unqualified.

Two Linux crash tests kill the target process on opposite sides of SQLite commit. Before commit, restart recovers an empty slot and reconciliation fences it. After commit but before checkpoint advancement, owner inspection finds one intent, its signed receipt and the matching decision evidence. The service refuses to reopen against the older checkpoint. An examiner can still authenticate the archived receipt offline. That check cannot override the service's recovery block. The trials cover process death on the test filesystem. Power-loss behavior remains unqualified.

## Trust and assurance

The Linux kernel, target implementation, pinned source, filesystem durability and target clock are trusted. A persisted watermark detects observed backwards clock movement. Process measurements are samples. They do not continuously measure loaded Python code, memory or descendants. The target checkpoint detects a separately restored ledger. Detecting coordinated restoration of both stores requires an independently retained head.

The local trial uses one OS account. Cross-UID custody is `UNSUPPORTED`, and independent administration and witness custody are unestablished. Assurance remains `SIMULATED_POLICY_ONLY`. Confinement and production remain `BLOCKED`, and certification is `NOT_ISSUED`. Settlement would require a separately authorized system and independently verifiable evidence. A verifier's `VERIFIED` result applies only to the historical target-signed intent and supplied pins.

[Gate 002 parent](https://github.com/Bropdrop/WolfAlibi/pull/32) · [VOIDCELL integration design](QUORVANE_VOIDCELL_INTEGRATION.md)
