# Gate 004 — historical financial reconciliation

Gate 004 lets an authorized auditor answer one question after the original caller has gone away. Did the fictional payment target record this particular pending intent at the pinned checkpoint? A successful inquiry returns the original Gate 003 packet and target-signed receipt unchanged, plus a separately signed disclosure. A resource owner can delegate the inquiry to an auditor or operate a separate audit credential. The historical authority holds its own disclosure key and takes only public verification inputs and a read-only payment archive.

## Reproduce a lost-reply inquiry

Use a non-root Linux account, Python 3.11 or newer, the repository's pinned packages, procfs, pidfds and Unix sockets with message credentials. The inherited test matrix also requires the `agent-all` extras and the earlier Linux fixture dependencies. The trials use local temporary directories, fictional accounts and ephemeral keys.

```sh
out=$(mktemp -d)
challenge=$(python -c 'import secrets; print(secrets.token_hex(32))')
python -m examples.quorvane_history_demo --challenge "$challenge" \
  --expectations-out "$out/inquiry-pins.json" > "$out/inquiry.json"
python -m wolfalibi.history_verify --challenge "$challenge" \
  --expectations "$out/inquiry-pins.json" --evidence "$out/inquiry.json"
```

The original caller sends one request and closes its socket before reading the response. The controller stops the payment target and caller, pins the original checkpoint, and copies only the quiescent ledger and signed checkpoint into a separate archive. It makes both copies read-only, waits for the original grant to expire, and retains the public inquiry inputs before requesting disclosure. The verifier checks the original payment authorization at the target's signed time and the auditor's grant at the later disclosure time. An authorized recipient sees the original fictional payment terms, signing keys, grant and process measurements in that packet. The expected result is `HISTORICAL_INTENT_DISCLOSURE` with `PENDING_EXTERNAL_SETTLEMENT` and `settlement=UNESTABLISHED`.

## Authority and failure behavior

| Boundary | What the implementation checks |
| --- | --- |
| Read permission | The pinned account owner signs a short-lived grant for the auditor key, tenant, account, original operation, target public key, payment request ID and historical-inquiry purpose. The auditor signs the exact grant, scope and fresh challenge. A separate key is required for each signing role. |
| Authoritative history | The operator supplies the expected finance scope, original issuer keys and measurements, plus an exact retained checkpoint digest. The archive reader verifies the target's signed checkpoint, recomputes the logical SQLite ledger and policy digests, and checks the effect row against its unique archived decision and original signed receipt. It opens a quiescent snapshot with SQLite `mode=ro` and `query_only`. |
| Current inquiry authority | The service checks its clock, durable revocations and the challenge inside a serialized transaction. It samples time again after archive verification. Only a committed disclosure may return evidence. Local owner administration can revoke an inquiry grant independently of the original payment authorization. |
| Restart and replay | The service records the consumed challenge and attestation digest in its own SQLite database and updates a signed head in a second, separately retained SQLite database. Both participate in a single SQLite rollback-journal transaction. A concurrent duplicate or replay after restart receives `CHALLENGE_USED`. An authorized fresh inquiry can recover the original receipt. |
| Uncertain outcomes | A missing intent, fence, ambiguous matching row, unanchored commit, snapshot substitution or mismatched retained head blocks disclosure. These outcomes leave settlement unestablished. An inquiry cannot fence an absent payment or redispatch it. |

The two process-death tests kill the inquiry authority on opposite sides of its SQLite commit. They test whether the same challenge can be reused after restart and compare the original payment ledger and checkpoint bytes before and after. The linearization point for inquiry authorization and revocation is the inquiry transaction commit. A receipt does not prove the auditor received a response or that a grant remains valid afterward.

## Optional experimental settlement phase

A second fictional authority can authenticate a synthetic source observation. It requires two distinct additional signing keys, an independently supplied source digest and reference, and the exact original intent receipt and business terms. Its `HISTORICAL_SYNTHETIC_SETTLEMENT` result describes those signed records. The original target receipt continues to say `PENDING_EXTERNAL_SETTLEMENT`. The historical authority has no settlement or payment execution method.

```sh
phase_challenge=$(python -c 'import secrets; print(secrets.token_hex(32))')
python -m examples.quorvane_history_demo --experimental-settlement --challenge "$phase_challenge" \
  --expectations-out "$out/phase-history-pins.json" \
  --settlement-expectations-out "$out/phase-source-pins.json" > "$out/phase.json"
python -m wolfalibi.history_settlement --challenge "$phase_challenge" \
  --history-expectations "$out/phase-history-pins.json" \
  --settlement-expectations "$out/phase-source-pins.json" --evidence "$out/phase.json"
```

## Qualification and trust limits

```sh
python scripts/qualify_history_gate.py --evidence-dir "$out/qualification" > "$out/qualification.json"
```

The qualifier checks a clean revision against PR #33, runs its 357 inherited tests, the Gate 004 tests, combined discovery and the eight original mutation checks. It records commands, environment and verifier results. The protocol uses a private local request channel. A captured signed inquiry is bearer material until consumed. Challenge consumption is local to one provisioned inquiry state. The portable verifier checks what the signing parties attested at their reported times. Repeating the archive integrity check requires the original snapshot and an authentic, independently retained checkpoint pin. The portable verifier alone cannot establish archive completeness or the current revocation state.

The clock, local kernel, SQLite/filesystem durability and the operator's distribution of reference keys, checkpoints and archive files are trusted. Restoring one inquiry store conflicts with its retained counterpart. Coordinated rollback of both inquiry stores, rollback of every external reference, compromised signing authorities, power loss and arbitrary-agent confinement remain unqualified. The demonstration uses one Linux UID and one operator. A principal with direct read access to the archive can inspect it outside the inquiry API. The signed disclosure does not carry a separately verifiable revocation or challenge-consumption checkpoint. Cross-UID custody is `UNSUPPORTED` and independent administration is unestablished. The verdict is conditional for this offline profile. Assurance remains `SIMULATED_POLICY_ONLY`, production is `BLOCKED`, and certification is `NOT_ISSUED`.

[Gate 003 engineering review](https://github.com/Bropdrop/WolfAlibi/pull/33) · [Gate 003 payment target and recovery semantics](QUORVANE_FINANCE_GATE_003.md)
