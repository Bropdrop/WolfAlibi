# BYOA 002.1 custody qualification

| Gate | Result | Evidence and scope |
|---|---|---|
| A. Cross-account authorization | UNSUPPORTED | One authorized effective UID. The policy tests use synthetic peer metadata. |
| B. Independent checkpoint custody | UNSUPPORTED | The target signs transitions and writes a separately located journal. The same administrator controls both locations. |
| C. State-restoration consistency | CONDITIONAL | The test restored the target and verifier snapshots, preserved the current journal and observed a custody disagreement and zero restored target rows. |
| D. Revocation continuity | CONDITIONAL | A restarted owner refused the revoked grant. Restoring the owner snapshot produced a custody disagreement before commitment. |
| E. Recovery without duplicate operations | CONDITIONAL | A reopened service retrieved the same receipt and acknowledgment. One target row matched the verifier head. Interruption after journal publication and before target commit required fail-stop handling. |
| F. Independent qualification readiness | BLOCKED | Independent custody, a distinct-account run and full baseline reproduction remain outstanding. |

Production deployment and arbitrary-agent confinement remain blocked. Certification was not issued.

## Operating procedure

Use the [split-role Linux host procedure](QUORVANE_BYOA_002.md) from enrollment through detached verification. It specifies private directories, role-specific commands, peer measurements, file-open probes, gateway restart, historical inquiry and direct owner ledger inspection. Use accounts already provisioned by the host administrator. Record actual UIDs, enrolled process measurements, owner-signed inventory, kernel probe errors, the authorized control and owner row counts. A failed setup or missing authorized control leaves the gate unsupported.

For the custody profile, the owner selects a new journal filename in a private existing directory outside the target and verifier snapshot sets. Add the same absolute path via `--custody-journal "$JOURNAL"` to init-target, serve-target and revoke. Init is create-only. The target binds its ledger to the selected profile and journal location. Retain the verifier head separately as specified in the split-role guide. Checkpoint generation zero binds the enrollment and target public key. Later signed generations bind the previous signed record, before/after state digests, action and challenge or grant digest. The state digest covers target receipt hashes keyed by operation and revoked grant hashes. The original verifier authenticates the pending challenge and retains the committed receipt.

Every new commitment or revocation compares the live journal within the owner transaction and appends its transition before target commit. Handoff checks the journal again. If publication succeeds and the target transaction fails, preserve both stores and report BLOCKED. No automatic rewind is provided. Receipt reconciliation can recover an existing durable decision if the target anchor and verifier permit it. Recipient delivery remains unestablished.

The journal file is a trusted latest-state input. An administrator capable of replacing every store can replace this input as well. Separate processes and directories supply no independent administrative custody. The checkpoint signer is the enrolled target. A reviewer must independently retain its public key, the enrollment digest and expected final head. The example public files were collected together under one UID and demonstrate the verifier interface only.

## Local reproduction

From the checkout, use an unprivileged Linux interpreter with the dependencies pinned in pyproject.toml. Use a new empty destination name for each sample.

```sh
python -m unittest -v test_byoa002_custody
python -I scripts/mutate_byoa002.py --custody
python -I scripts/sample_byoa0021.py /tmp/byoa0021-public-sample
python -I scripts/verify_byoa0021.py --history /tmp/byoa0021-public-sample/history.json --expect /tmp/byoa0021-public-sample/expect.json
```

The sample uses the inherited measured-cell decision fixture with synthetic peer and revision fields. Its enrollment revision is a protocol test input. The evidence manifest identifies the actual tested Git revision. Historical journal verification checks signature continuity and the exact retained final head. For verification of the complete grant, measured trial, request, receipt and acknowledgment, use the inherited package verifier and its detached expectations.

The original BYOA 002 duplicate-disclosure observation and fixture remain in the parent. This run exercised the guarded path. It did not repeat the known duplicate disclosure or establish the full 605-test and 14-mutation baseline. The first selected parent run had a fixture setup error due to missing LangChain. The retry used an isolated environment with the pinned dependencies. Exact test names and results are in the evidence directory.
