# WT-SWARM-002 · WolfAlibi Swarm Blackout

This standalone experiment runs a disposable SQLite counter, its original native gate, and a separate recovery service on private Unix sockets. The recovery service takes a read-only mount of the journal directory, including SQLite rollback sidecars. An empty mount masks the native signing key. It has its own response signer and lacks the native socket. Recovery clients mount one identity and the recovery socket. The native owner and verifier retain WT-SWARM-001's separate namespaces. A trusted local supervisor provisions identities, records observations and controls the faults.

## Recovery protocol

The two principals have separate short-lived client certificates from a disposable laboratory CA. TLS 1.3 mutually authenticates each connection. The client pins the reader certificate and the reader checks the actual peer fingerprint and certificate expiry on each query. A TLS-ready line precedes application frames. Each query identifies the principal, protected target, gate instance, operation and digest of the exact execution request. The provisioner validates the signed owner grant and frozen accepted fixture bundle before enrolling their bindings in an immutable access list. The trusted provisioner chooses the recovery principal. The native grant format carries execution authority only.

The reader opens SQLite with `mode=ro`, enables query-only mode and reads identity, counter consistency, operation and revocation in one transaction. Its Ed25519 proof binds all five query fields, the original grant ID, outcome, evidence basis, receipt digest and durable revocation timestamp where applicable.

| Outcome | Evidence |
|---|---|
| COMMITTED | The retained row matches the enrolled request, grant and assessment digests. The reader verifies the native target signature and returns the original effect receipt. |
| NOT_COMMITTED | The exact grant for a matching prepared operation appears in the durable native revocation table, and the operation has no committed receipt. The proof includes the revocation time. Subsequent execution of this grant goes through the native revocation check under the SQLite writer lock. |
| UNRESOLVED | A prepared or absent row, unavailable journal, insufficient evidence, access denial or transport loss. A prepared grant may still commit. This protocol derives a definitive negative only from permanent grant revocation. |

The private execution socket remains accessible to the trusted execution role. That role can use the inherited native status interface. Separate recovery principals can reach only the TLS reader. Both the gate and the reader rely on trusted local clocks, filesystem custody and integrity of the gate journal. A trusted administrator restoring an old database is outside this qualification.

## Experiments

- Reuse the complete WT-SWARM-001 native profiles with the same barrier, stop/resume point, request mix, admission observer and four gate workers. The additional supervisor samples measure process CPU and SQLite file sizes.
- A one-operation local relay buffers a complete approved frame. The client loses its reply. The controller holds delivery while the original is reconciled, optionally revokes it, then releases the original to the native gate. Only the private control pipe can release the fixture.
- In the post-commit partition, the relay withholds the original receipt while the controller kills the waiting coordinator. A fresh recovery-only process authenticates for the same principal. The native pre-commit exit fixture also interrupts settlement. After restart the original is unresolved, then its exact retry commits once.
- Reconcile a second principal's own operation and exercise cross-principal, wrong-digest, wrong-target, wrong-instance and expired-certificate controls. Submit a historical recovery proof to the native execute interface and require its schema denial.
- Restart the gate three times. After each restart, four barrier-synchronized, certificate-authenticated workers send 30,000 recovery queries over bounded TLS sessions. They rotate through committed, durably revoked and still-unresolved requests. The reader queries SQLite on every application frame. The client reuses signature validation only for a byte-identical reply and identical query on the same worker. Raw records preserve every worker's latency and exact observed reply by digest. The per-wave evidence deduplicates identical replies.

The native waves contain 1,000 concurrent attempts, two exact duplicates, and 10,000 overload attempts at 64-way concurrency. The post-restart waves add 90,000 read requests. The measured profiles contain 101,002 requests per run. Functional probes and setup calls are additional. Expired pending requests can remain explicitly unresolved. The protocol never reissues a grant.

## Timing and resources

The committed `budgets.json` predates stress execution. The limits apply to each measured service. CPU is Linux user plus system time in clock ticks. Gate CPU samples bracket the native wave and its health query. Reader wall time includes client session openings and rotation, I/O and client validation. Latencies use monotonic per-attempt timestamps and nearest-rank percentiles. Throughput divides completed attempts by the interval from first attempt start to last completion. Counts include capacity rejection and ambiguous transport. CPU, descriptor and thread samples are process-specific. RSS uses the kernel high-water mark. Database size and sampled transient sidecar size are reported separately. The original SQLite DELETE journal mode and the gate's freshness limits remain in effect.

The comparison command recomputes the same timing formulas on the pinned WT-SWARM-001 archive. Its historical raw records support latency, throughput, memory, descriptor, thread and ambiguous-outcome comparisons. Historical CPU and SQLite growth measurements are unavailable.

## Run

Use Python 3.12, the pinned `cryptography==50.0.0`, Linux with unprivileged namespaces, bubblewrap, PTYs and capacity for the 1,000-thread native profile. From the patched checkout run the following. Use a new output directory.

```bash
python -B -m unittest discover -s tests -v
python -B -m unittest research.blackout.test_recovery -v
python -B -m research.blackout.experiment /absolute/new/run
```

For a new run, retain the hashes of `native/profile.json` and `recovery/reader.json` in trusted custody. Use those independent hashes for public review. The delivered report records both pins for each archived run.

```bash
python -B -m research.blackout.review /absolute/new/run \
  --profile-sha256 "$profile_pin" --reader-sha256 "$reader_pin"
python -B -m research.blackout.compare /path/to/WT-SWARM-001-evidence.zip \
  /path/to/standalone /path/to/repeat
```

The offline reviewer validates the original signatures and enrollments, complete counter history, observed authorization decisions and raw response bindings. It checks mutation controls for request substitution, cross-principal disclosure, duplicate effects, missing durable settlement and premature non-execution claims. Proofs authenticate read-only observations under the lab reader key. Actual human approval remains NOT_RUN. All current verifier records are fabricated laboratory fixtures.
