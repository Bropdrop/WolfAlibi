# WT-SWARM-001 · WolfTrap Swarm Siege

This Linux qualification starts a private instance of the PR #50 SQLite counter gate. It accepts only a new output directory. The target has no network address, and the clients receive only a read-only mount containing the disposable Unix socket. The standalone run uses the repository's fabricated, signed verifier records. Genuine vTPM results in the inherited archive apply to their original CI run.

## Reproduce

Use Python 3.12 with the repository's pinned cryptography dependency, Git, bubblewrap with unprivileged user namespaces and PTYs, and a host capable of running 1,000 threads in one process. The client needs more than 1,000 available file descriptors. The measured gate has four executor workers, a 64-descriptor hard limit and a 512 MiB address-space hard limit. Use a private checkout and an ordinary local filesystem that supports durable SQLite locking.

From a clean checkout of the pin, apply the supplied patch. The evidence ZIP includes the same patch and contains the public inputs for repeating the historical receipt review.

```bash
git clone https://github.com/Bropdrop/WolfAlibi.git
cd WolfAlibi
git fetch origin refs/pull/50/head
test "$(git rev-parse FETCH_HEAD)" = c27556440b348fd8584fda4deaeacca0edb93004
git switch -c research/wt-swarm-001 FETCH_HEAD
git apply --check /absolute/path/to/WT-SWARM-001.patch
git apply /absolute/path/to/WT-SWARM-001.patch
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install 'cryptography==50.0.0'
evidence_dir=/absolute/path/to/unpacked/evidence
python -B -m research.wt_swarm.baseline --public-subset "$evidence_dir/inherited/public"
python -B -m unittest discover -s tests -v
run_dir="$(mktemp -d)/standalone"
python -B -m research.wt_swarm.run "$run_dir"
profile_pin="$(sha256sum "$run_dir/profile.json" | cut -d' ' -f1)"
python -B -m research.wt_swarm.review "$run_dir" --profile-sha256 "$profile_pin"
```

For independent review of a delivered run, use the profile hash in the delivered report. For external custody on a new run, retain the generated public profile hash at provisioning. The checksum list in the ZIP covers the evidence, patch and report. The ZIP hash accompanying delivery covers the list itself. An observer trusts the lab supervisor and operating system for the measurements.

To repeat the original PR archive check, obtain GitHub Actions artifact 15036573740 from run 45642790204. The baseline command verifies the original ZIP hash, both internal manifests, the retained repository manifests and the four audit results. The bundled public subset also permits the four cryptographic audits offline.

```bash
gh api repos/Bropdrop/WolfAlibi/actions/artifacts/15036573740/zip > pr50.zip
python -B -m research.wt_swarm.baseline --archive pr50.zip
```

## Cases and measurements

| Case | Stimulus and acceptance condition |
|---|---|
| Contention | 1,000 native Linux threads rendezvous at a barrier and open one socket each for four independently granted operations. A supervisor pauses the idle daemon until all 1,000 attempts are in flight, then immediately resumes it. Worker IDs, native thread IDs, connection and frame timestamps establish the achieved overlap. At least two distinct effects must commit in the wave. Recovery accounts for all four original operations. |
| Duplicate | Two synchronized workers submit the same fresh signed request. Exactly one commit and one recovery must return the journal's receipt. A changed retry of a committed operation must receive `OPERATION_CONFLICT`. |
| Authority | Three independently signed votes on one prepared operation, a verifier assessment presented as a grant, a coordinator's altered grant and a client-side administrative request each require their specific denial. The operation with withheld owner authority must remain prepared. |
| Overload | 64 barrier-synchronized threads submit 10,000 requests for the prepared operation with no owner grant. The server must record a decision for every connection, including both capacity rejection and native schema rejection. The ledger must remain intact and the same daemon must answer a health query. |
| Writer order | A trusted controller holds either the effect transaction at the existing pre-commit hook or the administrator's revocation transaction after taking the writer lock. SQLite trace events show the other writer attempted `BEGIN IMMEDIATE` before release. The former order commits once, the latter denies both attempts. |
| Interruption | One client sends its request and waits before reading. After an independent journal observation sees the effect, the controller kills that client. Fresh keyless clients recover by original operation ID and exact request. Native gate exit faults 70 and 71 exercise both sides of commit. The controller restarts the same state and observes it before any retry. |
| Reconciliation | Read-only SQL projects every committed row, all operation statuses and revoked grant IDs at quiescent checkpoints. The reviewer checks each signed owner grant, assessment, verifier and target challenges, target receipt, exact request hash, timestamps, uniqueness, consecutive counter values, unchanged ledger prefixes and the expected set of effects. |
| Mutation controls | The offline reviewer first requires a passing original, then checks public copies with consensus accepted as authority, a corrupted owner signature, an exact retry returning a second commit, a repeated journal row, or a counter advanced without a row. Each mutation must reach its designated detector. These are behavioral and record mutations. |

The owner signs inside its own mount and PID namespaces using the original CLI and a scripted foreground PTY. The synthetic verifier has its own namespaces and in-memory key. The executor has no signer pipe, owner journal or gate state mount. The lab controller provisions public pins, drives the scripted terminal and schedules faults. Role isolation in this run uses namespaces under one host UID. The inherited CI record covers a distinct separate-UID experiment.

The gate admission observer uses Python's local return-event monitoring on the pinned dispatch and denial functions. Each trace row records the returned decision and native thread ID. Busy decisions can precede receipt of a complete request. Client reads must satisfy the native framing and EOF checks. A lost reply stays ambiguous at the client even when the journal subsequently resolves an operation. Admission records and client records are joined by aggregate counts for a single isolated wave. Busy clients have no server-decoded operation ID.

Raw batches retain one row per attempted request, including timing and completed frame writes. Resource samples cover the gate process at about 10 ms intervals, with scheduler-dependent gaps. The thread and descriptor peaks are sampled, while `VmHWM` is the kernel's lifetime RSS high-water mark. The resource acceptance budgets are five total gate threads, at most 64 descriptors and at most 128 MiB peak RSS. The runs measure finite workloads and process interruption. Throughput and scheduling vary by host.

The evidence directory contains public signed inputs and historical receipts. The workload deletes its private directories and namespaces at exit. The harness makes zero model API calls. Actual human approval is recorded as `NOT_RUN`.
