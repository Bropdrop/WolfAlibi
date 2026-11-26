# WT-SWARM-003 · WolfAlibi Swarm Schism

Schism qualifies a standalone native WolfAlibi gate protecting one disposable counter on a single Linux host. The required parent is WT-SWARM-002 at `c9dbeef48fbb5e60a4edf89bcfbc444fbd995539`. Its evidence ZIP has SHA-256 `42b03dba0381abdff1fd01fbaa1a913446671822b637748f56778821f4a07eb1`. The evidence bundle contains the inherited reproduction, new runs, public keys, frozen signed records, per-attempt timings, service samples and independent reviews.

## Authority and storage

A dedicated issuer signs an epoch transition naming the gate, target, successor epoch, prior transition digest and one pre-enrolled executor. The custodian accepts each transition only after checking the prior epoch and digest inside the canonical writer transaction. A local coordinator may retain a request and claim leadership. Neither its claim nor recovery output is an input to the authority issuer. Each worker group can reach only its assigned socket. Its namespace has no owner, verifier, issuer or executor private key.

A request requires its original owner grant and assessment. An issuer-signed permit binds the complete request and grant digests, target, gate, operation, executor, epoch and transition head. The target records the preparation epoch. Preparing in an earlier epoch precludes subsequent re-enrollment. The native counter and receipt, signed executor endorsement, and latest state seal commit together. A stale executor fails the writer check. A current executor checks the preparation, permit and holder again at the effect boundary. The final native clock and freshness check follows the full state scan. Committed exact retries preserve the original receipt.

Three SQLite files use FULL synchronization and DELETE journals on the same local filesystem. SQLite's attached-database atomic commit coordinates the target, the custodian's authority database and a separate witness database. All writers acquire the canonical target writer lock first. Executing gates have a read-only mount of the custodian's database. The witness stores endorsements and a co-committed digest of the canonical state including the native clock and revocations. The custodian separately stores the target digest at each accepted epoch. The issuer, file identities and enrolled executor public keys are provisioned before serving. Changed file identities, mismatched seals or an unavailable floor deny new effects. A different inode is refused even when it contains the same bytes. An unfenced legacy gate refuses the fenced state schema.

The recovery reader has a read-only view of all three databases, its own signing key and no native signing key or execution socket. An authenticated original receipt establishes COMMITTED. An exact, permanently revoked grant and a matching uncommitted preparation establish NOT_COMMITTED. Missing state, unavailability and stale snapshots yield UNRESOLVED. Recovery authenticates the caller and historical binding. It rechecks file identities, current head and seal in its snapshot and verifies the separately signed historical endorsement and permit. Per-connection cryptographic validation results are reused only across the same SQLite data versions.

The trusted computing base includes the OS, the isolated gate and custodian code, the provisioner, SQLite locking and atomic commits, file-identity pins, and independent custody of the authority and witness files. The test restores the target while retaining the independent stores. Coordinated rollback of every trust store, a malicious host or a signing-key compromise falls outside this model. File availability is observed at the transaction boundary. No claim extends to disconnected writers on independent machines.

## Run

Use Linux, Python 3.12 with the repository's cryptography dependency, local SQLite rollback-journal storage, bubblewrap with unprivileged namespaces, accessible procfs, PTYs and sufficient process and memory limits for 1,000 client threads. The example paths below must be new output directories. Keep the source tree fixed while child processes are running. Test credentials are created fresh in a temporary directory. The public evidence contains expired laboratory grants and certificates.

First reproduce the exact baseline from a separate checkout at the required parent. Verify its archive using the digest above, run the inherited unit suites, and execute its own Blackout experiment and review as described in `research/blackout/README.md`. The local bundle includes the original pinned evidence and all the data needed for offline review.

```bash
python -B -m unittest discover -s tests -v
python -B -m unittest research.blackout.test_recovery research.schism.test_fence -v
python -B -m research.schism.experiment /absolute/new/schism-run
python -B -m research.schism.throughput /absolute/new/crossover
```

Capture the hashes of `native/profile.json`, `native/reader.json` and `native/anchors.json` separately at provisioning or from the trusted bundle manifest. For the archived runs the delivered report records the pins. The reviewer takes no private credentials and runs offline.

```bash
python -B -m research.schism.review /absolute/new/schism-run \
  --profile-sha256 "$profile_pin" --reader-sha256 "$reader_pin" \
  --anchors-sha256 "$anchors_pin"
python -B -m research.schism.compare /absolute/extracted/evidence
```

Repeat by applying the patch to a clean detached checkout of the exact parent, comparing its Git tree with the research branch, and running the same commands with fresh paths. A complete command sequence for reviewing the delivered artifacts is in the bundle's REPRODUCE.md.

## Measurements and controls

Each of two independent coordinator processes starts 500 native client threads. Each thread enters its attempt and opens a socket while its serving gate is paused. An external rendezvous resumes both gates after all 1,000 sockets exist. The offline review checks that all 1,000 attempt intervals overlap the same instant. Connection admission, successful commits, busy rejections and lost client replies are recorded separately. A second workload issues two overlapping exact duplicates. Another uses 64 workers for 10,000 attempts with a withheld grant. Three restarts each precede a four-worker, 30,000-query mTLS recovery wave. All role signers are disposable. The per-wave CPU, memory, FD, thread, wall and storage limits were committed before stress.

The schedules use local pipes, process signals, SQLite writer acquisition events and one private Unix relay. Two coordinators claim leadership simultaneously. The supervisor kills and restores the old coordinator from its durable pending queue. It separately interrupts the serving gate and the staged transition writer, contends two genuine issuer proposals and holds a native effect at its commit boundary. It restores two snapshots of different age into the original inode and disconnects the authoritative checkpoint after tentative native effect writes. The authoritative history and final oracle are collected independently of coordinator responses.

The seven mutation controls run disposable in-memory SQLite reference and weakened decision variants over public records. They project the weakened decisions into public transcript copies and replay the same independent verifier. This checks detector sensitivity. The gate fault schedules and focused transaction tests exercise the real gate. No weakened gate binaries are distributed. Genuine Shirudo attestation, HERCULES, personal owner approval and distributed consensus require separate qualification.
