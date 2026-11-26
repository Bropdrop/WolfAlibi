# Stationary target recovery protocol

## Recovery authority

A planned handoff enrolls an existing Sovereign target while its last enforcement process is alive. The commissioning custodian takes the native SQLite writer, challenges the old gate through authenticated read-only recovery, verifies its boot signature and exact binding, then stops and reaps the old process before releasing the writer. The live challenge checks the RAM floor against the same durable database held quiescent by the writer. Independent enrollment binds the logical target, native gate key and identity, owner, canonical journal device and inode, and the resulting seal. The boot private key is never transferred.

The surviving witness keeps its own durable, authenticated history outside the target restore domain. Each protected mutation reserves its exact candidate seal there while the native target still owns the local writer. The reservation compares the previous witnessed head, carries an incarnation signature, and advances the witness durably before the local commit. An intent alone proves neither commitment nor exclusion. After an interrupted write, only matching actual protected state can satisfy the witness. An intent advanced ahead of a rolled-back transaction deliberately sacrifices availability. This order has no distributed atomic-commit assumption.

## State machine

OFFLINE has no serving execution process. RECOVERING acquires a lifetime Linux flock on the independently enrolled canonical journal and generates a fresh in-memory Ed25519 boot identity. The commissioning trust configuration is outside the restored database. A contender holding an old TLS credential or copied directory cannot acquire a second valid enrolled writer.

STATE_VERIFIED means the native gate validated its original trust and protected database, the protected seal matched a signed witness head, and the complete historical snapshot was authenticated against the ordered authority prefix and exact request evidence. AUTHORITY_RECONCILED requires all intervening offline revocations and a fresh owner-signed activation for the exact candidate, target and epoch. ACTIVE starts at the local transaction which installs that authority and revocations. The witness reservation precedes that commit. The lifetime custody lock and native writer remain held across it. Execution still requires a new native grant, exact owner permit, holder proof and current local authority at settlement.

A missing prerequisite, unavailable authority source or conflicting state keeps execution closed. RECOVERY_UNRESOLVED carries no replacement authorization. An interrupted candidate starts again with a new key. Replay of its authorization cannot authorize that new identity.

## Historical outcomes and scope

A COMMITTED answer requires the original enrolled receipt on durable protected state or an independently verified frozen observation. NOT_COMMITTED requires positive, durable exact-request exclusion. A missing row, missing disk, unacknowledged intent or unreachable replica alone yields UNRESOLVED. Historical verification uses the signed command and boot in force when the request was enrolled and settled. Reader certificates and exact signed ACLs survive incarnations.

The trial trusts the kernel, stationary target custody, native gate, owner, independently provisioned witness and an honest Raft quorum. Ordinary target restoration must not restore the witness or its enrollment. Linux advisory locks protect cooperating native enforcement processes on the enrolled storage; host administrator attacks, writable relocation, cloned kernels, full-machine rollback and independent physical custody are outside the model. With target and all authoritative witnesses lost or rolled back there is no surviving local observation distinguishing a former commit from non-execution. Recovery stays unqualified for that condition.
