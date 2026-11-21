# Stage 3 synthetic execution trial

The trial qualifies one authorized read of `protected.txt` in a new private synthetic resource directory. A fixed worker attempts to open the same fixture by its absolute host path and checks a deliberately inheritable descriptor for that file. The worker then requests the fixture through an inherited Unix sequenced-packet socket. A successful transcript verifies at **`BROKER_ONLY`**. The engineering verdict for the trial is **CONDITIONAL**. Independent confinement qualification remains **`BLOCKED`**.

The implementation follows the published Stage 3 design and the per-run IPC controls reviewed in draft PR #6. It also implements challenge and checkpoint binding for this fixed profile. [Stage 3 design](STAGE3_DESIGN.md) · [Draft review protocol](https://github.com/Bropdrop/WolfAlibi/blob/4f24e7260bc7fc553501b1eb916676b12d7a976e/docs/STAGE3_REVIEW_PROTOCOL.md)

## Reproduce locally

Use Linux x86_64 with Bubblewrap and a system CPython runtime in the Debian-style layout described in the worker module. The supervisor also requires the existing project dependency `cryptography` and a filesystem that supports the broker's durable WAL and witness state. Kernel or container policy must permit Bubblewrap's user, PID, network, IPC, mount and UTS namespace setup. Missing static prerequisites report `UNSUPPORTED`. Runtime setup or incomplete worker evidence returns `BLOCKED`. Both outcomes give the CLI a nonzero exit status.

```bash
trial_dir=$(mktemp -d)
challenge=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
python3 -m wolfalibi.stage3 --state-dir "$trial_dir" \
  --run-id synthetic-review --challenge "$challenge"
python3 -m unittest -v test_stage3_execution.py
python3 -m unittest discover -v
python3 -u mutation_test.py
```

The CLI emits JSON. A successful run has `outcome=COMPLETED`, with broker verification `VERIFIED`, `direct_denied=true`, `canary_closed=true`, `child_exit=0` and `channel_eof=true`. The response SHA-256 is `c299faaa49cb5a383a4526cf3f15711a8ab226d03d2941230c362fbf4fbeb061`, computed over the synthetic fixture including its trailing newline. The broker WAL stays in the reported `run_dir`. The CLI generates demo signing keys in the supervisor and retains the starting witness digest in memory.

To verify an exported `evidence` object independently, call `verify_execution` with a separately supplied `contract`, the broker and witness public keys, the retained pre-run witness state digest and trusted current time as Unix seconds. The contract specifies run ID, 32-byte nonce, expiry, expected launcher profile, exact key and expected fixture digest. Keep these references outside the evidence bundle. The caller is responsible for retiring an accepted challenge and retaining the new witness head.

## What the transcript covers

1. The supervisor allocates a fresh run directory and journal. Before launch, the broker durably records a reserved key containing the contract hash and seals epoch 0. The witness signs the checkpoint after persisting its head.
2. Bubblewrap starts the fixed worker with a clear environment, unshared namespaces, dropped capabilities, a short list of read-only system runtime mounts and one bidirectional socket on descriptor 0. The worker checks its PID and UID/GID and sends its probe results with the one allowed request. The supervisor compares the entire canonical request to its expected run ID, challenge, sequence and key.
3. The broker logs the read through its existing write-ahead path before the supervisor sends any bytes. The worker acknowledges the received hash. The supervisor waits for the launcher to report successful exit and observes peer hangup. The local socket closes before epoch 1 is sealed. A missing acknowledgement, bad request, timeout or failed launch yields an incomplete trial and preserves any existing WAL for diagnosis.
4. The broker and witness sign an envelope over the contract, observations, two checkpoints and WAL digest. The witness persists the payload digest. The verifier checks both checkpoint signatures and roots, reconstructs the exact four WAL frames, and recomputes the three signed state transitions from the retained genesis digest.

The reserved epoch 0 leaf represents the run contract. Epoch 1 represents the single authorized fixture read. A failed trial can still have a durable read event if interruption happened after logging. The worker sends no acknowledgement in that case, so evidence of completed delivery is withheld. The execution transcript uses its own type, `WOLFALIBI_STAGE3_SYNTHETIC_READ_V1`. Receipt V1 and V2 APIs and formats remain available.

## Local results

Linux 6.18.57 x86_64, Bubblewrap 0.12.0, supervisor CPython 3.12.14, system worker CPython 3.13.5 and cryptography 50.0.0.

| Check | Result |
| --- | --- |
| Synthetic CLI trial | Completed with the expected digest, direct-path denial, canary exclusion, exit 0 and peer hangup. The verifier matched all four WAL frames (1,746 bytes). |
| `python3 -m unittest -v test_stage3_execution.py` | 11 passed, zero skips. Tests include duplicate and cross-run requests, interruption before WAL completion, child termination, a retained peer socket, path aliases, witness rollback, expiry, changed launch profile and missing or contradictory evidence. |
| `python3 -m unittest discover -v` | 62 passed, zero skips, including the 51 Stage 2 tests. |
| `python3 -u mutation_test.py` | 8 of 8 existing mutants caught. |

Run `git rev-parse HEAD 'HEAD^{tree}'` in the implementation checkout to identify the source under test.

## Qualification limits

- The direct-path and descriptor results come from the fixed worker under a trusted launcher and kernel. The profile records artifact hashes and requested controls. The experiment leaves OS-observed executable identity, effective mount inspection, syscall policy and comprehensive descriptor inventory to later qualification.
- Scope is one fixture in a supervisor-owned directory that is assumed stable for the run. Alternate copies, hostile concurrent root mutation, general path identity, arbitrary commands, access to unrelated resources and full network mediation are outside this test.
- The broker and witness cooperate on one host. The witness validates the supplied checkpoint and persists a signed history transition. It does not independently observe worker accesses. A separately retained digest detects state divergence relative to that digest. Persistent verifier-side challenge consumption, independent witness custody, key rotation and cross-verifier fork detection remain open.
- The fixed worker runs as PID 1 in the new PID namespace. The supervisor's evidence covers launcher exit and endpoint closure for this profile. General descendant lifecycle and a measured process scope need additional tests.
