# VOIDCELL 003 — independent principal qualification

This offline experiment covers one owner-approved increment of a synthetic counter. Its two-account trial checks the gateway's live kernel identity, attempts ordinary opens of the target's private files, and follows one signed effect through loss of a reply and a target restart. Independent qualification on the builder is **UNSUPPORTED**. Its only authorized workspace account has UID/GID 1000 and zero effective, permitted and ambient capabilities. [PR #28 engineering review](https://github.com/Bropdrop/WolfAlibi/pull/28#issuecomment-7058524430) · [Issue #26](https://github.com/Bropdrop/WolfAlibi/issues/26)

## Reproduce the builder controls

Use a clean checkout with the optional agent integrations installed and an output file outside the checkout.

```sh
python -m pip install -e '.[agent-all]'
python scripts/qualify_voidcell003.py > "$evidence_dir/qualification.json"
```

The report identifies the Git commit and tree, environment, commands, inherited and new test counts, mutations, and unexecuted independent gates. The single-account harness exits 2. Check `local_controls` for the local test verdict and `independent_principal_qualification` for custody.

The transport test keeps one local Unix connection idle during a status request, then occupies all four handler slots, attempts one excess connection, and checks recovery and FD counts. The configured read deadline is two seconds and the listen backlog is 16. A separate test sends an owner-originated signed dispatch to a live target while one peer is idle and compares its counter and checkpoint before and after. The bounded measurements cover this fixture and offered load. Sustained traffic, scheduler starvation and slow target storage remain outside the findings.

## Prepare two independent accounts

On a disposable Linux host, the resource owner and gateway operator each need an independently provisioned ordinary non-root UID, with matching real/effective/saved/filesystem IDs and zero effective, permitted and ambient capabilities. Their primary GIDs may coincide. Each operator needs a trusted clean checkout of the same revision, an interpreter with the project dependencies, and access to the kernel peer credentials, pidfd and procfs references used by the probe.

Prepare the following paths **before starting the 120-second execution qualification**. Use paths outside both checkouts.

| Owner | Paths |
| --- | --- |
| Gateway operator | An empty private `0700` gateway state directory and a separate gateway-owned `0711` or `0755` directory for public artifacts. |
| Target owner | Three distinct empty private `0700` directories for target state, the retained anchor and qualification state. A dedicated empty target-owned `0711` or `0755` endpoint directory and a separate directory of that mode for public artifacts. |

Choose parent directories that the gateway can traverse to the socket and to the target state directory **itself**. The target state directory stays private. Its protected ancestors must exclude non-owner replacement. The socket path must fit the host's Unix pathname limit. Separate directories permit testing single-store divergence. Independent rollback or administrator custody requires separate evidence.

The commands below use shell variables for these paths and public values. Exchange public keys and references through an authenticated operator channel. Reference and handoff files are created as public canonical JSON. Readiness and prepared packets can be transferred as public **copies** for this disposable synthetic trial. Keep seeds, private state, and the gateway journal with their respective owners. Keep output files outside the endpoint directory.

### Enroll and measure

As gateway, create the signing key and public reference. Give the owner the reference and independent UID, GID and public-key pins.

```sh
python -m wolfalibi.voidcell003_fixture gateway-init \
  --state-dir "$gateway_state" --public-ref "$gateway_ref"
```

As owner, create the fixed Stage 5 qualification, target key, ledger and signed owner grant. Record the emitted owner public key separately for the gateway.

```sh
python -m wolfalibi.voidcell003_fixture owner-init --consent \
  --target-state-dir "$target_state" --anchor-dir "$anchor" --qualification-dir "$qualification" \
  --gateway-ref "$gateway_ref" --expected-gateway-uid "$gateway_uid" \
  --expected-gateway-gid "$gateway_gid" --expected-gateway-pub "$gateway_pub" \
  --socket-path "$socket_path" --handoff "$handoff" --operation-id "$operation_id"
python -m wolfalibi.voidcell003_owner serve \
  --state-dir "$target_state" --anchor-dir "$anchor" --socket "$socket_path" > "$ready"
```

The daemon runs in the foreground. From a second owner shell, retain and transfer the readiness line after it is flushed. Pin the actual target PID and UID independently. The target signs the V2 inventory, which binds process start ticks, UIDs and device/inode identities. The effect count and checkpoint summary are owner status observations. Match the source revisions on both sides.

As gateway, prepare the exact signed test packet and send the owner a public copy. The prepare step creates no effect intent.

```sh
python -m wolfalibi.voidcell003_gateway prepare --handoff "$handoff" \
  --gateway-state "$gateway_state" --owner-pub "$owner_pub" > "$packet"
```

As owner, submit this packet from the wrong role. Record the attempted digest, the transport rejection and the unchanged counter and checkpoint. A third ordinary account, if provisioned for independent review, can contribute another wrong-UID observation by sending the same packet with the UID/PID-pinned local request API. Pair the result with owner counts. A connection failure alone cannot establish an authorization decision.

```sh
python -m wolfalibi.voidcell003_owner observe --socket "$socket_path" \
  --target-pid "$target_pid" --packet "$packet"
```

### Lose one reply and restart the target

As gateway, send the operation while the grant and qualification are current.

```sh
python -m wolfalibi.voidcell003_gateway dispatch --handoff "$handoff" \
  --gateway-state "$gateway_state" --owner-pub "$owner_pub" \
  --target-state "$target_state" --target-pid "$target_pid" --inventory "$ready"
```

This phase requires the real socket peer and V2 inventory to match. It sends a null dispatch as a missing-authority control, then attempts ordinary read and write opens of both `target.key` and `ledger.sqlite`. All four opens must receive `EACCES` or `EPERM`. The probe never creates, truncates or writes either file. When private directory permissions hide file metadata, the object identities come from the signed owner inventory. The kernel supplies the open errors.

The gateway persists an intent and sends **one signed effect dispatch**. The test observer captures the target's accepted signed receipt and withholds it from the gateway journal. Expect `AMBIGUOUS`, journal state `PENDING`, and the same dispatch digest seen in the wrong-role control. The gateway exercises its replay check internally. If there is no observed accepted signature, the pending journal cannot support a successful lost-reply trial.

As owner, stop the foreground target with an orderly interrupt and wait for it to exit. Start the same `serve` command with the same state and anchor, saving a **new** readiness record. Check the count is one. Give the gateway the new PID and readiness record through the operator channel. As gateway, reopen the original journal.

```sh
python -m wolfalibi.voidcell003_gateway reconcile --handoff "$handoff" \
  --gateway-state "$gateway_state" --owner-pub "$owner_pub" \
  --target-state "$target_state" --target-pid "$new_pid" --inventory "$new_ready"
```

A successful controlled trial returns `CONDITIONAL`. Check the fresh custody probe, original and new process identities, stable signed key/ledger identities, original signed receipt equality, one effect, and a terminal journal. The only effect-protocol RPC during recovery is reconciliation. The separate null dispatch belongs to the custody probe. Reconciliation records the historical disposition and grants no new authority.

### Interrupt a separate disposable trial

Repeat enrollment with fresh directories, keys, challenge, grant and operation ID. Start the owner crash fixture in place of the ordinary server. Retain the initial `anchor.anchor_sha256` from its readiness output outside the target state before dispatch.

```sh
python -m wolfalibi.voidcell003_owner serve-crash-trial \
  --state-dir "$crash_state" --anchor-dir "$crash_anchor" --socket "$crash_socket" > "$crash_ready"
```

Use the gateway dispatch command for this new trial. The owner process exits 73 after the first committed SQL increment and before checkpoint publication. The gateway should retain a pending journal and receive no accepted signed reply. After the process exits, the owner checks the original checkpoint digest, the one committed row and the ordinary startup decision.

```sh
python -m wolfalibi.voidcell003_owner inspect-crash \
  --state-dir "$crash_state" --anchor-dir "$crash_anchor" \
  --prior-anchor-sha256 "$prior_anchor_sha256" --operation-id "$crash_operation_id"
```

Expect `FAIL_STOP_OBSERVED` with the operation and dispatch digest and a ledger/checkpoint divergence on reopen. Preserve the ledger, retained checkpoint, pending journal, prior external checkpoint reference and process exit evidence for an authorized owner review. No automatic repair exists. Retiring the inconsistent synthetic fixture leaves its pending intent unresolved. Reanchoring from SQL alone or resending the operation would invalidate this recovery evidence.

## Assurance boundary

The test trusts the Linux kernel, the administrator, the target runtime and clock, and authenticated operator provisioning. The trial exercises named files and one synthetic counter through one declared local endpoint. Coordinated restoration of ledger and anchor, undiscovered access routes and general denial-of-service resistance remain unqualified. Existing `OBSERVATIONAL_ONLY`, `BROKER_ONLY` and `TARGET_RECEIPT_ONLY` evidence retain their scopes. Production confinement, independent witness custody and formal certification remain **BLOCKED**.
