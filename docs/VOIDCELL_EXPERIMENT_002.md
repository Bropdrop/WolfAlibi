# VOIDCELL Experiment 002 — target key and ledger custody

**Base** `f8828465ae1e8760d1e19119c91483d2f8a2957e`. [Draft PR #25](https://github.com/Bropdrop/WolfAlibi/pull/25)

The offline synthetic target generates and retains its own signing key and
ledger. Custody against a different, unprivileged UID requires a separate
host qualification. [PR #25 engineering review](https://github.com/Bropdrop/WolfAlibi/pull/25#issuecomment-7057950613) · [Issue #26](https://github.com/Bropdrop/WolfAlibi/issues/26)

## Roles and local transport

The existing `EffectVault`/`EffectGateway` protocol is served through one
long-lived pathname Unix `SOCK_SEQPACKET` endpoint.  Each record carries
kernel `SO_PASSCRED` credentials and the endpoint applies narrow peer roles:

| Peer | Permitted actions |
| --- | --- |
| Separately provisioned non-root gateway UID | `dispatch`, `reconcile` |
| Non-root target-owner UID | `status`, signed `revoke` |

The gateway receives only the target public key.  It must never receive the
target signing seed, a target-ledger write handle, or a target-state path with
write authority.  The target generates `target.key` itself under its owner
process in an exact mode-`0700` state directory; the key is a regular
mode-`0600` owner-only file.

The target configuration accepts these fields.

- `gateway_uid`;
- hexadecimal `owner_pub`, `gateway_pub`, `broker_pub`, `witness_pub`, and
  `supervisor_pub` values;
- a real Stage 5 `contract`;
- `operation_id`;
- hexadecimal `expected_witness_state_digest` and `initial_witness_head`.

The target needs trusted source, interpreter, and dependencies and protected
ancestors for its state and socket directories.
It retains a separate latest signed ledger anchor outside the database tree.
The anchor binds both the SQLite authorization pins and the owner configuration,
including the UID admitted by the transport.
Before each effect it compares the committed SQLite state with that anchor;
after a committed operation it advances the anchor before any reply.
Rollback of the ledger alone causes fail-stop. A crash between SQL commit and
anchor publication leaves an unacknowledged effect and blocks reopen.
Recovery requires owner review of the inconsistent stores. Coordinated
rollback of both stores and compromise of the target owner remain outside the
claim. Authorized reconciliation returns an anchored receipt or commits a
fence for an absent dispatch. Revocation and dispatch serialize at the target.

## Owner provisioning and service commands

On a suitable Linux host, run these commands from the separately provisioned
target account. Set `target_state` and `target_anchor` to existing private
`0700` directories in separate rollback domains. Set `socket_path` to a
new path under an empty, target-owned `0711` or `0755` directory with
ancestors traversable by the gateway. Keep the owner configuration file in
mode `0600`. No account creation or privilege changes are performed.

```bash
umask 077
python -m wolfalibi.voidcell002 init-key --state-dir "$target_state"
python -m wolfalibi.voidcell002 initialize \
  --state-dir "$target_state" --anchor-dir "$target_anchor" --config "$owner_config"
python -m wolfalibi.voidcell002 serve \
  --state-dir "$target_state" --anchor-dir "$target_anchor" --socket "$socket_path"
```

The daemon emits a readiness record with signed inventory. Keep that record
outside the endpoint directory and exchange only public references with the
gateway. Collect the target PID, UID and public key from the owner side.
Run the probe from the provisioned gateway account with those references.

```bash
python -m wolfalibi.voidcell002 probe \
  --target-uid "$target_uid" --target-pid "$target_pid" \
  --state-dir "$target_state" --socket "$socket_path" \
  --inventory "$owner_inventory" --target-pub "$target_pub"
```

The probe checks the kernel peer PID and UID on the request connection,
records the missing-authority denial, and attempts ordinary read and write
opens without reading, modifying, truncating or creating files. If the
directory hides file metadata, existence can be owner-attested with a signed
inventory pinned to the observed peer and directory. This permission probe
covers the named paths. The full cross-UID operation, crash and credential
tests still need a separately provisioned host and reviewer.

For an authorized operation, run the existing `EffectGateway` from the
gateway account with its own journal directory and signing key. Supply
`voidcell002_transport.request` as its transport, binding the socket and
the expected target UID and PID. Pin the target public key independently in
`EffectGateway`. Pass the real Stage 5 envelope and exact owner-signed grant
to `dispatch`. After `AMBIGUOUS`, call `reconcile` on the same journal.
The target never receives a replacement dispatch during reconciliation.

`doctor` emits machine-readable JSON. This builder has UID/GID 1000 and no
provisioned gateway principal, so custody is `UNSUPPORTED`. The local suite
exercises target policy, durability and wrong-UID rejection. A successful
local protocol suite leaves custody `UNSUPPORTED`.

## Reproduction and status

Install the active optional extras, then run the exact-tree local harness:

```bash
python -m pip install -e '.[agent-all]'
python scripts/qualify_voidcell002.py
```

The qualification reports the inherited regressions and the explicit custody
preflight.  Here its overall result and exit status are intentionally
`UNSUPPORTED` / `2`; that is the expected fail-closed result, not a test skip
or an assurance downgrade.

Production deployment, arbitrary-agent/process confinement, denial-of-service
containment, complete route inventory, independently administered owner/
gateway/witness custody, and real external effects remain **BLOCKED**.
