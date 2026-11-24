# Laboratory owner approval

The owner component holds a private Ed25519 key in its own account and signs
one grant only after reviewing a specific target operation and its accepted
assessment. The verifier, target and coordinator receive public records; they
do not receive the owner key. The existing counter gate still independently
checks the owner signature, verifier signature, complete policy, freshness
and one-use constraints before committing an effect.

The component provides an interactive approval path. A terminal is an input
boundary, not proof that its input came from a person. Scripted PTY tests and
automated laboratory demonstrations must report:

```json
{"approval_path":"SCRIPTED_PTY","actual_human_approval":"NOT_RUN"}
```

A real user must complete the ceremony before a demonstration can say that
human approval was exercised. The unit tests use deliberately fabricated
signed evidence and do not establish genuine TPM verification.

## Authority and deployment boundaries

Run the owner program under a dedicated owner UID with a private state
directory. Run the verifier under another UID with its own state. The
coordinator moves public records between those processes and the target.
Only the owner program reads the owner key or constructs owner signatures.
Provision these identities and permissions through the trusted deployment
procedure; the CLI does not create accounts, grant sudo access, install
software, or contact remote services.

The owner account, administrator, controlling terminal, local clock, installed
Python package and dependencies remain trusted. Another process with the same
UID, or the host administrator, can control that authority. Separate process
IDs or different keys alone do not establish separate custody. The actual
laboratory integration must test access from the unprivileged coordinator and
verifier accounts.

Owner state is created with mode `0700`. Its signing key, public identity and
SQLite journal require private ownership, regular files, and no shared hard
links or symlinks. Ancestors must be trusted and nonreplaceable; root-owned
sticky temporary directories are supported. Opening missing or incomplete
state never creates a replacement identity. The implementation detects
in-session file replacement, key changes, profile changes and malformed
journal records. Coordinated restoration of trusted state and clocks remains
outside this laboratory guarantee.

## Provisioning order

The complete policy depends on the measured configuration root. The target
gate identity is created only after its bootstrap policy is verified. Use
this order to avoid making an image contain the digest of itself:

1. Initialize the owner and verifier separately and retain their public
   identities through trusted provisioning.
2. Build the immutable gate image with its authority anchors. Include the
   image manifest in the signed Shirudo configuration and derive the expected
   image/configuration roots independently.
3. Boot the selected target and construct its complete policy from the trusted
   builder record and independent expected state.
4. Ask the owner process to sign the fixed boot-policy record.
5. Let the target verify that record against its immutable anchors and image
   manifest, then initialize the gate and export its public identity.
6. Pin the complete owner profile, including that independently retained gate
   identity. Its policy and authorities must match the recorded boot policy.

The CLI is available through the installed package:

```bash
python -m shirudo_adapter.owner_cli init --state /private/owner
python -m shirudo_adapter.owner_cli identity --state /private/owner

python -m shirudo_adapter.owner_cli sign-boot-policy \
  --state /private/owner \
  --anchor /approved/anchors.json \
  --manifest /approved/gate-image.json \
  --trust /approved/action-trust.json

python -m shirudo_adapter.owner_cli pin-profile \
  --state /private/owner \
  --profile /approved/owner-profile.json
```

These paths are examples for independently provisioned files. Do not derive
trusted keys or expected roots from an untrusted action request.

### Boot-policy signing

`sign-boot-policy` is explicit local laboratory provisioning, separate from
the terminal action ceremony. It calls the same strict bootstrap validation
contract used by the target. It verifies the owner identity, immutable
authority pins, manifest/anchor digest, verifier executable pins, supported
configuration measurement and maximum challenge lifetime before signing.

The signed payload has schema `wolfalibi.shirudo.boot-policy.v1` and scope
`LAB_IMMUTABLE_GATE_BOOTSTRAP`. It binds `anchors_sha256`, `gate_image_root`,
`config_root` and the complete target `trust`. It contains no operation ID,
counter grant or permission to execute an action. A boot-policy envelope
cannot substitute for an action grant.

The owner durably records one exact anchor/manifest/trust combination. Exact
retries return the identical envelope. A different combination is refused.
Signing may precede profile pinning; the later profile must match the signed
trust. If the profile is already pinned, signing must match it.

Successful output is:

```text
status: BOOT_POLICY_SIGNED
boot_policy: the signed envelope
boot_policy_sha256: SHA-256 of its canonical JSON
action_authorization: NONE
```

### Owner profile

The profile has exactly these keys:

| Field | Meaning |
|---|---|
| `schema` | `wolfalibi.shirudo.owner-profile.v1` |
| `target_id` | Independently selected target |
| `gate_instance_id` | Pinned 32-character target gate instance ID |
| `gate_public_key` | Pinned target Ed25519 public key |
| `policy_generation` | Expected positive generation number |
| `owner_public_key` | Must match the private owner state's public identity |
| `verifier_instance_id` | Independently pinned verifier instance ID |
| `verifier_public_key` | Independently pinned verifier Ed25519 public key |
| `policy` | Complete validated `wolfalibi.shirudo.policy.v1` policy |

The owner, verifier and gate use distinct public keys. The policy must be
`LAB_VTPM` for this target. Every configured quote PCR is required, including
PCR 15 if an independently provisioned policy selects it. The immutable gate
image design may instead bind its manifest through the configuration root;
the owner does not infer measurement coverage from source hashes alone.

`pin-profile` is one-time provisioning. An identical retry succeeds; different
content fails. The profile is not supplied inside an action bundle. This
version has no command to silently replace a profile or enlarge its scope.

## Two-phase approval

The stable intent describes the target and action before freshness starts.
It has exactly `schema`, `request_id`, `target_id`, `gate_instance_id`,
`policy_sha256`, `policy_generation` and `action`. Its schema is
`wolfalibi.shirudo.owner-intent.v1`. The request ID is 32 lowercase hexadecimal
characters. Its only action is:

```json
{"name":"increment_counter","delta":1}
```

Previewing an intent issues no authority:

```bash
python -m shirudo_adapter.owner_cli review \
  --state /private/owner --intent /exchange/intent.json
```

Start the ceremony with a bundle path that does not yet exist:

```bash
python -m shirudo_adapter.owner_cli approve \
  --state /private/owner \
  --intent /exchange/intent.json \
  --bundle /exchange/fresh-bundle.json
```

The owner sees the action, target, gate instance, policy generation, policy
digest and public keys. `READY` starts one fresh evidence attempt. Any other
input denies it. The initial review has a separate timeout, defaulting to
300 seconds and bounded to 900 seconds. It grants no authority and consumes
none of the gate's freshness window.

After `READY`, the keyless coordinator obtains a new verifier challenge,
immediately asks the target to prepare its operation, collects evidence, and
requests an assessment from the verifier process. It atomically installs the
complete public bundle at the selected path. A file present before readiness,
including one created while the stable review was open, is rejected. Do not
stream a partially written JSON file into that path.

The public bundle has exactly these keys:

```text
schema: wolfalibi.shirudo.owner-bundle.v1
request_id: the reviewed intent's request ID
attestation_challenge: verifier-signed challenge
action_challenge: target-signed operation challenge
assessment: verifier-signed assessment
```

The owner validates all three signatures against its pinned profile. It
checks target, instance, policy, generation, nonce, challenge IDs, record
digests, enrollment record, expected and observed verifier hash/version,
accepted upstream report and the complete policy-derived assertion set. A
self-consistent report that omits a policy-required PCR is refused. Synthetic,
rejected, blocked or hardware-labelled assessments cannot earn this lab grant.

The final prompt names the concrete operation and displays the bundle digest,
accepted evidence result and remaining lifetime. The owner must type the
exact phrase `APPROVE ` followed by the last twelve hexadecimal characters of
the displayed operation ID. No `--yes` option or stdin approval exists. Both
prompts read a single bounded line from the foreground controlling terminal.
Queued input is flushed before each prompt, so approval typed before the
concrete operation was displayed does not carry forward.

The intent, profile and public bundle are frozen. Replacing their input files
after display cannot change the grant subject. Signatures, bindings and time
are checked again after confirmation and immediately before the durable
transaction commits.

### Timing stays bounded

The target's original limits remain unchanged:

- Maximum attestation freshness: 30 seconds.
- Target admission of a verifier challenge: within 5 seconds of issuance.
- Maximum declared cross-host clock skew: 2 seconds.

The owner requires challenge issuance no earlier than its `READY` observation
minus that explicit skew. One owner attempt lasts at most 30 seconds. Bundle
arrival defaults to a 25-second wait; `--bundle-timeout` accepts 1–30 seconds.
The final confirmation and signing must leave at least two seconds of the
existing operation lifetime. This tightens the usable interval; it does not
extend the gate's expiry.

Late evidence, an expired prompt, a clock rollback, EOF, cancellation or a
wrong confirmation produces no grant. A new attempt requires another
explicit `READY` and a new challenge. There is no automatic renewal beneath
an existing approval.

## Public events and recovery

Human prompts go to the controlling terminal. Standard output carries one
bounded JSON document per line, suitable for a keyless coordinator:

| Event | Fields used by the coordinator |
|---|---|
| `READY` | `owner_instance_id`, `request_id`, `intent_sha256`, `profile_sha256`, `ready_at_ms` |
| `AWAITING_APPROVAL` | `operation_id`, `approval_phrase`, `bundle_sha256`, `expires_at_ms`, `remaining_ms`, verified summary fields |
| `GRANT_ISSUED` | `operation_id`, signed `grant`, `effect: NOT_ESTABLISHED` |
| `DENIED` | `reason`, `message`; process exits 1 |
| `BLOCKED` | `reason`, `message`; process exits 2 |

The `AWAITING_APPROVAL` event is emitted after discarding old typeahead and
displaying the final prompt. The CLI performs no subsequent flush before
reading the response. This permits a scripted PTY driver to respond to the
event without losing legitimate input. Such a driver remains an automated
test, not a human participant.

A successful command exits 0. The signed grant is committed to the private
SQLite journal before it is returned. Concurrent exact retries retain one
grant. The same operation or reviewed request cannot receive conflicting
authority. If the output is lost, recover the recorded grant by operation ID:

```bash
python -m shirudo_adapter.owner_cli grant \
  --state /private/owner --operation-id OPERATION_ID
```

Recovery returns `GRANT_RECORDED` and the original envelope. It does not renew
the grant or establish that an effect happened. A grant remains a bearer
capability until it expires or is consumed, so the exchange path belongs to
the approved local workflow. Historical publication should occur after its
short validity interval.

After execution, verify the target's effect receipt using the pinned target
key and the retained operation, grant and assessment bindings. On transport
loss, query the existing operation or retry its exact request. Do not infer
failure from a missing response or start a replacement operation automatically.

## Qualification boundaries

The unit suite checks strict authority bindings, required PCR coverage,
freshness, expiry during confirmation and final commit, state custody,
concurrent idempotence, provisioning locks and malformed records. Real
subprocess/PTY tests exercise both prompts, input flushing, stdin refusal,
timeouts, immutable snapshots and grant retrieval. A local environment that
cannot allocate a PTY may explicitly skip those tests; the GitHub Actions
qualification environment treats that inability as a failure.

The complete demonstration must additionally exercise separate owner and
verifier UIDs, genuine fresh Shirudo evidence from the immutable target image,
one approved counter effect and adverse controls. Record those outcomes from
the actual run. Neither the library's trusted signing primitive nor a
scripted terminal can assert a human decision on its own.
