# WolfAlibi–Shirudo laboratory prototype 0.1.0

**Qualification status: bounded LAB_VTPM prototype 0.1.0 PASS.**
The complete laboratory demonstration passed for source
[`86c28db9537558b4cc76d73baea4353652462147`](https://github.com/Bropdrop/WolfAlibi/commit/86c28db9537558b4cc76d73baea4353652462147),
[run 45318855750](https://github.com/Bropdrop/WolfAlibi/actions/runs/45318855750).
The reviewed artifact contains 89 public files, 19 passing controls, five
genuine assessments and two counter effects; all eight artifact-corruption
controls also passed. See the [qualification record](evidence/ci-45318855750/qualification.json).
Approval used `SCRIPTED_PTY`; actual human approval remains **`NOT_RUN`**.
Earlier experiments retain their own scope in [ACTION_GATE.md](ACTION_GATE.md).
Failed-attempt records are preserved in
[development-attempts.json](evidence/ci-45318855750/development-attempts.json).

The prototype answers one bounded question: can a target increment a protected
counter by exactly one only when it receives both fresh accepted Shirudo
evidence and a separately signed owner grant, then recover the recorded result
without repeating the effect?

The supported automated demonstration is the repository's **Shirudo complete
LAB prototype** workflow. It uses a disposable Linux VM, software TPM,
separate signing accounts and scripted terminal input. It is not a shield
deployment, hosted service, general command runner or production installer.

## How measurement and authorization connect

The evidence chain and the authority chain meet at the target gate:

| Boundary | What is checked |
|---|---|
| Native Shirudo configuration | The independently expected configuration root is checked through the genuine quote's PCR 14 configuration history. |
| Configuration to gate image | The signed native configuration contains `etc/wolfalibi/gate-image.json`, which names the separate gate image's dm-verity root, authority-anchor digest and source-manifest digest. |
| Image to running gate | Trusted initrd code mounts that image read-only. A fixed launcher enters it with `chroot`, drops to the gate's numeric UID/GID, and executes the fixed interpreter and entrypoint. Required observations check the final process identity, capabilities, root, executable and file-backed mappings. |
| Bootstrap authority | An owner-signed boot policy binds the complete target trust configuration to the approved anchors, gate-image root and configuration root. |
| Operation authority | The owner verifies a fresh signed bundle, then signs one concrete operation after `READY` and the final `APPROVE` confirmation. |
| Protected effect | One SQLite transaction records the counter increment, consumed authority and signed effect receipt. Exact retries return the retained receipt. |

The gate and its Python dependencies live in a **separate dm-verity image**.
They are not added to Shirudo's authority-bearing runtime image. The image
manifest declares `NO_SHIRUDO_RUNTIME_AUTHORITY`. This distinction matters:
the counter service must not gain Shirudo runtime authority merely because
its implementation uses an interpreter.

The gate image contains public authority anchors. It cannot contain a complete
policy whose configuration digest would recursively include itself. Instead,
the trusted builder constructs the images first; after their roots and the
target's independent baseline are known, the owner process signs the full
boot policy. Only then does the target initialize its gate identity. The owner
subsequently pins a profile containing that identity and the same policy.

This establishes a laboratory connection through trusted builder, initrd and
launcher observations. A quote does not, by itself, establish the current
identity or continuous integrity of every process after measurement.

## Install and inspect the CLI package

Use a reviewed checkout and Linux with Python 3.11 or later:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/wolfalibi-shirudo --help
.venv/bin/wolfalibi-shirudo-action-gate --help
.venv/bin/wolfalibi-shirudo-owner --help
```

The package pins `cryptography==50.0.0`. The three entrypoints expose evidence
assessment, the target counter gate, and owner provisioning/approval. Their
module equivalents are `shirudo_adapter.cli`,
`shirudo_adapter.action_gate_cli` and `shirudo_adapter.owner_cli`.

To build the same installable package type as CI:

```bash
.venv/bin/python -m pip wheel . --no-deps --wheel-dir packages
.venv/bin/python -m unittest discover -s tests -v
```

The wheel contains the CLIs; retain the repository scripts for the
integration experiment. Unit tests
include fabricated signed evidence, real subprocesses, Unix sockets and
scripted PTYs; passing them does not replace genuine TPM integration.

Build records retain source and dependency identities. Fresh keys, generated
metadata and host dependency versions can change output bytes; bit-for-bit
reproducible images across arbitrary hosts are not established.

## Run the maintained CI demonstration

The executable recipe is
[shirudo-prototype-integration.yml](../../.github/workflows/shirudo-prototype-integration.yml).
It targets Ubuntu 24.04, Python 3.12, Linux x86-64, available KVM, and permission
to raise the pinned verifier's memory-lock limit. It checks those prerequisites
before the expensive build. Complete host tests must pass before the VM job.

The candidate's completed prerequisites are:

| Check | Recorded result and scope |
|---|---|
| [Main host suite](evidence/ci-45318855750/host-test-review.json) | All 245 tests passed in each of the Python 3.11 and 3.12 PR jobs and the Python 3.12 integration prerequisite. |
| [Actual sudo terminal probe](evidence/ci-45318855750/sudo-terminal-review.json) | Both tests passed under a separate UID, reproducing the background-group rejection and completing READY/final APPROVE with a verified fabricated grant and zero counter effects. Human approval remains `NOT_RUN`. |
| [Historical verifier review](evidence/ci-45318855750/offline-artifact-review.json) | All eight recorded outcomes passed review using the pinned official executable and historical inputs; this establishes no fresh target state. |

Upstream is pinned to
`fb97c1ec5908c8bdbd46760c29e57677977fce74`. The official verifier comes from
artifact `14865910776`; `prepare_shirudo_binary.py` checks both the archive
digest and the extracted ELF digest. An unavailable artifact or changed bytes
must block the run, not trigger a substitution with a newer binary.

The following are the current workflow commands, executed from the repository
root **inside its disposable CI environment**. GitHub supplies the run IDs and
token; the workflow supplies `WOLFALIBI_DISPOSABLE_CI=1`. The helpers deliberately
reject ordinary environments. Do not set those guards merely to run them on an
unrelated machine.

```bash
python -m unittest discover -s tests -v
python -m unittest tests.prototype_sudo_probe -v

mkdir -p artifacts evidence
sudo env GITHUB_ACTIONS=true WOLFALIBI_DISPOSABLE_CI=1 \
  prlimit --memlock=unlimited:unlimited -- \
  python3 scripts/shirudo_ci_preflight.py \
  --output "$PWD/evidence/preflight.json"

gh api repos/shirudo-dev/shirudo/actions/artifacts/14865910776/zip \
  > artifacts/upstream.zip
python scripts/prepare_shirudo_binary.py \
  --archive artifacts/upstream.zip --output artifacts/verifier

bash scripts/shirudo_ci_vm.sh setup "$PWD/upstream" "$VM_NAME"
sudo prlimit --pid "$$" --memlock=unlimited:unlimited
python scripts/shirudo_prototype_host.py provision \
  --verifier "$PWD/artifacts/verifier/shirudo" \
  --output "$PWD/evidence/authorities"

bash scripts/shirudo_prototype_vm.sh build "$PWD/upstream" "$VM_NAME" \
  "$PWD/artifacts/prototype" "$PWD/evidence/authorities"
bash scripts/shirudo_prototype_vm.sh boot "$PWD/upstream" "$VM_NAME" \
  "$PWD/artifacts/prototype" "$PWD/evidence/authorities"

python scripts/shirudo_real_lab.py \
  --upstream "$PWD/upstream" --vm-name "$VM_NAME" \
  --verifier "$PWD/artifacts/verifier/shirudo" \
  --bundle "$PWD/artifacts/prototype/bundle" \
  --output "$PWD/evidence/lab"

python scripts/shirudo_prototype_lab.py \
  --upstream "$PWD/upstream" --vm-name "$VM_NAME" \
  --verifier "$PWD/artifacts/verifier/shirudo" \
  --build "$PWD/artifacts/prototype" \
  --authorities "$PWD/evidence/authorities" \
  --output "$PWD/evidence/prototype"
```

`VM_NAME` is exactly
`wolfalibi-prototype-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}`. Use new output
directories for a new run. The workflow additionally runs the unchanged
historical-fixture gate in its own job.

The build helper first creates upstream's
`upstream/build/test-vm/host-bundle-bpf-next-verity`, then invokes
`shirudo_prototype_image.py build` with that bundle, the reviewed repository,
`evidence/authorities/anchors.json`, and `artifacts/prototype` as a new output
directory. It copies the bundle, creates the separate gate image, rebuilds the
signed native configuration containing its manifest, and generates explicit
initrd inputs. Tracked upstream files remain unchanged.

### Where the live components reside

| Location | Purpose |
|---|---|
| `/var/lib/wolfalibi-prototype/<run>-<attempt>/owner/state` | Private owner state under `wolfproto-owner` |
| `/var/lib/wolfalibi-prototype/<run>-<attempt>/verifier/state` | Private verifier state under `wolfproto-verifier` |
| `/var/lib/wolfalibi-prototype/<run>-<attempt>/official-shirudo` | Digest-checked, root-owned `0555` verifier copy readable by the verifier role |
| `/var/tmp/wolfalibi-prototype-<run>-<attempt>` | Atomically published public exchange files |
| `artifacts/prototype/build-result.json` | Roots, generated bundle, initrd environment and build output paths |
| `artifacts/prototype/public/` | Image, manifest, source inventory and boot descriptor outputs |
| Guest `/run/wolfalibi/image` | Read-only gate image |
| Guest `/var/lib/wolfalibi-prototype/state` | Writable private gate state and public signed boot policy |
| Guest `/var/lib/wolfalibi-prototype/socket/gate.sock` | Restricted counter protocol socket; visible inside the image as `/socket/gate.sock` |
| Guest `/var/lib/wolfalibi-prototype/bootstrap/image-boot.json` | Root-owned `0444` public bootstrap-report copy, checked against the original by byte equality and SHA-256 |
| Guest `/run/wolfalibi/image-boot.json` | Original trusted-initrd report, retained in the public evidence |

### How the launcher enters the image

Trusted guest root prepares explicit bind mounts before starting the gate.
The writable state and socket sources reside on the ordinary filesystem under
`/var/lib/wolfalibi-prototype`, and appear inside the approved image at `/state`
and `/socket`. The configuration witness manifest is bound read-only at
`/run/wolfalibi/config-manifest.json` inside the image. The verified public
bootstrap-report copy is also bound read-only at its internal path,
`/run/wolfalibi/image-boot.json`. The original initrd report remains unchanged;
copy verification and retained evidence bind the ordinary-file handoff to its
exact bytes.

The harness selects a verified GNU coreutils launcher from
`/usr/sbin/gnuchroot`, `/usr/sbin/chroot` or `/usr/bin/chroot`. It records the
resolved path, root ownership, mode, size, SHA-256 and version in
`measurement/launch-bindings.json`. The qualified run selected root-owned
`0755` `/usr/sbin/gnuchroot`, reporting `chroot (GNU coreutils) 9.7`.
The systemd-launched command uses fixed
`--userspec=<numeric UID>:<numeric GID> --groups=<client GID>` arguments to enter the approved image, drop its IDs,
and execute `/usr/bin/python3 -I -B -S /opt/wolfalibi/gate_entry.py`. Its temporary
root launch context has only `CAP_SYS_CHROOT`, `CAP_SETUID` and `CAP_SETGID`.
Qualification requires all four UID values of the final gate process to be
identical and nonroot, with effective, permitted and ambient capabilities all
zero. The temporary launcher privilege is not an authority granted to the
running Python gate.

The host coordinator is a **trusted CI administrator with sudo access**. It
starts role processes through `sudo → prlimit → setpriv`; it is not a confined
agent. Actual peer-account probes must show that the owner, verifier and
unprivileged client cannot read one another's private signing state. This does
not deny access to the administrator.

For `SCRIPTED_PTY` approval only, a fixed launcher runs after the owner UID
drop. If necessary, it requests sudo's normal `SIGTTIN` foreground handoff,
restores the signal handler and verifies foreground status before executing
the owner CLI. JSON stdout remains a pipe; terminal input still uses `/dev/tty`.
Ordinary owner invocations retain their unchanged foreground-terminal checks.

The workflow always attempts to stop the selected VM and remove the exact
per-run private host-state and exchange directories. It records cleanup
results, not secure erasure. VM storage and remaining accounts belong to the
disposable runner lifecycle.

## Prepare trust and exercise the owner terminal

The full ceremony is documented in [OWNER_APPROVAL.md](OWNER_APPROVAL.md).
For an operator-arranged Linux session, initialize fresh identities **under
their respective separate accounts**, with approved private parent directories:

```bash
# Owner account
wolfalibi-shirudo-owner init --state /home/lab-owner/wolfalibi-state

# Verifier account
wolfalibi-shirudo init --state /home/lab-verifier/wolfalibi-state
```

Retain the public identities through trusted provisioning. Build and enroll
the selected laboratory target, derive its complete policy from independent
builder/measurement inputs, and keep private keys out of exchange files.
An assessment submitted by the target must never select its own trusted keys,
expected configuration or verifier binary.

After image/configuration construction, the owner provisioning command is:

```bash
wolfalibi-shirudo-owner sign-boot-policy \
  --state /home/lab-owner/wolfalibi-state \
  --anchor /approved/anchors.json \
  --manifest /approved/gate-image.json \
  --trust /approved/action-trust.json
```

It returns a boot-policy envelope, not an action grant. The target verifies
that envelope against its immutable anchors and manifest before initialization.
Retain its public gate identity, construct the matching owner profile, and run
`pin-profile --state ... --profile /approved/owner-profile.json`. A different
profile or boot-provisioning binding cannot silently replace the first one.

For the action, prepare a strict intent naming that target, gate instance,
policy digest/generation, a new request ID and exactly `increment_counter`
with `delta: 1`. The owner can preview it using `review`. Start approval from
the owner's actual foreground terminal:

```bash
wolfalibi-shirudo-owner approve \
  --state /home/lab-owner/wolfalibi-state \
  --intent /exchange/intent.json \
  --bundle /exchange/fresh-bundle.json
```

The bundle path must not exist. The owner first reviews stable target/action
details and types `READY`. Only then should the coordinator issue a new
verifier challenge, immediately obtain the target's signed operation challenge,
collect evidence, and obtain an accepted assessment. It atomically publishes
one bundle containing `request_id`, `attestation_challenge`, `action_challenge`
and `assessment`, with schema `wolfalibi.shirudo.owner-bundle.v1`.

The owner verifies those records against its complete pinned profile and asks
for `APPROVE <last twelve operation-ID characters>`. Approval is read from
`/dev/tty`, never stdin; there is no `--yes`. Input queued before the concrete
prompt is discarded. Frozen records are checked again before signing.

The gate retains its 30-second freshness limit, five-second challenge admission
window and two-second clock-skew allowance. The owner also requires two seconds
of remaining operation lifetime. A timeout creates no grant and requires a new
explicit attempt. Plan collection and transport before pressing READY.

There is no installed general-purpose coordinator for this manual exchange.
The maintained automated example is the fixed CI harness. These instructions
describe the owner interface and required file exchange; they do not claim
that a real user has completed it. Scripted demonstrations record
`actual_human_approval: NOT_RUN`.

## Execute once and recover accurately

`GRANT_ISSUED` means that the owner durably recorded a signed grant. It does
not mean that the target changed. Submit the exact
`{operation_id, grant, assessment}` through the gate's bounded Unix-socket
`execute` request. The target verifies both authorities and commits its counter,
consumption record and signed receipt together.

On a lost response, retain the operation ID. Query the same operation with
`status`, verify its effect receipt against the pinned target key and original
bindings, or retry the exact request. A committed retry returns
`ALREADY_COMMITTED` with the same receipt. Do not create a replacement operation
merely because the first reply was missing. The owner command
`grant --state ... --operation-id ...` retrieves the original recorded grant
without renewing it.

An assessment remains `HISTORICAL_EVIDENCE_ONLY` with `authorization: NONE`.
An effect receipt describes a past committed counter change. Neither proves
current authorization or current target state. An unexpired, unused grant is
a bearer capability for its one operation; handle it within the approved
exchange until its short validity interval ends.

## Inspect the qualification artifacts

The [standalone review](evidence/ci-45318855750/prototype-artifact-review.json)
accepted the exact 89-file prototype layout: all 19 controls passed, five fresh
assessments were accepted, and two operations committed two counter increments.
Controls covered cold dm-verity failures, bootstrap binding, peer-UID denial,
immutable execution, owner decline/tamper/timeout, forged grants, exact retries
and lost-reply recovery. The owned gate daemons were stopped after completion.

Start with `evidence/prototype/summary.json`, then its artifact manifest,
`cases/`, `materials/`, `measurement/`, public trust/profile files and cleanup
records. Material sets retain the intent, bundle, assessment verification,
scripted terminal events/transcript and execution request where applicable.
Compare public artifact hashes, executed source identity, image/source manifest,
signatures, binding fields and counter history. Retained records do not rerun
TPM cryptography by themselves.

Use the preserved original
`docs/shirudo/evidence/ci-45318855750/prototype-lab-public-records.zip`.
Check its SHA-256 against `artifact-provenance.json` and
`preserved-file-manifest.json`, together with the authenticated CI association.
Internal file hashes alone do not authenticate an archive's origin.

From the repository root:

```bash
prototype_records_dir="docs/shirudo/evidence/ci-45318855750"
prototype_review_dir="$(mktemp -d)"
sha256sum "$prototype_records_dir/prototype-lab-public-records.zip"
.venv/bin/python -m zipfile -t "$prototype_records_dir/prototype-lab-public-records.zip"
.venv/bin/python -m zipfile -e "$prototype_records_dir/prototype-lab-public-records.zip" "$prototype_review_dir"
.venv/bin/python -B docs/shirudo/review_prototype_artifact.py \
  "$prototype_review_dir/evidence/prototype"
.venv/bin/python -B docs/shirudo/review_prototype_corruptions.py \
  "$prototype_review_dir/evidence/prototype"
```

The standalone reviewer checks retained signatures, bindings, source pins and
observations without importing the adapter, executing Shirudo or contacting a
target. The corruption checker first requires a valid original, then changes
temporary copies and recomputes affected manifests. Its eight controls require
specific rejections for forged owner/target signatures, a foreign assessment,
ledger-request mismatch, boolean counter, missing EIO evidence, a false human
approval claim, and a changed source hash with coordinated manifests. It leaves
the original unchanged. All eight controls passed in
[review-corruption-checks.json](evidence/ci-45318855750/review-corruption-checks.json).
Compare rerun results with the retained reviews and bounded qualification.

The workflow uploads explicit public paths, the installable wheel and verifier
provenance. It does not upload private host journals, signing keys or entire
VM directories. Artifact names include the executed Git SHA and currently have
14-day retention; preserve reviewed evidence separately when publishing a
qualification record.

The final claim remains bounded: `LAB_VTPM`, trusted builder/administrator/
hypervisor/clocks, trusted gate UID and writable private state, and one counter
increment. Direct QEMU boot does not establish a measured UKI, Secure Boot or
hardware TPM identity. Continuous process identity, quote-to-effect atomicity,
administrative rollback resistance, power-loss durability, production readiness
and operational shield deployment are not qualified by this experiment.
