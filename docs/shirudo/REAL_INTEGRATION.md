# Genuine Shirudo integration: qualification runbook

This runbook describes the two real-upstream gates and the evidence needed to
interpret them. It is a procedure, not a record that either gate passed. Use the
machine-readable report and the exact workflow run for executed outcomes.

The reviewed upstream revision is
[`fb97c1ec5908c8bdbd46760c29e57677977fce74`](https://github.com/shirudo-dev/shirudo/tree/fb97c1ec5908c8bdbd46760c29e57677977fce74).
The adapter's existing synthetic tests remain a separate qualification layer.

## The gates establish different facts

| Gate | Required observation | Meaning of a successful result | What it does not establish |
| --- | --- | --- | --- |
| Host preflight | Supported Linux execution, sufficient inherited locked-memory limit, and the required files/tools; KVM access for the VM gate | The selected host can attempt the requested gate | Cryptographic verification, target identity, or a passing attestation |
| Historical corpus compatibility | The approved upstream ELF executes; archived, byte-pinned inputs produce the expected structured results and hostile changes fail | The real executable and adapter report contract interoperate with those historical inputs | Freshness, current target state, or a newly enrolled target |
| Fresh `LAB_VTPM` integration | A disposable VM answers a newly issued adapter nonce; independently selected builder and measurement records match; the real upstream verifier accepts; hostile controls fail | A fresh end-to-end laboratory assessment can produce `EVIDENCE_ACCEPTED` under the `LAB_VTPM` policy | A physical TPM, manufacturer-chain validation, independent witness durability, or authority to perform a target effect |

An archived corpus nonce must never be inserted into the challenge database to
make historical evidence appear fresh. The historical gate may use that nonce
as an explicit test input to the upstream verifier. It does not satisfy the
fresh-challenge gate and must not produce a fresh target assessment receipt.

The lab harness provisions and observes a disposable target. The adapter
continues to run only its local `version --version-id` and `attest verify`
commands. Lab setup is separate from the adapter's verification interface.

## Repository entry points

The workflow is
[`shirudo-real-integration.yml`](../../.github/workflows/shirudo-real-integration.yml).
The following commands are its narrow interfaces; they require their stated
prerequisites and do not imply that a gate has already run.

| Entry point | Purpose and output |
| --- | --- |
| `python scripts/prepare_shirudo_binary.py --archive ZIP --output NEW_DIRECTORY` | Verify the pinned archive, extract only the exact approved static ELF, and write `artifact.json` |
| `python scripts/shirudo_real_offline.py --upstream CHECKOUT --verifier ABSOLUTE_ELF --output EMPTY_DIRECTORY` | Run the historical gate and write `gate-a-report.json` plus bounded per-case evidence |
| `python scripts/shirudo_ci_preflight.py --output REPORT_JSON` | Observe the explicitly selected CI host, KVM API and inherited memlock without creating a VM |
| `bash scripts/shirudo_ci_vm.sh setup CHECKOUT VM_NAME` | Prepare the pinned upstream dependencies and kernel on disposable CI only |
| `bash scripts/shirudo_ci_vm.sh boot CHECKOUT VM_NAME` | Build the bundle and boot one named disposable VM on that CI host |
| `python scripts/shirudo_real_lab.py --upstream CHECKOUT --vm-name VM_NAME --verifier ABSOLUTE_ELF --output NEW_DIRECTORY` | Collect and assess fresh lab evidence, writing `summary.json` and `artifact-manifest.json` |
| `bash scripts/shirudo_ci_vm.sh stop CHECKOUT VM_NAME` | Stop that named VM without reevaluating build prerequisites |

The CI wrapper requires both `GITHUB_ACTIONS=true` and
`WOLFALIBI_DISPOSABLE_CI=1`. These are explicit execution-context guards, not a
security boundary against a caller who controls its own environment. The
local gate commands do not invoke `sudo` or install missing requirements.

Both real gates require the same reviewed official ELF digest. The fresh lab
uses its separately built target binary only inside the disposable VM; it
does not silently substitute that build for the approved verifier.

The workflow may run the fresh lab after historical corpus failure when the
historical job established that the exact approved executable started. Each
job retains its own verdict. A successful fresh lab does not change an earlier
historical job's failed result.

## Preconditions and local failure behavior

Run preflight before downloads, installation or VM startup. A local invocation
must report missing requirements and stop. It must not attempt `sudo`, change
host security settings, patch the upstream binary, disable memory locking, or
substitute a synthetic executable for a failed genuine run.

The fresh VM gate needs an x86-64 Linux host with readable and writable
`/dev/kvm`, a supported kernel bundle, QEMU, swtpm, tpm2-tools and its swtpm TCTI,
libguestfs, dracut, the upstream build dependencies, and sufficient disk and
memory for its selected VM sizes. Upstream's pinned defaults are four virtual
CPUs, 4 GiB guest memory and a 30 GiB virtual disk; these are configuration
defaults, not measured resource consumption for this adapter.

The upstream CLI locks its process memory even for `version --version-id`.
Successful artifact download is therefore insufficient evidence that the
verifier ran. An executable-loader error, a locked-memory failure, a timeout,
or missing KVM is a blocked prerequisite or execution result. None counts as a
cryptographic rejection of the supplied attestation.

The [pinned quickstart](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/Documentation/start/quickstart.rst)
and [process hardening implementation](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/util/harden.c)
define these startup requirements.

## Disposable CI preparation

The preparation sequence below is for a disposable, explicitly selected CI
runner. The repository workflow is the authoritative executable sequence.
Do not run the upstream CI setup script as a general workstation installer.

The workflow's early KVM probe runs with CI's explicitly selected privilege
because `/dev/kvm` may initially belong to root; upstream setup subsequently
configures the runner user's access. Create the public evidence directory as
the runner user before a privileged probe writes a report there, so a root-
owned directory does not prevent later unprivileged artifact creation.

At the pinned revision,
[`.github/scripts/tests.sh setup`](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/.github/scripts/tests.sh)
installs packages, removes large preinstalled SDK directories, changes KVM
device access, and adjusts AppArmor/user-namespace settings for libguestfs.
Those changes are intended for a runner discarded after the job. The local
preflight and verification paths must not invoke that setup implicitly.

### 1. Select the exact source and public kernel artifact

Verify the checkout's full commit before executing its scripts. Keep its work
tree clean apart from build outputs. Use a dedicated checkout for this gate;
do not reuse a developer's active source tree.

From that verified upstream checkout, the narrow artifact sequence is:

```sh
VM=1 TEST_VM_ARCH=x86_64 testing/vm/kernel-artifact.sh download
VM=1 KERNEL_CI_ARTIFACT_DIR="$PWD/build/kernel-ci-artifact" \
  .github/scripts/tests.sh setup
```

The `download` operation leaves the extracted packages in
`build/kernel-ci-artifact`; `setup` stages them. The `fetch` operation both
downloads and stages them, so using `fetch` before `setup` repeats the staging
step. Both are distinct from installing a kernel on the CI host.

At this source revision the default kernel run is `45212180772`. Its public
release asset is retrieved with `curl` and checked against the checksum pinned
in
[`testing/vm/kernel-artifact.sh`](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/testing/vm/kernel-artifact.sh).
An explicit different `KERNEL_RUN_ID` changes the retrieval path to `gh run
download` and requires suitable Actions read access. Do not assume a token
from an unrelated repository grants that access.

Keep `VM=1` for the VM gate: `VM=0` stages BTF only and is insufficient to boot
the target. Full staging validates the kernel image, config, modules, signed
BPF ABI and required LSM hooks. The staged files live under
`artifacts/bpf-next-kernel-debs/`.

Use this public artifact path instead of copying the pinned
`guides-linux.yml` download step: that older workflow names a separate kernel
repository and a dedicated secret token. The self-contained public downloader
is the appropriate interface for this integration.

### 2. Restore narrowly scoped build caches, when available

Cache reuse is an optimization, not an attestation or a reproducible-build
claim. Bind keys to the reviewed source, runner architecture/OS, and relevant
build inputs; do not restore an entire checkout or broad source/build tree.

| Candidate cache | Inputs that must identify its compatibility |
| --- | --- |
| `build/host-openssl` | `vm-toolchain.sh`, OS and architecture |
| `build/host-libtpms` | `vm-toolchain.sh`, `install-libtpms.sh`, OS and architecture |
| `build/target-deps` | `Makefile.target-deps`, OS, architecture and selected build flags |
| Prepared runtime-image cache | Runtime package list, rootfs identity, preparation scripts, architecture and selected image settings |

Use exact cache keys within the selected workflow's trust scope. Never cache
the verifier signing state, per-VM TPM state, SSH keys, host-private fixture
keys or a previous VM's writable disk. Retain the resolved executable hashes
and source/build records even when a cache is hit.

The
[upstream toolchain script](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/.github/scripts/vm-toolchain.sh)
installs clang/LLVM 23, builds or reuses OpenSSL 3.5.9 and the pinned libtpms
toolchain, and writes `build/vm-toolchain.env`. Distribution OpenSSL/libtpms
packages are not interchangeable with those selected inputs. The
[libtpms installer](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/.github/scripts/install-libtpms.sh)
explains the upstream state-restore fault avoided by its chosen revision.

### 3. Set the environment and memlock in each launching process

A later Actions step starts a new shell. Neither sourcing a file nor raising
the previous shell's resource limit configures that later process. Every step
that executes an upstream binary, builds a bundle, or launches the lab must
establish its own required environment and inherited resource limits.

Within the explicitly authorized CI step, upstream's pattern is:

```sh
. build/vm-toolchain.env
export BPF_VMLINUX_BTF="$PWD/artifacts/bpf-next-kernel-debs/vmlinux.btf"
sudo -n prlimit --pid "$$" --memlock=unlimited:unlimited
ulimit -l
```

Launch the gate as a descendant of that same shell. A separate earlier
`prlimit` step is insufficient. Record the limit observed by the process that
actually executes the verifier. A guest SSH command is another process
boundary; the harness must also handle and report the guest command's actual
startup result.

The host build tools may need the `PATH`, `PKG_CONFIG_PATH` and
`LD_LIBRARY_PATH` written by `vm-toolchain.env`. Upstream's privileged build
path explicitly forwards `PATH` and `LD_LIBRARY_PATH`, because `sudo -E`
alone does not preserve them reliably. The adapter's verifier subprocess
deliberately uses a restricted environment; do not loosen that environment to
make an unsuitable dynamic executable start.

### 4. Build and boot one named VM

The minimal supported upstream boot target is:

```sh
make -C testing vm BUILD_CONTAINER=0 LOCAL_STACK=0 \
  VM_NAME="$WOLFALIBI_SHIRUDO_VM_NAME"
```

The workflow or harness supplies a unique validated VM name, including the
workflow run and attempt when appropriate. Upstream permits at most 63
characters: an alphanumeric first character, followed by alphanumerics,
periods, underscores or hyphens. It rejects a name whose saved state already
exists.

`BUILD_CONTAINER=0` uses the prepared host toolchain.
`LOCAL_STACK=0` skips starting the local telemetry/OCI/backend stack. The
`vm` target builds the required bundle first; it does not run all upstream
unit, functional or end-to-end test suites. Do not invoke `make tests` or
`.github/scripts/tests.sh run` merely to create this one integration target.

A separate `build-operator` goal is unnecessary here: it depends on
`build-unit`, while the bundle already builds its operator, target, helper and
image prerequisites. A cold build still includes dependency compilation and
runtime-image preparation; record phase durations and allow an appropriate CI
job timeout instead of implying a fixed short completion time.

Pass the same explicit VM name and work directory to every later operation,
including SSH and cleanup. Unnamed upstream `vm-ssh` selects the most recent
saved VM. That behavior is unsuitable for a gate that must bind evidence to a
particular disposable target.

See the pinned
[`testing/Makefile`](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/testing/Makefile),
[`build-bundle-payload.sh`](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/testing/vm/build-bundle-payload.sh)
and [`run.sh`](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/testing/vm/run.sh)
for the selected build and VM behavior.

## Executable provenance and the historical gate

The historical gate must identify the official workflow artifact, its source
commit association, archive digest, extracted executable digest and runtime
`version --version-id` result. An artifact filename or package version is not
a substitute for a successful runtime version response.

The static PIE is suitable for the adapter's sealed-memfd execution route.
A dynamically linked operator binary may depend on libraries absent from the
host or on a bundle-relative loader path that does not survive that route.
The current harnesses require the independently pinned official static
executable and offer no command-line override for a different build. Do not
treat two builds from the same source revision as identical binaries.

The VM bundle builds its target with test-specific compile definitions. The
harness records the target build ID and selected host inputs; the approved
operator verifier has its separate executable digest and runtime version.
Do not describe the test target as an unmodified production package.
Upstream revision association and recorded build inputs do not by themselves
establish an independently reproduced or hermetic dependency closure.

For each archived input, preserve its source path, commit/blob identity when
available, exact byte digest, historical nonce, expected outcome, actual exit
status and complete bounded JSON report. Preserve negative controls as
separate inputs. If a corpus entry does not satisfy the adapter's full pinned
contract, report that limitation directly; do not remove required checks to
turn it into a positive case.

## Fresh `LAB_VTPM` sequence

The harness freezes these inputs before issuing its first challenge. Their
origins are deliberately different; the signed result depends on the selected
builder and laboratory baseline being trusted.

| Policy input | Source used by the harness | Trust limit |
| --- | --- | --- |
| AK and EK names | The named VM's pre-boot builder `enroll.json` | This is trusted-builder enrollment for a software TPM, not a manufacturer chain |
| Expected chain | The approved host verifier's `attest predict` result over the selected host certificates | The selected certificates and host build remain trusted inputs |
| Expected configuration root | The bundle's host-side `verity/config-boot-keys.roothash` | The host build and root-hash file remain trusted inputs |
| Configuration PCR selection | The pinned upstream runtime template | This harness requires the reviewed PCR-14 configuration, rather than accepting a response-supplied selector |
| Binding PCRs 9 and 11 | A pre-challenge status observation from the explicitly named, trusted lab VM | These values are a laboratory baseline; they are not independently calculated host expectations |
| Verifier identity | The fixed official ELF digest and its successful runtime version response | Source association is not a reproducible-build proof |

The harness records these decisions in `baseline-manifest.json`. This VM
uses upstream's direct QEMU kernel boot. In particular, an accepted PCR-11
baseline must not be described as a measured UKI or Secure Boot qualification;
the report records `measured_uki_qualification: false` and whether PCR 11 is
zero.

1. Boot a fresh named target with the reviewed kernel, bundle and software TPM.
   Preserve the builder's public enrollment record before collecting evidence.
2. Select the expected measurement values from the controlled build and
   known-good lab baseline. Register the policy before the challenge. Record
   which values come from build artifacts and which rely on the trusted lab
   baseline; do not silently copy expectations from the submitted response.
3. Use the adapter's normal `issue_challenge` route. Preserve its signed
   challenge, policy digest, target identity and expiry.
4. Ask only that named disposable VM to collect evidence for the issued nonce.
   Keep the collection command, guest startup result and evidence digest.
5. Submit the exact evidence bytes to the normal adapter assessment path with
   the approved real verifier. Require an `EVIDENCE_ACCEPTED` receipt with
   `LAB_VTPM` assurance, a matching execution profile, and a verifiable recorded
   upstream report.
6. Execute the selected hostile controls and record their precise rejection
   points. Replay must fail through the durable challenge state; wrong nonce,
   target, policy or measurements must not earn acceptance. A startup failure
   is not evidence that a cryptographic mutation was detected.
7. Retrieve and independently verify the signed historical receipt using the
   externally supplied verification key and expected target, policy and
   challenge. Its `current_authorization` remains `false`.
8. Stop only this VM and preserve the allowlisted evidence. Cleanup failure
   must be reported separately from the attestation result.

Interactive upstream VMs have a builder that creates and records AK/EK names
before boot. Its per-VM `tpm-names` and `enroll.json` are appropriate laboratory
enrollment inputs when that builder is trusted. Reading key names from a
target-supplied evidence document is not equivalent. There is no need to call
`vm-enroll`, which loads records into the upstream local stack, for this
standalone adapter gate.

The upstream builder also creates a laboratory endorsement CA. Its certificate
does not turn a software TPM into manufacturer-certified hardware. See
[`tpm-builder.sh`](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/testing/vm/tpm-builder.sh)
and the
[builder-enrollment guide](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/Documentation/operate/run/attest.rst).

### Interpreting the fresh controls

The real harness checks one accepted fresh response, same-challenge replay,
old evidence submitted for a new nonce, an altered quote signature, wrong AK
identity, wrong expected chain, wrong configuration root, wrong binding PCR,
expiry, and policy revocation. It also checks that revocation prevents issuing
a new challenge. These controls supplement the adapter's synthetic hostile
test suite; they do not mean that every synthetic test was repeated against
the VM.

The signature, configuration-root and binding-PCR cases require an actual
upstream failure report with the expected failed check. The identity, nonce
and chain cases can reject during the adapter's precheck. Replay is rejected
by the durable state without changing the original receipt. Those are
different observed rejection points, all recorded explicitly.

A lab `summary.json` with `result: PASS` requires all selected controls and
the positive case to pass. `positive_evidence_accepted: true` alone is
insufficient if a later control fails. `BLOCKED_ENVIRONMENT` identifies a
prerequisite or execution problem; `FAIL_ASSERTION` identifies an unexpected
qualification result. Always retain the workflow result as well, since VM
setup or cleanup can fail outside the Python harness.

## Evidence retention and final claims

Upload an explicit allowlist: source/artifact provenance, preflight and phase
results, public builder records, the registered policy, signed challenge,
exact attestation evidence, verifier report, signed receipt, public verification
key, hostile-control outcomes and relevant bounded logs. Include hashes that
connect those artifacts to the report.

Do not upload an entire VM or state directory. It can contain TPM state, SSH
private keys, verifier signing keys, fixture signing material and writable
guest disks. The upstream VM runner explicitly notes that failed guest
overlays can retain ephemeral signing material. Preserve public evidence
without publishing the lab's private state.

The final result must identify the executed adapter commit, upstream source
revision, actual executable digest/version, kernel identity, policy digest and
gate outcome. Report a blocked gate as blocked and a gate not reached as not
run. Green synthetic tests, successful dependency installation, or a completed
VM boot cannot substitute for a fresh accepted assessment.

Even a successful fresh lab establishes a laboratory integration result. It
does not qualify physical hardware enrollment, shield effectiveness,
production target compatibility, complete confinement, independent witnesses,
joint-restoration resistance or target-side authorization enforcement.
