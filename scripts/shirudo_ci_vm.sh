#!/usr/bin/env bash
# Run only the pinned upstream VM setup in an explicitly disposable CI host.
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true || ${WOLFALIBI_DISPOSABLE_CI:-} != 1 ]]; then
  echo 'This helper requires an explicitly selected disposable GitHub Actions host.' >&2
  exit 2
fi
if [[ $# != 3 ]]; then
  echo 'usage: shirudo_ci_vm.sh setup|boot|stop UPSTREAM VM_NAME' >&2
  exit 2
fi
mode=$1
upstream=$(realpath "$2")
vm_name=$3
if [[ ! $vm_name =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$ ]]; then
  echo 'Invalid qualification VM name.' >&2
  exit 2
fi
cd "$upstream"
if [[ $(git rev-parse HEAD) != fb97c1ec5908c8bdbd46760c29e57677977fce74 ]]; then
  echo 'Unsupported upstream source revision.' >&2
  exit 2
fi

case "$mode" in
  setup)
    VM=1 TEST_VM_ARCH=x86_64 testing/vm/kernel-artifact.sh download
    VM=1 KERNEL_CI_ARTIFACT_DIR="$upstream/build/kernel-ci-artifact" .github/scripts/tests.sh setup
    ;;
  boot)
    ci_host_path=$PATH
    # shellcheck source=/dev/null
    source build/vm-toolchain.env
    export BPF_VMLINUX_BTF="$upstream/artifacts/bpf-next-kernel-debs/vmlinux.btf"
    export TEST_VM_TIMEOUT=900
    # The limit must be raised in this launching shell; another Actions step
    # cannot change the resource limits inherited by its successors.
    sudo prlimit --pid "$$" --memlock=unlimited:unlimited
    make -C testing test-vm-bundle BUILD_CONTAINER=0 LOCAL_STACK=0
    # run.sh drops the build library path for QEMU/swtpm/dracut. Its TPM
    # builder must therefore also select the distribution's OpenSSL binary.
    # Keep the custom OpenSSL for the completed build, then restore host PATH.
    echo 'Checking the build OpenSSL without its custom library path:'
    env -u LD_LIBRARY_PATH "$upstream/build/host-openssl/bin/openssl" version -v || true
    export PATH="/usr/bin:/bin:$ci_host_path"
    echo 'Selected host OpenSSL for VM provisioning:'
    command -v openssl
    env -u LD_LIBRARY_PATH openssl version -v
    if make -C testing vm BUILD_CONTAINER=0 LOCAL_STACK=0 VM_NAME="$vm_name"; then
      :
    else
      vm_status=$?
      # Retain only bounded error diagnostics and public-file existence, not
      # raw TPM traffic, disks, temporary signing material or private state.
      python3 - "$upstream/build/test-vm/vms/$vm_name" <<'PY'
import json, re, sys
from pathlib import Path
root = Path(sys.argv[1])
files = {name: {"exists": (root / name).is_file(),
                "bytes": (root / name).stat().st_size if (root / name).is_file() else None}
         for name in ("tpm-names", "enroll.json", "ek-ca.pem", "shirudo-build")}
log = root / "swtpm.log"
lines = []
if log.is_file():
    with log.open("rb") as stream:
        stream.seek(max(0, log.stat().st_size - 65536))
        for line in stream.read(65536).decode("utf-8", errors="replace").splitlines():
            if re.search(r"error|warning|tpm-builder:|did not exit|not found", line, re.I):
                lines.append(re.sub(r"[0-9a-fA-F]{32,}", "[hex omitted]", line[:1000]))
print(json.dumps({"stage": "VM_BOOT_FAILURE", "public_files": files,
                  "bounded_error_lines": lines[-30:]}, sort_keys=True))
PY
      exit "$vm_status"
    fi
    ;;
  stop)
    # Do not let make reevaluate the expensive build prerequisites on cleanup.
    if [[ -d "$upstream/build/test-vm/vms/$vm_name" ]]; then
      VM_NAME="$vm_name" testing/vm/run.sh --stop
    else
      echo 'No qualification VM state was created.'
    fi
    ;;
  *)
    echo 'Unknown VM operation.' >&2
    exit 2
    ;;
esac
