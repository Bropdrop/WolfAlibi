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
    # shellcheck source=/dev/null
    source build/vm-toolchain.env
    export BPF_VMLINUX_BTF="$upstream/artifacts/bpf-next-kernel-debs/vmlinux.btf"
    export TEST_VM_TIMEOUT=900
    # The limit must be raised in this launching shell; another Actions step
    # cannot change the resource limits inherited by its successors.
    sudo prlimit --pid "$$" --memlock=unlimited:unlimited
    make -C testing vm BUILD_CONTAINER=0 LOCAL_STACK=0 VM_NAME="$vm_name"
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
