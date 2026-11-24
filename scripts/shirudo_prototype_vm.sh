#!/usr/bin/env bash
# Build and boot only a fresh, explicitly selected disposable prototype VM.
set -euo pipefail
if [[ ${GITHUB_ACTIONS:-} != true || ${WOLFALIBI_DISPOSABLE_CI:-} != 1 ]]; then
  echo 'This helper requires the explicitly selected disposable CI host.' >&2
  exit 2
fi
if [[ $# != 5 ]]; then
  echo 'usage: shirudo_prototype_vm.sh build|boot UPSTREAM VM_NAME BUILD_DIR AUTHORITIES_DIR' >&2
  exit 2
fi
mode=$1
upstream=$(realpath "$2")
vm_name=$3
build_dir=$(realpath -m "$4")
authorities=$(realpath "$5")
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
prototype_python=$(command -v python)
if [[ $vm_name != "wolfalibi-prototype-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}" ||
      ! $vm_name =~ ^wolfalibi-prototype-[1-9][0-9]{0,19}-[1-9][0-9]{0,5}$ ]]; then
  echo 'The VM name must select this exact fresh CI run.' >&2
  exit 2
fi
cd "$upstream"
if [[ $(git rev-parse HEAD) != fb97c1ec5908c8bdbd46760c29e57677977fce74 ||
      -n $(git status --porcelain --untracked-files=no) ]]; then
  echo 'The pinned upstream checkout must remain unchanged.' >&2
  exit 2
fi
sudo prlimit --pid "$$" --memlock=unlimited:unlimited
case "$mode" in
  build)
    # shellcheck source=/dev/null
    source build/vm-toolchain.env
    export BPF_VMLINUX_BTF="$upstream/artifacts/bpf-next-kernel-debs/vmlinux.btf"
    make -C testing test-vm-bundle BUILD_CONTAINER=0 LOCAL_STACK=0
    # Only this new output tree is root-owned. The selected interpreter and
    # dependency bytes are recorded individually in its public manifest.
    sudo env PATH="$PATH" LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" \
      GITHUB_ACTIONS=true WOLFALIBI_DISPOSABLE_CI=1 \
      "$prototype_python" "$repo_dir/scripts/shirudo_prototype_image.py" build \
      --upstream "$upstream" --bundle "$upstream/build/test-vm/host-bundle-bpf-next-verity" \
      --repo "$repo_dir" --anchors "$authorities/anchors.json" --output "$build_dir" \
      --python "$prototype_python"
    ;;
  boot)
    # The target uses the already built copied bundle; make must not rebuild
    # or replace its deliberately different signed configuration.
    export PATH="/usr/bin:/bin:$PATH"
    unset LD_LIBRARY_PATH
    "$prototype_python" - "$upstream" "$vm_name" "$build_dir" <<'PY'
import json, os, pathlib, sys
upstream, name, build = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
record = json.loads((build / 'build-result.json').read_text())
assert record['schema'] == 'wolfalibi.shirudo.prototype-image-build.v1'
assert set(record['environment']) == {'TEST_VM_HOST_BUNDLE', 'dracutbasedir', 'TEST_VM_INITRD_MODULES'}
assert record['bundle'] == str(build / 'bundle')
assert not (upstream / 'build/test-vm/vms' / name).exists()
env = dict(os.environ, **record['environment'])
env.update(VM_MODE='interactive', VM_NAME=name, TEST_VM_MODE='verity', TEST_VM_INITRD='1',
           TEST_VM_TIMEOUT='900', TEST_VM_LOCAL_STACK='0',
           TEST_VM_KERNEL_ARTIFACT_DIR=str(upstream / 'artifacts/bpf-next-kernel-debs'))
runner = str(upstream / 'testing/vm/run.sh')
os.execve(runner, [runner], env)
PY
    ;;
  *) echo 'Unsupported prototype VM operation.' >&2; exit 2 ;;
esac
