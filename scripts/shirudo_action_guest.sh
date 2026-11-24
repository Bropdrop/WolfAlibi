#!/usr/bin/env bash
# Prepare Python dependencies only in this workflow's disposable target guest.
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true || ${WOLFALIBI_DISPOSABLE_CI:-} != 1 ]]; then
  echo 'Guest preparation requires an explicitly selected disposable GitHub Actions host.' >&2
  exit 2
fi
if [[ $# != 2 ]]; then
  echo 'usage: shirudo_action_guest.sh UPSTREAM VM_NAME' >&2
  exit 2
fi
if [[ ! ${GITHUB_RUN_ID:-} =~ ^[1-9][0-9]*$ || ! ${GITHUB_RUN_ATTEMPT:-} =~ ^[1-9][0-9]*$ ]]; then
  echo 'A concrete workflow run and attempt are required.' >&2
  exit 2
fi

upstream=$(realpath "$1")
vm_name=$2
expected_vm="wolfalibi-action-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
if [[ $vm_name != "$expected_vm" || ${#vm_name} -gt 63 ]]; then
  echo 'Refusing a guest other than the target selected for this workflow attempt.' >&2
  exit 2
fi
if [[ $(git --no-replace-objects -C "$upstream" rev-parse HEAD) != fb97c1ec5908c8bdbd46760c29e57677977fce74 ]]; then
  echo 'Unsupported upstream source revision.' >&2
  exit 2
fi
if [[ -n $(git --no-replace-objects -C "$upstream" status --porcelain --untracked-files=no) ]]; then
  echo 'The pinned upstream tracked source must remain unchanged.' >&2
  exit 2
fi

# The upstream SSH helper verifies the selected VM is running and uses only
# its recorded localhost port and key. Independently require the builder's
# public enrollment record to name exactly the workflow-selected target.
python3 - "$upstream/build/test-vm/vms/$vm_name" "$vm_name" <<'PY'
import json, os, stat, sys
from pathlib import Path

directory = Path(sys.argv[1])
if not stat.S_ISDIR(directory.lstat().st_mode):
    raise SystemExit('The approved VM state directory must already exist without a symlink')
fd = os.open(directory / 'enroll.json', os.O_RDONLY | os.O_NOFOLLOW)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16384:
        raise SystemExit('The approved VM must have a bounded public builder enrollment record')
    with os.fdopen(fd, 'rb', closefd=False) as stream:
        raw = stream.read(16385)
finally:
    os.close(fd)
def unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate builder enrollment key')
        result[key] = value
    return result
record = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs)
if (type(record) is not dict or set(record) != {'source', 'nodes'}
        or record['source'] != 'test-vm' or type(record['nodes']) is not list
        or len(record['nodes']) != 1 or type(record['nodes'][0]) is not dict
        or set(record['nodes'][0]) != {'ak_name', 'ek_name', 'node_id'}
        or record['nodes'][0]['node_id'] != sys.argv[2]):
    raise SystemExit('Builder enrollment does not name this qualification target')
PY

# Both sides have deadlines. SSH input carries this fixed script, with no
# caller-supplied command, package, destination, or remote hostname. Package
# progress goes to stderr; stdout is a small public dependency report only.
timeout --signal=TERM --kill-after=10s 590s \
  env VM_NAME="$vm_name" VM_SSH_COMMAND='timeout --signal=TERM --kill-after=10s 570s bash -se' \
  "$upstream/testing/vm/run.sh" --ssh <<'GUEST'
set -euo pipefail
if [[ $(id -u) != 0 || ! -d /workspace/shirudo || ! -d /mnt/shirudo-src ]]; then
  echo 'Expected the prepared disposable Shirudo target guest as root.' >&2
  exit 2
fi
if [[ ! -d /opt || -L /opt || -e /opt/wolfalibi-action-venv || -L /opt/wolfalibi-action-venv ]]; then
  echo 'Dependency setup requires a new fixed action-gate virtual environment.' >&2
  exit 2
fi
umask 022
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=45 -o Acquire::https::Timeout=45 update >&2
apt-get -y --no-install-recommends -o Acquire::Retries=2 \
  -o Acquire::http::Timeout=45 -o Acquire::https::Timeout=45 install python3-venv >&2
python3 -m venv /opt/wolfalibi-action-venv
/opt/wolfalibi-action-venv/bin/python -m pip install \
  --disable-pip-version-check --no-input --no-cache-dir --only-binary=:all: \
  --timeout 45 --retries 2 --index-url https://pypi.org/simple cryptography==50.0.0 >&2
/opt/wolfalibi-action-venv/bin/python - <<'PY'
import json, platform, sys
import cryptography

if cryptography.__version__ != '50.0.0' or sys.prefix != '/opt/wolfalibi-action-venv':
    raise SystemExit('Guest dependency pins did not match')
print(json.dumps({'schema': 'wolfalibi.shirudo.action-guest-dependencies.v1',
                  'status': 'READY', 'scope': 'DEPENDENCY_SETUP_ONLY',
                  'python': platform.python_version(), 'venv': sys.prefix,
                  'cryptography': cryptography.__version__}, sort_keys=True))
PY
GUEST
