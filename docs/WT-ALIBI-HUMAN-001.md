# WolfAlibi human handoff

The handoff is scoped to a disposable Shirudo `LAB_VTPM` target and a single
SQLite `increment_counter` action with delta 1. Actual human approval remains
`NOT_RUN`. Scripted terminal tests use `SCRIPTED_PTY`. See the
[qualification status](LOCAL_EVIDENCE.json) for the local results.

The coordinator waits for the original owner CLI's stdout under the pinned
owner UID. It freezes the external intent and profile, reserves the request
ID durably, and obtains one verifier challenge, one target-signed operation
challenge, one fresh Shirudo evidence object and its signed assessment. The
verifier CLI runs under its separately provisioned account with the pinned
official executable. The coordinator sends bounded JSON through fixed lab
commands and publishes the complete bundle with an atomic no-replace link.

The original owner CLI reads both confirmations from its foreground
controlling terminal. Keep its stdout in an owner-controlled directory with
group read access for the trusted lab operator. The READY record is unsigned.
Its provenance depends on file custody, the original CLI's process lineage,
the owner account, and the controlling terminal. The administrator remains
trusted across the lab. The public event alone establishes no human identity.

The independent verifier takes only public inputs. It checks the challenge,
assessment, grant and effect receipt under the external profile, then matches
the exact execution request against two observer-pinned SQLite snapshots.
The observer uses SQLite read-only mode and a fixed projection. Every old
committed row must remain intact and the journal must gain exactly one
counter transition. The audit authenticates a historical effect with
`authorization: NONE`.

## Apply and test

Use a clean detached worktree at
`953d6a5f5c74c982ad35ee5ff0b15c60ecdae973` in `Bropdrop/WolfAlibi`.
Check the SHA-256 of the completed patch against the supplied bundle manifest.

```bash
git apply --check /absolute/path/WT-ALIBI-HUMAN-001-completed.patch
git apply /absolute/path/WT-ALIBI-HUMAN-001-completed.patch
python -m pip install .
python -m unittest discover -s tests -p 'test_human_handoff.py' -v
python -m unittest discover -s tests -v
```

The suite includes fixture signatures, bounded subprocesses, real SQLite
transactions, Unix sockets and scripted terminals. It covers ambiguous
prepare, loss of the execute reply, concurrent exact retries, and gate exits
before and after commit. The local process tests use fabricated Shirudo
evidence. The preserved earlier PR #49 qualification retains its own
source and scope. [Historical lab evidence](shirudo/PROTOTYPE.md)

## Exact disposable VM recipe

The workflow runs on Ubuntu 24.04 with Python 3.12, KVM,
unlimited memlock and a disposable runner. The workflow supplies
`GITHUB_ACTIONS`, `WOLFALIBI_DISPOSABLE_CI`, `GITHUB_RUN_ID`,
`GITHUB_RUN_ATTEMPT` and the authenticated artifact download token. Check out
upstream `shirudo-dev/shirudo` at `fb97c1ec5908c8bdbd46760c29e57677977fce74`
into `upstream/`. Run from the candidate repository root.

```bash
python -m pip install .
python -m unittest discover -s tests -v
python -m unittest tests.prototype_sudo_probe -v
python -m pip wheel . --no-deps --wheel-dir packages

mkdir -p artifacts evidence
sudo env GITHUB_ACTIONS=true WOLFALIBI_DISPOSABLE_CI=1 \
  prlimit --memlock=unlimited:unlimited -- python3 scripts/shirudo_ci_preflight.py \
  --output "$PWD/evidence/preflight.json"

gh api repos/shirudo-dev/shirudo/actions/artifacts/14865910776/zip > artifacts/upstream.zip
python scripts/prepare_shirudo_binary.py --archive artifacts/upstream.zip --output artifacts/verifier
sudo prlimit --pid "$$" --memlock=unlimited:unlimited
python scripts/shirudo_real_offline.py --upstream "$PWD/upstream" \
  --verifier "$PWD/artifacts/verifier/shirudo" --output "$PWD/evidence/offline"

VM_NAME="wolfalibi-prototype-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
bash scripts/shirudo_ci_vm.sh setup "$PWD/upstream" "$VM_NAME"
python scripts/shirudo_prototype_host.py provision \
  --verifier "$PWD/artifacts/verifier/shirudo" --output "$PWD/evidence/authorities"
bash scripts/shirudo_prototype_vm.sh build "$PWD/upstream" "$VM_NAME" \
  "$PWD/artifacts/prototype" "$PWD/evidence/authorities"
bash scripts/shirudo_prototype_vm.sh boot "$PWD/upstream" "$VM_NAME" \
  "$PWD/artifacts/prototype" "$PWD/evidence/authorities"

python scripts/shirudo_real_lab.py --upstream "$PWD/upstream" --vm-name "$VM_NAME" \
  --verifier "$PWD/artifacts/verifier/shirudo" --bundle "$PWD/artifacts/prototype/bundle" \
  --output "$PWD/evidence/lab"

python scripts/wt_alibi_human_lab.py test --upstream "$PWD/upstream" --vm-name "$VM_NAME" \
  --verifier "$PWD/artifacts/verifier/shirudo" --build "$PWD/artifacts/prototype" \
  --authorities "$PWD/evidence/authorities" --output "$PWD/evidence/prototype"
```

Run the workflow's cleanup steps on every outcome.

```bash
bash scripts/shirudo_ci_vm.sh stop "$PWD/upstream" "$VM_NAME"
python scripts/shirudo_prototype_host.py cleanup > evidence/host-cleanup.json
```

The genuine evidence cases require specific named upstream failures for the
changed quote signature, configuration root and binding PCR 9. The harness
retains the verifier's bounded original JSON stdout beside its signed
assessment. The handoff VM case uses five fresh assessments and two counter
effects in the scripted prototype scenarios, and invokes the standalone
effect verifier for initial and recovered receipts. It terminates the owned
gate after a recorded commit with a lost reply, then restarts that gate and
queries the original operation. [CI workflow](../.github/workflows/shirudo-prototype-integration.yml)

## Human-operated acceptance

Use a fresh VM and separate owner, verifier and lab operator accounts.
Follow the disposable VM recipe through boot. In this run, use `stage` in
place of the scripted `test` command. Keep the stage result and initial
SQLite observation hash in the independent observer's custody.

```bash
lab=(--upstream "$PWD/upstream" --vm-name "$VM_NAME")
exchange="/var/tmp/wolfalibi-prototype-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
owner_state="/var/lib/wolfalibi-prototype/${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}/owner/state"

python scripts/wt_alibi_human_lab.py stage "${lab[@]}" \
  --verifier "$PWD/artifacts/verifier/shirudo" --build "$PWD/artifacts/prototype" \
  --authorities "$PWD/evidence/authorities" --output "$PWD/evidence/human-stage"
```

The stage prepares `human-intent.json`, `human-pins.json`,
`owner-profile.json`, and `human-before.json` under `exchange`. It also
creates the owner-controlled `owner-events` directory with the dedicated lab
operator group as reader. The lab operator confirms the owner UID and
separate verifier UID using the stage's public authority records. The
operator starts the coordinator with the independently retained
`pins_sha256` from staging.

```bash
python scripts/wt_alibi_human_handoff.py "${lab[@]}" \
  --pins-sha256 "$approved_pins_sha256" --output "$PWD/evidence/human-collection"
```

The person acting as owner runs the following from their foreground
terminal. Use the same independently approved `exchange` and `owner_state`
paths. The shell wrapper only sets up protected stdout and execs the
original CLI. The person reads the intent and presses `READY` when ready
to collect. They then read the concrete operation and type its displayed
confirmation phrase or decline.

```bash
sudo -u wolfproto-owner -- /bin/bash -c '
  umask 027
  set -o noclobber
  exec "$1" -I -B -m shirudo_adapter.owner_cli approve --state "$2" \
    --intent "$3/human-intent.json" --bundle "$3/human-fresh-bundle.json" \
    > "$3/owner-events/events.jsonl"
' wolfalibi-owner "$(command -v python)" "$owner_state" "$exchange"
```

The independent observer retains the original READY record and the
`operation_id` and `bundle_sha256` from the owner's `AWAITING_APPROVAL` event. If the owner
declines or times out, collect the final observation and confirm the
counter and committed ledger match the initial observation. A missing
owner output or lost prepare reply leaves this request reserved. A new
attempt requires a distinct reviewed intent and another foreground READY.

For an approved **disposable counter** only, freeze the exact execution
request under a private operator directory. The following command takes
`operation_id` and `approved_bundle_sha256` from the independent observer.
It prints the canonical request hash to retain with that ID.

```bash
run_private="$(mktemp -d)"
python - "$exchange" "$run_private" "$operation_id" "$approved_bundle_sha256" <<'PY'
import os
from pathlib import Path
import sys

from shirudo_adapter.model import canonical_json, digest, read_bounded_file, strict_json
from shirudo_adapter.owner import MAX_BUNDLE_BYTES

exchange, private = map(Path, sys.argv[1:3])
operation, approved_bundle = sys.argv[3:]
events = [strict_json(line) for line in read_bounded_file(
    exchange / "owner-events/events.jsonl", 300_000).splitlines()]
if [event["status"] for event in events] != ["READY", "AWAITING_APPROVAL", "GRANT_ISSUED"]:
    raise SystemExit("The original owner process did not record a grant")
bundle = strict_json(read_bounded_file(exchange / "human-fresh-bundle.json", MAX_BUNDLE_BYTES), MAX_BUNDLE_BYTES)
if (events[1]["bundle_sha256"] != digest(bundle) or digest(bundle) != approved_bundle
        or events[1]["operation_id"] != operation or events[2]["operation_id"] != operation):
    raise SystemExit("The grant or bundle differs from the independently retained owner review")
request = {"operation_id": operation, "grant": events[2]["grant"], "assessment": bundle["assessment"]}
fd = os.open(private / "request.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as stream:
    stream.write(canonical_json(request) + b"\n")
    stream.flush()
    os.fsync(stream.fileno())
print(digest(request))
PY
```

Use the printed hash as `request_sha256`. Interpret the JSON reply.
A `DENIED` result has a reason. A missing reply or `AMBIGUOUS` result
requires recovery under the same operation ID.

```bash
python scripts/wt_alibi_human_lab.py submit "${lab[@]}" --operation-id "$operation_id" \
  --request "$run_private/request.json" --request-sha256 "$request_sha256" \
  > "$run_private/submit.json"

python scripts/wt_alibi_human_lab.py status "${lab[@]}" --operation-id "$operation_id" \
  > "$run_private/status.json"

python scripts/wt_alibi_human_lab.py observe "${lab[@]}" > "$run_private/after.json"
```

For `STATUS` with `COMMITTED`, retain the stored signed receipt from
`result.operation.receipt` and compare `result.operation.request_sha256`
with the frozen request digest. A `PREPARED` operation allows an explicit
retry of the same frozen request while its grant is valid. A committed
retry must return the same receipt with `ALREADY_COMMITTED`. A continuing
ambiguity leaves the original operation as the recovery subject.

The observer constructs `audit-pins.json` from their independently retained
request ID, operation ID, READY digest, owner-reviewed bundle digest and observation
digests. These fields use canonical JSON SHA-256 as defined by
`shirudo_adapter.model.digest`.

```json
{
  "schema": "wolfalibi.shirudo.effect-review-pins.v1",
  "request_id": "<staged request ID>",
  "operation_id": "<original owner-reviewed operation ID>",
  "ready_sha256": "<independently observed original READY digest>",
  "bundle_sha256": "<original owner-reviewed bundle digest>",
  "before_sha256": "<independently observed initial journal digest>",
  "after_sha256": "<independently observed final journal digest>"
}
```

The independent reviewer works from an approved read-only evidence copy in
their own protected directory. Obtain `approved_pins_sha256` and
`audit_pins_sha256` through the observer's separate custody. Include the
signed receipt as `receipt.json` and the original raw evidence as
`evidence.json`. The verifier accepts only public records.

```bash
python scripts/wt_alibi_human_verify.py \
  --pins "$review_dir/pins.json" --pins-sha256 "$approved_pins_sha256" \
  --audit-pins "$review_dir/audit-pins.json" --audit-pins-sha256 "$audit_pins_sha256" \
  --intent "$review_dir/intent.json" --profile "$review_dir/profile.json" \
  --ready "$review_dir/ready.json" --bundle "$review_dir/bundle.json" \
  --evidence "$review_dir/evidence.json" --request "$review_dir/request.json" \
  --receipt "$review_dir/receipt.json" --before "$review_dir/before.json" --after "$review_dir/after.json"
```

Retain the signed public records, original verifier stdout, oracle views,
source and binary hashes, status replies and cleanup evidence. Keep the
owner's terminal log and role state in private custody. Human presence is
observed separately by the person conducting the ceremony. Keep the
recorded status `NOT_RUN` until such a session has actually occurred.
Use the same VM and host cleanup commands after any outcome.

## Assurance

The admission, freshness, skew and minimum remaining lifetime bounds are
5 seconds, 30 seconds, 2 seconds and 2 seconds respectively. The coordinator
also respects the original 25-second owner bundle wait. Root, the VM
builder, the hypervisor, the software TPM, clocks, process lineage and the
owner's terminal stay in the trust base. The process tests cover SQLite
recovery under gate or client interruption. The lab establishes no hardware
identity, continuous measurement, production readiness, or power-loss
durability. [Owner ceremony and custody](shirudo/OWNER_APPROVAL.md)
