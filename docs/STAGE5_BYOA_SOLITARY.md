# Stage 5 BYOA Solitary callback profile

This local synthetic experiment builds on the Solitary and Clearance drafts
and preserves the Stage 4 baseline at
`ab0f105abb9db412054357ac32d5eda6821b9cb6`. Production confinement and
authorization remain blocked. [Stage 4 PR #18](https://github.com/Bropdrop/WolfAlibi/pull/18) ·
[Solitary PR #21](https://github.com/Bropdrop/WolfAlibi/pull/21) ·
[Clearance PR #23](https://github.com/Bropdrop/WolfAlibi/pull/23)

## Fixed callback inside the measured cell

`solitary-python-callback` runs one fixed synchronous Stage 4
`AgentProbe.wrap` custom hook (`python-callbacks` v1) *inside* the measured
Solitary cell around the broker read of synthetic `protected.txt`.
The supervisor hashes the Python executable and the command-line program that
embeds the fixed worker and probe sources. It also checks namespaces, mounts,
credentials, descriptors and hard and soft limits before release. The profile
uses the existing Solitary mount, environment, descriptor and syscall policy.

After the exact broker acknowledgement, the worker may emit one separately
tagged optional aggregate packet.  It is parsed only as an
`OBSERVATIONAL_ONLY` summary and exported as `observation.json`. Receipt and
Clearance verification use the separate broker and supervisor records. A
missing or invalid aggregate leaves the observation unavailable or rejected.
An unexpected transport frame or incomplete shutdown blocks terminal evidence.

The local run reports these outcomes separately.

| Axis | Result in this profile |
| --- | --- |
| AgentProbe aggregate | `OBSERVATIONAL_ONLY` |
| Broker evidence | `BROKER_ONLY` signed evidence |
| Confinement | `SYNTHETIC_CELL_CANDIDATE` observations, operational status `BLOCKED` |
| Owner authorization | `NOT_REQUESTED` |

The aggregate says only that the declared wrapper observed its one declared
callback.  It does not prove coverage of arbitrary application calls,
resource access, prompts, tools, or agents.

## Local synthetic run

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[agent-all]'

state=$(mktemp -d)
wolfalibi byoa test \
  --manifest examples/byoa_solitary_agent_manifest.json \
  --profile solitary-python-callback \
  --consent --state-dir "$state"
wolfalibi byoa verify \
  --evidence "$state/evidence.json" \
  --expect "$state/expected.json"
```

The state directory receives signed evidence, a separate expectation file and
the observational export. All reports stay local. Verification uses the
supplied expected keys, run, challenge, deadline, policy and retained witness
head. The demo supplies these inputs locally. An independent reviewer needs
custody of their own expectations. An accepted receipt covers the named
broker-mediated interval.

## Deliberately separate clearance demonstration

An optional demonstration uses a different private state directory.

```bash
clearance_state=$(mktemp -d)
wolfalibi byoa clearance demo \
  --profile solitary-python-callback \
  --consent --approve-synthetic-read \
  --state-dir "$clearance_state"
wolfalibi byoa clearance verify \
  --report "$clearance_state/report.json" --expect "$clearance_state/expected.json"
```

It requires a fresh verified broker receipt and an explicit grant signed with
a separate synthetic owner key. A later trusted local fixture may then make
one read of the local stub through Clearance. Omitting
`--approve-synthetic-read` leaves the stub read count at zero. The protected
stub call is distinct from the completed Solitary process. Its historical
report does not establish later-client confinement or independent effect
observation.

## Qualification and boundaries

Run the exact-tree local qualification after the editable install:

```bash
python scripts/qualify_stage5.py
```

The resource controls pair a small anonymous mapping with an oversized
`mmap` refused with `ENOMEM` under `RLIMIT_AS`. Scratch file opens succeed
up to the descriptor limit, where the next open returns `EMFILE`. The worker
also checks the 4,096-byte file-size cap, reports a successful broker and
scratch read, and checks refusals of direct fixture opens, new IPv4 sockets,
fork and exec. Those checks are worker-reported. The supervisor measures the
configured limits, seccomp mode and filter count, and waits for the launcher,
measured worker pidfd and broker channel to close.

CPU and core exhaustion, cgroup-wide accounting, continuous measurement,
arbitrary descendants, alternate access routes, loaded seccomp bytecode, and
externally administered witness custody remain unqualified. MCP, LangChain
and OpenAI Agents SDK retain their Stage 4 observation coverage outside the
cell. The fixed profile accepts one callback and no operator-selected code.
Operational confinement remains `BLOCKED`.
