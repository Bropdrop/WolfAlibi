# BYOA Solitary V1 candidate profile

Solitary runs a fixed synthetic Python worker and a single declared broker read of `protected.txt`. The launcher uses Bubblewrap and the pinned system Python runtime. The worker enters a default-deny seccomp policy before sending its request. A supervisor samples the live process before releasing the broker data and retains a pidfd through shutdown. This is a candidate for independent qualification. The receipt assurance is `BROKER_ONLY` and general confinement is `BLOCKED`. [Issue #15](https://github.com/Bropdrop/WolfAlibi/issues/15) · [Design in draft PR #16](https://github.com/Bropdrop/WolfAlibi/pull/16)

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[agent-all]'
wolfalibi byoa doctor
wolfalibi byoa inspect --manifest examples/byoa_solitary_manifest.json
state=$(mktemp -d)
wolfalibi byoa test --manifest examples/byoa_solitary_manifest.json --profile solitary-synthetic --consent --state-dir "$state"
wolfalibi byoa verify --evidence "$state/evidence.json" --expect "$state/expected.json"
```

The doctor exercises local kernel and launcher prerequisites. Missing mandatory prerequisites give `UNSUPPORTED` or `BLOCKED`. A successful doctor reports capability readiness, not receipt or isolation qualification. The cgroup status is informational. The live worker requires Linux x86_64, a usable Bubblewrap namespace setup, the system Python layout, libseccomp, pidfds, `openat2`, and supervisor access to the child proc records.

The inspect command parses the fixed manifest without loading agent code. The test command requires explicit consent and a private state directory. The built-in worker takes no Python entrypoint or provider credentials. The demo records the expected contract, three public keys, fresh challenge, witness genesis digest and verifier time in `expected.json` before launch, then exports the signed transcript separately. An independent verifier must approve and retain those references, including the full worker, launcher and runtime mount profile in the contract. Offline verification checks signatures against the supplied time and returns historical verification. The verifier database is the fresh-acceptance path and consumes each challenge at most once in that store.

## Control pairs

The worker runs the paired synthetic operations before requesting data. Its results are worker self-reports within the signed envelope. The supervisor independently samples process identity, executable bytes and arguments, mounts, credentials, namespace IDs, descriptor inventory, the exec environment keys and effective resource limits. The kernel reports an additional seccomp filter relative to the launcher. The snapshot does not recover the filter bytes.

| Scoped control | Allowed operation | Blocked operation or gate |
| --- | --- | --- |
| Protected fixture and scratch | Small scratch write/read succeeds and the broker returns the exact fixture | The fixture is unavailable to direct read and write-only opens, which must return `ENOENT`, `EACCES` or `EPERM`. The write probe creates and truncates nothing. The inherited fixture canary FD is absent. |
| Communications | The inherited Unix broker endpoint completes one bounded, challenge-bound read/ack round trip | Creation of a new IPv4 socket is denied. Synthetic malformed or unauthorized broker requests produce no release or successful seal. |
| Process lifecycle | The trusted launcher starts one fixed program, which exits through the expected broker and pidfd closure | Worker fork and subsequent exec return denial. Missing launcher exit, peer closure or pidfd exit blocks terminal evidence. |
| File-size limit | A small scratch file is written and read | A larger scratch write reaches the 4,096-byte cap and the next byte fails. This is the exercised size limit. |
| Environment | The worker has the expected `PWD` | The synthetic ambient canary is absent and unexpected sampled exec environment keys block at the read gate. |
| Replay and expectations | The composite signed envelope is accepted under separately pinned expectations | Reused challenge, changed expected scope or key, unsigned changes and incomplete evidence fail the applicable gate. |

CPU, address-space, core and descriptor limits are configured and sampled. The suite does not qualify exhaustion behavior for those limits. A six-second deadline bounds the supervisor's socket and launcher waits. It does not bound trusted host disk operations.

The fixed broker accepts one read request with the exact key, sequence and challenge. The WAL is durable before release. Killing the worker after that write and before the reply leaves a recoverable unsealed read and no terminal envelope. Requests outside the exact grammar stop the run without a terminal envelope. The transcript is not an exhaustive log of rejected requests or supervisor operations. The trusted supervisor itself opens the synthetic fixture for the FD canary and reads it for layout verification.

## Inspect the evidence

The verifier checks the fixture and declared policy against its expected contract. It checks the broker and witness transcript, supervisor signature, measured limits, kernel snapshot, worker self-report and recorded closure. The seccomp observations cover mode and filter count. Equivalence of the loaded filter to the declared rules depends on the trusted worker bootstrap. The supervisor signs after completion. Sequence and timing depend on the trusted supervisor control flow. Receipt generation waits for the launcher to exit, the measured pidfd to become readable, and the endpoint to close after a single acknowledged response. There is no delegated cgroup-wide process or memory accounting. The host's kernel, launcher, runtime, broker, witness and supervisor are in the trusted boundary.

```bash
python -m unittest -v test_byoa_solitary.py
python -m unittest discover -v
python -u mutation_test.py
python scripts/qualify_solitary.py > /tmp/solitary-qualification.json
```

The report captures exact commit and tree, the environment, commands and raw test results, capability preflight, separate expectations, the signed synthetic envelope, verification output and fixture/policy digests in the contract. The eight inherited mutations exercise the core `alibi.py` broker and proof code. Solitary control coverage comes from the focused integration suite. A dirty or changing revision, skipped required test, missing preflight control, or failed demonstration blocks qualification.

## Unqualified surfaces

- This profile is tied to the included worker. General descendant tracking, subprocesses before the gate, externally witnessed timing, untested alias and alternate-resource routes, and tests through a real network endpoint require separate qualification. A distinct network namespace and a denied local socket creation are the measured and exercised facts here.
- The demo keeps all keys and stores under one host operator. Multirun witness histories and cross-verifier fork detection require separately controlled retention and review.
- For arbitrary third-party agents, evaluate a minimal KVM microVM with a pinned guest image, no virtual NIC, an explicit vsock broker endpoint and no host filesystem sharing. A microVM places a separate guest kernel between agent and host, while adding a hypervisor, guest runtime and virtual device trust boundary. Validate device isolation, boot identity, resource quotas and teardown on a dedicated host before adopting it. No microVM profile is qualified here.
- `wolfalibi agent test` still provides separate, consented `OBSERVATIONAL_ONLY` reports. Solitary creates no observational export and neither path uploads reports.
