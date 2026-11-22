# Qualify a reviewed local Python agent

Quorvane BYOA 001 runs one operator-selected Python decision function against a fictional protected fixture. The target checks a resource-owner grant and a live measured worker. A reviewer can later check the owner, target, broker, supervisor and witness signatures using public inputs they retained before execution.

The sample agent reads a fictional observation through its declared callback and returns a decision. Its decision logic is deterministic. Optional LangChain orchestration uses a real installed framework and a local scripted model. The framework process runs outside the measured cell. The protected trial covers the approved decision package running inside it. No provider, remote model, real payment or outside account is involved.

## Run the example

Start in the WolfAlibi checkout, with Python 3.11+ and the repository's pinned cryptography dependency already installed. The protected trial needs Linux x86-64, working unprivileged Bubblewrap user/PID/network/IPC/UTS namespaces, the supported system Python and runtime mounts, libseccomp, openat2, pidfds, and access to the child's proc records. The full suite additionally uses the installed Agent Lab extras. Qualification installs nothing. Use a short local directory path for Linux socket fixtures.

The following Bash sequence uses the installed `wolfalibi` command. From a checkout you can use `python wolfalibi_cli.py` in its place. The example deliberately emulates all roles locally. On an actual review, distribute public pins through a separately authenticated channel and keep the verifier's expectations and the owner's key under their respective operators' control.

```bash
set -e
umask 077
work=$(mktemp -d)
manifest=examples/qualification001/agent.json
wolfalibi byoa doctor

wolfalibi byoa provision --role trial --output "$work/trial"
wolfalibi byoa provision --role owner --output "$work/owner"
wolfalibi byoa enroll-owner --trial "$work/trial" \
  --owner-pin "$work/owner/public.json" --approve-owner

wolfalibi byoa prepare --manifest "$manifest" --trial-pins "$work/trial/public.json" \
  --owner-pin "$work/owner/public.json" --output "$work/reviewer"
cp "$work/reviewer/expected.json" "$work/retained-public-inputs.json"
wolfalibi byoa grant-read --owner "$work/owner" --expect "$work/retained-public-inputs.json" \
  --approve-read --output "$work/read-grant.json"

wolfalibi byoa qualify --manifest "$manifest" --trial "$work/trial" --review "$work/reviewer" \
  --grant "$work/read-grant.json" --consent --output "$work/result"
wolfalibi byoa verify-qualification --expect "$work/retained-public-inputs.json" \
  --report "$work/result/report.json"
```

To exercise the **linked LangChain runner**, add `--framework langchain` to the single `qualify` invocation above. It needs the already installed versions `langchain==1.5.2` and `langchain-core==1.8.4`. Use a fresh set of role, review and output directories for each run. A second invocation against a spent trial must fail. The outer tool observation and the inner signed historic trial carry different scopes. The inherited OpenAI Agents SDK and MCP adapters remain available through the separate Stage 4 `agent test` interface. Only use that host interface with known, reviewed code.

`prepare` accepts an independently chosen `--run-id`, a 32-byte lowercase hex `--challenge` and a `--ttl` in seconds (1–300, default 180). By default it generates a new random run ID and challenge. It validates the package with no submission imports, pins the launch contract and issues the challenge. The target administrator explicitly enrolls the owner and the other roles once. Only the owner signs the single-read grant. `--consent` authorizes execution of this reviewed local package and must be supplied for every launch.

For independent historical review, transfer just the signed report and the previously retained public inputs through separate agreed channels. Keep all `.seed` files, runtime directories and verifier databases private. The verifier takes no signing keys. Its result concerns authority at the recorded time. The selected public keys, time source and witness head still need an independent basis of trust.

## Supply your own decision package

Copy the example directory to an operator-controlled local path. Use a lowercase package name, a zero-byte `__init__.py` and one ASCII `agent.py` file (at most 4 KiB). Specify `<package>.agent:run`. No other package files or namespace portions are accepted. The single synchronous function `run(tools)` can assign local values, compare values with equality or inequality, and branch with `if`. It has one statically declared `tools["read_fixture"]()` call site. A successful run must execute that callback once and return true or the exact fixture bytes. Imports, general attribute access, plugins, model weights and additional dependencies are outside this profile.

Update the `files` hashes in your manifest after reviewing the source. For example, `sha256sum review_agent/agent.py review_agent/__init__.py` from the copied example prints the input hashes. Keep the published dependency, tool declaration, policy and profile values. New source requires a new approval. The launcher captures the checked bytes and embeds them in the measured program. It does not search the operator's import path for code to run. [Strict manifest schema](schemas/byoa-qualification-manifest-v1.json) · [Example manifest](../examples/qualification001/agent.json)

## Read the evidence

| Question | Record and scope |
| --- | --- |
| What was approved? | The pre-run expectations identify the package, both source files, entrypoint, declared dependency, launch profile, exact read, five role keys and initial witness digest. The owner signature covers those expectations, the run and the grant window. |
| What was measured? | The supervisor samples the live child executable and measured command, namespaces, mounts, credentials, environment keys, descriptors, resource limits and filter state. It retains a pidfd through closure. The exact syscall-denial probes are trusted-bootstrap observations. |
| Who obtained the data? | The trusted bootstrap requested the fixture before loading the selected entrypoint. The target recorded admission after checking the live identity and started witness head. The broker recorded its read before replying. The agent subsequently read the returned bytes in memory through the instrumented callback. |
| What did the agent report? | The Stage 4 wrapper counted the selected callback. The signed report preserves its observational status and ties it to this run. The callback count alone cannot establish a protected effect. |
| What financial outcome occurred? | The cell has no finance credential or enrollment. A separate Gate 003 fixture tests the financial target. Its successful synthetic outcome is a pending intent. Settlement remains unestablished. |

## Revocation and interrupted runs

Before admission, the target administrator can run `wolfalibi byoa revoke-read --trial "$work/trial" --expect "$work/retained-public-inputs.json" --grant "$work/read-grant.json"`. After admission, the target holds a lease through the release sequence. A later revocation cannot undo bytes that have already been delivered.

To inspect an ambiguous run, use the read-only decision path:

```bash
wolfalibi byoa recover-read --trial "$work/trial" \
  --expect "$work/retained-public-inputs.json" --grant "$work/read-grant.json"
```

Recovery returns the original signed **admission** when the ledger and retained checkpoint agree. It does not attest delivery or retry the read. A missing admission or contradictory checkpoint blocks recovery. An interrupted run can have a durable admission or a broker WAL entry while lacking a terminal signed report. The launch attempt is reserved before execution. A fresh execution requires fresh approval. Keep the original directories to investigate interruptions.

## Reproduce qualification

Use a clean checkout of the exact draft revision and the pinned test dependencies. Obtain its expected Git IDs independently. Only the repository's reviewed examples are used in the consented harness.

```sh
python -I scripts/qualify_byoa001.py --expect-commit "$EXPECTED_COMMIT" \
  --expect-tree "$EXPECTED_TREE" --consent > ../byoa-qualification.json
```

The JSON records raw command outcomes, test and skip counts, mutations, platform details, the public trial and negative controls. Operational confinement and production remain blocked. Cross-UID custody is unsupported in this single-account experiment and certification is not issued. Do not load an unknown third-party submission on an ordinary development host. [Trust boundary](QUORVANE_BYOA_BOUNDARY.md) · [Independent qualification gaps](QUORVANE_BYOA_GAPS.md) · [Qualification controls](QUORVANE_BYOA_CONTROLS.md)
