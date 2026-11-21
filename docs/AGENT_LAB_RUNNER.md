# WolfAlibi Agent Lab — Manifest Runner v0

**Status:** experimental plug-in testing for Python agents *you own or have permission to run*. This is **not** the Stage 3.5 confinement system, not a security sandbox, and not a cryptographic negative-access receipt.

## Start in 30 seconds

From the repository root on the `feat/agent-lab-manifest-runner` branch:

```bash
# Parse the manifest without importing or executing any agent code.
python3 -m wolfalibi.agent_lab \
  --manifest examples/agent_lab_manifest.json --dry-run

# Execute a synthetic agent after explicit opt-in.
python3 -m wolfalibi.agent_lab \
  --manifest examples/agent_lab_manifest.json \
  --consent --allow-local-code \
  --output agent-observation-summary.json

# Reproduce the focused integration tests.
python3 -m unittest -v test_agent_lab.py test_agent_probe.py
```

The JSON report is created locally, mode 0600, and never overwritten. The observer sends no telemetry to WolfAlibi. An error is reported by coarse status only, without serializing tool arguments, results, exception strings or prompts. **Your agent itself may still access the network or your files**, because this runner does not restrict its privileges. Use local synthetic fixtures by default, or run in a separately configured, appropriately reviewed sandbox.

## Connect your own Python agent

Write an importable Python module exposing:

```python
def my_tool(text):
    return text.upper()

def run(tools, fixtures):
    # Re-register your agent's tool callbacks with the wrappers below.
    return tools["my_tool"](fixtures["query"])
```

Then point a local JSON manifest at those functions. The entrypoint receives `tools` (a dictionary of callbacks instrumented by `AgentProbe`) and `fixtures` (a dictionary of operator-provided strings). A tool may also be `async def`, and the entrypoint may return a coroutine. **The agent or operator must actually use the passed wrappers; direct calls and hidden framework tools are not observed.**

A manifest looks like:

```json
{
  "schema": "wolfalibi.agent_lab.manifest.v1",
  "agent_type": "custom",
  "entrypoint": {"module": "my_agent", "callable": "run"},
  "tools": [
    {"alias": "my_tool", "module": "my_agent", "callable": "my_tool",
     "surface": "tool", "operation": "invoke"}
  ],
  "fixtures": {"query": "synthetic hello"}
}
```

Run it only after inspecting the trusted module and explicitly approving local-code execution:

```bash
python3 -m wolfalibi.agent_lab --manifest my_agent_lab.json \
  --consent --allow-local-code --output local-summary.json
```

If integrating with a framework, register the wrapped callbacks into its actual tool registry before invoking the agent. MCP, LangChain and OpenAI Agents SDK specific automatic adapters are **future work**; there is no auto-discovery of installed agents or hidden monitoring.

## Data collected

- Counts of explicitly wrapped call categories and coarse outcomes: success, error, denied, timeout or cancelled.
- Coarse elapsed-time buckets.
- A random local run ID and a local manifest digest (a fingerprint, not plaintext).
- An explicit `OBSERVATIONAL_ONLY` assurance level and `EXPLICITLY_WRAPPED_CALLS_ONLY` coverage marker.

**Never collected by the observer:** prompts, raw arguments, tool return values, private file names, exception messages, credentials, cookies, API response bodies or chat transcripts.

The runner does not export the manifest itself; however, the digest can identify an identical low-entropy manifest if reports are shared. Do not upload reports by default. Any community submission must have separate per-report consent, data minimization, retention controls and privacy review.

## Hard limits

- Loading an authorized module runs its code with the ordinary Python process's OS privileges. `--dry-run` never performs imports, but `--allow-local-code` is **not** a confinement control.
- Only explicitly wrapped calls appear in reports. A clean report cannot prove that other accesses did not occur.
- The wrapper cannot guarantee the underlying tool's side effects or actual external delivery.
- A synchronous callback returning a coroutine or arbitrary awaitable is not yet treated as an async instrumented operation by the SDK; declare it `async def` where possible.
- No timeouts, child process scope, provider authentication management, network blocking, automatic consent verification, or independent trust anchor is supplied by this basic runner.
- No Web UI or hosting. No automatic telemetry upload. The exit status of an agent test is not a production security verdict.

## Qualification

The developer's local isolated harness passed **19/19 new manifest runner tests** for consent, dry-run non-import, JSON schema/duplicate rejection, sync/async callbacks, error redaction, create-only local reporting and execution behavior. A separate dry-run and synthetic two-tool example also completed locally.

The existing Stage 3.5 suite and the Stage 3.5 mutation harness have **not yet been rerun on this published branch**. Qualification of this PR is required before any merge or release. All changes are isolated from the cryptographic engine.

See [Agent SDK](AGENT_TESTING.md) and [Research intelligence model](AGENT_INTELLIGENCE_SPEC.md) for limits and future opt-in aggregation.
