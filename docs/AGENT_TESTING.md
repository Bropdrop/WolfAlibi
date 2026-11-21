# Bring your own agent — plug-and-play observation (experimental)

**This is not a sandbox or a cryptographic non-access proof.** The Stage 3.5 execution and broker receipt machinery is separate. This opt-in module only counts calls to functions **you deliberately wrap**. Any unwrapped tools, subprocess calls, direct I/O, network access or side channels remain outside its coverage.

## What an engineer can do today

Run a no-key, no-network demo from the WolfAlibi repository root:

```bash
python3 -m wolfalibi.agent_probe demo --output /tmp/wolfalibi-agent-observation.json
```

Or instrument one tool in an existing authorized Python agent:

```python
from wolfalibi.agent_probe import AgentProbe

# tool is the real callback already registered with your own agent.
with AgentProbe(consent=True, agent_type="custom") as probe:
    observed_tool = probe.wrap(tool, surface="tool", operation="invoke")
    # Register observed_tool with your agent's tool registry.
    # Run a test that you and any affected users have authorized.
    result = my_agent.run(tool=observed_tool)

probe.export_summary("agent-observation-summary.json")
```

The wrapper supports synchronous and async Python callbacks, preserves return values, and rethrows exceptions unchanged. It **never records** arguments, tool outputs, prompts, responses, file paths, API keys, or exception messages. Reports contain only coarse event-category/outcome counts and latency buckets. An exhausted or closed probe refuses instrumented calls rather than silently continuing without observation.

For a runnable synthetic example:

```bash
python3 examples/bring_your_agent.py
python3 -m unittest -v test_agent_probe.py
```

No connector credentials or API access are needed for these synthetic demos. To test a real agent, the operator must supply that agent and control which callbacks are wrapped. This SDK does **not** automatically discover, install, control or audit third-party agents.

## What we can learn, voluntarily

Aggregate failure rates, permission denials, timeouts, operation categories, rough latency distributions, and where agent integration breaks. This is **observational data**, not proof of complete mediation or non-access.

The local summary is created only after explicit code-level operator consent. It is written to a new mode-0600 file and never uploaded. There is **no telemetry service** or hidden collection endpoint. Sharing is a distinct, manual action by the report owner. Before publishing or ingesting community reports, obtain an additional explicit opt-in, respect data subject permissions, minimize/linkability of fields, and publish a clear retention/deletion policy. Do not solicit raw prompts, credentials, customer files or private execution traces.

## Trust and completeness limits

- Agent code or wrappers can misreport, bypass the hook, or omit calls.
- A successful wrapper event doesn't prove the underlying effect completed or that data was consumed.
- A missing event does **not** prove the agent did not do it through another path.
- This summary is not signed, attested, independently witnessed, or connected to the broker WAL.
- `complete_wrapped_calls=true` means no **wrapped** call was in flight when the probe closed; it is not a whole-agent lifecycle claim.
- The SDK is local, does not impose security boundaries, and may add measurement overhead or affect execution when its event cap is hit.

## Next engineering steps

1. Framework integration adapters (MCP tool hooks, LangChain callbacks, OpenAI Agents SDK) using up-to-date documented APIs and explicit per-provider controls. These are **not** implemented yet.
2. A structured test manifest describing *declared* tool surfaces, fixtures, expected denials, run scope and expected outputs. User-controlled fixtures only.
3. Signed broker evidence integration for agents genuinely launched inside the qualified execution boundary; observational metrics remain labeled separately from cryptographic receipts.
4. A voluntary, privacy-reviewed aggregate submission workflow with per-run approval, public data schema and independently inspected ingestion; no automatic outbound telemetry.

**Research promise:** make testing easier, not make unsupported security claims look stronger.
