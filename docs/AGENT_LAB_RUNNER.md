# WolfAlibi Agent Lab

Agent Lab runs operator-approved Python entrypoints with observed tool bindings and creates a local JSON report. Use it with your own agents or agents you have explicit authorization to run. The report's assurance is `OBSERVATIONAL_ONLY`.

## Run one local test

Run from a repository checkout with Python 3.11 or newer. Install only the base project for custom agents, or use the pinned `agent-all` extra for all example manifests.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[agent-all]'
wolfalibi agent test --manifest examples/agent_lab_manifest.json --dry-run
wolfalibi agent test --manifest examples/agent_lab_manifest.json \
  --consent --allow-local-code --output /tmp/custom.agent-observation.json
```

Dry runs validate configuration without importing the manifest's modules. Every execution requires both consent flags. Every report uses create-only local file creation with permissions at most `0600`. Omitting `--output` uses `<manifest-stem>.agent-observation.json` in the current directory.

The installed command starts a separate worker with a reduced environment. It forwards provider credentials only when named with `--credential-env NAME`, after both run consent flags are supplied. The bundled framework examples use local fake models or in-memory MCP. They require no provider credentials. SDK tracing is disabled by default in the worker environment. Trusted code can change its runtime configuration and retains ordinary OS and network permissions.

## Attach an agent

The module's `run(tools, fixtures)` entrypoint receives a mapping of explicit bindings. Register and use the bindings in your agent. Direct calls, SDK operations outside those callbacks, and framework tools registered elsewhere fall outside the observation scope.

| V2 `agent_type` | Binding and exact qualified SDK | Synthetic manifest |
| --- | --- | --- |
| `custom` | Python callback wrapped by AgentProbe | [Custom Python](../examples/agent_lab_manifest.json) |
| `mcp` | Wrapped callback for `MCPServer.add_tool` in `mcp==2.3.0`. The programmatic adapter can also wrap a supplied `Client` or `ClientSession.call_tool`. Select one observation point to avoid counting the same operation on both sides. | [MCP](../examples/agent_mcp_manifest.json) |
| `langchain` | `StructuredTool` through `langchain==1.5.2` and `langchain-core==1.8.4` | [LangChain](../examples/agent_langchain_manifest.json) |
| `openai-agents` | `FunctionTool` through `openai-agents==0.25.0` | [OpenAI Agents](../examples/agent_openai_manifest.json) |

Use the individual extras `.[mcp]`, `.[langchain]` or `.[openai-agents]` if you only need one SDK. Missing or different pins return `UNSUPPORTED` for an applicable V2 manifest. V1 manifests retain their Python-callback behavior. Their `agent_type` is a label.

V2 optionally accepts `limits.max_calls`, a cooperative `limits.agent_timeout_ms`, a per-tool `timeout_ms` for awaitable tools, and `expect_counts` with exact expected observations keyed by `surface.operation.outcome`. A timed tool is exposed as an async callback. Use `async def` for framework tools that await work. Blocking synchronous Python and tasks that suppress cancellation depend on the installed command's `--process-timeout`; child-process termination has limited scope. The run reports unfinished work or interruption explicitly.

Framework schema rejection before dispatch produces zero callback events. Retried or duplicate admissions produce separate events. `complete_wrapped_calls` refers to the admitted callbacks. A timed-out or incomplete run also carries a coarse `outcome`. Manual SDK events are labeled separately.

The API references cover the exact entrypoints exercised by the tests. [MCP v2.3.0 and migration](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.3.0) · [LangChain StructuredTool 1.8.4](https://github.com/langchain-ai/langchain/blob/langchain-core%3D%3D1.8.4/libs/core/langchain_core/tools/structured.py) · [OpenAI Agents SDK v0.25.0](https://github.com/openai/openai-agents-python/tree/v0.25.0)

## Reports and consent

The observation file contains aggregate counts and coarse duration buckets, adapter and outcome labels, and a local run identifier. The observer does not store prompts, callback inputs or outputs, credential values, resource names, or exception strings. An installed-command worker suppresses normal Python console writes during the run. Code and libraries still control their own file, descriptor, provider, and logging behavior.

Add `--research-consent --research-output /tmp/agent-research.json` to create a separate local aggregate for review. It omits the run ID, manifest digest, paths, aliases, and configuration. Its schema and bucket definitions support interpretation of results. It is unsigned and replayable and can still contain distinctive count patterns. Sharing requires separate consent and review.

**Evidence boundary.** Agent Lab observes callback lifecycles. Its reports cannot establish absence of access or receipt freshness. Stage 3.5's signed broker receipts carry the distinct `BROKER_ONLY` assurance. Independently qualified confinement and production operation remain `BLOCKED`. [Stage 3.5 evidence](STAGE35_EVIDENCE.md) · [Research privacy model](AGENT_INTELLIGENCE_SPEC.md)

## Qualification commands

```bash
python -m unittest discover -v
python -m unittest -v test_agent_probe.py test_agent_probe_stage4.py \
  test_agent_lab.py test_agent_lab_stage4.py test_agent_research.py \
  test_agent_mcp.py test_agent_langchain.py test_agent_openai.py
python -u mutation_test.py
```
