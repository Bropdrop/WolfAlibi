# WolfAlibi Agent Intelligence — research product design

**Status: proposal, not a hosted service.** The first implementation on this branch is `wolfalibi.agent_probe.AgentProbe`, an explicitly enabled *local* observation SDK. No upload, remote collector, SDK credential, or model/framework-specific auto-hook is implemented.

## The engineer experience we are aiming for

1. A developer voluntarily connects the tool callbacks of an agent they are authorized to test.
2. WolfAlibi runs local synthetic policies and captures **only explicitly wrapped** tool-call outcomes and coarse timing buckets.
3. The developer receives a local report alongside any *separately qualified* broker receipts.
4. They inspect a summary and, through a **separate explicit opt-in**, may contribute redacted aggregates to an open benchmark corpus.
5. Researchers compare failure modes and reproducibility, not individual messages, customers or credentials.

No unconsented monitoring, stealth agents, account scraping, unauthorized credential access, or silent reporting. Connecting an agent must not automatically connect its private files, API accounts, chat history, or cloud resources.

## Two distinct evidence planes

| Plane | What it can establish | What it cannot establish |
| --- | --- | --- |
| **AgentProbe observation (implemented)** | Counts/status/latency of callbacks intentionally wrapped by the agent owner | Whether every agent operation was observed; whether a failed tool caused effects; whether the agent never read a resource |
| **WolfAlibi broker receipts (separately implemented)** | Cryptographic evidence about specified events in a witnessed broker journal under the `BROKER_ONLY` trust model | Complete whole-agent confinement, unmonitored tools, or externally independent witness observations |

A public dashboard must never combine them into one green "AI is safe" score.

## Initial normalized observation schema

`wolfalibi.agent_observation.v0` uses:
- Random local run ID; not a customer ID.
- Framework category from a small allowlist, not usernames, account IDs, provider tokens or model prompts.
- Counts of `surface.operation.outcome`, e.g. `tool.invoke.denied`.
- Coarse duration buckets only.
- Explicit `OBSERVATIONAL_ONLY` and `EXPLICITLY_WRAPPED_CALLS_ONLY` fields; `nonaccess_proof=false`.
- Never includes file names, tools' raw arguments, responses, prompts, exception strings, access tokens, complete execution logs, or private source code.

The first SDK holds counters locally and writes an exclusive-create, mode-0600 summary only at the operator's request.

## Future community intelligence pipeline (NOT implemented)

A proposed opt-in ingestion endpoint should require a *separate per-report action*, show the exact sanitized payload before submission, and let contributors retract reports under a public retention policy. Do not build a receiver that silently accepts whole conversation content or secrets.

Before any aggregated public dataset:
- Validate a strict schema and reject unrecognized fields and oversized samples.
- Scrub source-level identifiers including run IDs; never place them on a public dashboard.
- Enforce a minimum cohort size before category-level aggregation and address rare-category reidentification.
- Avoid cross-run linking unless a contributor specifically requests it and the privacy policy covers it.
- Publish clear provenance classes: `SELF_REPORTED`, `HOOK_OBSERVED`, `BROKER_WITNESSED`, `INDEPENDENTLY_ATTESTED` (the last is future work).
- Require authorization and permissions from affected users before collecting traces from shared/customer agents.
- Distinguish voluntary software telemetry from vulnerability reports; responsibly disclose third-party faults without publishing private customer content.
- Protect ingestion from forged benchmarks, duplicated submissions, replay, poisoned corpora, malicious payloads and reputational abuse.
- Keep uploaded evidence under contributor-specified retention and deletion rules.

## High-value experiments for real agents

- How often does a tool attempt a denied operation?
- Does an agent properly handle an unavailable tool or a timeout?
- Does it retry requests without changing authorization or target?
- Does it continue operating after a trust-boundary refusal?
- Can an agent demonstrate a run-bound, verifier-controlled challenge with a broker-only receipt?
- How much unsupported/blocked evidence is correctly refused rather than incorrectly labeled safe?
- Under an explicitly qualified synthetic environment, which tool/framework adapter produces the most reproducible evidence?

## Roadmap to genuinely plug-and-play

**A.** Framework adapters for the current OpenAI Agents SDK, LangChain and MCP documented callback surfaces, with host-only synthetic fixtures and explicit permissions. Validate API versions against authoritative documentation before implementation.

**B.** A local `agent test` CLI that loads a manifest describing an authorized Python entrypoint, tool bindings, synthetic fixtures, expected observations and explicit operator consent. The harness loads operator-supplied local modules and forwards only explicitly selected credential variables. Those modules retain their ordinary OS and network permissions.

**C.** An experimental worker bridge to the Stage 3.5 broker that permits a narrow, declared resource set under a measured Linux execution profile. Never promote coverage to complete because a framework callback fired.

**D.** A separately opted-in, privacy-reviewed data-sharing flow for aggregated community research. First ship local exports; only then consider any hosted collection with a consent, governance and deletion design.

## Acceptance gates

- Tool wrapper does not alter return values or swallow exceptions; supports sync/async callbacks.
- No data collection when consent is absent.
- No sensitive payload capture even if tool arguments, output or exceptions contain fabricated secrets.
- The harness sends no telemetry or reports. Provider and network activity of authorized agent code follows the operator's own configuration.
- Thread-safe bounded aggregate counters with close/in-flight handling.
- Reports clearly labeled observational rather than security proof.
- Unknown external frameworks or missing hooks do not receive misleading coverage claims.
- Integration tests use synthetic data with no provider keys or external accounts.

**Value proposition:** let engineers voluntarily bring a real agent into a repeatable research workflow, learn from failures, and get precisely scoped evidence. Hard security claims belong to the separately qualified confinement and witnessing stack.
