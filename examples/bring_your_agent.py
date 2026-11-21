"""Replace synthetic_search with your own already-authorized agent tool callback.

This demonstrates voluntary wrapping, not automatic agent confinement or a
cryptographic non-access receipt. Nothing is uploaded automatically.
"""
from pathlib import Path
from wolfalibi.agent_probe import AgentProbe


def synthetic_search(query):
    return "synthetic tool response"


def my_agent(search_tool):
    # In a real integration, pass the wrapped callback into your agent's
    # tool registry. The SDK does not inspect the argument or the response.
    return search_tool("synthetic query")


if __name__ == "__main__":
    with AgentProbe(consent=True, agent_type="custom") as probe:
        instrumented_tool = probe.wrap(synthetic_search, surface="network", operation="request")
        assert my_agent(instrumented_tool) == "synthetic tool response"
    target = Path("agent-observation-summary.json")
    probe.export_summary(target)
    print(f"Created {target} (local aggregate only; no network upload)")
