"""Opt-in observation of explicitly registered LangChain tool callbacks."""

from importlib.metadata import PackageNotFoundError, version
import inspect

from .agent_probe import AgentProbe


SUPPORTED_VERSIONS = {"langchain": "1.5.2", "langchain-core": "1.8.4"}


class LangChainUnsupported(RuntimeError):
    """The local LangChain installation falls outside the qualified API."""

    outcome = "UNSUPPORTED"


def langchain_status() -> dict:
    """Report whether the optional packages match the qualified versions."""
    installed = {}
    for package in SUPPORTED_VERSIONS:
        try:
            installed[package] = version(package)
        except PackageNotFoundError:
            installed[package] = None
    return {
        "outcome": "SUPPORTED" if installed == SUPPORTED_VERSIONS else "UNSUPPORTED",
        "installed": installed,
        "qualified": dict(SUPPORTED_VERSIONS),
    }


def langchain_tool(
    probe: AgentProbe,
    *,
    func=None,
    coroutine=None,
    surface: str = "tool",
    operation: str = "invoke",
    **tool_options,
):
    """Build a StructuredTool with explicitly observed sync and async callbacks.

    Tool options are passed through to the public StructuredTool builder.
    LangChain applies its own input validation, error policy and result
    formatting. The probe counts entries into the registered callbacks.
    """
    if not isinstance(probe, AgentProbe):
        raise TypeError("an explicitly opted-in AgentProbe is required")
    status = langchain_status()
    if status["outcome"] != "SUPPORTED":
        pins = ", ".join(f"{package}=={expected}"
                         for package, expected in status["qualified"].items())
        raise LangChainUnsupported(f"qualified versions are {pins}")
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:
        raise LangChainUnsupported("qualified tool dependencies are unavailable") from exc

    if func is not None and (not callable(func) or inspect.iscoroutinefunction(func)):
        raise TypeError("func must be a synchronous callback")
    if coroutine is not None and not inspect.iscoroutinefunction(coroutine):
        raise TypeError("coroutine must be declared with async def")
    if func is not None and (inspect.isgeneratorfunction(func) or inspect.isasyncgenfunction(func)):
        raise TypeError("streaming generator callbacks are unsupported")

    # Build the schema from the original functions and annotations. LangChain
    # continues to own tool metadata, validation and callback dispatch.
    tool = StructuredTool.from_function(func=func, coroutine=coroutine, **tool_options)
    if func is not None:
        tool.func = probe.wrap(func, surface=surface, operation=operation)
    if coroutine is not None:
        tool.coroutine = probe.wrap(coroutine, surface=surface, operation=operation)
    return tool
