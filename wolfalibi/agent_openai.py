"""Opt-in callback observation for the OpenAI Agents SDK.

The SDK owns tool schemas, errors, model selection and tracing. This adapter
adds aggregate observations at the callback boundary through AgentProbe.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
import inspect
from typing import TYPE_CHECKING, Callable

from .agent_probe import AgentProbe

if TYPE_CHECKING:
    from agents import FunctionTool


OPENAI_AGENTS_VERSION = "0.25.0"


class OpenAIAgentsUnavailable(RuntimeError):
    """The version qualified for this adapter is unavailable."""


def require_openai_agents_version() -> str:
    """Check package metadata before importing the optional SDK."""
    try:
        installed = version("openai-agents")
    except PackageNotFoundError as exc:
        raise OpenAIAgentsUnavailable(
            f"install openai-agents=={OPENAI_AGENTS_VERSION} for this adapter"
        ) from exc
    if installed != OPENAI_AGENTS_VERSION:
        raise OpenAIAgentsUnavailable(
            f"openai-agents=={OPENAI_AGENTS_VERSION} is required, found {installed}"
        )
    return installed


def observed_function_tool(
    probe: AgentProbe,
    callback: Callable,
    *,
    surface: str = "tool",
    operation: str = "invoke",
    **tool_options,
) -> FunctionTool:
    """Create an SDK tool from one explicitly registered Python function.

    Pass SDK options such as `name_override` or `failure_error_function`
    unchanged. A call contributes an observation only if the SDK invokes the
    wrapped callback. SDK validation and error formatting keep their normal
    behavior.
    """
    if not isinstance(probe, AgentProbe):
        raise TypeError("probe must be an opted-in AgentProbe")
    if not (inspect.isfunction(callback) or inspect.ismethod(callback)):
        raise TypeError("register a Python function or bound method as the tool callback")

    require_openai_agents_version()
    from agents import function_tool

    return function_tool(probe.wrap(callback, surface=surface, operation=operation), **tool_options)
