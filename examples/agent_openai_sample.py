"""Run an Agents SDK tool round trip with a scripted local model."""

from __future__ import annotations

import argparse
import asyncio
import json

from agents import Agent, Model, ModelResponse, ModelTracing, RunConfig, Runner, Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from wolfalibi.agent_openai import observed_function_tool
from wolfalibi.agent_probe import AgentProbe


class LocalFixtureModel(Model):
    """Emit one synthetic tool call and validate its output on the next turn."""

    def __init__(self, tool_name, arguments, expected_output):
        self.tool_name = tool_name
        self.arguments = arguments
        self.expected_output = expected_output
        self.turn = 0

    async def get_response(self, system_instructions, input, model_settings, tools,
                           output_schema, handoffs, tracing, *, previous_response_id,
                           conversation_id, prompt):
        if tracing is not ModelTracing.DISABLED:
            raise AssertionError("the local fixture requires tracing_disabled=True")
        self.turn += 1
        if self.turn == 1:
            if self.tool_name not in {tool.name for tool in tools}:
                raise AssertionError("the requested tool was not registered")
            item = ResponseFunctionToolCall(
                type="function_call", name=self.tool_name,
                call_id="synthetic-call", arguments=json.dumps(self.arguments),
            )
        elif self.turn == 2:
            if not isinstance(input, list) or not any(
                item.get("type") == "function_call_output"
                and item.get("call_id") == "synthetic-call"
                and item.get("output") == self.expected_output
                for item in input
            ):
                raise AssertionError("the SDK did not return the expected synthetic tool output")
            item = ResponseOutputMessage(
                type="message", id="synthetic-message", role="assistant", status="completed",
                content=[ResponseOutputText(
                    type="output_text", text="Local fixture complete", annotations=[],
                )],
            )
        else:
            raise AssertionError("unexpected additional model turn")
        return ModelResponse(output=[item], usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):
        raise AssertionError("this fixture uses the non-streaming Runner")


def lookup(value: str) -> str:
    """Return a synthetic tool result."""
    return f"fixture:{value}"


async def run(tools, fixtures):
    """Run the V2 manifest's registered tool against its synthetic fixture."""
    tool = tools["lookup"]
    value = fixtures["query"]
    model = LocalFixtureModel(tool.name, {"value": value}, f"fixture:{value}")
    result = await Runner.run(
        Agent(name="Synthetic fixture", model=model, tools=[tool]),
        "Run the synthetic fixture", max_turns=2,
        run_config=RunConfig(tracing_disabled=True),
    )
    if result.final_output != "Local fixture complete":
        raise AssertionError("unexpected final result")


async def run_demo(output):
    with AgentProbe(consent=True, agent_type="openai-agents") as probe:
        await run({"lookup": observed_function_tool(probe, lookup)}, {"query": "hello"})
    probe.export_summary(output)
    return probe.summary()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new local aggregate report path")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run_demo(args.output)), sort_keys=True))
