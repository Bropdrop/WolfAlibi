"""Local LangChain manifest fixture with a scripted model and synthetic lookup."""


def lookup(value: str) -> str:
    """Look up a synthetic value."""
    return "synthetic:" + value


def run(tools, fixtures):
    """Register the supplied StructuredTool with a local scripted agent."""
    tool = tools["lookup"]

    from langchain.agents import create_agent
    from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
    from langchain_core.messages import AIMessage, ToolMessage
    from langsmith import tracing_context

    class LocalToolCallingModel(FakeMessagesListChatModel):
        def bind_tools(self, tools, *, tool_choice=None, **kwargs):
            return self

    model = LocalToolCallingModel(responses=[
        AIMessage(content="", tool_calls=[{
            "name": tool.name, "args": {"value": fixtures["query"]}, "id": "sample-1",
        }]),
        AIMessage(content="Synthetic task complete"),
    ])
    with tracing_context(enabled=False):
        agent = create_agent(model, tools=[tool])
        result = agent.invoke({"messages": [{"role": "user", "content": "Synthetic task"}]})
    responses = [message for message in result["messages"] if isinstance(message, ToolMessage)]
    assert [message.content for message in responses] == ["synthetic:" + fixtures["query"]]
    return result
