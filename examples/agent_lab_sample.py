"""A small synthetic agent and two tools; replace with your own authorized code."""


def lookup(value):
    return "synthetic:" + value


def denied(value):
    raise PermissionError("synthetic refusal: no real data was accessed")


def run(tools, fixtures):
    assert tools["lookup"](fixtures["query"]) == "synthetic:hello"
    try:
        tools["denied"](fixtures["query"])
    except PermissionError:
        pass
