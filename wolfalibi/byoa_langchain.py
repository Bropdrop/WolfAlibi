"""Let one observed, offline LangChain tool request a separately measured local trial."""

import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wolfalibi.agent_langchain import SUPPORTED_VERSIONS
from wolfalibi.solitary_cli import _read, _write_new


def _sdk_worker(channel):
    from wolfalibi.agent_langchain import langchain_status, langchain_tool
    from wolfalibi.agent_probe import AgentProbe

    if langchain_status()["outcome"] != "SUPPORTED":
        channel.sendall(b"unsupported")
        return
    try:
        from langchain.agents import create_agent
        from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
        from langchain_core.messages import AIMessage, ToolMessage
        from langsmith import tracing_context
    except ImportError:
        channel.sendall(b"unsupported")
        return

    class LocalModel(FakeMessagesListChatModel):
        def bind_tools(self, tools, *, tool_choice=None, **kwargs):
            return self

    def request_trial() -> str:
        """Request the one locally approved qualification."""
        channel.sendall(b"invoke")
        reply = channel.recv(32)
        if reply not in (b"completed", b"refused"):
            raise ValueError("unexpected trial reply")
        return reply.decode("ascii")

    with AgentProbe(consent=True, agent_type="langchain", max_calls=1) as probe:
        tool = langchain_tool(probe, func=request_trial)
        model = LocalModel(responses=[
            AIMessage(content="", tool_calls=[{"name": tool.name, "args": {}, "id": "fixture"}]),
            AIMessage(content="Review complete"),
        ])
        with tracing_context(enabled=False):
            agent = create_agent(model, tools=[tool])
            run = agent.invoke({"messages": [{"role": "user", "content": "Review the local fixture"}]})
        replies = [msg.content for msg in run["messages"] if isinstance(msg, ToolMessage)]
        if replies not in (["completed"], ["refused"]):
            raise ValueError("framework did not receive one tool result")
    channel.sendall(json.dumps(probe.summary(), sort_keys=True).encode("utf-8"))


def _observe(callback):
    """Only the supervisor holds the callback, operator arguments and signing-role references."""
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with parent, child, TemporaryDirectory(prefix="quorvane-lc-") as scratch:
        environment = {"PATH": "/usr/bin:/bin", "HOME": scratch, "LANGSMITH_TRACING": "false",
                       "LANGCHAIN_TRACING_V2": "false", "OTEL_SDK_DISABLED": "true"}
        proc = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve())],
                                cwd=scratch, env=environment, close_fds=True, stdin=child,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child.close()
        parent.settimeout(30)
        try:
            first = parent.recv(32)
            if first == b"unsupported":
                return {"outcome": "UNSUPPORTED", "reason": "pinned LangChain runner unavailable",
                        "agent_started": False}, None
            if first != b"invoke":
                raise ValueError("framework did not request the single approved trial")
            result = callback()
            parent.sendall(b"completed" if result.get("outcome") == "COMPLETED" else b"refused")
            frame, ancillary, flags, _ = parent.recvmsg(4096)
            if not frame or ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                raise ValueError("framework summary incomplete")
            summary = json.loads(frame)
            if (proc.wait(timeout=15) != 0 or parent.recv(1) != b"" or not isinstance(summary, dict)
                    or summary.get("counts") != {"tool.invoke.success": 1} or summary.get("events") != 1
                    or summary.get("agent_type") != "langchain" or summary.get("assurance") != "OBSERVATIONAL_ONLY"
                    or summary.get("coverage") != "EXPLICITLY_WRAPPED_CALLS_ONLY"
                    or summary.get("complete_wrapped_calls") is not True or summary.get("nonaccess_proof") is not False
                    or summary.get("manual_events") != 0 or summary.get("inflight") != 0
                    or summary.get("network_upload") is not False):
                raise ValueError("incomplete or inconsistent framework observation")
            return result, summary
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()


def run_linked(args):
    """Run the observer outside the cell. Its tool callback invokes the ordinary BYOA gate."""
    from wolfalibi.byoa_attestation import verify_trial
    from wolfalibi.byoa_qualification_cli import qualify

    if not args.consent:
        raise ValueError("explicit consent is required before starting the LangChain worker")
    expected = _read(Path(args.review) / "expected.json", 65536)
    result, summary = _observe(lambda: qualify(args))
    if result.get("outcome") != "COMPLETED":
        return result
    output = Path(args.output)
    evidence_path = output / "report.json"
    raw = evidence_path.read_bytes()
    if len(raw) > 262144:
        raise ValueError("completed trial exceeds the report limit")
    checked = verify_trial(json.loads(raw), expected)
    if checked.get("outcome") != "VERIFIED":
        raise ValueError("completed trial does not verify against the pre-run expectations")
    record = {"schema": "quorvane.byoa.langchain-observation.v1", "assurance": "OBSERVATIONAL_ONLY",
              "runtime": "TRUSTED_HOST_SDK_OUTSIDE_MEASURED_CELL", "framework": SUPPORTED_VERSIONS,
              "model": "SCRIPTED_LOCAL_MODEL", "wrapped_action": "request_trial", "summary": summary,
              "inner_report_sha256": hashlib.sha256(raw).hexdigest(), "run_id": checked["run_id"],
              "challenge": checked["challenge"], "network_upload": False}
    _write_new(output / "framework-observation.json", record)
    return dict(result, framework_observation=record)


if __name__ == "__main__":
    with socket.socket(fileno=0) as endpoint:
        endpoint.settimeout(45)
        _sdk_worker(endpoint)
