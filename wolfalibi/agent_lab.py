"""Manifest-driven local runner for opt-in, user-owned agent tool integration.

This is an observational development harness, not a confinement boundary.
Importing the manifest's Python entrypoint executes operator-approved local
code with the process's ordinary OS and network privileges.
"""
from __future__ import annotations

import argparse
import asyncio
from functools import wraps
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from .agent_probe import AgentProbe, ProbeError, AGENT_TYPES, SURFACES, OPERATIONS, OUTCOMES

SCHEMA = "wolfalibi.agent_lab.manifest.v1"
SCHEMA_V2 = "wolfalibi.agent_lab.manifest.v2"
_RUN_OUTCOMES = frozenset({"PASS", "AGENT_ERROR", "TIMEOUT", "INTERRUPTED",
                           "INCOMPLETE", "EXPECTATION_FAILED", "BLOCKED"})
_MODULE = re.compile(r"^[a-zA-Z_][a-zA-Z_0-9]*(\.[a-zA-Z_][a-zA-Z_0-9]*)*$")
_NAME = re.compile(r"^[a-zA-Z][a-zA-Z_0-9]{0,63}$")
_ALLOWED_FIELDS = frozenset({"schema", "agent_type", "entrypoint", "tools", "fixtures"})
_TOOL_FIELDS = frozenset({"alias", "module", "callable", "surface", "operation"})
_MAX_MANIFEST = 32768
_MAX_WORKER_RESULT = 16384


class ManifestError(ValueError):
    """An agent manifest fails schema validation."""


class UnsupportedAdapter(ManifestError):
    """The requested framework or version lacks qualification."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("duplicate manifest field")
        result[key] = value
    return result


def _reference(obj):
    if not isinstance(obj, dict) or set(obj) != {"module", "callable"}:
        raise ManifestError("entrypoint requires module and callable")
    if not isinstance(obj["module"], str) or not _MODULE.fullmatch(obj["module"]):
        raise ManifestError("invalid local Python module reference")
    if not isinstance(obj["callable"], str) or not _NAME.fullmatch(obj["callable"]):
        raise ManifestError("invalid callable name")
    return obj


def load_manifest(path):
    """Validate the strict, size-limited manifest without importing agent code."""
    with Path(path).open("rb") as stream:
        raw = stream.read(_MAX_MANIFEST + 1)
    if not 0 < len(raw) <= _MAX_MANIFEST:
        raise ManifestError("manifest size out of range")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                         parse_constant=lambda _: (_ for _ in ()).throw(ManifestError("invalid JSON number")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError("malformed JSON manifest") from exc
    if not isinstance(obj, dict) or obj.get("schema") not in (SCHEMA, SCHEMA_V2):
        raise ManifestError("unexpected manifest fields or schema")
    v2 = obj["schema"] == SCHEMA_V2
    allowed = _ALLOWED_FIELDS | ({"limits", "expect_counts"} if v2 else set())
    if not _ALLOWED_FIELDS <= obj.keys() <= allowed:
        raise ManifestError("unexpected manifest fields or schema")
    if type(obj["agent_type"]) is not str or obj["agent_type"] not in AGENT_TYPES:
        raise ManifestError("invalid agent type")
    if v2 and obj["agent_type"] == "other":
        raise ManifestError("v2 requires a supported adapter")
    limits = obj.get("limits", {})
    if (not isinstance(limits, dict) or limits.keys() - {"agent_timeout_ms", "max_calls"}
            or any(type(v) is not int or not 1 <= v <= 1_000_000 for v in limits.values())):
        raise ManifestError("invalid run limits")
    expected = obj.get("expect_counts", {})
    count_keys = {f"{s}.{o}.{r}" for s in SURFACES for o in OPERATIONS for r in OUTCOMES}
    if (not isinstance(expected, dict) or not expected.keys() <= count_keys
            or any(type(v) is not int or not 0 <= v <= 1_000_000 for v in expected.values())):
        raise ManifestError("invalid expected observation counts")
    _reference(obj["entrypoint"])
    tools = obj["tools"]
    if not isinstance(tools, list) or not 1 <= len(tools) <= 32:
        raise ManifestError("manifest needs 1..32 declared tools")
    names = set()
    for item in tools:
        tool_fields = _TOOL_FIELDS | ({"timeout_ms"} if v2 else set())
        if not isinstance(item, dict) or not _TOOL_FIELDS <= item.keys() <= tool_fields:
            raise ManifestError("unknown tool fields")
        if "timeout_ms" in item and (type(item["timeout_ms"]) is not int
                                     or not 1 <= item["timeout_ms"] <= 1_000_000):
            raise ManifestError("invalid tool timeout")
        if not isinstance(item["alias"], str) or not _NAME.fullmatch(item["alias"]):
            raise ManifestError("invalid tool alias")
        if item["alias"] in names:
            raise ManifestError("duplicate tool alias")
        names.add(item["alias"])
        _reference({"module": item["module"], "callable": item["callable"]})
        if (type(item["surface"]) is not str or item["surface"] not in SURFACES or
                type(item["operation"]) is not str or item["operation"] not in OPERATIONS):
            raise ManifestError("unsupported tool category")
    fixtures = obj["fixtures"]
    if not isinstance(fixtures, dict) or len(fixtures) > 32:
        raise ManifestError("fixtures must be a small object")
    if any(not isinstance(k, str) or not _NAME.fullmatch(k) or
           not isinstance(v, str) or len(v) > 2048 for k, v in fixtures.items()):
        raise ManifestError("fixtures must contain short named synthetic strings")
    return obj, hashlib.sha256(raw).hexdigest()


def _load_callable(ref):
    # Imports execute code. This is only called after explicit authorization.
    module = importlib.import_module(ref["module"])
    fn = getattr(module, ref["callable"], None)
    if not callable(fn):
        raise ManifestError("declared Python callable is unavailable")
    return fn


async def _resolve(value):
    return await value if inspect.isawaitable(value) else value


def _timed(callback, timeout_ms):
    @wraps(callback)
    async def timed(*args, **kwargs):
        return await asyncio.wait_for(_resolve(callback(*args, **kwargs)), timeout_ms / 1000)
    return timed


def _is_async(callback):
    return inspect.iscoroutinefunction(callback) or inspect.iscoroutinefunction(
        getattr(callback, "__call__", None))


def _adapter(manifest, probe):
    category = manifest["agent_type"] if manifest["schema"] == SCHEMA_V2 else "custom"
    if category == "custom":
        return "python-callbacks", "1", lambda callback, _, labels: probe.wrap(callback, **labels)
    if category == "mcp":
        from .agent_mcp import MCPAdapterError, require_mcp_version
        try:
            version = require_mcp_version()
        except MCPAdapterError as exc:
            raise UnsupportedAdapter("install the qualified MCP extra") from exc
        return "mcp", version, lambda callback, _, labels: probe.wrap(callback, **labels)
    if category == "langchain":
        from .agent_langchain import langchain_status, langchain_tool
        status = langchain_status()
        if status["outcome"] != "SUPPORTED":
            raise UnsupportedAdapter("install the qualified LangChain extra")

        def build(callback, alias, labels):
            kind = "coroutine" if _is_async(callback) else "func"
            return langchain_tool(probe, name=alias, description="Operator-declared tool",
                                  **{kind: callback}, **labels)
        return "langchain", status["qualified"]["langchain"], build
    if category == "openai-agents":
        from .agent_openai import (OpenAIAgentsUnavailable, observed_function_tool,
                                   require_openai_agents_version)
        try:
            version = require_openai_agents_version()
        except OpenAIAgentsUnavailable as exc:
            raise UnsupportedAdapter("install the qualified OpenAI Agents extra") from exc

        def build(callback, alias, labels):
            return observed_function_tool(probe, callback, name_override=alias,
                                          description_override="Operator-declared tool", **labels)
        return "openai-agents", version, build
    raise UnsupportedAdapter("unknown adapter")


async def _finish_agent(returned, timeout_ms):
    try:
        if timeout_ms is None:
            await returned
        else:
            await asyncio.wait_for(_resolve(returned), timeout_ms / 1000)
    except asyncio.CancelledError:
        outcome = "INTERRUPTED"
    except TimeoutError:
        outcome = "TIMEOUT"
    except (Exception, SystemExit):
        outcome = "AGENT_ERROR"
    else:
        outcome = "PASS"
    # The private loop belongs to this run. Drain tasks the entrypoint left
    # behind and report the boundary as incomplete even if they cancel cleanly.
    pending = asyncio.all_tasks() - {asyncio.current_task()}
    if pending:
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        if outcome == "PASS":
            outcome = "INCOMPLETE"
    return outcome


def _write_report(path, report):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def run_manifest(path, output, *, consent=False, allow_local_code=False,
                 expected_manifest_sha256=None):
    """Run an operator-owned entrypoint with wrapped tools and export local counts.

    No outputs, tool arguments, exceptions or fixture values are included in
    the report or CLI response. The agent can still use its usual OS privileges.
    """
    manifest, digest = load_manifest(path)
    if expected_manifest_sha256 is not None and expected_manifest_sha256 != digest:
        raise ManifestError("manifest changed after validation")
    if consent is not True or allow_local_code is not True:
        raise ProbeError("requires --consent and --allow-local-code before importing agent code")
    if os.path.lexists(output):
        raise FileExistsError("report already exists")
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise ProbeError("run_manifest requires a thread without an active event loop")
    limits = manifest.get("limits", {})
    probe = AgentProbe(consent=True, agent_type=manifest["agent_type"],
                       max_calls=limits.get("max_calls", 100_000))
    adapter, version, build = _adapter(manifest, probe)
    try:
        entry = _load_callable(manifest["entrypoint"])
    except (Exception, SystemExit):
        raise ManifestError("agent entrypoint could not be imported") from None
    tools = {}
    for item in manifest["tools"]:
        try:
            callback = _load_callable(item)
        except (Exception, SystemExit):
            raise ManifestError("declared tool cannot be imported") from None
        if "timeout_ms" in item:
            callback = _timed(callback, item["timeout_ms"])
        try:
            tools[item["alias"]] = build(callback, item["alias"], {
                "surface": item["surface"], "operation": item["operation"]})
        except Exception:
            raise ManifestError("adapter could not build the tool; check version and signature") from None
    try:
        returned = entry(tools, dict(manifest["fixtures"]))
        status = (asyncio.run(_finish_agent(returned, limits.get("agent_timeout_ms")))
                  if inspect.isawaitable(returned) else "PASS")
    except (KeyboardInterrupt, asyncio.CancelledError):
        status = "INTERRUPTED"
    except TimeoutError:
        status = "TIMEOUT"
    except (Exception, SystemExit):
        status = "AGENT_ERROR"
    try:
        probe.close()
    except ProbeError:
        status = "INCOMPLETE"
    summary = probe.summary()
    if status == "PASS" and "expect_counts" in manifest:
        if summary["counts"] != {key: n for key, n in manifest["expect_counts"].items() if n}:
            status = "EXPECTATION_FAILED"
    summary.update(outcome=status, adapter=adapter, adapter_version=version,
                   declared_bindings=len(tools), runtime_scope="IN_PROCESS_TOOL_OBSERVATION")
    _write_report(output, summary)
    return {"outcome": status, "assurance": "OBSERVATIONAL_ONLY",
            "coverage": summary["coverage"], "manifest_sha256": digest,
            "events": summary["events"], "report": str(output), "uploaded": False}


def configure_parser(parser):
    parser.add_argument("--manifest", required=True, help="trusted local manifest JSON")
    parser.add_argument("--output", help="new local report path; never overwritten")
    parser.add_argument("--consent", action="store_true", help="consent to local aggregate observation")
    parser.add_argument("--allow-local-code", action="store_true",
                        help="execute Python code named by manifest with your current privileges")
    parser.add_argument("--dry-run", action="store_true", help="validate JSON only; no Python imports")
    parser.add_argument("--process-timeout", type=int, default=120,
                        help="installed command worker timeout in seconds (default: 120)")
    parser.add_argument("--credential-env", action="append", default=[], metavar="NAME",
                        help="explicitly forward this existing environment variable to the worker")
    parser.add_argument("--research-output", help="optional local de-identified aggregate path")
    parser.add_argument("--research-consent", action="store_true",
                        help="consent separately to writing the aggregate file")
    parser.add_argument("--expected-manifest", help=argparse.SUPPRESS)
    parser.add_argument("--worker-result", help=argparse.SUPPRESS)
    return parser


def _blocked(reason, *, outcome="BLOCKED", guidance=None):
    result = {"outcome": outcome, "reason": reason, "assurance": "OBSERVATIONAL_ONLY"}
    if guidance is not None:
        result["guidance"] = guidance
    return result


def _child(args, digest):
    if not 1 <= args.process_timeout <= 3600:
        raise ManifestError("invalid worker process timeout")
    # Do not inherit provider or tracing credentials from the calling shell.
    environment = {name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT")
                   if name in os.environ}
    tracing_defaults = {"OPENAI_AGENTS_DISABLE_TRACING": "1", "LANGSMITH_TRACING": "false",
                        "LANGCHAIN_TRACING_V2": "false"}
    for name in args.credential_env:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", name) or name not in os.environ:
            raise ManifestError("credential reference is unavailable")
        if name.startswith(("PYTHON", "LD_", "DYLD_")) or name in environment or name in tracing_defaults:
            raise ManifestError("credential variable would alter the worker runtime")
        environment[name] = os.environ[name]
    environment.update(tracing_defaults)
    command = [
        sys.executable, "-m", "wolfalibi.agent_lab", "--manifest", args.manifest,
        "--output", args.output, "--consent", "--allow-local-code",
        "--expected-manifest", digest,
    ]
    if args.research_output:
        command.extend(["--research-output", args.research_output, "--research-consent"])
    # Discard agent-owned console output across Python, native code, and
    # subprocesses. Read only a bounded harness result from a private directory.
    with tempfile.TemporaryDirectory(prefix="wolfalibi-agent-worker-") as directory:
        result_file = Path(directory) / "result.json"
        command.extend(["--worker-result", str(result_file)])
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=False,
                                   timeout=args.process_timeout, env=environment)
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(result_file, flags), "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    return _blocked("WORKER_PROTOCOL")
                raw = stream.read(_MAX_WORKER_RESULT + 1)
            if len(raw) > _MAX_WORKER_RESULT:
                return _blocked("WORKER_PROTOCOL")
            result = json.loads(raw)
        except (OSError, ValueError, RecursionError):
            return _blocked("WORKER_PROTOCOL", guidance="check local adapter and report paths")
    # Accept only the harness's fixed fields and values, never raw child output.
    if not isinstance(result, dict) or result.get("assurance") != "OBSERVATIONAL_ONLY":
        return _blocked("WORKER_PROTOCOL")
    outcome = result.get("outcome")
    if type(outcome) is not str:
        return _blocked("WORKER_PROTOCOL")
    if outcome == "UNSUPPORTED":
        return _blocked("UNSUPPORTED_ADAPTER", outcome=outcome,
                        guidance="install the matching optional SDK extra")
    if outcome == "BLOCKED":
        reason = result.get("reason")
        if reason not in ("ManifestError", "ProbeError", "FileExistsError", "OSError", "ValueError"):
            reason = "WORKER_BLOCKED"
        return _blocked(reason, guidance="check entrypoint, tool signatures and output paths")
    if outcome not in _RUN_OUTCOMES or result.get("manifest_sha256") != digest:
        return _blocked("WORKER_PROTOCOL")
    succeeded = outcome == "PASS" and result.get("research_export") != "BLOCKED"
    if completed.returncode != (0 if succeeded else 2) or not Path(args.output).is_file():
        return _blocked("WORKER_PROTOCOL")
    events = result.get("events")
    coverage = result.get("coverage")
    if (type(events) is not int or not 0 <= events <= 1_000_000 or
            coverage not in ("EXPLICITLY_WRAPPED_CALLS_ONLY",
                             "EXPLICITLY_WRAPPED_CALLS_AND_DECLARED_MANUAL_EVENTS")):
        return _blocked("WORKER_PROTOCOL")
    validated = {"outcome": outcome, "assurance": "OBSERVATIONAL_ONLY",
                 "coverage": coverage, "events": events, "manifest_sha256": digest,
                 "report": args.output, "uploaded": False}
    if args.research_output:
        validated["research_report"] = args.research_output
        validated["research_export"] = result.get("research_export")
        if (validated["research_export"] != "CREATED" or
                not Path(args.research_output).is_file()):
            return {**validated, "outcome": "BLOCKED", "agent_outcome": outcome,
                    "research_export": "BLOCKED"}
    return validated


def run_cli(args, *, child=False):
    try:
        manifest, digest = load_manifest(args.manifest)
        if args.dry_run:
            result = {"outcome": "VALID", "manifest_sha256": digest,
                      "imports_executed": False, "assurance": "OBSERVATIONAL_ONLY",
                      "declared_bindings": len(manifest["tools"]),
                      "guidance": "use --consent and --allow-local-code to start a trusted local run"}
        elif not args.consent or not args.allow_local_code:
            result = _blocked("CONSENT_REQUIRED",
                              guidance="review the manifest with --dry-run, then provide --consent and --allow-local-code")
        else:
            if not args.output:
                args.output = Path(args.manifest).stem + ".agent-observation.json"
            if args.research_output and not args.research_consent:
                raise ProbeError("research export requires separate consent")
            if os.path.lexists(args.output) or (args.research_output and
                    (os.path.lexists(args.research_output) or
                     Path(args.output).resolve() == Path(args.research_output).resolve())):
                raise FileExistsError("output path is already in use")
            if child:
                result = _child(args, digest)
            elif args.credential_env:
                raise ProbeError("credential forwarding is available through the installed command")
            else:
                result = run_manifest(args.manifest, args.output, consent=True,
                                      allow_local_code=True,
                                      expected_manifest_sha256=args.expected_manifest)
                if args.research_output:
                    from .agent_research import ResearchExportError, export_research
                    summary = json.loads(Path(args.output).read_bytes())
                    try:
                        export_research(summary, args.research_output,
                                        outcome=result["outcome"], consent=True)
                    except (ResearchExportError, OSError):
                        result["research_export"] = "BLOCKED"
                    else:
                        result.update(research_report=args.research_output, research_export="CREATED")
    except UnsupportedAdapter:
        result = _blocked("UNSUPPORTED_ADAPTER", outcome="UNSUPPORTED",
                          guidance="install the matching optional SDK extra")
    except subprocess.TimeoutExpired:
        result = _blocked("PROCESS_TIMEOUT", outcome="TIMEOUT")
    except KeyboardInterrupt:
        result = _blocked("OPERATOR_INTERRUPTION", outcome="INTERRUPTED")
    except (ManifestError, ProbeError, ValueError, OSError) as exc:
        result = _blocked(type(exc).__name__)
    if args.worker_result and args.expected_manifest and not child:
        _write_report(args.worker_result, result)
    else:
        print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in ("VALID", "PASS") and result.get("research_export") != "BLOCKED" else 2


def main(argv=None):
    parser = configure_parser(argparse.ArgumentParser(description=__doc__))
    return run_cli(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
