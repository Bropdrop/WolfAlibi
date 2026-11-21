"""Manifest-driven local runner for opt-in, user-owned agent tool integration.

This is an observational development harness, not a confinement boundary.
Importing the manifest's Python entrypoint executes operator-approved local
code with the process's ordinary OS and network privileges.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import re
import sys

from .agent_probe import AgentProbe, ProbeError, AGENT_TYPES, SURFACES, OPERATIONS

SCHEMA = "wolfalibi.agent_lab.manifest.v1"
_MODULE = re.compile(r"^[a-zA-Z_][a-zA-Z_0-9]*(\.[a-zA-Z_][a-zA-Z_0-9]*)*$")
_NAME = re.compile(r"^[a-zA-Z][a-zA-Z_0-9]{0,63}$")
_ALLOWED_FIELDS = frozenset({"schema", "agent_type", "entrypoint", "tools", "fixtures"})
_TOOL_FIELDS = frozenset({"alias", "module", "callable", "surface", "operation"})
_MAX_MANIFEST = 32768


class ManifestError(ValueError):
    """An agent manifest fails schema validation."""


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
    raw = Path(path).read_bytes()
    if not 0 < len(raw) <= _MAX_MANIFEST:
        raise ManifestError("manifest size out of range")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                         parse_constant=lambda _: (_ for _ in ()).throw(ManifestError("invalid JSON number")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError("malformed JSON manifest") from exc
    if not isinstance(obj, dict) or set(obj) != _ALLOWED_FIELDS or obj["schema"] != SCHEMA:
        raise ManifestError("unexpected manifest fields or schema")
    if type(obj["agent_type"]) is not str or obj["agent_type"] not in AGENT_TYPES:
        raise ManifestError("invalid agent type")
    _reference(obj["entrypoint"])
    tools = obj["tools"]
    if not isinstance(tools, list) or not 1 <= len(tools) <= 32:
        raise ManifestError("manifest needs 1..32 declared tools")
    names = set()
    for item in tools:
        if not isinstance(item, dict) or set(item) != _TOOL_FIELDS:
            raise ManifestError("unknown tool fields")
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


def run_manifest(path, output, *, consent=False, allow_local_code=False):
    """Run an operator-owned entrypoint with wrapped tools and export local counts.

    No outputs, tool arguments, exceptions or fixture values are included in
    the report or CLI response. The agent can still use its usual OS privileges.
    """
    manifest, digest = load_manifest(path)
    if consent is not True or allow_local_code is not True:
        raise ProbeError("requires --consent and --allow-local-code before importing agent code")
    try:
        entry = _load_callable(manifest["entrypoint"])
    except (ImportError, AttributeError, ManifestError) as exc:
        raise ManifestError("agent entrypoint could not be imported") from None
    status = "PASS"
    probe = AgentProbe(consent=True, agent_type=manifest["agent_type"])
    try:
        with probe:
            tools = {}
            for item in manifest["tools"]:
                try:
                    callback = _load_callable(item)
                except (ImportError, AttributeError, ManifestError):
                    raise ManifestError("declared tool cannot be imported") from None
                tools[item["alias"]] = probe.wrap(callback, surface=item["surface"],
                                                   operation=item["operation"])
            try:
                returned = entry(tools, dict(manifest["fixtures"]))
                if inspect.isawaitable(returned):
                    asyncio.run(returned)
            except BaseException:
                status = "AGENT_ERROR"
    except BaseException as exc:
        # Do not report a clean run if hooks are still in-flight or cannot close.
        if isinstance(exc, ManifestError):
            raise
        raise ProbeError("agent lab could not close all instrumented operations") from None
    probe.export_summary(output)
    return {"outcome": status, "assurance": "OBSERVATIONAL_ONLY",
            "coverage": "EXPLICITLY_WRAPPED_CALLS_ONLY", "manifest_sha256": digest,
            "events": probe.summary()["events"], "report": str(output), "uploaded": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local, opt-in agent observation, not confinement")
    parser.add_argument("--manifest", required=True, help="trusted local manifest JSON")
    parser.add_argument("--output", help="new local report path; never overwritten")
    parser.add_argument("--consent", action="store_true", help="consent to local aggregate observation")
    parser.add_argument("--allow-local-code", action="store_true",
                        help="execute Python code named by manifest with your current privileges")
    parser.add_argument("--dry-run", action="store_true", help="validate JSON only; no Python imports")
    args = parser.parse_args(argv)
    try:
        if args.dry_run:
            _, digest = load_manifest(args.manifest)
            result = {"outcome": "VALID", "manifest_sha256": digest,
                      "imports_executed": False, "assurance": "OBSERVATIONAL_ONLY"}
        else:
            if not args.output:
                raise ManifestError("--output is required for a test run")
            result = run_manifest(args.manifest, args.output, consent=args.consent,
                                  allow_local_code=args.allow_local_code)
    except (ManifestError, ProbeError, FileExistsError, OSError) as exc:
        # Errors may contain paths or raw input: never echo exceptions in the CLI.
        result = {"outcome": "BLOCKED", "reason": type(exc).__name__,
                  "assurance": "OBSERVATIONAL_ONLY"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in ("VALID", "PASS") else 2


if __name__ == "__main__":
    sys.exit(main())
