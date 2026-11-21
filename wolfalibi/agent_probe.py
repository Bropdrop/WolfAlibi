"""Opt-in, local-only instrumented tool-call aggregates for bring-your-own-agent testing.

This is *observational telemetry*, not a non-access receipt or proof of confinement.
Unwrapped tool calls, direct syscalls, and out-of-band routes are not covered.
The module sends no network requests and never captures tool inputs, outputs,
error text, prompts, resource identifiers, or model responses.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from concurrent import futures
from functools import wraps
import inspect
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Callable

SCHEMA = "wolfalibi.agent_observation.v0"
SURFACES = frozenset({"tool", "filesystem", "network", "database", "model", "other"})
OPERATIONS = frozenset({"invoke", "read", "write", "list", "query", "request", "other"})
OUTCOMES = frozenset({"success", "error", "timeout", "cancelled", "denied"})
AGENT_TYPES = frozenset({"custom", "mcp", "langchain", "openai-agents", "other"})


class ProbeError(RuntimeError):
    """Instrumented run does not meet the explicitly declared local contract."""


def _validate(surface: str, operation: str) -> None:
    if (type(surface) is not str or surface not in SURFACES or
            type(operation) is not str or operation not in OPERATIONS):
        raise ValueError("unknown telemetry category; raw names and payloads are prohibited")


def _duration_bucket(elapsed_ms: int) -> str:
    if elapsed_ms < 10:
        return "0-9"
    if elapsed_ms < 100:
        return "10-99"
    if elapsed_ms < 1000:
        return "100-999"
    return "1000+"


class AgentProbe:
    """Wrap user-authorized tool callbacks, collecting only bounded aggregates.

    Consent is explicit. A call that cannot be recorded (closed or exhausted
    probe) is refused before the tool runs. `complete_wrapped_calls` covers
    the observed lifecycle of wrapped callbacks only.
    """

    def __init__(self, *, consent: bool, agent_type: str = "custom", max_calls: int = 100_000):
        if consent is not True:
            raise ProbeError("agent operator must explicitly opt in to local observation")
        if type(agent_type) is not str or agent_type not in AGENT_TYPES:
            raise ValueError("unsupported agent category")
        if type(max_calls) is not int or not 1 <= max_calls <= 1_000_000:
            raise ValueError("max_calls must be an integer between 1 and 1000000")
        self._run_id = secrets.token_hex(16)
        self._agent_type = agent_type
        self._max_calls = max_calls
        self._count = 0
        self._manual_count = 0
        self._inflight = 0
        self._closed = False
        self._counts: Counter[str] = Counter()
        self._latency: Counter[str] = Counter()
        self._lock = threading.RLock()

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def agent_type(self) -> str:
        return self._agent_type

    @property
    def max_calls(self) -> int:
        return self._max_calls

    def _begin(self) -> int:
        with self._lock:
            if self._closed or self._count + self._inflight >= self.max_calls:
                raise ProbeError("observation is closed or at capacity; tool not invoked")
            self._inflight += 1
        return time.monotonic_ns()

    def _finish(self, surface: str, operation: str, outcome: str, start_ns: int) -> None:
        elapsed_ms = max(0, (time.monotonic_ns() - start_ns) // 1_000_000)
        with self._lock:
            self._inflight -= 1
            self._count += 1
            self._counts[f"{surface}.{operation}.{outcome}"] += 1
            self._latency[_duration_bucket(elapsed_ms)] += 1

    @staticmethod
    def _error_kind(exc: BaseException) -> str:
        if isinstance(exc, (asyncio.CancelledError, futures.CancelledError)):
            return "cancelled"
        if isinstance(exc, (TimeoutError, asyncio.TimeoutError, futures.TimeoutError)):
            return "timeout"
        if isinstance(exc, PermissionError):
            return "denied"
        return "error"

    def wrap(self, callback: Callable, *, surface: str = "tool", operation: str = "invoke") -> Callable:
        """Observe a callback from invocation through its return or awaited outcome.

        An async callback begins when its wrapper executes. A synchronous
        callback begins immediately, even if it returns an awaitable. In that
        case callers must await the wrapped result before closing this probe.
        """
        _validate(surface, operation)
        if not callable(callback):
            raise TypeError("callback must be callable")

        async def resolve(awaitable, start):
            outcome = "success"
            try:
                return await awaitable
            except BaseException as exc:
                outcome = self._error_kind(exc)
                raise
            finally:
                self._finish(surface, operation, outcome, start)

        if (inspect.iscoroutinefunction(callback) or
                inspect.iscoroutinefunction(getattr(type(callback), "__call__", None))):
            @wraps(callback)
            async def async_wrapper(*args, **kwargs):
                start = self._begin()
                try:
                    awaitable = callback(*args, **kwargs)
                except BaseException as exc:
                    self._finish(surface, operation, self._error_kind(exc), start)
                    raise
                return await resolve(awaitable, start)
            return async_wrapper

        @wraps(callback)
        def wrapper(*args, **kwargs):
            start = self._begin()
            try:
                result = callback(*args, **kwargs)
            except BaseException as exc:
                self._finish(surface, operation, self._error_kind(exc), start)
                raise
            if inspect.isawaitable(result):
                return resolve(result, start)
            self._finish(surface, operation, "success", start)
            return result
        return wrapper

    def record(self, *, surface: str, operation: str, outcome: str, duration_ms: int = 0) -> None:
        """Record an explicitly declared external framework hook; never accepts payloads."""
        _validate(surface, operation)
        if (type(outcome) is not str or outcome not in OUTCOMES or type(duration_ms) is not int or
                not 0 <= duration_ms <= 86_400_000):
            raise ValueError("invalid outcome or duration")
        with self._lock:
            if self._closed or self._count + self._inflight >= self.max_calls:
                raise ProbeError("observation is closed or at capacity")
            self._count += 1
            self._manual_count += 1
            self._counts[f"{surface}.{operation}.{outcome}"] += 1
            self._latency[_duration_bucket(duration_ms)] += 1

    def close(self) -> None:
        with self._lock:
            if self._inflight:
                raise ProbeError("instrumented operations remain in flight")
            self._closed = True

    def summary(self) -> dict:
        with self._lock:
            return {
                "schema": SCHEMA,
                "run_id": self.run_id,
                "agent_type": self.agent_type,
                "assurance": "OBSERVATIONAL_ONLY",
                "coverage": ("EXPLICITLY_WRAPPED_CALLS_AND_DECLARED_MANUAL_EVENTS"
                             if self._manual_count else "EXPLICITLY_WRAPPED_CALLS_ONLY"),
                "complete_wrapped_calls": self._closed and self._inflight == 0,
                "events": self._count,
                "manual_events": self._manual_count,
                "inflight": self._inflight,
                "counts": dict(sorted(self._counts.items())),
                "duration_buckets_ms": dict(sorted(self._latency.items())),
                "privacy": "No prompts, arguments, outputs, credentials, file names or error strings collected",
                "nonaccess_proof": False,
                "network_upload": False,
            }

    def export_summary(self, output: str | Path) -> Path:
        """Write a 0600, create-only local report. Never sends a report anywhere."""
        with self._lock:
            if not self._closed or self._inflight:
                raise ProbeError("close and finish all wrapped operations before exporting")
            data = (json.dumps(self.summary(), sort_keys=True, separators=(",", ":")) + "\n").encode()
        path = Path(output)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return path

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _demo(output: str) -> None:
    with AgentProbe(consent=True, agent_type="custom") as probe:
        @probe.wrap
        def good_tool(secret_arg):
            return "synthetic-result"
        @probe.wrap
        def failing_tool(secret_arg):
            raise PermissionError("synthetic secret value that must not be stored")
        assert good_tool("synthetic-personal-prompt") == "synthetic-result"
        try:
            failing_tool("synthetic-personal-prompt")
        except PermissionError:
            pass
    path = probe.export_summary(output)
    print(json.dumps({"outcome": "LOCAL_REPORT_CREATED", "path": str(path),
                      "assurance": "OBSERVATIONAL_ONLY", "events": probe.summary()["events"]}, sort_keys=True))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Local-only, opt-in tool-call observation (not nonaccess proof)")
    parser.add_argument("demo", choices=["demo"])
    parser.add_argument("--output", required=True, help="new report path; existing files are never overwritten")
    args = parser.parse_args()
    _demo(args.output)
