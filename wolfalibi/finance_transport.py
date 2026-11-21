"""Thin Gate003 finance bindings for the shared Linux local transport.

The common implementation remains in education_transport.  This module fixes a
separate trusted profile: finance wire namespace, two finance RPC actions, and
the finance caller artifact.  It does not add a settlement action or any
transport-side authority.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import education_transport as _shared
from .finance_records import validate_peer


FINANCE_PROFILE = _shared.TransportProfile(
    label="FINANCE",
    wire_type="wolfalibi.finance.local-transport.v1",
    actions=frozenset({"initiate", "reconcile"}),
    caller_path=Path(__file__).with_name("finance_fixture_caller.py").absolute(),
    peer_validator=validate_peer,
)
FinanceTransportError = _shared.EducationTransportError
# The shared implementation defines metrics only when Linux socket controls
# are importable.  Keep this module importable so callers can report
# UNSUPPORTED before attempting a local finance trial.
TransportMetrics = getattr(_shared, "TransportMetrics", None)
CONNECT_TIMEOUT_SECONDS = _shared.CONNECT_TIMEOUT_SECONDS
CONNECTION_TIMEOUT_SECONDS = _shared.CONNECTION_TIMEOUT_SECONDS
MAX_ACTIVE_CONNECTIONS = _shared.MAX_ACTIVE_CONNECTIONS
LISTEN_BACKLOG = _shared.LISTEN_BACKLOG
MAX_FRAME_BYTES = _shared.MAX_FRAME_BYTES


def measure_peer(pid: int) -> dict:
    """Measure only the fixed finance caller under the immutable profile."""
    return _shared.measure_peer(pid, profile=FINANCE_PROFILE)


def request(path, action, packet, *, expected_target_pid: int) -> dict:
    """Send one closed finance initiate/reconcile request."""
    return _shared.request(
        path, action, packet, expected_target_pid=expected_target_pid,
        profile=FINANCE_PROFILE,
    )


def _open_client_session(socket_path, *, expected_target_pid: int):
    """Open the finance-profile session used by the lost-reply control."""
    return _shared._open_client_session(
        socket_path, expected_target_pid=expected_target_pid, profile=FINANCE_PROFILE,
    )


def serve(target, socket_path, *, on_ready=None, stop_event=None, metrics=None) -> None:
    """Serve a normal finance target through the shared guarded socket path."""
    return _shared.serve(
        target, socket_path, on_ready=on_ready, stop_event=stop_event, metrics=metrics,
        profile=FINANCE_PROFILE,
    )


def main(argv=None) -> int:
    """Run one provisioned FinanceTarget; readiness is sent over its socket."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path)
    parser.add_argument("anchor", type=Path)
    parser.add_argument("socket", type=Path)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args(argv)
    try:
        _shared._linux_controls()
        from .finance_target import FinanceTarget

        with FinanceTarget(args.state, args.anchor, create=args.create) as target:
            serve(target, args.socket)
        return 0
    except KeyboardInterrupt:
        return 0
    except (ImportError, OSError, RuntimeError, TypeError, ValueError, FinanceTransportError):
        print(json.dumps(_shared._unavailable(FINANCE_PROFILE), sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "CONNECT_TIMEOUT_SECONDS",
    "CONNECTION_TIMEOUT_SECONDS",
    "FINANCE_PROFILE",
    "FinanceTransportError",
    "LISTEN_BACKLOG",
    "MAX_ACTIVE_CONNECTIONS",
    "MAX_FRAME_BYTES",
    "TransportMetrics",
    "measure_peer",
    "request",
    "serve",
)
