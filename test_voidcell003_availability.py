"""Bounded same-UID Unix fixture tests for VOIDCELL's local transport."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
from threading import Event, Lock, Thread, enumerate as enumerate_threads
import time
import unittest

from alibi import canon
from wolfalibi import voidcell002_transport as transport


_EVIDENCE_FILE = "WOLFALIBI_VOIDCELL003_AVAILABILITY_FILE"


class _FixtureAuthority:
    """A local status-only authority with no protected side effects."""

    def __init__(self):
        self.gateway_uid = 65533 if os.geteuid() == 65534 else 65534
        self._lock = Lock()
        self.calls = 0
        self.active = 0
        self.peak_active = 0
        self.first_entered = Event()
        self.release_first = Event()
        self.release_first.set()

    def status(self):
        with self._lock:
            self.calls += 1
            self.active += 1
            self.peak_active = max(self.active, self.peak_active)
            first = self.calls == 1
        try:
            if first:
                self.first_entered.set()
                if not self.release_first.wait(5):
                    raise RuntimeError("synthetic first callback did not resume")
            return {"outcome": "READY", "effect_count": 0}
        finally:
            with self._lock:
                self.active -= 1

    def dispatch(self, _):
        raise RuntimeError("no fixture dispatch")

    reconcile = revoke = dispatch


@unittest.skipUnless(sys.platform == "linux" and hasattr(socket, "SCM_CREDENTIALS")
                     and os.geteuid() != 0, "requires the ordinary Linux Unix-credential fixture")
class Voidcell003AvailabilityTests(unittest.TestCase):
    @contextmanager
    def _endpoint(self, authority):
        metrics = transport.TransportMetrics()
        stop, ready = Event(), Event()
        errors = []
        with TemporaryDirectory(prefix="wolfalibi-availability-") as directory:
            endpoint_dir = Path(directory) / "endpoint"
            endpoint_dir.mkdir(mode=0o711)
            endpoint_dir.chmod(0o711)
            endpoint = endpoint_dir / "target.sock"

            def run():
                try:
                    transport.serve(authority, socket_path=endpoint, gateway_uid=authority.gateway_uid,
                                    on_ready=ready.set, stop_event=stop, metrics=metrics)
                except Exception as error:
                    errors.append(error)
                    ready.set()

            server = Thread(target=run, daemon=True)
            server.start()
            try:
                self.assertTrue(ready.wait(5), "local endpoint did not become ready")
                self.assertFalse(errors, errors)
                yield endpoint, metrics
            finally:
                authority.release_first.set()
                stop.set()
                server.join(6)
                self.assertFalse(server.is_alive(), "local endpoint did not stop")
                self.assertFalse(errors, errors)
                self.assertFalse(endpoint.exists())

    def _await(self, condition, label):
        deadline = time.monotonic() + 5
        while not condition():
            if time.monotonic() >= deadline:
                self.fail(label)
            time.sleep(0.005)

    @staticmethod
    def _idle(stack, endpoint):
        channel = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET))
        channel.settimeout(2)
        channel.connect(str(endpoint))
        return channel

    @staticmethod
    def _status(endpoint):
        return transport.request(endpoint, "status", expected_target_uid=os.geteuid(),
                                 expected_target_pid=os.getpid())

    @staticmethod
    def _fds():
        return len(list(Path("/proc/self/fd").iterdir()))

    @staticmethod
    def _workers():
        return sum(thread.name.startswith(transport._WORKER_PREFIX) for thread in enumerate_threads())

    def test_idle_peers_saturate_only_fixed_slots_and_recover(self):
        authority = _FixtureAuthority()
        limit = transport.MAX_ACTIVE_CONNECTIONS
        with self._endpoint(authority) as (endpoint, metrics):
            baseline_fds = self._fds()
            with ExitStack() as idle_stack:
                self._idle(idle_stack, endpoint)
                self._await(lambda: metrics.snapshot()["active"] == 1, "idle peer was not admitted")
                response = self._status(endpoint)
                self.assertEqual(response, {"outcome": "READY", "effect_count": 0})
                self._await(lambda: metrics.snapshot()["active"] == 1,
                            "idle peer or responsive status did not reach the expected phase")
                after_interleave = metrics.snapshot()
                self.assertEqual(after_interleave["completed"], 1)
                for _ in range(limit - 1):
                    self._idle(idle_stack, endpoint)
                self._await(lambda: metrics.snapshot()["active"] == limit,
                            "fixed idle fixture did not reach the connection cap")
                refused = self._status(endpoint)
                self.assertEqual(refused["outcome"], "BLOCKED", refused)
                self._await(lambda: metrics.snapshot()["rejected_capacity"] == 1,
                            "the only excess connection did not register as rejected")
                saturated = metrics.snapshot()
                self.assertEqual(saturated["peak_active"], limit)
                self.assertEqual(saturated["admitted"], limit + 1)
                self.assertEqual(authority.calls, 1)
                # Each open idle fixture contributes its client FD. Subtract
                # those known test FDs from the process-wide delta.
                server_fd_growth = self._fds() - baseline_fds - limit
                worker_growth = self._workers()
                self.assertLessEqual(server_fd_growth, limit)
                self.assertLessEqual(worker_growth, limit)
                self._await(lambda: metrics.snapshot()["active"] == 0,
                            "idle connections did not release their slots after the deadline")
            recovered = self._status(endpoint)
            self.assertEqual(recovered, response)
            self._await(lambda: metrics.snapshot()["active"] == 0,
                        "the resumed status connection did not close")
            self.assertEqual(self._fds(), baseline_fds)
            final = metrics.snapshot()
            self.assertEqual(final["admitted"], final["completed"])
            self.assertEqual(authority.calls, 2)

        self.assertEqual(self._workers(), 0)
        output = os.environ.get(_EVIDENCE_FILE)
        if output is not None:
            public = {
                "schema": "WOLFALIBI_VOIDCELL_003_AVAILABILITY_V1",
                "assurance": "SAME_UID_LOCAL_TRANSPORT_FIXTURE_ONLY",
                "configuration": {
                    "transport": "AF_UNIX_SOCK_SEQPACKET",
                    "max_active_connections": limit, "listen_backlog": transport.LISTEN_BACKLOG,
                    "read_deadline_ms": int(transport.CONNECTION_TIMEOUT_SECONDS * 1000),
                },
                "observed": {
                    "interleaved_status": response["outcome"],
                    "excess_connection": refused["outcome"],
                    "recovered_status": recovered["outcome"],
                    "server_fd_growth_at_cap": server_fd_growth,
                    "handler_threads_at_cap": worker_growth,
                    "handler_threads_after_stop": self._workers(),
                },
                "metrics": {"after_interleave": after_interleave, "at_cap": saturated,
                            "after_recovery": final},
            }
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            with os.fdopen(os.open(output, flags, 0o600), "wb") as evidence:
                os.fchmod(evidence.fileno(), 0o600)
                evidence.write(canon(public) + b"\n")
                evidence.flush()
                os.fsync(evidence.fileno())

    def test_admitted_status_callbacks_remain_serialized(self):
        authority = _FixtureAuthority()
        authority.release_first.clear()
        with self._endpoint(authority) as (endpoint, metrics), ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self._status, endpoint)
            try:
                self.assertTrue(authority.first_entered.wait(2))
                second = pool.submit(self._status, endpoint)
                self._await(lambda: metrics.snapshot()["active"] == 2,
                            "concurrent status connection did not enter its handler")
            finally:
                authority.release_first.set()
            expected = {"outcome": "READY", "effect_count": 0}
            self.assertEqual(first.result(timeout=5), expected)
            self.assertEqual(second.result(timeout=5), expected)
        self.assertEqual(authority.calls, 2)
        self.assertEqual(authority.peak_active, 1)


if __name__ == "__main__":
    unittest.main()
