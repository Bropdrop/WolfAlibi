"""Linux per-run transport for the synthetic education target.

The endpoint accepts one canonical read or reconcile record per local connection.
Offline revocation is deliberately not a socket action. Kernel credentials,
pidfds, and procfs measurements bind the fixed caller process; they do not
establish production confinement or independent custody.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import sys
from threading import BoundedSemaphore, Lock
import time
from typing import Any, Mapping, Optional

from .education_records import validate_peer
from .voidcell_service import MAX_PACKET_BYTES, _canonical, _decode, _snapshot

if sys.platform.startswith("linux"):
    from .voidcell002_transport import (
        TransportMetrics, _credentials, _endpoint_inventory, _expect_eof, _peer_credentials, _recv,
    )


MAX_FRAME_BYTES = 65_536
CONNECT_TIMEOUT_SECONDS = 2.0
CONNECTION_TIMEOUT_SECONDS = 2.0
MAX_ACTIVE_CONNECTIONS = 4
LISTEN_BACKLOG = 16

_TYPE = "wolfalibi.education.local-transport.v1"
_ACTIONS = frozenset({"read", "reconcile"})
_BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_READY = _canonical({"type": _TYPE, "ready": True})
_REJECTED = {"outcome": "BLOCKED", "reason": "EDUCATION_TRANSPORT_REJECTED"}
_UNAVAILABLE = {"outcome": "BLOCKED", "reason": "EDUCATION_TRANSPORT_UNAVAILABLE"}
_UNKNOWN = {"outcome": "UNKNOWN", "reason": "RECONCILE_ORIGINAL_DISPATCH"}
_PEER_DENIED = {"outcome": "DENIED", "reason": "PEER_IDENTITY_MISMATCH"}
_FIXED_CALLER = Path(__file__).with_name("education_fixture_caller.py").absolute()


class EducationTransportError(RuntimeError):
    """The fixed local education endpoint cannot substantiate its boundary."""


class _PeerDenied(EducationTransportError):
    """The connecting process is not the independently enrolled fixed peer."""


class _TerminalResult(EducationTransportError):
    """A well-formed terminal result arrived before the READY handshake."""

    def __init__(self, result: dict) -> None:
        super().__init__("target rejected the local admission handshake")
        self.result = result


def _linux_controls() -> None:
    if not (
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(socket, "AF_UNIX")
        and hasattr(socket, "SOCK_SEQPACKET")
        and hasattr(socket, "SO_PEERCRED")
        and hasattr(socket, "SO_PASSCRED")
        and hasattr(socket, "SCM_CREDENTIALS")
        and hasattr(socket, "MSG_CMSG_CLOEXEC")
    ):
        raise EducationTransportError("Linux pidfd and Unix credential controls are required")


def _unsigned(value: object, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0) or value >= 1 << 63:
        raise EducationTransportError("invalid " + label)
    return value


def _pidfd_alive(descriptor: int) -> bool:
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poller.poll(0)


def _read_at(directory: int, name: str, maximum: int) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory,
    )
    try:
        chunks = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if not data or len(data) > maximum:
        raise EducationTransportError("process metadata is unavailable")
    return data


def _process_ids(status: bytes) -> tuple[int, int]:
    found = {}
    try:
        for line in status.decode("ascii", "strict").splitlines():
            name, separator, text = line.partition(":")
            if name not in {"Uid", "Gid"} or not separator:
                continue
            values = [int(member, 10) for member in text.split()]
            if len(values) != 4 or any(value < 0 or value >= 1 << 32 for value in values):
                raise ValueError
            found[name] = values
    except (UnicodeDecodeError, ValueError) as exc:
        raise EducationTransportError("process credentials are unavailable") from exc
    if found.keys() != {"Uid", "Gid"}:
        raise EducationTransportError("process credentials are unavailable")
    return found["Uid"][1], found["Gid"][1]


def _process_start_ticks(raw: bytes) -> int:
    try:
        _prefix, delimiter, remainder = raw.rpartition(b")")
        fields = remainder.split()
        if not delimiter or len(fields) < 20 or not fields[19].isdigit():
            raise ValueError
        value = int(fields[19], 10)
        if not 0 <= value < 1 << 63:
            raise ValueError
        return value
    except (TypeError, ValueError) as exc:
        raise EducationTransportError("process start ticks are unavailable") from exc


def _boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii", errors="strict"
        ).strip()
    except (OSError, UnicodeError) as exc:
        raise EducationTransportError("kernel boot identity is unavailable") from exc
    if _BOOT_ID.fullmatch(value) is None:
        raise EducationTransportError("kernel boot identity is unavailable")
    return value


def _executable_digest(directory: int) -> str:
    descriptor = os.open("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(descriptor, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _source_digest() -> str:
    """Sample the fixed source on disk and reject changes during the read."""
    def fingerprint(item):
        return (item.st_dev, item.st_ino, item.st_size, item.st_ctime_ns)

    descriptor = os.open(_FIXED_CALLER, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o022
                or not 0 < opened.st_size <= 1024 * 1024):
            raise EducationTransportError("invalid fixed caller source")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if (fingerprint(opened) != fingerprint(os.fstat(stream.fileno()))
                or fingerprint(opened) != fingerprint(_FIXED_CALLER.lstat())):
            raise EducationTransportError("fixed caller source changed during measurement")
        return digest


def _caller_argv(directory: int, *, endpoint: Optional[str]) -> str:
    """Validate the fixed supervisor launch shape and hash raw NUL argv bytes."""
    raw = _read_at(directory, "cmdline", 16_384)
    if not raw.endswith(b"\0"):
        raise EducationTransportError("fixed caller command line is invalid")
    argv = raw[:-1].split(b"\0")
    expected_interpreter = os.fsencode(str(Path(sys.executable).absolute()))
    expected_source = os.fsencode(str(_FIXED_CALLER))
    if len(argv) != 4 or argv[:3] != [expected_interpreter, b"-I", expected_source]:
        raise EducationTransportError("fixed caller command line differs from supervisor profile")
    try:
        supplied_endpoint = os.fsdecode(argv[3])
    except UnicodeDecodeError as exc:
        raise EducationTransportError("fixed caller endpoint is invalid") from exc
    if (
        not supplied_endpoint
        or "\0" in supplied_endpoint
        or not os.path.isabs(supplied_endpoint)
        or os.path.abspath(supplied_endpoint) != supplied_endpoint
    ):
        raise EducationTransportError("fixed caller endpoint is invalid")
    if endpoint is not None and supplied_endpoint != endpoint:
        raise EducationTransportError("fixed caller endpoint differs from target endpoint")
    return hashlib.sha256(raw).hexdigest()


def _measure_process(pid: int, *, pidfd: int, fixed_caller=False, endpoint=None) -> dict:
    if not _pidfd_alive(pidfd):
        raise EducationTransportError("enrolled process is no longer live")
    directory = os.open(Path("/proc") / str(pid), os.O_RDONLY | os.O_DIRECTORY |
                        os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        uid, gid = _process_ids(_read_at(directory, "status", 65_536))
        observed = {"pid": pid, "uid": uid, "gid": gid,
                    "start_ticks": _process_start_ticks(_read_at(directory, "stat", 65_536)),
                    "exe_sha256": _executable_digest(directory), "boot_id": _boot_id()}
        if fixed_caller:
            observed.update(argv_sha256=_caller_argv(directory, endpoint=endpoint),
                            source_sha256=_source_digest())
    finally:
        os.close(directory)
    if not _pidfd_alive(pidfd):
        raise EducationTransportError("process exited during measurement")
    return observed


def measure_peer(pid: int) -> dict:
    """Measure the fixed education caller from procfs, never from a packet.

    The exact return schema is pid, uid, gid, start_ticks, boot_id,
    exe_sha256, argv_sha256, and source_sha256. It rejects a caller not
    launched as sys.executable, -I, fixed caller source, and endpoint.
    """
    with _PinnedProcess(pid, fixed_caller=True) as caller:
        return caller.identity


class _PinnedProcess:
    """Pin one live process and reject detected changes in its sampled identity."""

    def __init__(
        self,
        pid: int,
        *,
        expected: Optional[Mapping[str, Any]] = None,
        fixed_caller: bool = False,
        endpoint: Optional[str] = None,
    ) -> None:
        _linux_controls()
        self._closed = False
        self._fixed_caller = fixed_caller
        self._endpoint = endpoint
        self._pid = _unsigned(pid, "process PID", positive=True)
        try:
            self._pidfd = os.pidfd_open(self._pid)
        except OSError as exc:
            raise EducationTransportError("process is unavailable") from exc
        try:
            identity = self._observe()
            if expected is not None:
                shaped = validate_peer(expected)
                if identity != shaped:
                    raise EducationTransportError(
                        "measured process differs from the enrolled identity"
                    )
            self._identity = identity
        except BaseException:
            os.close(self._pidfd)
            self._closed = True
            raise

    def _observe(self) -> dict:
        return _measure_process(self._pid, pidfd=self._pidfd, fixed_caller=self._fixed_caller,
                                endpoint=self._endpoint)

    @property
    def identity(self) -> dict:
        return dict(self._identity)

    def alive(self) -> bool:
        return not self._closed and _pidfd_alive(self._pidfd)

    def current(self) -> dict:
        if self._closed:
            raise EducationTransportError("process pidfd is closed")
        identity = self._observe()
        if identity != self._identity:
            raise EducationTransportError("process identity changed during transport")
        return dict(identity)

    def match_credentials(self, credentials: tuple[int, int, int]) -> dict:
        identity = self.current()
        if credentials != (identity["pid"], identity["uid"], identity["gid"]):
            raise EducationTransportError(
                "kernel credentials differ from measured process identity"
            )
        return identity

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            os.close(self._pidfd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _decode_request(raw: bytes) -> tuple[str, dict]:
    try:
        frame = _decode(raw, maximum=MAX_FRAME_BYTES)
    except Exception as exc:
        raise EducationTransportError("invalid education request frame") from exc
    if (
        type(frame) is not dict
        or frozenset(frame) != {"type", "action", "packet"}
        or frame["type"] != _TYPE
        or type(frame["action"]) is not str
        or frame["action"] not in _ACTIONS
        or type(frame["packet"]) is not dict
    ):
        raise EducationTransportError("invalid education request frame")
    return frame["action"], frame["packet"]


def _encode_request(action: str, packet: object) -> bytes:
    if type(action) is not str or action not in _ACTIONS or type(packet) is not dict:
        raise ValueError("unsupported education request")
    try:
        frozen = _snapshot(packet, maximum=MAX_PACKET_BYTES)
        if type(frozen) is not dict:
            raise ValueError
        raw = _canonical({"type": _TYPE, "action": action, "packet": frozen})
    except Exception as exc:
        raise ValueError("invalid education request") from exc
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError("education request exceeds the transport bound")
    return raw


def _encode_result(result: object) -> bytes:
    try:
        frozen = _snapshot(result, maximum=MAX_FRAME_BYTES // 2)
        if type(frozen) is not dict:
            raise ValueError
        raw = _canonical({"type": _TYPE, "result": frozen})
    except Exception:
        raw = _canonical({"type": _TYPE, "result": _REJECTED})
    if len(raw) > MAX_FRAME_BYTES:
        raw = _canonical({"type": _TYPE, "result": _REJECTED})
    return raw


def _decode_result(raw: bytes) -> dict:
    try:
        frame = _decode(raw, maximum=MAX_FRAME_BYTES)
    except Exception as exc:
        raise EducationTransportError("invalid education response frame") from exc
    if (
        type(frame) is not dict
        or frozenset(frame) != {"type", "result"}
        or frame["type"] != _TYPE
        or type(frame["result"]) is not dict
    ):
        raise EducationTransportError("invalid education response frame")
    return frame["result"]


def _safe_send(channel: socket.socket, raw: bytes, *, close_write: bool) -> None:
    if channel.send(raw) != len(raw):
        raise EducationTransportError("short local transport write")
    if close_write:
        channel.shutdown(socket.SHUT_WR)


def _safe_terminal(channel: socket.socket, result: Mapping[str, Any]) -> None:
    try:
        _safe_send(channel, _encode_result(dict(result)), close_write=True)
    except OSError:
        pass


def _endpoint_directory(path: Path, peer_uid: int) -> Path:
    if path.name in {"", ".", ".."} or path.name != Path(path.name).name:
        raise EducationTransportError("invalid endpoint name")
    directory = path.parent.absolute()
    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise EducationTransportError("endpoint directory is unavailable") from exc
    try:
        item = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    mode = stat.S_IMODE(item.st_mode)
    allowed = {0o711, 0o755}
    if peer_uid == os.geteuid():
        allowed.add(0o700)
    if (
        not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.geteuid()
        or mode not in allowed
        or mode & 0o022
    ):
        raise EducationTransportError(
            "endpoint directory is not a dedicated traversable target directory"
        )
    for parent in directory.parents:
        try:
            ancestor = parent.lstat()
        except OSError as exc:
            raise EducationTransportError("endpoint directory ancestors are unavailable") from exc
        sticky_root = ancestor.st_uid == 0 and bool(ancestor.st_mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(ancestor.st_mode)
            or ancestor.st_uid not in (0, os.geteuid())
            or (ancestor.st_mode & 0o022 and not sticky_root)
        ):
            raise EducationTransportError(
                "endpoint directory ancestors permit unsafe replacement"
            )
    return directory


def _target_peer(target: object) -> dict:
    return validate_peer(target.peer)


def _check_target(target: object) -> None:
    if not callable(getattr(target, "handle", None)):
        raise EducationTransportError("education target must expose handle")
    _target_peer(target)


def _serve_connection(
    channel: socket.socket,
    target: object,
    enrolled: _PinnedProcess,
    expected: Mapping[str, Any],
    *,
    target_lock: Lock,
) -> None:
    """Serve one credential-bound connection with a READY-before-request handshake."""
    submitted = False
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        channel.settimeout(CONNECTION_TIMEOUT_SECONDS)
        deadline = time.monotonic() + CONNECTION_TIMEOUT_SECONDS
        credentials = _peer_credentials(channel)
        if credentials != (expected["pid"], expected["uid"], expected["gid"]):
            raise _PeerDenied("connection comes from an unenrolled process")
        enrolled.match_credentials(credentials)
        _safe_send(channel, _READY, close_write=False)

        data, ancillary, _ = _recv(channel)
        if not data:
            raise EducationTransportError("empty education request")
        _credentials(ancillary, credentials)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EducationTransportError("education request deadline expired")
        channel.settimeout(remaining)
        _expect_eof(channel)
        if time.monotonic() >= deadline:
            raise EducationTransportError("education request deadline expired")
        action, packet = _decode_request(data)

        # Socket parsing may be concurrent, but target admission and durable
        # state changes remain serial at this process boundary.
        with target_lock:
            peer = enrolled.match_credentials(credentials)
            submitted = True
            result = target.handle(action, packet, peer)
        if type(result) is not dict:
            raise EducationTransportError("education target returned an invalid result")
        enrolled.match_credentials(credentials)
    except _PeerDenied:
        result = _PEER_DENIED
    except Exception:
        result = _UNKNOWN if submitted else _REJECTED
    _safe_terminal(channel, result)


def serve(
    target: object,
    socket_path: object,
    *,
    on_ready=None,
    stop_event=None,
    metrics: Optional[TransportMetrics] = None,
) -> None:
    """Serve one target endpoint until stopped or the fixed caller dies.

    The configured caller is pidfd-pinned before bind and remeasured before
    every target action. Caller exit stops the listener. A request with changed
    process measurements is refused. An admitted
    connection receives a credential-bearing READY frame before it may send
    its sole read/reconcile request.
    """
    _linux_controls()
    if os.geteuid() == 0:
        raise EducationTransportError("education target transport refuses to run as root")
    _check_target(target)
    expected = _target_peer(target)
    if expected["uid"] == 0:
        raise EducationTransportError("education caller must be non-root")
    if on_ready is not None and not callable(on_ready):
        raise TypeError("on_ready must be callable")
    if stop_event is not None and not callable(getattr(stop_event, "is_set", None)):
        raise TypeError("stop_event must expose is_set")
    if metrics is None:
        metrics = TransportMetrics()
    elif type(metrics) is not TransportMetrics:
        raise TypeError("metrics must be TransportMetrics")
    try:
        path = Path(os.fspath(socket_path)).absolute()
    except (TypeError, OSError) as exc:
        raise EducationTransportError("invalid endpoint path") from exc
    directory = _endpoint_directory(path, expected["uid"])
    if os.path.lexists(path):
        raise EducationTransportError("endpoint path already exists")

    bound = None
    slots = BoundedSemaphore(MAX_ACTIVE_CONNECTIONS)
    target_lock = Lock()

    with _PinnedProcess(
        expected["pid"], expected=expected, fixed_caller=True, endpoint=str(path)
    ) as enrolled:
        def handle(channel: socket.socket) -> None:
            try:
                with channel:
                    _serve_connection(
                        channel, target, enrolled, expected, target_lock=target_lock
                    )
            finally:
                metrics._end()
                slots.release()

        def reject(channel: socket.socket, field: str, result: Mapping[str, Any]) -> None:
            with channel:
                channel.setblocking(False)
                _safe_terminal(channel, result)
            metrics._reject(field)

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            listener.bind(str(path))
            os.chmod(path, 0o666)
            item = path.lstat()
            if (
                not stat.S_ISSOCK(item.st_mode)
                or item.st_uid != os.geteuid()
                or stat.S_IMODE(item.st_mode) != 0o666
            ):
                raise EducationTransportError("endpoint binding is unsafe")
            bound = (item.st_dev, item.st_ino)
            _endpoint_inventory(directory, path.name)
            listener.listen(LISTEN_BACKLOG)
            listener.settimeout(0.25)
            with ThreadPoolExecutor(
                max_workers=MAX_ACTIVE_CONNECTIONS,
                thread_name_prefix="education-local",
            ) as pool:
                if on_ready is not None:
                    on_ready()
                while stop_event is None or not stop_event.is_set():
                    if not enrolled.alive():
                        break
                    try:
                        channel, _address = listener.accept()
                    except (socket.timeout, InterruptedError):
                        continue
                    if stop_event is not None and stop_event.is_set():
                        channel.close()
                        break
                    try:
                        credentials = _peer_credentials(channel)
                    except (OSError, RuntimeError):
                        reject(channel, "rejected_credentials", _REJECTED)
                        continue
                    if credentials != (
                        expected["pid"], expected["uid"], expected["gid"]
                    ):
                        reject(channel, "rejected_credentials", _PEER_DENIED)
                        continue
                    try:
                        enrolled.match_credentials(credentials)
                    except (OSError, ValueError, RuntimeError):
                        reject(channel, "rejected_credentials", _REJECTED)
                        continue
                    if not slots.acquire(blocking=False):
                        reject(channel, "rejected_capacity", _REJECTED)
                        continue
                    metrics._begin()
                    try:
                        pool.submit(handle, channel)
                    except RuntimeError:
                        channel.close()
                        metrics._end()
                        slots.release()
                        raise
        except KeyboardInterrupt:
            return
        finally:
            try:
                listener.close()
            finally:
                if bound is not None:
                    try:
                        item = path.lstat()
                        if (
                            stat.S_ISSOCK(item.st_mode)
                            and (item.st_dev, item.st_ino) == bound
                        ):
                            path.unlink()
                    except OSError:
                        pass


class _ClientSession:
    """Internal READY-validated channel for controlled lost-reply qualification."""

    def __init__(
        self,
        channel: socket.socket,
        target: _PinnedProcess,
        credentials: tuple[int, int, int],
    ) -> None:
        self._channel = channel
        self._target = target
        self._credentials = credentials
        self._sent = False
        self._closed = False

    def send(self, action: str, packet: object) -> None:
        if self._closed or self._sent:
            raise EducationTransportError("education request session is not writable")
        raw = _encode_request(action, packet)
        self._target.match_credentials(self._credentials)
        _safe_send(self._channel, raw, close_write=True)
        self._sent = True

    def receive(self) -> dict:
        if self._closed or not self._sent:
            raise EducationTransportError("education request was not sent")
        try:
            data, ancillary, _ = _recv(self._channel)
            if not data:
                raise EducationTransportError("empty education response")
            _credentials(ancillary, self._credentials)
            _expect_eof(self._channel)
            self._target.match_credentials(self._credentials)
            return _decode_result(data)
        finally:
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._channel.close()
        finally:
            self._target.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _open_client_session(socket_path: object, *, expected_target_pid: int) -> _ClientSession:
    """Open a READY-validated internal session; callers must close it."""
    _linux_controls()
    expected_target_pid = _unsigned(
        expected_target_pid, "expected target PID", positive=True
    )
    try:
        path = Path(os.fspath(socket_path)).absolute()
        item = path.lstat()
    except (TypeError, OSError) as exc:
        raise EducationTransportError("endpoint is unavailable") from exc
    if not stat.S_ISSOCK(item.st_mode):
        raise EducationTransportError("endpoint is not a socket")
    target = _PinnedProcess(expected_target_pid)
    channel = None
    try:
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        channel.settimeout(CONNECT_TIMEOUT_SECONDS)
        channel.connect(str(path))
        credentials = _peer_credentials(channel)
        target.match_credentials(credentials)
        data, ancillary, _ = _recv(channel)
        if not data:
            raise EducationTransportError("target did not signal readiness")
        _credentials(ancillary, credentials)
        if data != _READY:
            terminal = _decode_result(data)
            raise _TerminalResult(terminal)
        target.match_credentials(credentials)
        return _ClientSession(channel, target, credentials)
    except BaseException:
        if channel is not None:
            channel.close()
        target.close()
        raise


def request(
    path: object,
    action: str,
    packet: object,
    *,
    expected_target_pid: int,
) -> dict:
    """Send one read/reconcile request through a pidfd-validated target endpoint."""
    try:
        session = _open_client_session(path, expected_target_pid=expected_target_pid)
    except _TerminalResult as exc:
        return dict(exc.result)
    except (OSError, RuntimeError):
        return dict(_UNAVAILABLE)
    with session:
        try:
            session.send(action, packet)
            return session.receive()
        except (OSError, RuntimeError):
            # Once dispatch starts, the peer may have committed before loss
            # of the write acknowledgement, the response, or either process.
            return dict(_UNKNOWN)


def main(argv=None) -> int:
    """Run one provisioned target process; READY is emitted over its endpoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path)
    parser.add_argument("anchor", type=Path)
    parser.add_argument("socket", type=Path)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args(argv)
    try:
        _linux_controls()
        from .education_target import EducationTarget

        with EducationTarget(args.state, args.anchor, create=args.create) as target:
            serve(target, args.socket)
        return 0
    except KeyboardInterrupt:
        return 0
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        print(json.dumps(_UNAVAILABLE, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "CONNECT_TIMEOUT_SECONDS",
    "CONNECTION_TIMEOUT_SECONDS",
    "EducationTransportError",
    "LISTEN_BACKLOG",
    "MAX_ACTIVE_CONNECTIONS",
    "MAX_FRAME_BYTES",
    "measure_peer",
    "request",
    "serve",
)
