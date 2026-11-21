"""Narrow Linux live-caller authority for the checked-in Quorvane fixture.

This module authenticates one fixed local process over an inherited Unix
sequenced-packet socket. It is not a generic sandbox or a confinement claim:
the authority is limited to process identity and per-packet kernel credentials
on this local host.
"""
from __future__ import annotations

from array import array
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import subprocess
import sys
from threading import RLock
import time


MAX_MESSAGE_BYTES = 65_536
START_TIMEOUT_SECONDS = 2.0
EXCHANGE_TIMEOUT_SECONDS = 5.0
_TYPE = "wolfalibi.quorvane.live.v1"
_RUN_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_CHALLENGE = re.compile(r"[0-9a-f]{64}\Z")
_INT_SIZE = array("i").itemsize
_CREDENTIAL_SIZE = 3 * _INT_SIZE
_ANCILLARY_SPACE = socket.CMSG_SPACE(_CREDENTIAL_SIZE) + socket.CMSG_SPACE(32 * _INT_SIZE)
_PYTHON = Path(sys.executable).resolve()

# This standalone source is intentionally the only worker LiveCaller launches.
# It uses no package imports, paths, secrets, files, listeners, or privileges.
_FIXTURE_SOURCE = r'''import json
import os
import socket
import sys

MAX_PACKET = 65536

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def reject_constant(value):
    raise ValueError

def receive(channel):
    data, ancillary, flags, _ = channel.recvmsg(MAX_PACKET, 1)
    if not data and not ancillary:
        raise EOFError
    if (not data or ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)):
        raise ValueError
    value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=reject_constant,
                       parse_float=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(value) is not dict or canonical(value) != data:
        raise ValueError
    return data, value

def main():
    run_id, challenge = sys.argv[1:]
    with socket.socket(fileno=0) as channel:
        while True:
            try:
                raw, value = receive(channel)
            except EOFError:
                return 0
            except ValueError:
                return 3
            if (value.keys() != {"type", "run_id", "challenge", "message"}
                    or value["type"] != "quorvane-live-request"
                    or value["run_id"] != run_id or value["challenge"] != challenge
                    or type(value["message"]) is not dict):
                return 3
            if channel.send(raw) != len(raw):
                return 4

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        os._exit(3)
'''
_FIXTURE_BYTES = _FIXTURE_SOURCE.encode("ascii")
_FIXTURE_SHA256 = hashlib.sha256(_FIXTURE_BYTES).hexdigest()


class LiveCallerError(RuntimeError):
    """The fixed live caller cannot currently be authenticated."""


class _InvalidPacket(ValueError):
    """A packet or copied run is not bounded canonical JSON."""


def _duplicates(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise _InvalidPacket("duplicate JSON field")
        result[name] = value
    return result


def _reject_constant(_value):
    raise _InvalidPacket("non-finite JSON value")


def _reject_float(_value):
    raise _InvalidPacket("floating-point JSON value")


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _decode(raw: bytes, *, maximum: int) -> object:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise _InvalidPacket("packet size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
        if _canonical(value) != raw:
            raise _InvalidPacket("noncanonical packet")
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError,
            OverflowError, RecursionError) as exc:
        raise _InvalidPacket("packet encoding") from exc


def _copy_json(value, *, maximum: int) -> object:
    try:
        raw = _canonical(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise _InvalidPacket("non-JSON value") from exc
    if len(raw) > maximum:
        raise _InvalidPacket("packet too large")
    return _decode(raw, maximum=maximum)


def _read_at(directory: int, name: str, *, binary: bool = False):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        value = stream.read()
    return value if binary else os.fsdecode(value)


def _start_ticks(directory: int) -> tuple[int, int]:
    # A comm field may contain whitespace and closing parentheses.
    fields = _read_at(directory, "stat").rsplit(")", 1)[1].split()
    return int(fields[1]), int(fields[19])


def _hash_fd(directory: int, name: str) -> str:
    digest = hashlib.sha256()
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _status(directory: int) -> dict[str, str]:
    fields = {}
    for line in _read_at(directory, "status").splitlines():
        label, separator, value = line.partition(":\t")
        if separator:
            fields[label] = value
    return fields


def _close_rights(ancillary) -> None:
    """Close all received SCM_RIGHTS before rejecting the packet."""
    for level, kind, value in ancillary:
        if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            continue
        descriptors = array("i")
        descriptors.frombytes(value[:len(value) - len(value) % _INT_SIZE])
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _credentials(ancillary) -> tuple[int, int, int]:
    if [(level, kind, len(value)) for level, kind, value in ancillary] != [
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, _CREDENTIAL_SIZE)]:
        raise LiveCallerError("live caller kernel credentials are unavailable")
    values = array("i")
    values.frombytes(ancillary[0][2])
    if len(values) != 3:
        raise LiveCallerError("live caller kernel credentials are invalid")
    return tuple(values)


class LiveCaller:
    """Launch and authenticate the one fixed local synchronous echo fixture."""

    def __init__(self, run):
        try:
            copied = _copy_json(run, maximum=MAX_MESSAGE_BYTES)
        except _InvalidPacket as exc:
            raise ValueError("run must be a bounded plain JSON object") from exc
        if type(copied) is not dict:
            raise ValueError("run must be a bounded plain JSON object")
        run_id, challenge = copied.get("run_id"), copied.get("challenge")
        if (type(run_id) is not str or _RUN_ID.fullmatch(run_id) is None or
                type(challenge) is not str or _CHALLENGE.fullmatch(challenge) is None):
            raise ValueError("run requires a canonical run_id and challenge")
        self._run = copied
        self._lock = RLock()
        self._run_id = run_id
        self._challenge = challenge
        self._channel = None
        self._process = None
        self._pidfd = None
        self._procdir = None
        self._baseline = None
        self._endpoint_inode = None
        self._expected_uid = os.geteuid()
        self._expected_gid = os.getegid()

    @property
    def run(self) -> dict:
        """Return a fresh plain copy; extra run fields are never put in argv."""
        return _copy_json(self._run, maximum=MAX_MESSAGE_BYTES)

    def __enter__(self):
        with self._lock:
            if self._channel is not None:
                raise LiveCallerError("live caller is already started")
            self._start()
        return self

    def __exit__(self, *_):
        self.close()

    def _supported(self) -> None:
        required = ("AF_UNIX", "SOCK_SEQPACKET", "SO_PASSCRED", "SCM_CREDENTIALS",
                    "SCM_RIGHTS", "MSG_CMSG_CLOEXEC")
        if (sys.platform != "linux" or not hasattr(os, "pidfd_open") or
                any(not hasattr(socket, name) for name in required)):
            raise LiveCallerError("Linux pidfd and Unix credentialed seqpacket support are required")
        if not _PYTHON.is_file() or not Path("/proc").is_dir():
            raise LiveCallerError("fixed caller runtime or procfs is unavailable")

    def _start(self) -> None:
        self._supported()
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        proc = None
        try:
            parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            endpoint_inode = os.fstat(child.fileno()).st_ino
            proc = subprocess.Popen(
                [
                    str(_PYTHON), "-I", "-S", "-B", "-c", _FIXTURE_SOURCE,
                    self._run_id, self._challenge,
                ],
                stdin=child.fileno(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, env={"LC_ALL": "C"}, start_new_session=True,
            )
            child.close()
            self._channel = parent
            self._process = proc
            self._pidfd = os.pidfd_open(proc.pid)
            self._procdir = os.open(
                Path("/proc") / str(proc.pid),
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            self._endpoint_inode = endpoint_inode
            deadline = time.monotonic() + START_TIMEOUT_SECONDS
            last_error = None
            while time.monotonic() < deadline:
                try:
                    identity = self._measure()
                except LiveCallerError as exc:
                    last_error = exc
                    if proc.poll() is not None:
                        break
                    time.sleep(0.01)
                    continue
                self._baseline = identity
                return
            raise LiveCallerError("fixed live caller did not reach its pinned identity") from last_error
        except (OSError, subprocess.SubprocessError, LiveCallerError):
            self.close()
            raise
        finally:
            if child.fileno() >= 0:
                child.close()

    def _alive(self) -> None:
        if self._channel is None or self._process is None or self._pidfd is None or self._procdir is None:
            raise LiveCallerError("live caller is not running")
        poller = select.poll()
        poller.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0) or self._process.poll() is not None:
            raise LiveCallerError("live caller exited or changed")

    def _measure(self) -> dict:
        """Return a stable snapshot from retained pidfd/proc-dir handles."""
        try:
            self._alive()
            ppid, ticks = _start_ticks(self._procdir)
            if ppid != os.getpid():
                raise LiveCallerError("live caller parent identity changed")
            executable = os.readlink("exe", dir_fd=self._procdir)
            executable_digest = _hash_fd(self._procdir, "exe")
            if executable_digest != _hash_file(_PYTHON):
                raise LiveCallerError("live caller executable digest changed")
            argv = _read_at(self._procdir, "cmdline", binary=True).split(b"\0")
            expected = [
                os.fsencode(str(_PYTHON)), b"-I", b"-S", b"-B", b"-c", _FIXTURE_BYTES,
                self._run_id.encode("ascii"), self._challenge.encode("ascii"), b"",
            ]
            if argv != expected:
                raise LiveCallerError("live caller command line changed")
            status = _status(self._procdir)
            uid = [int(value) for value in status["Uid"].split()]
            gid = [int(value) for value in status["Gid"].split()]
            if (len(uid) != 4 or len(gid) != 4 or any(value != self._expected_uid for value in uid)
                    or any(value != self._expected_gid for value in gid)):
                raise LiveCallerError("live caller credentials changed")
            if _read_at(self._procdir, "environ", binary=True) != b"LC_ALL=C\0":
                raise LiveCallerError("live caller environment changed")
            fd_dir = os.open("fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=self._procdir)
            try:
                if set(os.listdir(fd_dir)) != {"0", "1", "2"}:
                    raise LiveCallerError("live caller descriptor set changed")
                endpoint = os.stat("0", dir_fd=fd_dir)
                stdout = os.stat("1", dir_fd=fd_dir)
                stderr = os.stat("2", dir_fd=fd_dir)
            finally:
                os.close(fd_dir)
            if (not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_ino != self._endpoint_inode or
                    not stat.S_ISCHR(stdout.st_mode) or not stat.S_ISCHR(stderr.st_mode) or
                    [os.major(stdout.st_rdev), os.minor(stdout.st_rdev)] != [1, 3] or
                    [os.major(stderr.st_rdev), os.minor(stderr.st_rdev)] != [1, 3]):
                raise LiveCallerError("live caller descriptor identity changed")
            self._alive()
        except LiveCallerError:
            raise
        except (OSError, KeyError, ValueError, IndexError) as exc:
            raise LiveCallerError("live caller proc measurements are unavailable") from exc
        return {
            "type": _TYPE,
            "pid": self._process.pid,
            "start_ticks": ticks,
            "executable": {
                "path": executable,
                "sha256": executable_digest,
                "source_sha256": _FIXTURE_SHA256,
                "flags": ["-I", "-S", "-B", "-c"],
            },
            "run_id": self._run_id,
            "challenge": self._challenge,
            "credentials": {"uid": self._expected_uid, "gid": self._expected_gid},
            "environment": {"LC_ALL": "C"},
            "descriptors": {
                "0": {"kind": "socket", "inode": str(self._endpoint_inode)},
                "1": {"kind": "character_device", "major": 1, "minor": 3},
                "2": {"kind": "character_device", "major": 1, "minor": 3},
            },
            "provisioning": {
                "argv_fields": ["run_id", "challenge"],
                "credential_metadata": "kernel_scm_credentials_per_packet",
                "network": "not_created_by_fixture",
                "stdout": "null",
                "stderr": "null",
            },
        }

    def identity(self) -> dict:
        """Return a fresh stable identity or fail if the process changed."""
        with self._lock:
            identity = self._measure()
            if self._baseline is None:
                self._baseline = identity
            if identity != self._baseline:
                raise LiveCallerError("live caller identity changed")
            return _copy_json(identity, maximum=MAX_MESSAGE_BYTES)

    def _receive(self) -> bytes:
        try:
            self._channel.settimeout(EXCHANGE_TIMEOUT_SECONDS)
            data, ancillary, flags, _ = self._channel.recvmsg(
                MAX_MESSAGE_BYTES,
                _ANCILLARY_SPACE,
                socket.MSG_CMSG_CLOEXEC,
            )
        except (OSError, ValueError) as exc:
            raise LiveCallerError("live caller response is unavailable") from exc
        _close_rights(ancillary)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise LiveCallerError("live caller response is truncated or has control data")
        if not data:
            raise LiveCallerError("live caller closed its authenticated channel")
        pid, uid, gid = _credentials(ancillary)
        if (pid, uid, gid) != (self._process.pid, self._expected_uid, self._expected_gid):
            raise LiveCallerError("live caller kernel credentials differ from its live identity")
        return data

    def exchange(self, message) -> dict:
        """Send one opaque canonical JSON object and return the fixture's echo."""
        with self._lock:
            return self._exchange(message)

    def _require_idle_channel(self):
        poller = select.poll()
        poller.register(self._channel, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            self._close()
            raise LiveCallerError("unexpected data or hangup on the live caller channel")

    def _exchange(self, message):
        try:
            copied = _copy_json(message, maximum=MAX_MESSAGE_BYTES // 2)
        except _InvalidPacket as exc:
            raise ValueError("message must be a bounded plain JSON object") from exc
        if type(copied) is not dict:
            raise ValueError("message must be a bounded plain JSON object")
        before = self.identity()
        self._require_idle_channel()
        frame = {
            "type": "quorvane-live-request",
            "run_id": self._run_id,
            "challenge": self._challenge,
            "message": copied,
        }
        raw = _canonical(frame)
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("message exceeds the live caller packet bound")
        try:
            self._channel.settimeout(EXCHANGE_TIMEOUT_SECONDS)
            if self._channel.send(raw) != len(raw):
                raise LiveCallerError("live caller request send was incomplete")
        except LiveCallerError:
            raise
        except OSError as exc:
            raise LiveCallerError("live caller request is unavailable") from exc
        response = self._receive()
        if response != raw:
            raise LiveCallerError("live caller did not echo the exact fixed protocol")
        try:
            decoded = _decode(response, maximum=MAX_MESSAGE_BYTES)
        except _InvalidPacket as exc:
            raise LiveCallerError("live caller response is not canonical JSON") from exc
        if type(decoded) is not dict or decoded != frame:
            raise LiveCallerError("live caller response differs from its request")
        after = self.identity()
        if after != before:
            raise LiveCallerError("live caller changed during the exchange")
        self._require_idle_channel()
        return _copy_json(decoded["message"], maximum=MAX_MESSAGE_BYTES // 2)

    def close(self) -> None:
        """Close the private endpoint and reclaim the fixed child process."""
        with self._lock:
            self._close()

    def _close(self):
        channel, process, pidfd, procdir = self._channel, self._process, self._pidfd, self._procdir
        self._channel = self._process = self._pidfd = self._procdir = None
        self._baseline = None
        if channel is not None:
            try:
                channel.close()
            except OSError:
                pass
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        for descriptor in (pidfd, procdir):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


__all__ = ("LiveCaller", "LiveCallerError", "MAX_MESSAGE_BYTES")
