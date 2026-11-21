"""The fixed synthetic worker and its Bubblewrap launch profile.

The profile describes requested controls and local artifact measurements.
The worker's two observations cover one path and one descriptor.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys


_SYSTEM_PYTHON = Path("/usr/bin/python3")
_BWRAP = Path("/usr/bin/bwrap")
_MULTIARCH = Path("/usr/lib/x86_64-linux-gnu")
_LOADER = Path("/lib64/ld-linux-x86-64.so.2")
_LAUNCH_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
_MAX_PACKET = 128 * 1024
_MODES = {"normal", "duplicate", "terminate", "wait"}
_CONTROLS = (
    "--unshare-user", "--uid", "1000", "--gid", "1000",
    "--unshare-pid", "--unshare-ipc", "--unshare-net", "--unshare-uts",
    "--disable-userns", "--as-pid-1", "--die-with-parent", "--new-session",
    "--cap-drop", "ALL", "--clearenv", "--dir", "/work", "--chdir", "/work",
)


class UnsupportedWorker(RuntimeError):
    """The fixed Linux worker profile cannot be constructed on this host."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _tool_output(command: list[str]) -> str:
    return subprocess.check_output(
        command, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8", env=_LAUNCH_ENV, timeout=5,
    ).strip()


def _profile(source: bytes) -> dict:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise UnsupportedWorker("the fixed worker requires Linux x86_64")
    if not hasattr(socket, "SOCK_SEQPACKET"):
        raise UnsupportedWorker("Unix sequenced-packet sockets are unavailable")
    try:
        launcher = _BWRAP.resolve(strict=True)
        python = _SYSTEM_PYTHON.resolve(strict=True)
        if (python.parent != Path("/usr/bin") or
                re.fullmatch(r"python3\.\d+", python.name) is None):
            raise UnsupportedWorker("the worker requires the system CPython runtime")
        stdlib = Path("/usr/lib") / python.name
        library = stdlib.resolve(strict=True)
        if not library.is_dir() or not _MULTIARCH.is_dir() or not _LOADER.is_file():
            raise UnsupportedWorker("the fixed x86_64 runtime mounts are unavailable")
        mounts = [
            (str(python), str(python)),
            (str(library), str(stdlib)),
            (str(_MULTIARCH.resolve(strict=True)), "/lib/x86_64-linux-gnu"),
            (str(_LOADER.resolve(strict=True)), str(_LOADER)),
        ]
        return {
            "type": "WOLFALIBI_STAGE3_FIXED_WORKER_V1",
            "assurance": "BLOCKED",
            "worker_sha256": hashlib.sha256(source).hexdigest(),
            "launcher": str(launcher),
            "launcher_version": _tool_output([str(launcher), "--version"]),
            "launcher_sha256": _sha256_file(launcher),
            "kernel_release": platform.release(),
            "python": str(python),
            "python_abi": python.name,
            "python_sha256": _sha256_file(python),
            "controls": list(_CONTROLS),
            "readonly_mounts": [
                {"source": src, "destination": dst} for src, dst in mounts
            ],
            "broker_descriptor": 0,
            "stdout": "devnull",
            "stderr": "devnull",
            "artifact_binding": "DECLARED_LOCAL_ARTIFACT_NOT_EXECUTION_ATTESTATION",
        }
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise UnsupportedWorker("system Bubblewrap or CPython prerequisite failed") from error


def worker_profile() -> dict:
    """Return the declared profile and hashes of the local launch artifacts."""
    return _profile(Path(__file__).read_bytes())


def launch(endpoint: socket.socket, root: Path, key: str, run_id: str,
           challenge: bytes, canary_fd: int, *, mode: str = "normal",
           expected_profile: dict | None = None) -> subprocess.Popen:
    """Run the fixed worker with one bidirectional stdio broker endpoint."""
    if mode not in _MODES:
        raise ValueError("unknown synthetic worker mode")
    source = Path(__file__).read_bytes()
    profile = _profile(source)
    if expected_profile is not None and _canonical(expected_profile) != _canonical(profile):
        raise ValueError("worker launch profile changed after measurement")
    root = Path(root).resolve(strict=True)
    command = [profile["launcher"], *profile["controls"]]
    for mount in profile["readonly_mounts"]:
        host_path = Path(mount["source"])
        if root == host_path or root in host_path.parents or host_path in root.parents:
            raise ValueError("the protected root overlaps a worker runtime mount")
        command.extend(["--ro-bind", mount["source"], mount["destination"]])
    command.extend([
        "--", profile["python"], "-I", "-S", "-B", "-c", source.decode("utf-8"),
        str(root / key), key, run_id, challenge.hex(), str(canary_fd), mode,
    ])
    return subprocess.Popen(
        command, stdin=endpoint.fileno(), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True, env=_LAUNCH_ENV,
        start_new_session=True,
    )


def _canonical(packet: dict) -> bytes:
    return json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()


def _send(channel: socket.socket, packet: dict) -> None:
    payload = _canonical(packet)
    if channel.send(payload) != len(payload):
        raise OSError("short sequenced-packet send")


def _direct_denied(path: str) -> bool:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as error:
        return error.errno in {errno.ENOENT, errno.EACCES, errno.EPERM}
    os.close(fd)
    return False


def _canary_closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError as error:
        return error.errno == errno.EBADF
    return False


def _worker_main() -> int:
    path, key, run_id, challenge, canary_fd, mode = sys.argv[1:]
    if os.getpid() != 1 or os.getuid() != 1000 or os.getgid() != 1000:
        return 2
    with socket.socket(fileno=0) as channel:
        request = {
            "type": "read", "seq": 1, "key": key, "run_id": run_id,
            "challenge": challenge,
            "direct_denied": _direct_denied(path),
            "canary_closed": _canary_closed(int(canary_fd)),
        }
        _send(channel, request)
        payload, ancillary, flags, _ = channel.recvmsg(_MAX_PACKET)
        if not payload or ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            return 3
        response = json.loads(payload)
        if _canonical(response) != payload or response.get("type") != "data":
            return 3
        data = bytes.fromhex(response["data"])
        if mode == "terminate":
            os._exit(4)
        if mode == "duplicate":
            _send(channel, request)
            return 5
        if mode == "wait":
            channel.recv(1)
            return 6
        _send(channel, {"type": "done", "data_sha256": hashlib.sha256(data).hexdigest()})
    return 0


if __name__ == "__main__":
    raise SystemExit(_worker_main())
