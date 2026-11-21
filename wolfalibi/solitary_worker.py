"""Fixed synthetic Solitary worker and its declared Linux launch profile."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys


POLICY_VERSION = "WOLFALIBI_SOLITARY_SECCOMP_V1"
LIMITS = {
    "RLIMIT_AS": [134217728, 134217728],
    "RLIMIT_CPU": [2, 2],
    "RLIMIT_FSIZE": [4096, 4096],
    "RLIMIT_NOFILE": [16, 16],
    "RLIMIT_CORE": [0, 0],
}
CONTROL_RESULTS = {
    "ambient_canary_absent": True,
    "scratch_roundtrip": True,
    "file_size_cap_enforced": True,
    "new_socket_denied": True,
    "fork_denied": True,
    "protected_write_denied": True,
    "exec_denied": True,
}
_ALLOW_SYSCALLS = (
    "brk", "close", "exit", "exit_group", "fstat", "mmap", "mremap", "munmap",
    "newfstatat", "openat", "read", "rt_sigprocmask", "rt_sigreturn", "write",
)
_ALLOW_FD0_SYSCALLS = ("recvmsg", "sendto")
_LIBSECCOMP = "libseccomp.so.2"
_MULTIARCH = "/lib/x86_64-linux-gnu"
_ENV_CANARY = "WOLFALIBI_SOLITARY_ENV_CANARY"
_MAX_PACKET = 4096


def _profile(source: bytes) -> dict:
    from .stage3_worker import UnsupportedWorker, _profile as base_profile, _sha256_file

    profile = base_profile(source)
    library = Path("/usr/lib/x86_64-linux-gnu", _LIBSECCOMP)
    try:
        library_digest = _sha256_file(library)
    except OSError as exc:
        raise UnsupportedWorker("Solitary requires system libseccomp.so.2") from exc
    profile["solitary"] = {
        "policy_version": POLICY_VERSION,
        "limits": {name: values[:] for name, values in LIMITS.items()},
        "control_results": dict(CONTROL_RESULTS),
        "seccomp": {
            "library_sha256": library_digest,
            "default_errno": errno.EPERM,
            "allow": list(_ALLOW_SYSCALLS),
            "allow_fd0": list(_ALLOW_FD0_SYSCALLS),
        },
    }
    return profile


def worker_profile() -> dict:
    """Describe the qualified program and requested controls."""
    return _profile(Path(__file__).read_bytes())


def launch(endpoint: socket.socket, root: Path, key: str, run_id: str,
           challenge: bytes, canary_fd: int, *, mode: str = "normal",
           expected_profile: dict | None = None) -> subprocess.Popen:
    """Start the fixed worker with the inherited broker endpoint on FD 0."""
    from .stage3_worker import _LAUNCH_ENV

    if mode != "normal":
        raise ValueError("Solitary only supports the normal fixed worker")
    source = Path(__file__).read_bytes()
    profile = _profile(source)
    if expected_profile is not None and _canonical(expected_profile) != _canonical(profile):
        raise ValueError("Solitary launch profile changed after measurement")
    root = Path(root).resolve(strict=True)
    command = [profile["launcher"], *profile["controls"]]
    for mount in profile["readonly_mounts"]:
        host_path = Path(mount["source"])
        if root == host_path or root in host_path.parents or host_path in root.parents:
            raise ValueError("the protected root overlaps a Solitary runtime mount")
        command.extend(["--ro-bind", mount["source"], mount["destination"]])
    command.extend([
        "--", profile["python"], "-I", "-S", "-B", "-c", source.decode("utf-8"),
        str(root / key), key, run_id, challenge.hex(), str(canary_fd), mode,
    ])
    launch_env = {**_LAUNCH_ENV, _ENV_CANARY: os.urandom(16).hex()}
    return subprocess.Popen(
        command, stdin=endpoint.fileno(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True, env=launch_env,
        start_new_session=True,
    )


def _install_limits() -> None:
    import resource

    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    for name, values in LIMITS.items():
        kind = getattr(resource, name)
        resource.setrlimit(kind, values)
        if resource.getrlimit(kind) != tuple(values):
            raise RuntimeError("Solitary rlimit setup failed")


def _install_seccomp() -> None:
    import ctypes as C

    class ArgumentComparison(C.Structure):
        _fields_ = [
            ("argument", C.c_uint), ("comparison", C.c_int),
            ("datum_a", C.c_uint64), ("datum_b", C.c_uint64),
        ]

    lib = C.CDLL(f"{_MULTIARCH}/{_LIBSECCOMP}")
    lib.seccomp_init.argtypes = (C.c_uint32,)
    lib.seccomp_init.restype = C.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = (C.c_char_p,)
    lib.seccomp_syscall_resolve_name.restype = C.c_int
    lib.seccomp_rule_add_array.argtypes = (
        C.c_void_p, C.c_uint32, C.c_int, C.c_uint, C.POINTER(ArgumentComparison),
    )
    lib.seccomp_rule_add_array.restype = C.c_int
    lib.seccomp_load.argtypes = (C.c_void_p,)
    lib.seccomp_load.restype = C.c_int
    lib.seccomp_release.argtypes = (C.c_void_p,)
    lib.seccomp_release.restype = None

    allow, errno_action = 0x7fff0000, 0x00050000
    compare_equal = 4
    context = lib.seccomp_init(errno_action | errno.EPERM)
    if not context:
        raise RuntimeError("could not create the Solitary seccomp filter")
    try:
        for name in _ALLOW_SYSCALLS:
            number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0 or lib.seccomp_rule_add_array(context, allow, number, 0, None) != 0:
                raise RuntimeError("could not add a Solitary seccomp rule")
        fd0 = ArgumentComparison(0, compare_equal, 0, 0)
        for name in _ALLOW_FD0_SYSCALLS:
            number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0 or lib.seccomp_rule_add_array(context, allow, number, 1, C.byref(fd0)) != 0:
                raise RuntimeError("could not add a Solitary broker socket rule")
        if lib.seccomp_load(context) != 0:
            raise RuntimeError("could not load the Solitary seccomp filter")
    finally:
        lib.seccomp_release(context)


def _canonical(packet: dict) -> bytes:
    return json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()


def _send(channel: socket.socket, packet: dict) -> None:
    payload = _canonical(packet)
    if channel.send(payload) != len(payload):
        raise OSError("short sequenced-packet send")


def _direct_denied(path: str, flags: int = os.O_RDONLY) -> bool:
    try:
        fd = os.open(path, flags | os.O_NONBLOCK)
    except OSError as exc:
        return exc.errno in (errno.ENOENT, errno.EACCES, errno.EPERM)
    os.close(fd)
    return False


def _canary_closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError as exc:
        return exc.errno == errno.EBADF
    return False


def _scratch_roundtrip() -> bool:
    value = b"solitary synthetic scratch"
    fd = os.open("positive.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if os.write(fd, value) != len(value):
            return False
    finally:
        os.close(fd)
    fd = os.open("positive.txt", os.O_RDONLY)
    try:
        return os.read(fd, len(value) + 1) == value
    finally:
        os.close(fd)


def _file_size_cap_enforced() -> bool:
    cap = LIMITS["RLIMIT_FSIZE"][0]
    fd = os.open("cap.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if os.write(fd, b"x" * (cap + 1)) != cap:
            return False
        try:
            os.write(fd, b"x")
        except OSError as exc:
            return exc.errno == errno.EFBIG and os.fstat(fd).st_size == cap
        return False
    finally:
        os.close(fd)


def _new_socket_denied() -> bool:
    try:
        channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return exc.errno == errno.EPERM
    channel.close()
    return False


def _fork_denied() -> bool:
    try:
        pid = os.fork()
    except OSError as exc:
        return exc.errno == errno.EPERM
    if pid == 0:
        os._exit(1)
    return False


def _exec_denied() -> bool:
    try:
        os.execv(sys.executable, (sys.executable, "-I", "-S", "-B", "-c", "raise SystemExit(5)"))
    except OSError as exc:
        return exc.errno == errno.EPERM
    return False


def _worker_main() -> int:
    path, key, run_id, challenge, canary_fd, mode = sys.argv[1:]
    if mode != "normal" or os.getpid() != 1 or os.getuid() != 1000 or os.getgid() != 1000:
        return 2
    with socket.socket(fileno=0) as channel:
        _install_limits()
        # Initialize the digest provider before narrowing the syscall surface.
        hashlib.sha256(b"")
        _install_seccomp()
        controls = {
            "ambient_canary_absent": _ENV_CANARY not in os.environ,
            "scratch_roundtrip": _scratch_roundtrip(),
            "file_size_cap_enforced": _file_size_cap_enforced(),
            "new_socket_denied": _new_socket_denied(),
            "fork_denied": _fork_denied(),
            "protected_write_denied": _direct_denied(path, os.O_WRONLY | os.O_NOFOLLOW),
            "exec_denied": _exec_denied(),
        }
        _send(channel, {
            "type": "read", "seq": 1, "key": key, "run_id": run_id,
            "challenge": challenge, "direct_denied": _direct_denied(path),
            "canary_closed": _canary_closed(int(canary_fd)), "controls": controls,
        })
        payload, ancillary, flags, _ = channel.recvmsg(_MAX_PACKET)
        if not payload or ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            return 3
        response = json.loads(payload)
        if (type(response) is not dict or response.keys() != {"type", "data"}
                or response["type"] != "data" or _canonical(response) != payload):
            return 3
        data = bytes.fromhex(response["data"])
        _send(channel, {"type": "done", "data_sha256": hashlib.sha256(data).hexdigest()})
    return 0


if __name__ == "__main__":
    # The worker closes its endpoint before returning. Use the allowed process
    # exit directly so interpreter finalizers do not expand the syscall policy.
    os._exit(_worker_main())
