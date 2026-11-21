"""Local support checks for the experimental Solitary Linux worker.

This is a bounded doctor, not a confinement receipt.  It exercises a small
set of local kernel/launcher capabilities with synthetic data and reports
which facts are merely declared versus actually exercised.  It does not
create cgroups, contact a network service, upload anything, or alter the
calling process's seccomp policy.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping

from alibi import _RESOLVE_IN_ROOT, _RESOLVE_NO_MAGICLINKS, _openat2
from .stage3_worker import UnsupportedWorker
from .solitary_worker import worker_profile


TYPE = "WOLFALIBI_SOLITARY_PREFLIGHT_V1"
ASSURANCE = "BLOCKED"
_DEFAULT_TIMEOUT = 5.0
_MAX_TIMEOUT = 15.0
_SAFE_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
_SECCOMP_ACT_ALLOW = 0x7FFF0000
_SECCOMP_ACT_ERRNO = 0x00050000
_PROCESS_SYSCALLS = ("clone", "clone3", "fork", "vfork", "unshare", "setns")


def _feature(state: str, reason: str, **details: object) -> dict[str, object]:
    return {"state": state, "reason": reason, **details}


def _canonical_digest(value: Mapping[str, object]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _platform() -> dict[str, object]:
    linux = sys.platform == "linux"
    machine = platform.machine().lower()
    supported = linux and machine == "x86_64"
    return {
        "state": "EXERCISED" if supported else "UNSUPPORTED",
        "reason": "Linux x86_64 host detected" if supported else "Solitary requires Linux x86_64",
        "system": sys.platform,
        "machine": machine,
        "kernel_release": platform.release(),
    }


def _declared_worker_profile() -> tuple[dict[str, object] | None, dict[str, object]]:
    try:
        profile = worker_profile()
    except UnsupportedWorker:
        return None, _feature("UNSUPPORTED", "fixed Stage 3 worker profile is unavailable")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None, _feature("BLOCKED", "fixed Stage 3 worker profile could not be read")
    try:
        mounts = profile["readonly_mounts"]
        controls = profile["controls"]
        solitary = profile["solitary"]
        seccomp = solitary["seccomp"]
        pins = {
            "profile_type": profile["type"],
            "profile_digest": _canonical_digest(profile),
            "launcher": profile["launcher"],
            "launcher_version": profile["launcher_version"],
            "launcher_sha256": profile["launcher_sha256"],
            "python": profile["python"],
            "python_sha256": profile["python_sha256"],
            "worker_sha256": profile["worker_sha256"],
            "readonly_mounts": mounts,
            "controls": controls,
            "solitary_policy": {
                "policy_version": solitary["policy_version"],
                "limits": solitary["limits"],
                "control_results": solitary["control_results"],
                "seccomp": seccomp,
            },
            "worker_declares_seccomp": True,
        }
        if (not isinstance(mounts, list) or not isinstance(controls, list) or
                not all(isinstance(item, dict) for item in mounts) or
                not all(isinstance(item, str) for item in controls) or
                not isinstance(solitary, dict) or not isinstance(seccomp, dict)):
            raise ValueError("malformed fixed worker profile")
    except (KeyError, TypeError, ValueError):
        return None, _feature("BLOCKED", "fixed Stage 3 worker profile has invalid declared pins")
    return profile, _feature("DECLARED", "worker profile pins were read; not execution attestation", **pins)


def _pidfd_smoke() -> dict[str, object]:
    if not hasattr(os, "pidfd_open"):
        return _feature("UNSUPPORTED", "pidfd_open is unavailable")
    fd = None
    try:
        fd = os.pidfd_open(os.getpid(), 0)
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            return _feature("BLOCKED", "pidfd unexpectedly signalled for the live supervisor")
        return _feature("EXERCISED", "pidfd_open and poll succeeded for the live supervisor")
    except OSError as exc:
        state = "UNSUPPORTED" if exc.errno in (errno.ENOSYS, errno.EINVAL) else "BLOCKED"
        return _feature(state, "pidfd smoke failed", errno=exc.errno)
    finally:
        if fd is not None:
            os.close(fd)


def _openat2_smoke() -> dict[str, object]:
    root_fd = file_fd = None
    try:
        with tempfile.TemporaryDirectory(prefix="wolfalibi-solitary-openat2-") as directory:
            root = Path(directory)
            marker = root / "synthetic-marker"
            marker.write_bytes(b"solitary-openat2-smoke\n")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            file_fd = _openat2(root_fd, "synthetic-marker", os.O_RDONLY | os.O_CLOEXEC,
                               0, _RESOLVE_IN_ROOT | _RESOLVE_NO_MAGICLINKS)
            if os.read(file_fd, 64) != b"solitary-openat2-smoke\n":
                return _feature("BLOCKED", "openat2 returned unexpected synthetic content")
        return _feature("EXERCISED", "openat2 rooted read succeeded on a temporary synthetic root")
    except OSError as exc:
        state = "UNSUPPORTED" if exc.errno in (errno.ENOSYS, errno.EINVAL) else "BLOCKED"
        return _feature(state, "openat2 rooted smoke failed", errno=exc.errno)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if root_fd is not None:
            os.close(root_fd)


def _seqpacket_smoke() -> dict[str, object]:
    if not hasattr(socket, "SOCK_SEQPACKET") or not hasattr(socket, "AF_UNIX"):
        return _feature("UNSUPPORTED", "Unix sequenced-packet sockets are unavailable")
    try:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with left, right:
            left.settimeout(1.0)
            right.settimeout(1.0)
            if left.send(b"S") != 1 or right.recv(8) != b"S":
                return _feature("BLOCKED", "Unix sequenced-packet round trip was incomplete")
        return _feature("EXERCISED", "local AF_UNIX SOCK_SEQPACKET round trip succeeded")
    except OSError as exc:
        return _feature("BLOCKED", "Unix sequenced-packet smoke failed", errno=exc.errno)


def _kernel_seccomp_status() -> dict[str, object]:
    """Check that the kernel exposes the status fields needed for observation.

    This observes the supervisor's status interface only.  It does not claim
    that its filter, if any, equals the fixed Solitary worker policy.
    """
    try:
        fields = {}
        for line in Path("/proc/self/status").read_text(encoding="ascii", errors="replace").splitlines():
            if line.startswith(("Seccomp:\t", "Seccomp_filters:\t")):
                key, value = line.split(":\t", 1)
                fields[key] = int(value.strip())
        if set(fields) != {"Seccomp", "Seccomp_filters"}:
            return _feature("UNSUPPORTED", "kernel does not expose complete seccomp status fields")
        if fields["Seccomp"] not in (0, 1, 2) or fields["Seccomp_filters"] < 0:
            return _feature("BLOCKED", "kernel reported invalid seccomp status fields")
        return _feature("EXERCISED", "kernel seccomp status interface is available",
                        supervisor_seccomp_mode=fields["Seccomp"],
                        supervisor_filter_count=fields["Seccomp_filters"])
    except (OSError, ValueError):
        return _feature("UNSUPPORTED", "kernel seccomp status fields could not be read")


def _cgroup_v2_info() -> dict[str, object]:
    """Read cgroup v2 state without making a cgroup or writing a controller."""
    root = Path("/sys/fs/cgroup")
    controllers = root / "cgroup.controllers"
    membership_visible = False
    scope = None
    try:
        membership = Path("/proc/self/cgroup").read_text(encoding="utf-8", errors="replace")
        for line in membership.splitlines():
            if not line.startswith("0::"):
                continue
            membership_visible = True
            relative = line[3:].lstrip("/")
            parts = tuple(part for part in relative.split("/") if part)
            if all(part not in (".", "..") for part in parts):
                scope = root.joinpath(*parts)
            break
    except OSError:
        pass
    if not controllers.is_file():
        return _feature("INFORMATION_ONLY", "cgroup v2 controller file is unavailable",
                        v2_mounted=False, membership_visible=membership_visible,
                        delegation="NOT_ATTEMPTED_NO_CGROUP_MUTATION")
    try:
        values = sorted(set(controllers.read_text(encoding="ascii").split()))
    except OSError:
        return _feature("INFORMATION_ONLY", "cgroup v2 controllers could not be read",
                        v2_mounted=True, membership_visible=membership_visible,
                        delegation="NOT_ATTEMPTED_NO_CGROUP_MUTATION")
    if scope is None:
        scope = root
    subtree = scope / "cgroup.subtree_control"
    return _feature(
        "INFORMATION_ONLY", "cgroup v2 was inspected without creating or configuring a scope",
        v2_mounted=True,
        controllers=values,
        membership_visible=membership_visible,
        current_scope_permission_hint={
            "directory_writable": os.access(scope, os.W_OK | os.X_OK),
            "subtree_control_writable": os.access(subtree, os.W_OK),
        },
        delegation="NOT_ATTEMPTED_NO_CGROUP_MUTATION",
    )


def _load_seccomp_library() -> tuple[ctypes.CDLL | None, dict[str, object]]:
    library_name = ctypes.util.find_library("seccomp")
    if not library_name:
        return None, _feature("UNSUPPORTED", "libseccomp is unavailable; no process-denial policy was built")
    try:
        library = ctypes.CDLL(library_name, use_errno=True)
        library.seccomp_api_get.argtypes = []
        library.seccomp_api_get.restype = ctypes.c_uint
        library.seccomp_init.argtypes = [ctypes.c_uint32]
        library.seccomp_init.restype = ctypes.c_void_p
        library.seccomp_release.argtypes = [ctypes.c_void_p]
        library.seccomp_release.restype = None
        library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        library.seccomp_syscall_resolve_name.restype = ctypes.c_int
        # seccomp_rule_add is variadic; these are its non-variadic arguments.
        library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                            ctypes.c_int, ctypes.c_uint]
        library.seccomp_rule_add.restype = ctypes.c_int
        library.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
        library.seccomp_export_bpf.restype = ctypes.c_int
        return library, _feature("DECLARED", "libseccomp loaded; no filter was applied to this process",
                                 api_level=int(library.seccomp_api_get()))
    except (AttributeError, OSError):
        return None, _feature("UNSUPPORTED", "libseccomp could not be loaded safely")


def _build_seccomp_bpf(library: ctypes.CDLL) -> tuple[int | None, dict[str, object]]:
    """Export an allow-by-default BPF filter that denies process creation.

    The filter is exported to an anonymous fd for Bubblewrap.  It is never
    loaded into this preflight process.
    """
    context = library.seccomp_init(_SECCOMP_ACT_ALLOW)
    if not context:
        return None, _feature("BLOCKED", "libseccomp could not initialize a synthetic policy")
    fd = None
    try:
        action = _SECCOMP_ACT_ERRNO | errno.EPERM
        installed: list[str] = []
        for name in _PROCESS_SYSCALLS:
            number = int(library.seccomp_syscall_resolve_name(name.encode("ascii")))
            if number < 0:
                continue
            if library.seccomp_rule_add(context, action, number, 0) != 0:
                return None, _feature("BLOCKED", "libseccomp could not add a process-denial rule")
            installed.append(name)
        if "clone" not in installed:
            return None, _feature("UNSUPPORTED", "libseccomp cannot resolve clone for the smoke policy")
        if not hasattr(os, "memfd_create"):
            return None, _feature("UNSUPPORTED", "memfd_create is unavailable for a bounded seccomp smoke")
        fd = os.memfd_create("wolfalibi-solitary-seccomp", os.MFD_CLOEXEC)
        if library.seccomp_export_bpf(context, fd) != 0:
            return None, _feature("BLOCKED", "libseccomp could not export a BPF policy")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, _feature(
            "DECLARED", "default-allow libseccomp capability-probe policy exported for Bubblewrap",
            denied_syscalls=installed, default_action="ALLOW", denial="EPERM",
            relation_to_solitary_worker_policy="NOT_THE_DECLARED_DEFAULT_DENY_WORKER_POLICY",
        )
    except OSError:
        if fd is not None:
            os.close(fd)
        return None, _feature("BLOCKED", "synthetic libseccomp policy export failed")
    finally:
        library.seccomp_release(context)


def _smoke_command(profile: Mapping[str, object], *, seccomp_fd: int | None) -> list[str]:
    launcher = profile["launcher"]
    controls = profile["controls"]
    mounts = profile["readonly_mounts"]
    runtime_destinations = tuple(item["destination"] for item in mounts)
    script = (
        "import errno,os,sys\n"
        "runtime=" + repr(runtime_destinations) + "\n"
        "if os.getpid()!=1 or os.getuid()!=1000 or os.getgid()!=1000: sys.exit(40)\n"
        "if not os.path.isdir('/work') or not all(os.path.exists(path) for path in runtime): sys.exit(41)\n"
    )
    if seccomp_fd is None:
        script += "sys.exit(0)\n"
    else:
        script += (
            "try:\n"
            "    child=os.fork()\n"
            "except OSError as error:\n"
            "    sys.exit(0 if error.errno==errno.EPERM else 42)\n"
            "else:\n"
            "    if child==0: os._exit(0)\n"
            "    os.waitpid(child,0)\n"
            "    sys.exit(43)\n"
        )
    command = [str(launcher), *controls]
    for mount in mounts:
        command.extend(["--ro-bind", str(mount["source"]), str(mount["destination"])])
    if seccomp_fd is not None:
        command.extend(["--seccomp", str(seccomp_fd)])
    command.extend(["--", str(profile["python"]), "-I", "-S", "-B", "-c", script])
    return command


def _bubblewrap_smoke(profile: Mapping[str, object], *, timeout: float,
                      seccomp_fd: int | None = None) -> dict[str, object]:
    """Exercise the exact fixed worker mounts/namespace controls with no output."""
    try:
        command = _smoke_command(profile, seccomp_fd=seccomp_fd)
        completed = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=_SAFE_ENV, close_fds=True, pass_fds=(() if seccomp_fd is None else (seccomp_fd,)),
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return _feature("BLOCKED", "Bubblewrap smoke timed out")
    except (KeyError, TypeError, ValueError, OSError):
        return _feature("BLOCKED", "Bubblewrap smoke could not start from declared worker pins")
    if completed.returncode != 0:
        return _feature("BLOCKED", "Bubblewrap smoke exited unsuccessfully",
                        child_returncode=completed.returncode)
    if seccomp_fd is None:
        return _feature(
            "EXERCISED", "Bubblewrap completed a bounded namespace/mount smoke",
            requested="user,pid,ipc,network,uts namespaces and approved read-only runtime mounts",
        )
    return _feature(
        "EXERCISED", "Bubblewrap capability probe observed synthetic process-creation denial",
        requested="approved runtime mounts plus independent default-allow libseccomp capability probe",
    )


def _remaining(deadline: float) -> float | None:
    remaining = deadline - time.monotonic()
    return remaining if remaining > 0 else None


def _overall(required: list[dict[str, object]]) -> str:
    states = {feature["state"] for feature in required}
    if "UNSUPPORTED" in states:
        return "UNSUPPORTED"
    return "READY" if states == {"EXERCISED", "DECLARED"} or states == {"EXERCISED"} else "BLOCKED"


def preflight(*, timeout: float = _DEFAULT_TIMEOUT) -> dict[str, object]:
    """Run bounded local Solitary prerequisite checks.

    ``READY`` means the listed local smokes completed.  It does not mean the
    fixed worker is a complete sandbox or that a WolfAlibi receipt has a
    stronger assurance level.  ``UNSUPPORTED`` denotes an unavailable host or
    required package; ``BLOCKED`` denotes a failed/ambiguous local smoke.
    """
    limitations = [
        "This unsigned local doctor is not a WolfAlibi receipt or independent attestation.",
        "A successful Bubblewrap smoke exercises requested controls only; it does not prove complete mediation, broker-only IPC, code identity, or all resource routes.",
        "The cgroup result is read-only information. No cgroup was created, delegated, or used for lifecycle enforcement.",
        "The seccomp capability probe is an independent default-allow policy. It is not the declared default-deny Solitary worker policy and does not establish policy equivalence.",
    ]
    if (type(timeout) not in (int, float) or isinstance(timeout, bool) or
            timeout <= 0 or timeout > _MAX_TIMEOUT):
        return {
            "type": TYPE, "assurance": ASSURANCE, "outcome": "BLOCKED",
            "reason": "timeout must be a positive bounded number of seconds",
            "limitations": limitations,
        }
    timeout = float(timeout)
    platform_feature = _platform()
    cgroup = _cgroup_v2_info()
    report: dict[str, object] = {
        "type": TYPE,
        "assurance": ASSURANCE,
        "timeout_seconds": timeout,
        "platform": platform_feature,
        "declared_pins": {},
        "exercised": {},
        "cgroup_v2": cgroup,
        "limitations": limitations,
    }
    if platform_feature["state"] != "EXERCISED":
        report.update(outcome="UNSUPPORTED", reason="Solitary requires Linux x86_64")
        return report

    profile, declared_profile = _declared_worker_profile()
    report["declared_pins"]["worker_profile"] = declared_profile
    library, declared_seccomp = _load_seccomp_library()
    report["declared_pins"]["seccomp_library"] = declared_seccomp
    pidfd = _pidfd_smoke()
    openat2 = _openat2_smoke()
    seqpacket = _seqpacket_smoke()
    kernel_seccomp = _kernel_seccomp_status()
    report["exercised"].update(pidfd=pidfd, openat2=openat2, unix_seqpacket=seqpacket,
                                kernel_seccomp_status=kernel_seccomp)

    deadline = time.monotonic() + timeout
    if profile is None:
        namespace_smoke = _feature("SKIPPED", "Bubblewrap smoke requires declared worker pins")
    else:
        remaining = _remaining(deadline)
        namespace_smoke = (_bubblewrap_smoke(profile, timeout=remaining)
                           if remaining is not None else _feature("BLOCKED", "Bubblewrap smoke deadline expired"))
    report["exercised"]["bubblewrap_namespaces"] = namespace_smoke

    if profile is None or library is None:
        seccomp_smoke = _feature("SKIPPED", "seccomp smoke requires worker pins and libseccomp")
    else:
        fd, policy = _build_seccomp_bpf(library)
        report["declared_pins"]["capability_probe_seccomp_policy"] = policy
        if fd is None:
            state = policy["state"] if policy["state"] in ("UNSUPPORTED", "BLOCKED") else "BLOCKED"
            seccomp_smoke = _feature(state, "synthetic seccomp policy was not available to Bubblewrap")
        else:
            try:
                remaining = _remaining(deadline)
                seccomp_smoke = (_bubblewrap_smoke(profile, timeout=remaining, seccomp_fd=fd)
                                 if remaining is not None else _feature("BLOCKED", "seccomp smoke deadline expired"))
            finally:
                os.close(fd)
    report["exercised"]["seccomp_process_denial"] = seccomp_smoke

    required = [declared_profile, declared_seccomp, pidfd, openat2, seqpacket, kernel_seccomp,
                namespace_smoke, seccomp_smoke]
    outcome = _overall(required)
    report["outcome"] = outcome
    report["reason"] = {
        "READY": "all required local capability smokes completed; assurance remains BLOCKED",
        "UNSUPPORTED": "one or more required host/package capabilities are unavailable",
        "BLOCKED": "one or more required local capability smokes failed or were incomplete",
    }[outcome]
    return report


def doctor(*, timeout: float = _DEFAULT_TIMEOUT) -> dict[str, object]:
    """Alias for :func:`preflight` for local diagnostic callers."""
    return preflight(timeout=timeout)


if __name__ == "__main__":
    print(json.dumps(preflight(), sort_keys=True))
