"""Narrow, reproducible Linux confinement demonstrations.

This module builds one explicit Bubblewrap policy rather than implying that a
generic subprocess call is a sandbox. Its result is useful as evidence of the
exact controls requested and probes observed, but never upgrades a WolfAlibi
receipt above ``BROKER_ONLY``. There is no broker IPC route, code attestation,
seccomp policy, or proof that every resource channel is closed.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from typing import Any, Mapping, Sequence, Union


ISOLATION_POLICY_TYPE = "WOLFALIBI_LINUX_BWRAP_POLICY_V1"
ISOLATION_BOUNDARY_TYPE = "WOLFALIBI_LINUX_BWRAP_BOUNDARY_V1"
ASSURANCE_BLOCKED = "BLOCKED"
_MAX_CAPTURED_OUTPUT = 64 * 1024
_RUNTIME_PATHS = ("/usr", "/lib", "/lib64")


def _canon(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def policy_digest(manifest: Mapping[str, Any]) -> str:
    """Return a deterministic digest of an explicit confinement manifest."""
    return hashlib.sha256(_canon(manifest)).hexdigest()


def _launcher_version(launcher: str) -> str | None:
    try:
        completed = subprocess.run([launcher, "--version"], stdin=subprocess.DEVNULL,
                                   capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return text[0] if completed.returncode == 0 and text else None


def _runtime_mounts() -> list[str]:
    """Runtime directories deliberately exposed read-only to the child."""
    return [path for path in _RUNTIME_PATHS if os.path.isdir(path)]


def isolation_status() -> dict[str, object]:
    """Report prerequisites without pretending that they prove confinement."""
    base: dict[str, object] = {
        "type": "WOLFALIBI_LINUX_CONFINEMENT_STATUS_V1",
        "assurance": ASSURANCE_BLOCKED,
        "platform": sys.platform,
        "machine": platform.machine(),
        "required_controls": [
            "bubblewrap user/pid/network/ipc/uts namespaces",
            "cleared environment and closed inherited descriptors",
            "read-only runtime mounts, one writable host bind at /work, and ephemeral /tmp",
            "no broker IPC or execution attestation in this prototype",
        ],
    }
    if not sys.platform.startswith("linux"):
        return {
            **base,
            "outcome": "UNSUPPORTED",
            "reason": "Linux namespaces are required for this experimental launcher",
        }
    launcher = shutil.which("bwrap")
    if launcher is None:
        return {
            **base,
            "outcome": "UNSUPPORTED",
            "reason": "bubblewrap (bwrap) is not installed; no confinement was attempted",
        }
    version = _launcher_version(launcher)
    if version is None:
        return {
            **base,
            "outcome": "BLOCKED",
            "launcher": launcher,
            "reason": "bubblewrap could not report a usable version",
        }
    userns = Path("/proc/sys/kernel/unprivileged_userns_clone")
    if userns.exists():
        try:
            if userns.read_text().strip() == "0" and os.geteuid() != 0:
                return {
                    **base,
                    "outcome": "BLOCKED",
                    "launcher": launcher,
                    "launcher_version": version,
                    "reason": "kernel policy disables unprivileged user namespaces",
                }
        except OSError:
            return {
                **base,
                "outcome": "BLOCKED",
                "launcher": launcher,
                "launcher_version": version,
                "reason": "could not inspect user-namespace policy",
            }
    missing_runtime = [path for path in _RUNTIME_PATHS if not os.path.isdir(path)]
    if missing_runtime:
        return {
            **base,
            "outcome": "BLOCKED",
            "launcher": launcher,
            "launcher_version": version,
            "reason": "required runtime paths are unavailable: " + ", ".join(missing_runtime),
        }
    return {
        **base,
        "outcome": "READY",
        "launcher": launcher,
        "launcher_version": version,
        "runtime_mounts": _runtime_mounts(),
        "reason": (
            "launcher prerequisites found; a child result records requested controls "
            "but no broker IPC, code attestation, or complete mediation"
        ),
    }


def confinement_manifest(workdir: Union[str, Path], *, launcher: str | None = None,
                         launcher_version: str | None = None) -> dict[str, object]:
    """Return the versioned policy that ``run_isolated`` will request.

    The host path is intentionally included: a verifier can bind a receipt to
    the exact declared workspace scope, but must not mistake that declaration
    for proof that the command actually ran only there.
    """
    work = Path(workdir).resolve()
    if not work.is_dir():
        raise ValueError("workdir is not a directory")
    runtime_mounts = _runtime_mounts()
    if len(runtime_mounts) != len(_RUNTIME_PATHS):
        raise ValueError("required runtime paths are unavailable")
    return {
        "type": ISOLATION_POLICY_TYPE,
        "v": 1,
        "launcher": launcher,
        "launcher_version": launcher_version,
        "workdir_source": str(work),
        "workdir_target": "/work",
        "writable_host_bind_mounts": ["/work"],
        "writable_mounts": ["/work", "/tmp"],
        "read_only_runtime_mounts": runtime_mounts,
        "temporary_mounts": ["/tmp"],
        "namespaces": ["user", "pid", "network", "ipc", "uts"],
        "capabilities": "drop-all",
        "environment": {
            "clear": True,
            "set": {"HOME": "/nonexistent", "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "TMPDIR": "/tmp"},
        },
        "stdio": {"stdin": "devnull", "close_fds": True},
        "broker_ipc": "ABSENT",
        "code_identity": "NOT_ATTESTED",
        "receipt_assurance": ASSURANCE_BLOCKED,
    }


def _valid_command(command: Sequence[str]) -> bool:
    return (isinstance(command, Sequence) and not isinstance(command, (str, bytes)) and
            bool(command) and all(isinstance(item, str) and item for item in command))


def _trim_output(value: str) -> str:
    if len(value) <= _MAX_CAPTURED_OUTPUT:
        return value
    return value[:_MAX_CAPTURED_OUTPUT] + "\n[wolfalibi output truncated]"


def _arguments(manifest: Mapping[str, object], command: Sequence[str]) -> list[str]:
    args = [
        str(manifest["launcher"]), "--die-with-parent", "--new-session", "--unshare-user",
        "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
        "--cap-drop", "ALL", "--clearenv", "--setenv", "HOME", "/nonexistent",
        "--setenv", "LANG", "C.UTF-8", "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "TMPDIR", "/tmp", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
    ]
    for path in manifest["read_only_runtime_mounts"]:
        args.extend(["--ro-bind", str(path), str(path)])
    args.extend(["--bind", str(manifest["workdir_source"]), "/work", "--chdir", "/work", "--"])
    args.extend(command)
    return args


def run_isolated(command: Sequence[str], workdir: Union[str, Path], *,
                 timeout: float = 30.0) -> dict[str, object]:
    """Run a direct argv command under the documented narrow policy.

    ``COMPLETED`` means only that Bubblewrap returned after the requested
    policy was passed to it. It is not a verified confinement verdict.
    """
    if not _valid_command(command):
        return {"outcome": "BLOCKED", "assurance": ASSURANCE_BLOCKED,
                "reason": "invalid command"}
    if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
            not math.isfinite(timeout) or timeout <= 0):
        return {"outcome": "BLOCKED", "assurance": ASSURANCE_BLOCKED,
                "reason": "timeout must be positive"}
    status = isolation_status()
    try:
        manifest = confinement_manifest(workdir, launcher=status.get("launcher"),
                                        launcher_version=status.get("launcher_version"))
    except (TypeError, ValueError) as ex:
        return {"outcome": "BLOCKED", "assurance": ASSURANCE_BLOCKED, "reason": str(ex),
                "status": status}
    result: dict[str, object] = {
        "outcome": status["outcome"],
        "assurance": ASSURANCE_BLOCKED,
        "reason": status["reason"],
        "status": status,
        "manifest": manifest,
        "manifest_digest": policy_digest(manifest),
    }
    if status["outcome"] != "READY":
        return result
    try:
        completed = subprocess.run(_arguments(manifest, command), stdin=subprocess.DEVNULL,
                                   capture_output=True, text=True, errors="replace", close_fds=True,
                                   timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {**result, "outcome": "BLOCKED", "reason": "isolation launcher timed out"}
    except OSError as ex:
        return {**result, "outcome": "BLOCKED",
                "reason": f"isolation launcher did not start: {ex}"}
    return {
        **result,
        "outcome": "COMPLETED",
        "returncode": completed.returncode,
        "stdout": _trim_output(completed.stdout),
        "stderr": _trim_output(completed.stderr),
        "reason": (
            "launcher completed with a declared mount/namespace policy, but no broker IPC, "
            "code attestation, or proof that every resource route was closed"
        ),
    }


def boundary_descriptor(result: Mapping[str, object]) -> dict[str, object]:
    """Create bindable, non-escalating receipt metadata from a launcher result."""
    manifest_digest = result.get("manifest_digest")
    if not isinstance(manifest_digest, str) or len(manifest_digest) != 64:
        raise ValueError("isolation result has no valid policy digest")
    return {
        "type": ISOLATION_BOUNDARY_TYPE,
        "v": 1,
        "outcome": ("LAUNCHER_COMPLETED" if result.get("outcome") == "COMPLETED"
                    else result.get("outcome")),
        "launcher_outcome": result.get("outcome"),
        "child_returncode": result.get("returncode"),
        "policy_digest": manifest_digest,
        "assurance": ASSURANCE_BLOCKED,
        "meaning": "declared-policy-and-narrow-probe-binding-not-complete-mediation-proof",
    }


def probe_confinement(workdir: Union[str, Path], protected_marker: Union[str, Path], *,
                      timeout: float = 30.0) -> dict[str, object]:
    """Run two synthetic, narrow probes against the explicit mount view.

    A ``DEMONSTRATED`` outcome means only that this marker path and this parent
    descriptor were absent from this child. Callers must use synthetic marker
    files they own; this helper is not a scanner and performs no network test.
    """
    work = Path(workdir).resolve()
    marker = Path(protected_marker).resolve()
    if not work.is_dir() or not marker.is_file():
        return {"outcome": "BLOCKED", "assurance": ASSURANCE_BLOCKED,
                "reason": "workdir must be a directory and protected marker must be a file"}
    try:
        marker.relative_to(work)
    except ValueError:
        pass
    else:
        return {"outcome": "BLOCKED", "assurance": ASSURANCE_BLOCKED,
                "reason": "protected marker is inside the writable workdir"}
    status = isolation_status()
    if status["outcome"] != "READY":
        return {"outcome": status["outcome"], "assurance": ASSURANCE_BLOCKED,
                "status": status, "reason": status["reason"]}
    test_binary = "/usr/bin/test"
    if not os.path.isfile(test_binary):
        return {"outcome": "BLOCKED", "assurance": ASSURANCE_BLOCKED,
                "reason": "synthetic probe requires /usr/bin/test"}
    try:
        fd = os.open(marker, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as ex:
        return {"outcome": "BLOCKED", "assurance": ASSURANCE_BLOCKED,
                "reason": f"could not open synthetic protected marker: {ex}"}
    try:
        path_probe = run_isolated([test_binary, "!", "-e", str(marker)], work, timeout=timeout)
        fd_probe = run_isolated([test_binary, "!", "-e", f"/proc/self/fd/{fd}"], work,
                                timeout=timeout)
    finally:
        os.close(fd)
    probes = {"host_marker_path": path_probe, "inherited_marker_fd": fd_probe}
    successful = all(item.get("outcome") == "COMPLETED" and item.get("returncode") == 0
                     for item in probes.values())
    if successful:
        return {
            "outcome": "DEMONSTRATED",
            "assurance": ASSURANCE_BLOCKED,
            "observed": {
                "synthetic_host_marker_absent": True,
                "synthetic_parent_fd_not_inherited": True,
                "network_isolation": "requested-but-not-externally-tested",
            },
            "manifest": path_probe["manifest"],
            "manifest_digest": path_probe["manifest_digest"],
            "probes": probes,
            "reason": (
                "two synthetic exclusions were observed; no broker IPC, code attestation, "
                "seccomp policy, or complete mediation proof exists"
            ),
        }
    outcomes = {item.get("outcome") for item in probes.values()}
    return {
        "outcome": "UNSUPPORTED" if outcomes == {"UNSUPPORTED"} else "BLOCKED",
        "assurance": ASSURANCE_BLOCKED,
        "probes": probes,
        "reason": "one or more requested synthetic confinement probes did not succeed",
    }
