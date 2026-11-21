"""Optional Linux process-isolation demonstration.

The launcher deliberately reports a typed non-success when its prerequisites
are absent.  It does not claim that Bubblewrap, a namespace, or a unit test is
an attestation of complete agent confinement.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence, Union


def isolation_status() -> dict[str, object]:
    """Describe whether the optional Bubblewrap launcher can even be attempted."""
    if not sys.platform.startswith("linux"):
        return {
            "outcome": "UNSUPPORTED",
            "assurance": "BLOCKED",
            "reason": "Linux namespaces are required for this experimental launcher",
        }
    launcher = shutil.which("bwrap")
    if launcher is None:
        return {
            "outcome": "UNSUPPORTED",
            "assurance": "BLOCKED",
            "reason": "bubblewrap (bwrap) is not installed; no confinement was attempted",
        }
    userns = Path("/proc/sys/kernel/unprivileged_userns_clone")
    if userns.exists():
        try:
            if userns.read_text().strip() == "0" and os.geteuid() != 0:
                return {
                    "outcome": "BLOCKED",
                    "assurance": "BLOCKED",
                    "reason": "kernel policy disables unprivileged user namespaces",
                    "launcher": launcher,
                }
        except OSError:
            return {
                "outcome": "BLOCKED",
                "assurance": "BLOCKED",
                "reason": "could not inspect user-namespace policy",
                "launcher": launcher,
            }
    return {
        "outcome": "READY",
        "assurance": "BLOCKED",
        "launcher": launcher,
        "reason": (
            "launcher prerequisites found; a successful child still needs a "
            "separate policy review and does not upgrade receipt assurance"
        ),
    }


def run_isolated(command: Sequence[str], workdir: Union[str, Path], *,
                 timeout: float = 30.0) -> dict[str, object]:
    """Run a command in a deliberately narrow, no-network mount namespace.

    Only ``workdir`` is mounted writable at ``/work``.  The runtime library
    mounts are read-only so ordinary dynamically linked programs can start.
    Standard input is disconnected and ``close_fds=True`` prevents ambient
    descriptors from being inherited.  There is intentionally no broker socket
    in this first demonstration, so the result never claims an evidence-grade
    mediation route.
    """
    status = isolation_status()
    if status["outcome"] != "READY":
        return status
    if (not isinstance(command, Sequence) or isinstance(command, (str, bytes)) or
            not command or not all(isinstance(item, str) and item for item in command)):
        return {"outcome": "BLOCKED", "assurance": "BLOCKED", "reason": "invalid command"}
    workdir = Path(workdir).resolve()
    if not workdir.is_dir():
        return {"outcome": "BLOCKED", "assurance": "BLOCKED", "reason": "workdir is not a directory"}

    # Minimal runtime mounts.  A deployment must audit these against the exact
    # executable; they are intentionally not a general host filesystem mount.
    args = [
        status["launcher"], "--die-with-parent", "--new-session", "--unshare-user",
        "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
        "--cap-drop", "ALL", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
    ]
    for path in ("/usr", "/lib", "/lib64"):
        if os.path.exists(path):
            args.extend(["--ro-bind", path, path])
    args.extend(["--bind", str(workdir), "/work", "--chdir", "/work", "--"])
    args.extend(command)
    try:
        completed = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                   text=True, close_fds=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as ex:
        return {
            "outcome": "BLOCKED",
            "assurance": "BLOCKED",
            "reason": f"isolation launcher did not complete: {ex}",
        }
    return {
        "outcome": "COMPLETED",
        "assurance": "BLOCKED",
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "reason": (
            "process launcher completed, but this prototype has no broker IPC, "
            "code attestation, or proof that every resource route was closed"
        ),
    }
