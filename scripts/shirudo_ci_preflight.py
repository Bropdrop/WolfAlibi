#!/usr/bin/env python3
"""Observe the disposable CI host before the expensive upstream VM build."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import resource
import shutil


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": "wolfalibi.shirudo.ci-preflight.v1", "system": platform.system(),
              "machine": platform.machine(), "cpu_count": os.cpu_count(),
              "memlock": list(resource.getrlimit(resource.RLIMIT_MEMLOCK)),
              "free_disk_bytes": shutil.disk_usage(Path.cwd()).free,
              "kvm_api": None,
              "tools_before_setup": {item: bool(shutil.which(item)) for item in
                                     ("qemu-system-x86_64", "swtpm", "tpm2_createprimary", "make")}}
    failures = []
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("WOLFALIBI_DISPOSABLE_CI") != "1":
        failures.append("An explicitly selected disposable GitHub CI host is required")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        failures.append("The pinned official verifier requires Linux x86-64")
    if resource.getrlimit(resource.RLIMIT_MEMLOCK)[0] != resource.RLIM_INFINITY:
        failures.append("The launching process lacks the upstream unlimited memlock allowance")
    try:
        fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
        try:
            report["kvm_api"] = fcntl.ioctl(fd, 0xAE00, 0)  # KVM_GET_API_VERSION; no VM is created.
        finally:
            os.close(fd)
        if report["kvm_api"] != 12:
            failures.append("Unsupported KVM API version")
    except OSError as error:
        failures.append(f"KVM is unavailable: errno {error.errno}")
    report.update(result="BLOCKED" if failures else "PASS", failures=failures)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
