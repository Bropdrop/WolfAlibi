"""Compose and launch the fixed Solitary worker with the Stage 4 callback probe."""

from __future__ import annotations

import hashlib
from pathlib import Path
import socket
import subprocess

from .solitary_worker import AGENT_CONTROL_RESULTS, _launch_profile, _profile


AGENT_PROFILE = "solitary-python-callback"
OBSERVATION_PREFIX = b"agent-observation-v1\0"


def _source_and_profile():
    package = Path(__file__).resolve().parent
    probe = (package / "agent_probe.py").read_bytes()
    worker = (package / "solitary_worker.py").read_bytes()
    # The trusted bootstrap embeds only these two repository sources. Their
    # module labels suppress standalone entry points during initialization.
    # The regular launcher measures this entire program in the worker argv.
    source = (
        "from types import ModuleType\n"
        "import os\n"
        "probe = ModuleType('wolfalibi.agent_probe')\n"
        f"exec(compile({probe!r}, 'wolfalibi/agent_probe.py', 'exec'), probe.__dict__)\n"
        "worker = ModuleType('wolfalibi.solitary_worker')\n"
        f"exec(compile({worker!r}, 'wolfalibi/solitary_worker.py', 'exec'), worker.__dict__)\n"
        "def make_probe():\n"
        "    return probe.AgentProbe(consent=True, agent_type='custom', max_calls=1)\n"
        "os._exit(worker._worker_main(probe_factory=make_probe, "
        f"observation_prefix={OBSERVATION_PREFIX!r}))\n"
    ).encode("ascii")
    profile = _profile(source)
    profile["solitary"]["control_results"] = dict(AGENT_CONTROL_RESULTS)
    profile["agent_adapter"] = {
        "name": "python-callbacks", "version": "1",
        "probe_sha256": hashlib.sha256(probe).hexdigest(),
        "protocol": "observation-v1",
    }
    return source, profile


def agent_worker_profile() -> dict:
    """Bind the fixed embedded worker and probe sources to the launch profile."""
    _, profile = _source_and_profile()
    return profile


def launch_agent(endpoint: socket.socket, root: Path, key: str, run_id: str,
                 challenge: bytes, canary_fd: int, *, mode: str = "normal",
                 expected_profile: dict | None = None) -> subprocess.Popen:
    """Run the fixed callback worker with the existing isolated launch controls."""
    if mode != "normal":
        raise ValueError("Solitary only supports the normal fixed worker")
    source, profile = _source_and_profile()
    return _launch_profile(source, profile, endpoint, root, key, run_id, challenge, canary_fd,
                           mode=mode, expected_profile=expected_profile)
