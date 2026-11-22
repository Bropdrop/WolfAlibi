"""Run a captured, authorized package through the measured Solitary fixture protocol."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import time

from alibi import DurableWitness, canon

from . import stage3
from .agent_solitary_observation import parse_observation
from .agent_solitary_worker import OBSERVATION_PREFIX
from .byoa_bundle import validate_bundle
from .solitary import WALL_TIMEOUT_S, _exited, _seccomp_filters
from .solitary_evidence import sign_envelope
from .solitary_worker import AGENT_CONTROL_RESULTS, LIMITS, _launch_profile, _profile
from .stage35 import inspect_layout
from .stage35_measure import MeasurementBlocked, _process_fields, measure_worker


def _program(bundle):
    validate_bundle(bundle)
    package = Path(__file__).resolve().parent
    probe = (package / "agent_probe.py").read_bytes()
    worker = (package / "solitary_worker.py").read_bytes()
    bootstrap = (package / "byoa_cell_bootstrap.py").read_bytes()
    probe_hash = hashlib.sha256(probe).hexdigest()
    identity = bundle.identity()
    if identity["dependencies"][0]["sha256"] != probe_hash:
        raise ValueError("AgentProbe dependency differs from the selected inventory")
    source = (
        "from types import ModuleType\n"
        "import os\n"
        "probe = ModuleType('wolfalibi.agent_probe')\n"
        f"exec(compile({probe!r}, 'agent_probe.py', 'exec'), probe.__dict__)\n"
        "worker = ModuleType('wolfalibi.solitary_worker')\n"
        f"exec(compile({worker!r}, 'solitary_worker.py', 'exec'), worker.__dict__)\n"
        "adapter = ModuleType('wolfalibi.byoa_cell_bootstrap')\n"
        f"exec(compile({bootstrap!r}, 'byoa_cell_bootstrap.py', 'exec'), adapter.__dict__)\n"
        "def make_adapter():\n"
        "    observer = probe.AgentProbe(consent=True, agent_type='custom', max_calls=1)\n"
        f"    return adapter.SubmittedAgent(observer, {bundle.source!r}, "
        f"{hashlib.sha256(stage3.FIXTURE_BYTES).hexdigest()!r})\n"
        f"os._exit(worker._worker_main(probe_factory=make_adapter, observation_prefix={OBSERVATION_PREFIX!r}))\n"
    ).encode("ascii")
    profile = _profile(source)
    profile["byoa"] = identity
    profile["solitary"]["control_results"] = dict(AGENT_CONTROL_RESULTS)
    profile["agent_adapter"] = {
        "name": "python-callbacks", "version": "1", "probe_sha256": probe_hash, "protocol": "observation-v1",
    }
    return source, profile


def cell_contract(bundle, run_id, challenge, expires_at):
    contract = stage3.trial_contract(run_id, challenge, expires_at)
    contract["profile"] = _program(bundle)[1]
    return contract


def _live_identity(identity, pidfd):
    path = Path(f"/proc/{identity['worker_pid']}/stat")
    if (_exited(pidfd) or _process_fields(path.read_text())[1:] !=
            (identity["launcher_pid"], identity["worker_start_ticks"])):
        raise stage3.TrialBlocked("measured worker is no longer live")
    return path


def run_cell(state_dir, *, bundle, contract, signer, witness, supervisor,
             expected_witness_state_digest, read_gate, consent=False):
    """Return terminal evidence only after live admission, one callback and measured exit."""
    from .byoa_effect_gate import ReadGate

    if consent is not True:
        return {"outcome": "BLOCKED", "reason": "explicit operator consent is required"}
    if type(read_gate) is not ReadGate:
        return {"outcome": "BLOCKED", "reason": "a resource-owner read gate is required"}
    if (not isinstance(witness, DurableWitness) or
            len({signer.pub, witness.signer.pub, supervisor.pub}) != 3):
        return {"outcome": "BLOCKED", "reason": "distinct broker, witness and supervisor keys required"}
    try:
        contract = json.loads(canon(contract))
        source, profile = _program(bundle)
        if canon(contract["profile"]) != canon(profile):
            return {"outcome": "BLOCKED", "reason": "approved package or runtime differs"}
    except (TypeError, ValueError, OSError, KeyError, stage3.UnsupportedWorker) as exc:
        return {"outcome": "UNSUPPORTED" if isinstance(exc, stage3.UnsupportedWorker) else "BLOCKED",
                "reason": str(exc)}
    observed = {}
    pidfd = None

    def launch(endpoint, root, key, run_id, challenge, canary_fd, *, mode, expected_profile):
        return _launch_profile(source, profile, endpoint, root, key, run_id, challenge, canary_fd,
                               mode=mode, expected_profile=expected_profile)

    def authorize_before_release(proc, endpoint_inode, root, canary_fd, deadline):
        import resource

        nonlocal pidfd
        inspect_layout(root, stage3.FIXTURE_KEY)
        snapshot = measure_worker(proc, contract, endpoint_inode, root, canary_fd=canary_fd, deadline=deadline)
        identity = snapshot["identity"]
        pid = identity["worker_pid"]
        pidfd = os.pidfd_open(pid)
        path = _live_identity(identity, pidfd)
        limits = {name: list(resource.prlimit(pid, getattr(resource, name))) for name in LIMITS}
        launcher_filters, worker_filters = _seccomp_filters(proc.pid), _seccomp_filters(pid)
        with path.with_name("environ").open("rb") as stream:
            if stream.read(64) != b"PWD=/work\0":
                raise stage3.TrialBlocked("unexpected worker exec environment")
        if (limits != LIMITS or worker_filters <= launcher_filters or
                snapshot["credentials"]["seccomp_mode"] != 2):
            raise stage3.TrialBlocked("Solitary resource limits or additional worker filter missing")
        snapshot["solitary_kernel"] = {
            "launcher_seccomp_filters": launcher_filters, "worker_seccomp_filters": worker_filters,
            "environment_keys": ["PWD"],
        }
        _live_identity(identity, pidfd)
        # The domain gate independently checks the live process, owner grant,
        # challenge and retained state and commits admission before returning.
        read_gate(deepcopy(contract), deepcopy(snapshot), pidfd)
        if time.monotonic() >= deadline or time.time() >= contract["expires_at"]:
            raise stage3.TrialBlocked("the run deadline elapsed at admission")
        _live_identity(identity, pidfd)
        observed.update(snapshot=snapshot, limits=limits)

    def collect(packet):
        if not packet.startswith(OBSERVATION_PREFIX):
            raise stage3.TrialBlocked("unexpected frame after the agent acknowledgement")
        observation = parse_observation(packet[len(OBSERVATION_PREFIX):])
        if observation["outcome"] != "OBSERVED":
            raise stage3.TrialBlocked("required callback observation did not validate")
        observed["observation"] = observation

    def check_closure(proc):
        if "observation" not in observed or pidfd is None or not _exited(pidfd) or proc.returncode != 0:
            raise stage3.TrialBlocked("missing callback or incomplete worker lifecycle")
        observed["closure"] = {
            "launcher_reaped": True, "worker_pidfd_exited": True, "peer_hangup": True, "broker_drained": True,
        }

    try:
        result = stage3.run_trial(
            state_dir, contract=contract, signer=signer, witness=witness,
            expected_witness_state_digest=expected_witness_state_digest, timeout=WALL_TIMEOUT_S,
            _launcher=launch, _worker_profile=lambda: profile, _before_release=authorize_before_release,
            _after_close=check_closure, _control_results=AGENT_CONTROL_RESULTS, _observation_packet=collect,
        )
    except (MeasurementBlocked, ValueError, OSError, RuntimeError) as exc:
        return {"outcome": "BLOCKED", "reason": str(exc)}
    finally:
        if pidfd is not None:
            os.close(pidfd)
    if result["outcome"] != "COMPLETED":
        return result
    try:
        envelope = sign_envelope(result["evidence"], observed["snapshot"], AGENT_CONTROL_RESULTS,
                                 observed["limits"], observed["closure"], supervisor)
    except (KeyError, ValueError) as exc:
        return {"outcome": "BLOCKED", "reason": f"incomplete Solitary evidence: {exc}",
                "run_dir": result["run_dir"]}
    return {"outcome": "COMPLETED", "envelope": envelope, "observation": observed["observation"],
            "run_dir": result["run_dir"]}
