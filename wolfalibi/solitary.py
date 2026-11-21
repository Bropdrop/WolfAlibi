"""Orchestrate a fixed, resource-limited Linux broker trial."""

from __future__ import annotations

import os
from pathlib import Path
import select

from alibi import DurableWitness
from . import stage3
from .stage35 import inspect_layout
from .stage35_measure import MeasurementBlocked, _process_fields, measure_worker
from .solitary_evidence import sign_envelope
from .solitary_worker import CONTROL_RESULTS, LIMITS, launch, worker_profile


WALL_TIMEOUT_S = 6


def solitary_contract(run_id, challenge, expires_at):
    """Record the fixed fixture and the exact local worker profile before launch."""
    contract = stage3.trial_contract(run_id, challenge, expires_at)
    contract["profile"] = worker_profile()
    return contract


def _seccomp_filters(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        label, _, value = line.partition(":")
        if label == "Seccomp_filters":
            return int(value.strip())
    raise MeasurementBlocked("kernel did not expose the loaded seccomp filter count")


def _exited(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    return any(bits & select.POLLIN for _, bits in poll.poll(0))


def run_solitary(state_dir, *, contract, signer, witness, supervisor,
                 expected_witness_state_digest):
    """Require measured pre-read limits and exit of the same single worker."""
    return _run_solitary(
        state_dir, contract=contract, signer=signer, witness=witness, supervisor=supervisor,
        expected_witness_state_digest=expected_witness_state_digest,
        launch_worker=launch, expected_profile=worker_profile, controls=CONTROL_RESULTS,
    )


def _run_solitary(state_dir, *, contract, signer, witness, supervisor, expected_witness_state_digest,
                  launch_worker, expected_profile, controls, observation_packet=None):
    if (not isinstance(witness, DurableWitness) or
            len({supervisor.pub, signer.pub, witness.signer.pub}) != 3):
        return {"outcome": "BLOCKED", "reason": "distinct broker, witness and supervisor keys required"}
    measured = {}
    worker_fd = None

    def observe(proc, endpoint, root, canary, deadline):
        import resource

        nonlocal worker_fd
        try:
            inspect_layout(root, stage3.FIXTURE_KEY)
            snapshot = measure_worker(proc, contract, endpoint, root,
                                      canary_fd=canary, deadline=deadline)
            identity = snapshot["identity"]
            worker_pid = identity["worker_pid"]
            worker_fd = os.pidfd_open(worker_pid)
            path = Path(f"/proc/{worker_pid}/stat")
            expected_identity = proc.pid, identity["worker_start_ticks"]
            if _exited(worker_fd) or _process_fields(path.read_text())[1:] != expected_identity:
                raise MeasurementBlocked("worker changed before limits were measured")

            observed_limits = {
                name: list(resource.prlimit(worker_pid, getattr(resource, name))) for name in LIMITS
            }
            launcher_filters = _seccomp_filters(proc.pid)
            worker_filters = _seccomp_filters(worker_pid)
            # The launcher only receives fixed synthetic variables. Require the
            # effective exec environment to contain just Bubblewrap's PWD.
            with path.with_name("environ").open("rb") as stream:
                if stream.read(64) != b"PWD=/work\x00":
                    raise MeasurementBlocked("unexpected worker exec environment")
            if (observed_limits != LIMITS or worker_filters <= launcher_filters or
                    snapshot["credentials"]["seccomp_mode"] != 2):
                raise MeasurementBlocked("fixed limits or additional seccomp filter missing")
            if _exited(worker_fd) or _process_fields(path.read_text())[1:] != expected_identity:
                raise MeasurementBlocked("worker changed during limit measurement")
            snapshot["solitary_kernel"] = {
                "launcher_seccomp_filters": launcher_filters, "worker_seccomp_filters": worker_filters,
                "environment_keys": ["PWD"],
            }
            measured.update(snapshot=snapshot, limits=observed_limits)
        except (MeasurementBlocked, OSError, AttributeError, ValueError) as exc:
            raise stage3.TrialBlocked(f"Solitary pre-read measurement blocked: {exc}") from exc

    def closed(proc):
        if worker_fd is None or not _exited(worker_fd) or proc.returncode != 0:
            raise stage3.TrialBlocked("Solitary has no closed worker lifecycle")
        # Stage 3 calls this only after reaping the launcher, receiving the
        # acknowledgement and confirming peer hangup and an empty queue.
        measured["closure"] = {
            "launcher_reaped": True, "worker_pidfd_exited": True,
            "peer_hangup": True, "broker_drained": True,
        }

    try:
        result = stage3.run_trial(
            state_dir, contract=contract, signer=signer, witness=witness,
            expected_witness_state_digest=expected_witness_state_digest,
            timeout=WALL_TIMEOUT_S, _launcher=launch_worker, _worker_profile=expected_profile,
            _before_release=observe, _after_close=closed, _control_results=controls,
            _observation_packet=observation_packet,
        )
    finally:
        if worker_fd is not None:
            os.close(worker_fd)
    if result["outcome"] != "COMPLETED":
        return result
    try:
        envelope = sign_envelope(result["evidence"], measured["snapshot"], controls,
                                 measured["limits"], measured["closure"], supervisor)
    except (KeyError, ValueError) as exc:
        return {"outcome": "BLOCKED", "reason": f"Solitary evidence incomplete: {exc}"}
    return {"outcome": "COMPLETED", "envelope": envelope, "run_dir": result["run_dir"]}
