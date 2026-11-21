"""Run the fixed Stage 4 Python callback inside the measured Solitary cell."""

from . import stage3
from .agent_solitary_observation import parse_observation
from .agent_solitary_worker import (
    AGENT_CONTROL_RESULTS, OBSERVATION_PREFIX, agent_worker_profile, launch_agent,
)
from .solitary import _run_solitary


def agent_solitary_contract(run_id, challenge, expires_at):
    """Pin the combined worker and adapter source as a distinct profile."""
    contract = stage3.trial_contract(run_id, challenge, expires_at)
    contract["profile"] = agent_worker_profile()
    return contract


def run_agent_solitary(state_dir, *, contract, signer, witness, supervisor,
                       expected_witness_state_digest):
    """Run one fixed observed callback and verify the separate broker lifecycle."""
    observation = parse_observation(b"")

    def collect(packet):
        nonlocal observation
        if not packet.startswith(OBSERVATION_PREFIX):
            raise stage3.TrialBlocked("unexpected data after the worker acknowledgement")
        observation = parse_observation(packet[len(OBSERVATION_PREFIX):])

    result = _run_solitary(
        state_dir, contract=contract, signer=signer, witness=witness, supervisor=supervisor,
        expected_witness_state_digest=expected_witness_state_digest,
        launch_worker=launch_agent, expected_profile=agent_worker_profile,
        controls=AGENT_CONTROL_RESULTS, observation_packet=collect,
    )
    if result["outcome"] != "COMPLETED":
        return result
    return {**result, "observation": observation}
