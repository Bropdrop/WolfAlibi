"""Disposable roles. Invoked inside separate networkless bubblewrap namespaces."""
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.wt_alibi_human_lab import make_intent
from shirudo_adapter.owner import Owner
from tests.support import policy_for, write_nonexecuted_fixture
from tests.test_action_gate import GateFixture
from tests.test_owner_cli import OwnerTerminal


def emit(item):
    print(json.dumps(item, separators=(",", ":")), flush=True)


def receive():
    return json.loads(input())


class VerifierFixture:
    """Reuse the inherited fabricated assessment format with the real wall clock."""
    challenge = GateFixture.challenge
    assessment = GateFixture.assessment

    @property
    def now(self):
        return time.time_ns() // 1_000_000

    def __init__(self):
        self.verifier_key = Ed25519PrivateKey.generate()
        self.verifier_instance_id = secrets.token_hex(16)
        self.policy = policy_for(write_nonexecuted_fixture(Path("/tmp/fixture")))
        self.policy["assurance"] = "LAB_VTPM"
        self.policy["enrollment"]["method"] = "trusted_builder"
        self.policy["expected"].update(config_pcr=14, quote_pcrs={"15": "51" * 32})


def custody():
    return {"pid_namespace": os.readlink("/proc/self/ns/pid"),
            "mount_namespace": os.readlink("/proc/self/ns/mnt"),
            "socket_visible": Path("/endpoint/gate.sock").exists()}


def verifier():
    f = VerifierFixture()
    emit({"policy": f.policy, "public_key": f.verifier_key.public_key().public_bytes_raw().hex(),
          "instance_id": f.verifier_instance_id, "custody": custody()})
    for line in sys.stdin:
        if json.loads(line) != "collect":
            raise ValueError("unknown verifier command")
        challenge = f.challenge()
        emit({"challenge": challenge, "assessment": f.assessment(challenge)})


def owner():
    state = Path("/tmp/lab-owner")
    authority = Owner.initialize(state)
    emit(dict(authority.public_identity(), custody=custody()))
    profile = receive()
    authority.pin_profile(profile)
    emit("pinned")
    for line in sys.stdin:
        if json.loads(line) != "begin":
            raise ValueError("unknown owner command")
        case = TestCase()
        with tempfile.TemporaryDirectory() as temp:
            fixture = SimpleNamespace(state=state, root=Path(temp), intent=lambda: make_intent(profile))
            try:
                terminal = OwnerTerminal(case, fixture)
                ready = terminal.ready()
                emit({"intent": terminal.intent, "ready": ready})
                bundle = receive()
                terminal.publish(bundle)
                awaiting = terminal.event()
                case.assertEqual(awaiting["status"], "AWAITING_APPROVAL")
                terminal.prompt(b"APPROVE ")
                terminal.send(awaiting["approval_phrase"] + "\n")
                issued = terminal.event()
                case.assertEqual(issued["status"], "GRANT_ISSUED")
                terminal.exit(0)
                emit(issued)
            finally:
                case.doCleanups()


if __name__ == "__main__":
    {"verifier": verifier, "owner": owner}[sys.argv[1]]()
