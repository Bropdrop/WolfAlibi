"""Disposable role signers. Only the supervisor holds each private control pipe."""
import json,sys,tempfile,time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shirudo_adapter.receipt import sign_record
from tests.test_action_gate import GateFixture
from research.wt_swarm.roles import emit

def main():
    role=sys.argv[1]
    if role=="verifier":
        with tempfile.TemporaryDirectory() as temp:
            fixture=GateFixture(Path(temp)/"v")
            emit(dict(policy=fixture.policy,key=fixture.trust["verifier_public_key"],instance=fixture.verifier_instance_id))
            for raw in sys.stdin:
                command=json.loads(raw)
                if command=="collect":
                    fixture.now=time.time_ns()//1000000
                    emit(fixture.challenge())
                else:emit(fixture.assessment(command))
        return
    k=Ed25519PrivateKey.generate()
    emit(k.public_key().public_bytes_raw().hex())
    allowed={"owner":{"wolfalibi.sovereign.order.v1","wolfalibi.sovereign.permit.v1","wolfalibi.sovereign.recover.v1","wolfalibi.shirudo.action-grant.v1"},
             "executor":{"wolfalibi.sovereign.submit.v1"}}[role]
    for raw in sys.stdin:
        doc=json.loads(raw)
        if doc["schema"] not in allowed:raise ValueError("signing domain")
        emit(sign_record(k,doc))

if __name__=="__main__":main()
