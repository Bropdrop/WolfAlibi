"""Fixed synthetic caller for the owner-controlled education demo."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
import sys

# The fixture is launched by its pinned absolute source path under Python -I.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alibi import Signer, canon
from wolfalibi.education_records import dispatch, validate_scope
from wolfalibi.education_transport import _open_client_session, request


_MAX_COMMAND_BYTES = 65_536
_FIXED_SCOPE = {
    "tenant": "fictional-school",
    "student": "fictional-aster",
    "purpose": "approved-support",
    "operation": "edu.student_record.read",
}


def _publish(value):
    sys.stdout.buffer.write(canon(value) + b"\n")
    sys.stdout.buffer.flush()


def _handle(endpoint, signer, instruction):
    mode = instruction["mode"]
    target_pid = instruction["target_pid"]
    if mode == "reconcile":
        packet = instruction["packet"]
        return {"result": request(endpoint, "reconcile", packet, expected_target_pid=target_pid)}
    scope = validate_scope(instruction["scope"])
    if any(scope[name] != expected for name, expected in _FIXED_SCOPE.items()):
        raise ValueError("fixture scope differs from the fictional support record")
    packet = dispatch(signer, scope, instruction["grant"], instruction["qualification"])

    def deliver(value):
        return request(endpoint, "read", value, expected_target_pid=target_pid)

    if mode == "sign":
        return {"packet": packet}
    if mode == "read":
        return {"packet": packet, "result": deliver(packet)}
    if mode == "unsigned":
        return {"result": deliver({"scope": scope})}
    if mode == "caller-time":
        return {"result": deliver(dict(packet, checked_at=instruction["grant"]["payload"]["not_before"]))}
    if mode == "lost-reply":
        with closing(_open_client_session(endpoint, expected_target_pid=target_pid)) as session:
            session.send("read", packet)
        return {"packet": packet, "result": {"outcome": "UNKNOWN", "response_read": False}}
    if mode == "parallel":
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(deliver, (packet, packet)))
        return {"packet": packet, "results": results}
    raise ValueError("unsupported fixture action")


def main():
    if len(sys.argv) != 2:
        return 2
    signer = Signer()
    _publish({"caller_pub": signer.pub.hex()})
    while line := sys.stdin.buffer.readline(_MAX_COMMAND_BYTES + 1):
        if not line.endswith(b"\n") or len(line) > _MAX_COMMAND_BYTES:
            return 2
        try:
            result = _handle(sys.argv[1], signer, json.loads(line))
        except (KeyError, TypeError, ValueError, OSError, RuntimeError):
            result = {"result": {"outcome": "BLOCKED", "reason": "FIXTURE_INSTRUCTION_BLOCKED"}}
        _publish(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
