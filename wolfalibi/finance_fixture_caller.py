"""Fixed synthetic caller for the local finance-intent demo."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sys

# This entry point is launched by absolute path under Python -I.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wolfalibi.education_fixture_caller import run_handler
from wolfalibi.finance_records import ACCOUNT, CURRENCY, OPERATION, TENANT, dispatch, validate_scope
from wolfalibi.finance_transport import _open_client_session, request


_FIXED_SCOPE = {"tenant": TENANT, "account": ACCOUNT, "currency": CURRENCY, "operation": OPERATION}


def _handle(endpoint, signer, instruction):
    mode = instruction["mode"]
    target_pid = instruction["target_pid"]
    if mode == "reconcile":
        return {"result": request(endpoint, "reconcile", instruction["packet"], expected_target_pid=target_pid)}

    scope = validate_scope(instruction["scope"])
    if any(scope[name] != expected for name, expected in _FIXED_SCOPE.items()):
        raise ValueError("finance fixture scope must remain synthetic")
    grant = None if mode == "no-owner" else instruction["grant"]
    packet = dispatch(signer, scope, grant, instruction["qualification"])

    def deliver(value):
        return request(endpoint, "initiate", value, expected_target_pid=target_pid)

    if mode == "sign":
        return {"packet": packet}
    if mode in ("initiate", "no-owner"):
        return {"packet": packet, "result": deliver(packet)}
    if mode == "unsigned":
        return {"result": deliver({key: value for key, value in packet.items() if key != "caller_proof"})}
    if mode == "fake-settlement":
        return {"result": deliver(dict(packet, settlement="SETTLED"))}
    if mode == "lost-reply":
        retained = instruction["packet"]
        if retained != packet:
            raise ValueError("the retained finance dispatch must match the pending request")
        with closing(_open_client_session(endpoint, expected_target_pid=target_pid)) as session:
            session.send("initiate", retained)
        return {"result": {"outcome": "UNKNOWN", "response_read": False}}
    if mode == "parallel":
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(deliver, (packet, packet)))
        return {"packet": packet, "results": results}
    raise ValueError("unsupported finance fixture action")


if __name__ == "__main__":
    raise SystemExit(run_handler(_handle))
