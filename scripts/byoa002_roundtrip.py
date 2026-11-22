"""Exercise the two local services and reconcile a historical result after restart."""

from pathlib import Path
import time

from wolfalibi.byoa002_enrollment import digest
from wolfalibi.byoa002_transport import measure_gateway, request
from wolfalibi.byoa_qualification_cli import _read
from wolfalibi.solitary_cli import _write_new


def roundtrip(stack, root, gateway, socket_path, v, target, en, signed_inputs,
              packet, enrollment, peer, lose_reply):
    from scripts.byoa002_demo import Child, GATEWAY, ROLE, _command, require, ledger_rows

    witness_socket = root / "witness.sock"
    ledger = Path(target[target.index("--state") + 1]) / "ledger" / "ledger.sqlite"
    before = root / "before.json"
    after = root / "after.json"
    same_uid_flag = ["--single-account-control"] if enrollment["owner_uid"] == peer["uid"] else []

    def services(head):
        verifier = Child(stack, ROLE, "serve-verifier", *v, "--expect-head", head, "--socket", witness_socket)
        owner = Child(stack, ROLE, "serve-target", *target, "--witness-socket", witness_socket,
                      "--socket", socket_path, *same_uid_flag)
        pins = {"expected_target_pid": owner.process.pid, "expected_target_uid": enrollment["owner_uid"]}
        require(owner.ready["pid"] == owner.process.pid and owner.ready["uid"] == pins["expected_target_uid"],
                "resource owner process identity differs from enrollment")
        return verifier, owner, pins

    witness, owner, pins = services(before)
    require(not ledger_rows(ledger), "expected a fresh owner ledger")
    controls = {}
    controls["wrong_peer"] = request(socket_path, "dispatch", packet, **pins)
    require(controls["wrong_peer"]["outcome"] == "DENIED" and not ledger_rows(ledger),
            "unexpected live peer reached the protected read")
    controls["custody"] = gateway.call("custody", **pins, inventory=owner.ready["inventory"],
                                       target_pub=enrollment["target_pub"])
    require(controls["custody"]["outcome"] == "UNSUPPORTED",
            "single-account control cannot qualify separate custody")

    gateway_attempts = {"dispatch": 0, "reconcile": 0}

    def submit(actor, action, submitted, pins):
        gateway_attempts["reconcile" if action == "reconcile" else "dispatch"] += 1
        return actor.call(action, packet=submitted, **pins)

    controls["accepted"] = submit(gateway, "lose-reply" if lose_reply else "dispatch", packet, pins)
    expected = "UNKNOWN" if lose_reply else "RELEASED"
    require(controls["accepted"]["outcome"] == expected, "authorized gateway outcome differs: " +
            str(controls["accepted"].get("reason", controls["accepted"]["outcome"])))
    controls["duplicate"] = {"outcome": "NOT_ATTEMPTED"}
    if not lose_reply:
        require(controls["accepted"].get("record") == {"record": "fictional-record-002", "review_status": "available"},
                "unexpected synthetic response")
        controls["duplicate"] = submit(gateway, "dispatch", packet, pins)
        require(controls["duplicate"]["outcome"] == "DENIED" and "record" not in controls["duplicate"],
                "authorized identity could dispatch twice")
    # Observe the asynchronous commit using only the owner's read-only ledger connection.
    deadline = time.monotonic() + 8
    rows = ledger_rows(ledger)
    while not rows and time.monotonic() < deadline:
        time.sleep(0.025)
        rows = ledger_rows(ledger)
    require(len(rows) == 1, "target did not retain exactly one commitment")
    original, = rows
    if not lose_reply:
        require(controls["accepted"]["receipt"] == original, "returned receipt differs from the owner ledger")

    original_target = owner.ready["inventory"]["payload"]["target"]
    original_witness = witness.process.pid
    owner.stop()  # finish any pending retention and socket handoff with original gateway still live

    # Retain the verifier's head before reopening. Its value must also match the independently read target row.
    _command(ROLE, "head", *v, "--output", after)
    retained = _read(after, 4096)
    prior = _read(before, 4096)
    require(retained == {"generation": prior["generation"] + 1, "digest": digest(original)},
            "verifier did not retain the original target commitment")
    witness.stop()
    gateway.stop()
    next_gateway = Child(stack, GATEWAY, socket_path)
    next_peer = measure_gateway(next_gateway.process.pid, socket_path)
    require(next_gateway.ready["peer"] == next_peer and next_peer["pid"] != peer["pid"],
            "replacement gateway identity was not independently measured")
    witness, owner, pins = services(after)
    new_target = owner.ready["inventory"]["payload"]["target"]
    require(new_target["pid"] != original_target["pid"] and witness.process.pid != original_witness,
            "expected different service processes after restart")
    controls["replacement_dispatch"] = {"outcome": "NOT_ATTEMPTED"}
    if not lose_reply:
        controls["replacement_dispatch"] = submit(next_gateway, "dispatch", packet, pins)
        require(controls["replacement_dispatch"]["outcome"] == "DENIED" and ledger_rows(ledger) == [original],
                "the replacement process inherited live dispatch permission")

    recovery_pin = root / "recovery-peer.json"
    inquiry = root / "reconciliation.json"
    _write_new(recovery_pin, next_peer)
    _command(ROLE, "request", *signed_inputs, "--action", "reconcile", "--recovery-peer", recovery_pin,
             "--output", inquiry)
    controls["reconciled"] = submit(next_gateway, "reconcile", _read(inquiry, 65_536), pins)
    found = controls["reconciled"]
    require(set(found) == {"outcome", "receipt", "ack"} and found["outcome"] == "RECONCILED"
            and found["receipt"] == original and ledger_rows(ledger) == [original],
            "recovery did not return the original receipt from the unchanged ledger: " +
            str(found.get("reason", found.get("outcome"))))
    if not lose_reply:
        require(found["ack"] == controls["accepted"]["ack"], "retained witness acknowledgment changed")
    owner.stop()
    witness.stop()
    latest = root / "after-reconciliation.json"
    _command(ROLE, "head", *v, "--output", latest)
    require(_read(latest, 4096) == retained, "read-only reconciliation advanced verifier history")
    return {"controls": controls, "effect_count": len(rows),
            "gateway_dispatch_attempts": gateway_attempts["dispatch"],
            "reconciliation_attempts": gateway_attempts["reconcile"], "original_receipt_sha256": digest(original),
            "gateway_before": peer, "gateway_after": next_peer,
            "target_before": original_target, "target_after": new_target,
            "verifier_pid_before": original_witness, "verifier_pid_after": witness.process.pid}
