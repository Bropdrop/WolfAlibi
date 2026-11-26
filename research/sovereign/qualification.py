"""Review a complete measured run, including independent observer and fault results."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from research.sovereign.controls import controls
from research.sovereign.review import inspect, load, run
from research.wt_swarm.review import require
from shirudo_adapter.model import AdapterError
from shirudo_adapter.receipt import verify_record


def qualify(root, anchors):
    require(
        set(anchors) == {"enrollment", "materials", "oracle", "quorum-audit"}, "ANCHORS"
    )
    for name, pin in anchors.items():
        require(
            hashlib.sha256((root / (name + ".json")).read_bytes()).hexdigest() == pin,
            "OBSERVER_PIN",
        )
    pins = anchors["enrollment"]
    summary = run(root, pins)
    require(
        summary["overlap"] == 1000 and sum(summary["outcomes"].values()) == 100000,
        "WORKLOAD",
    )
    counts, _, receipts = inspect(root, pins)
    require(
        summary["effects"] == 4 and counts == load(root, "auditor"), "INDEPENDENT_COUNT"
    )
    faults = load(root, "faults")
    orders = load(root, "quorum-audit")[0]
    owner = load(root, "enrollment")["trust"]["owner_public_key"]
    clash = faults["conflict"]
    require(
        clash["accepted"].count(True) == 1 and len(clash["candidates"]) == 2, "CONFLICT"
    )
    for doc, won in zip(clash["candidates"], clash["accepted"]):
        v = verify_record(doc, owner)
        require((orders[v["index"] - 1] == doc) == won, "ORDER_WINNER")
    require(load(root, "replies")["replay-cas"] is False, "REPLAY")
    invalid = faults["unsigned-succession"]
    try:
        verify_record(invalid["command"], owner)
    except AdapterError as exc:
        require(exc.code == "INVALID_SIGNATURE", "INVALID_TEST")
    else:
        raise ValueError("expected an unsigned successor")
    require(
        invalid["command"] not in orders
        and invalid["denial"] == dict(state="DENIED", reason="INVALID_SIGNATURE"),
        "UNAUTHORIZED_SUCCESSION",
    )
    p = faults["partition"]
    require(
        p["minority"] == "UNAVAILABLE"
        and p["old"] != p["replacement"]
        and p["unavailable_ns"] > 0,
        "MINORITY",
    )
    dead, new, restored = faults["leader-crash"]
    require(dead == restored and dead != new, "LEADER_REPLACEMENT")
    require(
        faults["restored"] == dict(state="UNRESOLVED", reason="TARGET_ROLLBACK")
        and faults["storage-offline"]
        == dict(state="UNRESOLVED", reason="STATE_UNAVAILABLE")
        and faults["clone"] == "TARGET_RESTART_UNRESOLVED",
        "STORAGE",
    )
    combined = faults["coordinated-rollback"]
    require(
        combined["recovery"] == faults["restored"]
        and combined["submission"]["state"] == "DENIED"
        and combined["authority"] == dict(state="DENIED", reason="AUTHORITY_FLOOR"),
        "COORDINATED_RESTORE",
    )
    require(
        faults["auditor-unauthorized"]
        == faults["sql-probe-unauthorized"]
        == "NO_RESPONSE_BODY",
        "AUDITOR_ACCESS",
    )
    historical = load(root, "historical")
    require(
        historical
        == {
            "alice/lost": dict(state="COMMITTED", receipt=receipts["lost"]),
            "bob/lost": dict(state="UNRESOLVED"),
            "alice/pending": dict(state="UNRESOLVED"),
            "alice/revoked": dict(state="NOT_COMMITTED"),
        },
        "HISTORICAL_ACCESS",
    )
    perf = load(root, "performance")
    attempts = load(root, "attempts")
    tally = Counter(r[3] for r in attempts)
    require(tally == perf["attempt_outcomes"] and tally["COMMITTED"] == 1, "CONTENTION")
    require(
        perf["recoveries"] == 100000 and perf["attempts"] == 1000 and perf["overlap"],
        "MEASUREMENTS",
    )
    summary.update(
        mutations=controls(root),
        budget_exceedances=perf["exceeded"],
        stationary="PASS" if not perf["exceeded"] else "FAIL",
    )
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("observer_pins", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            qualify(args.directory, json.loads(args.observer_pins.read_bytes())),
            sort_keys=True,
            indent=2,
        )
    )
