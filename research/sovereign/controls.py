"""Disposable protocol doubles. Each consumes real public run inputs, with no live credentials or protected output."""

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shirudo_adapter.model import AdapterError
from shirudo_adapter.receipt import sign_record, verify_record
from research.sovereign.review import (
    eligible,
    distinct,
    partition,
    lineage,
    outcome,
    load,
)
from research.wt_swarm.review import Mismatch


def controls(root):
    m = load(root, "materials")
    j = load(root, "oracle")
    e = load(root, "enrollment")
    replies = load(root, "replies")
    orders = load(root, "orders")
    windows = []
    for doc in orders:
        ack = verify_record(doc["ack"], e["boot"])
        windows.append((ack["counter"], ack["order"]))
    counter = j["counter"][0]["value"]
    settled = j["settlements"]
    frame = m["original"]["frame"]
    permit = verify_record(frame["permit"], e["trust"]["owner_public_key"])
    gr = frame["request"]["grant"]["payload"]["grant_id"]
    receipts = {
        row["op"]: json.loads(
            next(r["receipt"] for r in j["operations"] if r["id"] == row["op"])
        )
        for row in settled
    }

    def stale():
        # Mutant authorizes the next increment from an authentic but retired permit.
        if verify_record(frame["permit"], e["trust"]["owner_public_key"]):
            eligible(windows, counter + 1, permit["head"], set(), gr)

    def succession():
        # The mutant orders a successor on the strength of its own signature.
        replacement = Ed25519PrivateKey.generate()
        accepted = sign_record(replacement, orders[-1]["command"]["payload"])
        verify_record(accepted, e["trust"]["owner_public_key"])

    def duplicate():
        # New coordinator loses its consumed-request set on replacement.
        lost = m["lost"]["frame"]["request"]["operation_id"]
        state = settled.copy()
        if lost not in set():
            state.append(
                dict(next(r for r in state if r["op"] == lost), seq=counter + 1)
            )
        distinct(state, counter + 1)

    def substitute():
        # Resolve lineage by most recent executor evidence, ignoring operation ID.
        record = dict(settled[0], endorsement=settled[-1]["endorsement"])
        lineage(record, frame, permit, receipts[permit["op"]], e["boot"])

    def false():
        # A replica converts an absent local entry to a definitive outcome.
        lookup = {}
        result = lookup.get("pending", dict(state="NOT_COMMITTED", receipt=None))
        outcome(
            result, "pending", m["pending"]["binding"], "UNRESOLVED", None, e["boot"]
        )

    def partitioned():
        # A disconnected forwarder answers a fresh attempt with cached success.
        response_cache = [replies["original"]]
        partition(response_cache[-1])

    result = {}
    for name, reason, exercise in (
        ("stale fencing", "STALE_FENCE", stale),
        ("unauthorized succession", "INVALID_SIGNATURE", succession),
        ("duplicate settlement", "DUPLICATE_SETTLEMENT", duplicate),
        ("lineage substitution", "LINEAGE", substitute),
        ("false reconciliation", "FALSE_RECOVERY", false),
        ("unsafe partition recovery", "UNSAFE_PARTITION", partitioned),
    ):
        try:
            exercise()
        except (AdapterError, Mismatch) as error:
            actual = error.code if isinstance(error, AdapterError) else str(error)
            if actual != reason:
                raise AssertionError((name, actual, reason))
            result[name] = actual
        else:
            raise AssertionError("Undetected: " + name)
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path)
    print(json.dumps(controls(p.parse_args().directory), sort_keys=True))
