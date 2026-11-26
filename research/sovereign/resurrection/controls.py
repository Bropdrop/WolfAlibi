"""Disposable faulty recovery decisions over real authenticated laboratory evidence."""

from copy import deepcopy
from research.sovereign.review import load, distinct
from research.sovereign.resurrection.verify import (
    PHASES,
    transition,
    revocations,
    retained,
)
from research.wt_swarm.review import Mismatch, require
from shirudo_adapter.receipt import verify_record


def controls(root):
    rounds = load(root, "activations")
    first, last = rounds
    context = load(root, "resurrection")
    owner = context["pin"]["owner"]
    records = context["records"]
    fault = load(root, "faults")
    valid = verify_record(last["auth"], owner)
    old = verify_record(first["auth"], owner)
    witness = {r["payload"]["version"]: r for r in records}
    version = last["result"]["anchor"]["payload"]["version"] - 1
    floor = witness[version]["payload"]["seal"]
    journal = load(root, "oracle")
    hist = load(root, "historical")

    def activate(steps=PHASES, letter=valid, candidate=None, local=None):
        transition(
            steps,
            letter,
            candidate or valid["boot"],
            valid["epoch"],
            last["before"],
            floor,
            local or last["before_seal"],
        )

    activate()

    def automatic():
        activate(steps=["RECOVERING", "ACTIVE"])

    def stale():
        activate(letter=old, candidate=old["boot"])

    def reused():
        restored_identity = verify_record(fault["interrupted-recovery"], owner)["boot"]
        activate(candidate=restored_identity)

    def restore():
        activate(local=first["before_seal"])

    def duplicate():
        settled = list(journal["settlements"])
        # The replacement forgets its consumption map and counts a redelivery.
        retry = dict(settled[0], seq=len(settled) + 1)
        settled.append(retry)
        distinct(settled, len(settled))

    def absence():
        missing = {}
        retained(
            missing.get("uncertain", dict(state="NOT_COMMITTED")), "UNRESOLVED", None
        )

    def substitute():
        cached = hist["alice/new-lost"]
        retained(cached, "COMMITTED", hist["alice/lost"]["receipt"])

    def ignore_offline():
        restored = deepcopy(journal)
        restored["revoked_grants"] = first["before"]["revoked_grants"]
        revocations(restored, {r["id"] for r in journal["revoked_grants"]})

    results = {}
    for fn, reason in (
        (automatic, "RECONCILIATION_REQUIRED"),
        (stale, "STALE_EPOCH"),
        (reused, "INCARNATION"),
        (restore, "RESTORED_STATE"),
        (duplicate, "DUPLICATE_SETTLEMENT"),
        (absence, "FALSE_OUTCOME"),
        (substitute, "ORIGINAL_RECEIPT"),
        (ignore_offline, "OFFLINE_REVOCATION"),
    ):
        try:
            fn()
        except Mismatch as exc:
            require(str(exc) == reason, "UNEXPECTED_DETECTION")
            results[fn.__name__] = reason
        else:
            raise AssertionError("undetected mutant " + fn.__name__)
    return results
