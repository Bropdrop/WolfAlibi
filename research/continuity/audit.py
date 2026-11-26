"""Verify public trial evidence without importing any continuity gate, importer or verifier."""

import argparse
from collections import Counter
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
from research.wt_swarm.review import require
from research.blackout.review import timing
from shirudo_adapter.action_gate import verify_effect_receipt
from shirudo_adapter.model import AdapterError, digest
from shirudo_adapter.receipt import verify_record


def load(path):
    return json.loads(path.read_bytes())


def authentication(r, package, parent, prior_effects):
    source, origin = r["source"], r["enrollment"]
    j = package["journal"]
    claims = verify_record(package["checkpoint"], r["observer"])
    require(
        digest(package["checkpoint"]) == r["checkpoint_sha256"]
        and claims
        == dict(
            schema="wolfalibi.continuity.frozen.v1",
            target=source["target"],
            destination=r["destination"],
            journal=digest(j),
        ),
        "OBSERVATION",
    )
    require(
        j["floor"] == r["floor"]
        and j["metadata"]["public_key"] == origin["key"]
        and j["metadata"]["gate_instance_id"] == origin["gate"] == source["gate"]
        and json.loads(j["metadata"]["trust_document"]) == origin["trust"],
        "ORIGIN",
    )
    epoch, head = parent["journal"]["floor"][:2] if parent else (0, "0" * 64)
    holder = None
    previous = {row["id"]: row for row in parent["journal"]["rows"]} if parent else {}
    rows = {row["id"]: row for row in j["rows"]}
    require(len(rows) == len(j["rows"]), "DUPLICATE_SETTLEMENT")
    require(all(rows.get(k) == v for k, v in previous.items()), "ORIGINAL_ROW")
    if parent:
        require(
            all(
                j["revocations"].get(k) == v
                for k, v in parent["journal"]["revocations"].items()
            ),
            "LOST_REVOCATION",
        )
        require(
            all(
                j["recovery"].get(k) == v
                for k, v in parent["journal"]["recovery"].items()
            ),
            "LOST_RECOVERY",
        )
    results = prior_effects.copy()
    prepared = {op: (ep, h) for op, ep, h in j["prepared"]}
    for index, event in enumerate(j["events"], 1):
        require(event["seq"] == index, "EVENT_ORDER")
        rec = event["record"]
        if event["kind"] == "transition":
            tr = verify_record(rec, source["issuer"])
            require(
                tr["previous"] == head
                and tr["epoch"] == epoch + 1
                and tr["gate"] == origin["gate"]
                and tr["target"] == source["target"]
                and (index == 1 or holder is not None),
                "EPOCH_CHAIN",
            )
            epoch, head, holder = tr["epoch"], digest(rec), tr["executor"]
            if holder is None:
                a = verify_record(tr["authorization"], source["migration_authorizer"])
                require(
                    tr["schema"] == "wolfalibi.exodus.source-fence.v1"
                    and a
                    == dict(
                        schema="wolfalibi.exodus.retire-authority.v1",
                        epoch=epoch,
                        previous=tr["previous"],
                        gate=origin["gate"],
                        target=source["target"],
                        destination=r["destination"],
                    )
                    and tr["destination"] == r["destination"],
                    "RETIREMENT_AUTH",
                )
            else:
                require(
                    tr["schema"] == "wolfalibi.schism.transition.v1"
                    and holder in source["executors"],
                    "EXECUTOR_ENROLLMENT",
                )
            continue
        require(
            event["kind"] == "effect" and holder in source["executors"],
            "RETIRED_EXECUTOR",
        )
        effect = verify_record(rec, holder)
        op = effect["op"]
        require(op not in results and prepared[op] == (epoch, head), "EPOCH_EFFECT")
        row = rows[op]
        req = json.loads(row["request"])
        receipt = json.loads(row["receipt"])
        act = json.loads(row["document"])
        owner = verify_record(req["grant"], origin["trust"]["owner_public_key"])
        verify_record(req["assessment"], origin["trust"]["verifier_public_key"])
        action = verify_record(act, origin["key"])
        require(
            owner["operation_id"] == action["operation_id"] == req["operation_id"] == op
            and owner["action_challenge_sha256"] == digest(act)
            and row["grant_id"] == owner["grant_id"],
            "OWNER_BINDING",
        )
        permit = j["permits"][op]
        binding = dict(
            schema="wolfalibi.schism.permit.v1",
            epoch=epoch,
            head=head,
            executor=holder,
            target=source["target"],
            gate=origin["gate"],
            op=op,
            request=digest(req),
            grant=digest(req["grant"]),
        )
        require(
            verify_record(permit, source["issuer"]) == binding
            and effect
            == dict(
                binding,
                schema="wolfalibi.schism.effect.v1",
                receipt=digest(receipt),
                permit=digest(permit),
            ),
            "ENDORSEMENT",
        )
        verify_effect_receipt(
            receipt,
            origin["key"],
            expected_target=source["target"],
            expected_gate_instance_id=origin["gate"],
            expected_operation_id=op,
            expected_grant_id=owner["grant_id"],
            expected_grant_sha256=digest(req["grant"]),
            expected_assessment_sha256=digest(req["assessment"]),
            expected_action_challenge=act,
        )
        require(
            (receipt["payload"]["counter_before"], receipt["payload"]["counter_after"])
            == (len(results), len(results) + 1)
            and row["request_sha256"] == digest(req)
            and row["status"] == "COMMITTED",
            "COUNTER",
        )
        results[op] = dict(
            request=digest(req), receipt=receipt, epoch=epoch, gate=origin["gate"]
        )
    require(holder is None and j["floor"] == [epoch, head, j["seal"]], "SOURCE_FENCE")
    require(
        len(results) == j["counter"]
        and set(results)
        == {row["id"] for row in rows.values() if row["status"] == "COMMITTED"},
        "CONSUMPTION",
    )
    return results


def activation(floor, target, approval, src, target_digest):
    require(floor is not None, "LIVE_CHECKPOINT_REQUIRED")
    require(
        src["executor"] is None and src["schema"] == "wolfalibi.exodus.source-fence.v1",
        "SOURCE_STILL_ACTIVE",
    )
    require(
        digest(target) == target_digest == src["destination"], "DESTINATION_BINDING"
    )
    p = verify_record(approval, target["issuer"])
    require(
        p
        == dict(
            schema="wolfalibi.schism.transition.v1",
            previous=floor[1],
            epoch=floor[0] + 1,
            target=target["target"],
            gate=target["gate"],
            executor=target["executors"][0],
        ),
        "ACTIVATION",
    )


def recover(reply, key, binding, j, effects, wanted_checkpoint):
    proof = verify_record(reply["proof"], key)
    require(
        proof
        == dict(
            {k: v for k, v in binding.items() if k != "grant_id"},
            schema="wolfalibi.continuity.historical-recovery.v1",
            authority="READ_ONLY",
            outcome=proof["outcome"],
            checkpoint=wanted_checkpoint,
            receipt_sha256=digest(reply["receipt"]) if reply["receipt"] else None,
        ),
        "QUERY_BINDING",
    )
    op = binding["operation_id"]
    if op in effects:
        require(
            proof["outcome"] == "COMMITTED"
            and reply["receipt"] == effects[op]["receipt"]
            and effects[op]["request"] == binding["request_sha256"],
            "ORIGINAL_RECEIPT",
        )
    else:
        expected = (
            "NOT_COMMITTED" if binding["grant_id"] in j["revocations"] else "UNRESOLVED"
        )
        require(
            reply["receipt"] is None and proof["outcome"] == expected, "FALSE_OUTCOME"
        )
    return proof["outcome"]


def continuity(before, after):
    a, b = before["journal"], after["journal"]
    require(
        all(b["revocations"].get(k) == v for k, v in a["revocations"].items()),
        "LOST_REVOCATION",
    )
    for original in a["rows"]:
        copies = [r for r in b["rows"] if r["id"] == original["id"]]
        if original["status"] == "COMMITTED":
            require(len(copies) <= 1, "DUPLICATE_SETTLEMENT")
            require(
                copies and copies[0]["grant_id"] == original["grant_id"],
                "MISSING_CONSUMPTION",
            )
            require(copies[0]["receipt"] == original["receipt"], "MISSING_RECEIPT")
        require(copies == [original], "HISTORICAL_ROW")


def review(path, anchors):
    read = lambda n: load(path / (n + ".json"))
    for n, pin in anchors.items():
        require(
            hashlib.sha256((path / (n + ".json")).read_bytes()).hexdigest() == pin,
            "EXTERNAL_PIN",
        )
    r, p, r2, p2 = map(read, ("pins", "transfer", "lineage", "segments"))
    require(
        r2["parent"] == r
        and p2["parent"] == p
        and digest(r2["source"]) == r["destination"],
        "SEGMENT_CHAIN",
    )
    first = authentication(r, p, None, {})
    continuity(p, p2)
    both = authentication(r2, p2, p, first)
    dest = read("destination")
    outcomes = read("boundaries")
    require(
        outcomes["interrupted_writer"] == -9
        and outcomes["competing_results"] == ["ALREADY_ACTIVATED", "RESPONSE_LOST"],
        "ACCEPTED_TWICE",
    )
    src = p["journal"]["events"][-1]["record"]["payload"]
    args = (
        p["journal"]["floor"],
        r2["source"],
        dest["activation"],
        src,
        r["destination"],
    )
    activation(*args)
    activation(
        p2["journal"]["floor"],
        read("third-enrollment"),
        read("second-activation"),
        p2["journal"]["events"][-1]["record"]["payload"],
        r2["destination"],
    )
    require(
        len(first) == 1
        and len(both) == 2
        and dest["final_counter"] == 2
        and both[dest["request"]["operation_id"]]["receipt"] == dest["receipt"],
        "NEW_EFFECT",
    )

    def mutation(name, code, fn):
        try:
            fn()
        except (ValueError, AdapterError) as e:
            require(getattr(e, "code", str(e)) == code, "WRONG_DETECTOR_" + name)
            return code
        raise ValueError("Undetected " + name)

    m = {}
    m["activation before fence"] = mutation(
        "early",
        "SOURCE_STILL_ACTIVE",
        lambda: activation(
            *args[:3], dict(src, executor=r["source"]["executors"][0]), args[4]
        ),
    )
    m["missing destination binding"] = mutation(
        "binding", "DESTINATION_BINDING", lambda: activation(*args[:4], "0" * 64)
    )
    m["activation without floor"] = mutation(
        "floor", "LIVE_CHECKPOINT_REQUIRED", lambda: activation(None, *args[1:])
    )
    m["restored source as current"] = mutation(
        "restored", "ACTIVATION", lambda: activation([1, "0" * 64, ""], *args[1:])
    )
    bad = deepcopy(p)
    bad["journal"]["counter"] = 0
    m["unverified manifest"] = mutation(
        "manifest", "OBSERVATION", lambda: authentication(r, bad, None, {})
    )
    for tag, code in (
        ("revocation", "LOST_REVOCATION"),
        ("consumed grant", "MISSING_CONSUMPTION"),
        ("duplicate", "DUPLICATE_SETTLEMENT"),
        ("receipt", "MISSING_RECEIPT"),
    ):
        bad = deepcopy(p2)
        row = next(row for row in bad["journal"]["rows"] if row["id"] in first)
        if tag == "revocation":
            bad["journal"]["revocations"].clear()
        elif tag == "consumed grant":
            row["grant_id"] = None
        elif tag == "duplicate":
            bad["journal"]["rows"].append(row)
        else:
            row["receipt"] = None
        m[tag] = mutation(tag, code, lambda: continuity(p, bad))
    rec = read("recovery")
    j = p["journal"]
    for obs in rec["observations"]:
        if obs["role"] == "bob":
            require(
                obs["result"] == dict(outcome="UNRESOLVED", reason="RECOVERY_DENIED"),
                "DISCLOSURE",
            )
        else:
            key = obs["result"]["proof"]["payload"]["request_sha256"]
            require(
                recover(
                    obs["result"],
                    rec["proof_key"],
                    j["recovery"][key],
                    j,
                    first,
                    r["checkpoint_sha256"],
                )
                == obs["expected"],
                "OUTCOME",
            )
    con = read("contention")
    rows = con["batch"]["rows"]
    require(
        len(rows) == len({x["tid"] for x in rows}) == 1000
        and max(x["start_ns"] for x in rows)
        <= con["begin"]
        <= con["end"]
        <= min(x["end_ns"] for x in rows)
        and all(x["outcome"] in ("DENIED", "AMBIGUOUS") for x in rows),
        "OVERLAP",
    )
    require(
        con["latency"] == timing([(x["start_ns"], x["end_ns"]) for x in rows]),
        "CONTENTION_METRICS",
    )
    metrics = read("storm-metrics")
    with gzip.open(path / "storm.json.gz") as fp:
        groups = json.load(fp)
    counts = Counter()
    spans = []
    require(len(groups) == 4, "CLIENT_WORKERS")
    for worker, g in enumerate(groups):
        require(len(g["rows"]) == 25000, "VOLUME")
        validation = {}
        for ref, reply in g["replies"].items():
            require(digest(reply) == ref, "WIRE_DIGEST")
            binding = j["recovery"][reply["proof"]["payload"]["request_sha256"]]
            validation[ref] = recover(
                reply, metrics["key"], binding, j, first, r["checkpoint_sha256"]
            )
        for i, (s, e, index, ref) in enumerate(g["rows"]):
            require(
                s <= e
                and index == (worker + i) % 3
                and validation[ref]
                == ("COMMITTED", "UNRESOLVED", "NOT_COMMITTED")[index],
                "RECOVERY_ORDER",
            )
            counts[validation[ref]] += 1
            spans.append((s, e))
    require(timing(spans) == metrics["timing"], "RECOVERY_METRICS")
    return dict(
        reconciled=len(both),
        outcomes=counts,
        overlap=len(rows),
        requests=len(rows) + len(spans),
        detected=m,
        source_epochs=[1, 3],
        active_epoch=5,
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence", type=Path)
    p.add_argument("trusted_sha256", type=Path)
    a = p.parse_args()
    print(
        json.dumps(review(a.evidence, load(a.trusted_sha256)), sort_keys=True, indent=2)
    )
