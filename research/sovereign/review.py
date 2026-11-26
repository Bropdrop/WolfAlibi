"""Offline auditor. Only native cryptographic primitives and historical receipt verification are reused."""

import argparse
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path

from research.wt_swarm.review import require
from shirudo_adapter.action_gate import (
    verify_effect_receipt,
    make_grant_payload,
    CLOCK_SKEW_MS,
    FRESHNESS_MS,
)
from shirudo_adapter.receipt import verify_receipt
from shirudo_adapter.receipt import verify_record
from shirudo_adapter.model import digest


def load(root, name):
    return json.loads((root / (name + ".json")).read_bytes())


def eligible(windows, sequence, head, revoked, grant):
    require(
        [h for c, h in windows if c < sequence][-1] == head and grant not in revoked,
        "STALE_FENCE",
    )


def distinct(settlements, total):
    require(
        len({r["op"] for r in settlements}) == len(settlements) == total,
        "DUPLICATE_SETTLEMENT",
    )
    require(
        {r["seq"] for r in settlements} == set(range(1, total + 1)), "COUNTER_SEQUENCE"
    )


def partition(reply):
    require(
        reply.get("reason") == "QUORUM_UNAVAILABLE"
        and "receipt" not in reply
        and reply.get("state") == "DENIED",
        "UNSAFE_PARTITION",
    )


def lineage(s, frame, payload, receipt, boot):
    require(
        json.loads(s["permit"]) == frame["permit"]
        and json.loads(s["sender"]) == frame["sender"]
        and verify_record(json.loads(s["endorsement"]), boot)
        == dict(
            payload,
            schema="wolfalibi.sovereign.effect.v1",
            receipt=digest(receipt),
            permit=digest(frame["permit"]),
        ),
        "LINEAGE",
    )


def inspect(root, pin):
    require(
        hashlib.sha256((root / "enrollment.json").read_bytes()).hexdigest() == pin,
        "PROVISIONING",
    )
    enrollment = load(root, "enrollment")
    owner = enrollment["trust"]["owner_public_key"]
    boot = enrollment["boot"]
    native = enrollment["identity"]["public_key"]
    gate = enrollment["identity"]["gate_instance_id"]
    target = enrollment["trust"]["target_id"]
    j = load(root, "oracle")
    m = load(root, "materials")
    copies = load(root, "quorum-audit")
    require(
        len(copies) == 3 and all(orders == copies[0] for orders in copies), "DIRECTORY"
    )
    require(len(j["commands"]) == len(copies[0]), "PREFIX")
    heads = {}
    epoch = 0
    previous = "0" * 64
    floor = 0
    revoked = set()
    windows = []
    for index, (row, cmd) in enumerate(zip(j["commands"], copies[0]), 1):
        require(json.loads(row["command"]) == cmd and row["idx"] == index, "ORDER")
        p = verify_record(cmd, owner)
        ack = verify_record(json.loads(row["acknowledgement"]), boot)
        require(
            p["index"] == index
            and p["previous"] == previous
            and (p["boot"], p["gate"], p["target"]) == (boot, gate, target),
            "CHAIN",
        )
        require(
            p["schema"] == "wolfalibi.sovereign.order.v1"
            and p["holder"] in enrollment["holders"].values(),
            "ENROLLMENT",
        )
        if p["kind"] == "activate":
            epoch += 1
            holder = p["holder"]
            require(p["revoked"] is None, "ACTIVATION")
        else:
            require(p["kind"] == "revoke" and p["holder"] == holder, "REVOCATION")
            revoked.add(p["revoked"])
        previous = digest(cmd)
        require(
            p["epoch"] == epoch
            and ack
            == dict(
                schema="wolfalibi.sovereign.installed.v1",
                order=previous,
                index=index,
                epoch=epoch,
                target=target,
                counter=ack["counter"],
            )
            and floor <= ack["counter"] <= j["counter"][0]["value"],
            "INSTALL",
        )
        floor = ack["counter"]
        windows.append((floor, previous))
        heads[previous] = (epoch, holder, set(revoked))
    require({r["id"] for r in j["revoked_grants"]} == revoked, "REVOKED_SET")
    rows = {r["id"]: r for r in j["operations"]}
    acl = {r["op"]: json.loads(r["binding"]) for r in j["recovery_acl"]}
    prepared = {r["op"]: (r["epoch"], r["head"]) for r in j["bindings"]}
    byop = {v["frame"]["request"]["operation_id"]: n for n, v in m.items()}
    require(
        len(rows) == len(m) == len(byop)
        and rows.keys() == acl.keys() == prepared.keys() == byop.keys(),
        "EXACT_OPERATIONS",
    )
    grants = set()
    receipts = {}
    expect = {}
    settled = {r["op"]: r for r in j["settlements"]}
    distinct(j["settlements"], j["counter"][0]["value"])
    for op, row in rows.items():
        name = byop[op]
        material = m[name]
        frame = material["frame"]
        req = frame["request"]
        authority = verify_record(req["grant"], owner)
        assessor = verify_record(
            req["assessment"], enrollment["trust"]["verifier_public_key"]
        )
        action = material["action"]
        a = verify_record(action, native)
        att = verify_record(
            material["challenge"], enrollment["trust"]["verifier_public_key"]
        )
        assessment = verify_receipt(
            req["assessment"],
            enrollment["trust"]["verifier_public_key"],
            expected_target=target,
            expected_policy_sha256=digest(enrollment["trust"]["policy"]),
            expected_challenge_id=att["challenge_id"],
        )
        require(
            assessment["historical_outcome"] == "EVIDENCE_ACCEPTED"
            and assessor["nonce"] == att["nonce"]
            and json.loads(row["attestation_document"]) == material["challenge"],
            "ASSESSMENT",
        )
        require(
            json.loads(row["document"]) == action
            and a["attestation_challenge_sha256"] == digest(material["challenge"])
            and assessor["instance_id"] == enrollment["trust"]["verifier_instance_id"],
            "NATIVE_BINDING",
        )
        require(
            authority
            == make_grant_payload(
                action,
                req["assessment"],
                grant_id=authority["grant_id"],
                issued_at_ms=authority["issued_at_ms"],
                expires_at_ms=authority["expires_at_ms"],
            ),
            "GRANT",
        )
        common = dict(target=target, gate=gate, boot=boot, op=op, request=digest(req))
        binding = verify_record(acl[op], owner)
        require(
            acl[op] == material["binding"]
            and binding
            == dict(
                common,
                schema="wolfalibi.sovereign.recover.v1",
                principal=enrollment["cert"]["alice"],
                grant=authority["grant_id"],
            ),
            "PRINCIPAL",
        )
        ep, head = prepared[op]
        epoch, holder, banned = heads[head]
        payload = dict(
            common,
            schema="wolfalibi.sovereign.permit.v1",
            epoch=epoch,
            head=head,
            holder=holder,
            grant=digest(req["grant"]),
        )
        require(
            ep == epoch and verify_record(frame["permit"], owner) == payload, "PERMIT"
        )
        require(
            verify_record(frame["sender"], holder)
            == dict(
                schema="wolfalibi.sovereign.submit.v1",
                permit=digest(frame["permit"]),
                request=digest(req),
            ),
            "HOLDER",
        )
        if op not in settled:
            require(
                row["status"] == "PREPARED" and row["receipt"] is None,
                "MISSING_RECEIPT",
            )
            expect[name] = (
                "NOT_COMMITTED" if authority["grant_id"] in revoked else "UNRESOLVED"
            )
            continue
        s = settled[op]
        seq = s["seq"]
        eligible(windows, seq, head, banned, authority["grant_id"])
        require(authority["grant_id"] not in grants, "REPLAY")
        grants.add(authority["grant_id"])
        receipt = json.loads(row["receipt"])
        rp = verify_effect_receipt(
            receipt,
            native,
            expected_target=target,
            expected_gate_instance_id=gate,
            expected_operation_id=op,
            expected_grant_id=authority["grant_id"],
            expected_grant_sha256=digest(req["grant"]),
            expected_assessment_sha256=digest(req["assessment"]),
            expected_action_challenge=action,
        )
        now = receipt["payload"]["committed_at_ms"]
        require(
            a["issued_at_ms"]
            <= now
            < min(a["expires_at_ms"], authority["expires_at_ms"])
            and now - att["issued_at_ms"] <= FRESHNESS_MS
            and max(assessor["completed_at_ms"], authority["issued_at_ms"])
            <= now + CLOCK_SKEW_MS,
            "FRESHNESS",
        )
        require(
            row["status"] == "COMMITTED"
            and row["request_sha256"] == digest(req)
            and json.loads(row["request"]) == req
            and rp["counter_after"] == row["counter_after"] == seq
            and rp["counter_before"] == row["counter_before"] == seq - 1,
            "EXACT_RECEIPT",
        )
        lineage(s, frame, payload, receipt, boot)
        expect[name] = "COMMITTED"
        receipts[name] = receipt
    return dict(effects=len(settled), transitions=len(windows)), expect, receipts


def outcome(reply, name, binding, expected, receipt, boot):
    require(
        reply["state"] == expected and reply["receipt"] == receipt, "FALSE_RECOVERY"
    )
    require(
        verify_record(reply["proof"], boot)
        == dict(
            schema="wolfalibi.sovereign.recovery-proof.v1",
            binding=digest(binding),
            state=expected,
            receipt=digest(receipt) if receipt else None,
        ),
        "RECOVERY_PROOF",
    )


def run(root, pin):
    result, expect, receipts = inspect(root, pin)
    e = load(root, "enrollment")
    m = load(root, "materials")
    replies = load(root, "replies")
    partition(replies["quorum-down"])
    require(
        replies["late"].get("reason") == "STALE_EXECUTOR"
        and replies["cross-principal"]
        == dict(state="UNRESOLVED", reason="ACCESS_DENIED"),
        "ACCESS",
    )
    require(
        replies["retry"]["receipt"] == receipts["lost"]
        and replies["original"]["receipt"] == receipts["original"]
        and replies["inflight"]["receipt"] == receipts["racing"],
        "ORIGINALS",
    )
    if (root / "performance.json").exists():
        raw = load(root, "attempts")
        require(
            len(raw) == len({r[0] for r in raw}) == 1000
            and max(r[1] for r in raw) <= min(r[2] for r in raw),
            "OVERLAP",
        )
        tally = Counter()
        for i in range(4):
            proofs = load(root, f"proof-{i}")
            with gzip.open(root / f"recover-{i}.json.gz", "rt") as f:
                calls = json.load(f)
            require(len(calls) == 25000, "VOLUME")
            checked = set()
            for index, (start, end, name, h) in enumerate(calls):
                require(
                    name == ("lost", "revoked", "pending")[(index + i) % 3]
                    and end >= start
                    and h in proofs,
                    "WORKLOAD",
                )
                if (name, h) not in checked:
                    require(digest(proofs[h]) == h, "RESPONSE_HASH")
                    outcome(
                        proofs[h],
                        name,
                        m[name]["binding"],
                        expect[name],
                        receipts.get(name),
                        e["boot"],
                    )
                    checked.add((name, h))
                tally[expect[name]] += 1
        result.update(outcomes=dict(tally), overlap=1000)
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path)
    p.add_argument("observer_pins", type=Path)
    a = p.parse_args()
    pins = json.loads(a.observer_pins.read_bytes())
    require(
        set(pins) == {"oracle", "materials", "quorum-audit", "enrollment"}, "PIN_SET"
    )
    for name, expected in pins.items():
        require(
            hashlib.sha256((a.directory / (name + ".json")).read_bytes()).hexdigest()
            == expected,
            "OBSERVER_PIN",
        )
    print(json.dumps(run(a.directory, pins["enrollment"]), sort_keys=True))
