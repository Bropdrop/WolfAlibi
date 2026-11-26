"""Verify a retired native journal using independently enrolled public credentials."""

from pathlib import Path
import hashlib
import argparse
import json
from research.schism.storage import FENCE, TRANSITION, PERMIT, STAMP, ZERO, check_fence
from shirudo_adapter.action_gate import Gate
from shirudo_adapter.receipt import verify_record
from shirudo_adapter.model import digest, canonical_json
from research.wt_swarm.review import require


class HistoricalDecoder:
    """Only native validation methods. No socket, database, private key or executor."""

    _attestation = Gate._attestation
    _assessment = Gate._assessment
    _grant = Gate._grant
    _execution_times = Gate._execution_times
    decode = Gate._decode_operation

    def __init__(self, enrollment):
        self._trust = enrollment["trust"]
        self.instance_id = enrollment["gate"]
        self._public_key = enrollment["key"]
        self._policy_sha = digest(self._trust["policy"])


def state_seal(data):
    columns = (
        "id nonce attestation_id attestation_nonce attestation_sha256 document attestation_document "
        "status request request_sha256 grant_id grant_sha256 assessment_sha256 receipt counter_before counter_after"
    ).split()
    h = hashlib.sha256()
    tables = [
        (
            "metadata",
            sorted((k, v) for k, v in data["metadata"].items() if k != "last_clock"),
        ),
        ("counter", [(1, data["counter"])]),
        (
            "operations",
            (
                [r[k] for k in columns]
                for r in sorted(data["rows"], key=lambda r: r["id"])
            ),
        ),
        ("revoked_grants", sorted(data["revocations"].items())),
        ("schism_head", [(1, *data["floor"][:2])]),
        ("schism_prepared", sorted(data["prepared"])),
    ]
    for name, rows in tables:
        h.update(name.encode() + b"\n")
        for row in rows:
            h.update(canonical_json(list(row)) + b"\n")
    return digest([h.hexdigest(), data["metadata"]["last_clock"]])


def verify(roots, package):
    p = roots["source"]
    audit = verify_record(package["checkpoint"], roots["observer"])
    data = package["journal"]
    require(
        digest(package["checkpoint"]) == roots["checkpoint_sha256"], "STALE_CHECKPOINT"
    )
    require(
        audit
        == dict(
            schema="wolfalibi.continuity.frozen.v1",
            target=p["target"],
            destination=roots["destination"],
            journal=digest(data),
        ),
        "JOURNAL_CHECKPOINT",
    )
    enrollment = roots["enrollment"]
    require(
        enrollment["gate"] == p["gate"]
        and enrollment["trust"]["target_id"] == p["target"],
        "ENROLLMENT",
    )
    require(
        data["floor"] == roots["floor"]
        and state_seal(data) == data["seal"] == data["floor"][2],
        "SOURCE_STATE_SEAL",
    )
    meta = data["metadata"]
    require(
        meta["public_key"] == enrollment["key"]
        and meta["gate_instance_id"] == enrollment["gate"]
        and json.loads(meta["trust_document"]) == enrollment["trust"]
        and meta["policy_active"] == data["policy_active"]
        and meta["last_clock"] == data["clock"],
        "SOURCE_IDENTITY",
    )
    decoder = HistoricalDecoder(enrollment)
    epoch, head, holder = 0, ZERO, None
    receipts = {}
    rows = {r["id"]: r for r in data["rows"]}
    require(len(rows) == len(data["rows"]), "DUPLICATE_ID")
    inherited = {}
    if "parent" in roots:
        prior = package["parent"]
        receipts = verify(roots["parent"], prior)
        require(
            roots["parent"]["destination"] == digest(p)
            and roots["parent"]["source"]["target"] == p["target"],
            "LINEAGE_TARGET",
        )
        epoch, head, _ = prior["journal"]["floor"]
        require(
            all(
                data["recovery"].get(k) == v
                for k, v in prior["journal"]["recovery"].items()
            ),
            "LOST_RECOVERY",
        )
        inherited = {r["id"]: r for r in prior["journal"]["rows"]}
        require(all(rows.get(k) == v for k, v in inherited.items()), "HISTORICAL_ROW")
        require(
            all(
                data["revocations"].get(k) == v
                for k, v in prior["journal"]["revocations"].items()
            ),
            "LOST_REVOCATION",
        )
    for seq, event in enumerate(data["events"], 1):
        record = event["record"]
        require(seq == event["seq"], "SEQUENCE")
        if event["kind"] == "transition":
            payload = verify_record(record, p["issuer"])
            require(
                payload["gate"] == p["gate"]
                and payload["target"] == p["target"]
                and payload["previous"] == head
                and payload["epoch"] == epoch + 1
                and (
                    epoch == 0 or holder is not None or (seq == 1 and "parent" in roots)
                ),
                "FORK",
            )
            epoch, head, holder = payload["epoch"], digest(record), payload["executor"]
            if payload["schema"] == FENCE:
                check_fence(payload, p)
                require(payload["destination"] == roots["destination"], "DESTINATION")
            else:
                require(
                    payload["schema"] == TRANSITION and holder in p["executors"],
                    "EXECUTOR",
                )
            continue
        require(event["kind"] == "effect" and holder is not None, "FENCED_EFFECT")
        e = verify_record(record, holder)
        row = rows[e["op"]]
        operation = decoder.decode(row)
        receipt = operation["receipt"]
        permit = data["permits"][row["id"]]
        expected = dict(
            schema=PERMIT,
            epoch=epoch,
            head=head,
            executor=holder,
            op=row["id"],
            gate=p["gate"],
            target=p["target"],
            request=row["request_sha256"],
            grant=row["grant_sha256"],
        )
        require(
            verify_record(permit, p["issuer"]) == expected
            and e
            == dict(
                expected, schema=STAMP, receipt=digest(receipt), permit=digest(permit)
            ),
            "EPOCH_BINDING",
        )
        require(
            row["status"] == "COMMITTED"
            and row["id"] not in receipts
            and (row["counter_before"], row["counter_after"])
            == (len(receipts), len(receipts) + 1),
            "COUNTER",
        )
        receipts[row["id"]] = dict(
            epoch=epoch,
            gate=p["gate"],
            target=p["target"],
            request=row["request_sha256"],
            receipt=row["receipt"],
        )
    require(
        epoch > 1
        and holder is None
        and data["floor"] == [epoch, head, data["seal"]]
        and data["counter"] == len(receipts),
        "RETIREMENT",
    )
    for row in rows.values():
        if row["id"] not in inherited:
            decoder.decode(row)
        require(
            (row["id"] in receipts) == (row["status"] == "COMMITTED"), "OMITTED_EFFECT"
        )
    require(set(data["recovery"]) == set(data["recovery_requests"]), "RECOVERY_SET")
    for key, b in data["recovery"].items():
        if "parent" in roots and key in package["parent"]["journal"]["recovery"]:
            require(
                b == package["parent"]["journal"]["recovery"][key]
                and data["recovery_requests"][key]
                == package["parent"]["journal"]["recovery_requests"][key],
                "RECOVERY_CONTINUITY",
            )
            continue
        req = data["recovery_requests"][key]
        row = rows[b["operation_id"]]
        action = json.loads(row["document"])
        att = decoder._attestation(json.loads(row["attestation_document"]))
        decoder._assessment(req["assessment"], action["payload"], att)
        grant = decoder._grant(req["grant"], action, req["assessment"])
        permit = verify_record(data["permits"][row["id"]], p["issuer"])
        require(
            key == digest(req) == b["request_sha256"] == permit["request"]
            and req["operation_id"] == row["id"] == permit["op"]
            and grant["grant_id"] == b["grant_id"]
            and permit["grant"] == digest(req["grant"])
            and b["gate_instance_id"] == p["gate"]
            and b["target_id"] == p["target"],
            "RECOVERY_BINDING",
        )
    return receipts


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("pins", type=Path)
    p.add_argument("package", type=Path)
    args = p.parse_args()
    print(
        json.dumps(
            verify(
                json.loads(args.pins.read_bytes()),
                json.loads(args.package.read_bytes()),
            ),
            sort_keys=True,
        )
    )
