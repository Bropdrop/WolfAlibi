"""Inspect a signed transfer proposal against independently retained Schism evidence."""

import argparse
import json
from pathlib import Path
from research.schism.review import Review
from research.wt_swarm.review import load, require
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import verify_record


def source_snapshot(root, trusted):
    audit = Review(root, trusted)
    for check in (
        audit.custody,
        audit.authority,
        audit.effects,
        audit.schedules,
        audit.outcomes,
    ):
        check()
    rows = audit.views["final"]["ledger"]
    inventory = audit.inventory["final"]
    checkpoint = audit.checkpoints["final"]
    return dict(
        logical_target=audit.anchors["pins"]["target"],
        source_gate=audit.native.profile["gate_instance_id"],
        source_gate_key=audit.native.profile["gate_public_key"],
        epoch=checkpoint["local"][0],
        journal_head=checkpoint["local"][2],
        checkpoint=checkpoint,
        counter=len(rows),
        history=[
            dict(
                operation=r["operation_id"],
                request=r["request_sha256"],
                grant=r["grant_id"],
                receipt=digest(r["receipt"]),
            )
            for r in rows
        ],
        endorsements=audit.history,
        revocations=inventory["revocations"],
        operations=inventory["operations"],
        recovery_bindings=audit.bindings,
        recovery_records={name: digest(event) for name, event in audit.events.items()},
        unresolved=sorted(
            op
            for op, state in inventory["operations"].items()
            if state == "PREPARED"
            and not any(
                b["operation_id"] == op and b["grant_id"] in inventory["revocations"]
                for b in audit.bindings.values()
            )
        ),
    )


def inspect(root, trusted, package):
    source = source_snapshot(root, trusted["source"])
    auth = verify_record(package["authorization"], trusted["authorizer"])
    expected = dict(
        schema="wolfalibi.exodus.inspect.v1",
        source=digest(source),
        destination=trusted["destination"],
        epoch=source["epoch"],
        next_epoch=source["epoch"] + 1,
    )
    require(auth == expected, "MIGRATION_AUTHORIZATION")
    manifest = verify_record(package["manifest"], trusted["exporter"])
    require(
        manifest
        == dict(
            schema="wolfalibi.exodus.transfer.v1",
            source=source,
            destination=trusted["destination"],
            authorization=digest(package["authorization"]),
        ),
        "TRANSFER_BINDING",
    )
    return dict(
        transfer_evidence="VERIFIED",
        migration_state="MIGRATION_UNRESOLVED",
        destination_admission="CLOSED",
        reason="NO_ATOMIC_RELOCATION_CERTIFICATE",
        counter=source["counter"],
        unresolved=source["unresolved"],
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run", "pins", "package"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            inspect(args.run, load(args.pins), load(args.package)), sort_keys=True
        )
    )
