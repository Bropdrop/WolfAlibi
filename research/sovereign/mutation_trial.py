"""Synthetic signed protocol transcripts for independent mutation qualification.

Every invocation creates a new native fixture in a temporary directory. The
doubles model faulty protocol decisions and have no connection to a live gate.
"""

import argparse
import hashlib
import json
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.sovereign.review import inspect, outcome, partition, load
from research.wt_swarm.review import Mismatch
from shirudo_adapter.model import AdapterError, canonical_json, digest
from shirudo_adapter.receipt import sign_record
from tests.test_action_gate import GateFixture

CASES = {
    "control": "ACCEPTED",
    "stale-fencing": "STALE_FENCE",
    "unauthorized-succession": "INVALID_SIGNATURE",
    "duplicate-settlement": "DUPLICATE_SETTLEMENT",
    "lineage-substitution": "LINEAGE",
    "false-reconciliation": "FALSE_RECOVERY",
    "unsafe-partition-recovery": "UNSAFE_PARTITION",
}


def save(path, value):
    path.write_bytes(canonical_json(value) + b"\n")


def pub(key):
    return key.public_key().public_bytes_raw().hex()


def generate(path, case):
    path.mkdir()
    with tempfile.TemporaryDirectory() as temp:
        lab = GateFixture(Path(temp) / "fixture")
        boot, first, second, other = [Ed25519PrivateKey.generate() for _ in range(4)]
        principal = "1a" * 32
        e = dict(
            boot=pub(boot),
            identity=lab.identity,
            trust=lab.trust,
            cert=dict(alice=principal),
            holders=dict(a=pub(first), b=pub(second)),
        )
        native = lab.identity["gate_instance_id"]
        target = lab.trust["target_id"]
        commands = []
        settlements = []
        bindings = []
        acl = []
        materials = {}
        records = []
        issued = []
        for i, holder in enumerate((first, second), 1):
            order = dict(
                schema="wolfalibi.sovereign.order.v1",
                boot=pub(boot),
                gate=native,
                target=target,
                index=i,
                epoch=i,
                previous=digest(records[-1]) if records else "0" * 64,
                kind="activate",
                holder=pub(holder),
                revoked=None,
            )
            signer = (
                other if case == "unauthorized-succession" and i == 2 else lab.owner_key
            )
            record = sign_record(signer, order)
            records.append(record)
            ack = sign_record(
                boot,
                dict(
                    schema="wolfalibi.sovereign.installed.v1",
                    order=digest(record),
                    index=i,
                    epoch=i,
                    target=target,
                    counter=i - 1,
                ),
            )
            commands.append(
                dict(
                    idx=i,
                    command=canonical_json(record).decode(),
                    acknowledgement=canonical_json(ack).decode(),
                )
            )
        for i, name in enumerate(("original", "replacement", "pending")):
            epoch = 1 if i == 0 or (i == 1 and case == "stale-fencing") else 2
            holder = (first, second)[epoch - 1]
            head = digest(records[epoch - 1])
            challenge, action, req = lab.operation()
            op = req["operation_id"]
            common = dict(
                boot=pub(boot), gate=native, target=target, op=op, request=digest(req)
            )
            p = dict(
                common,
                schema="wolfalibi.sovereign.permit.v1",
                epoch=epoch,
                head=head,
                holder=pub(holder),
                grant=digest(req["grant"]),
            )
            permit = sign_record(lab.owner_key, p)
            sender = sign_record(
                holder,
                dict(
                    schema="wolfalibi.sovereign.submit.v1",
                    permit=digest(permit),
                    request=digest(req),
                ),
            )
            binding = sign_record(
                lab.owner_key,
                dict(
                    common,
                    schema="wolfalibi.sovereign.recover.v1",
                    principal=principal,
                    grant=req["grant"]["payload"]["grant_id"],
                ),
            )
            bindings.append(dict(op=op, epoch=epoch, head=head))
            acl.append(dict(op=op, binding=canonical_json(binding).decode()))
            materials[name] = dict(
                action=action,
                challenge=challenge,
                binding=binding,
                frame=dict(request=req, permit=permit, sender=sender),
            )
            if name == "pending":
                continue
            # Real receipts from this newly provisioned native-only counter are
            # kept byte-for-byte in every projection. The outer test ledger
            # applies each schedule independently of native issuance.
            receipt = lab.gate.execute(req)["receipt"]
            issued.append(receipt)
            origin = (
                p
                if not (case == "lineage-substitution" and i == 1)
                else materials["original"]["frame"]["permit"]["payload"]
            )
            endorsement = sign_record(
                boot,
                dict(
                    origin,
                    schema="wolfalibi.sovereign.effect.v1",
                    receipt=digest(receipt),
                    permit=digest(permit),
                ),
            )
            settlements.append(
                dict(
                    seq=i + 1,
                    op=op,
                    permit=canonical_json(permit).decode(),
                    sender=canonical_json(sender).decode(),
                    endorsement=canonical_json(endorsement).decode(),
                )
            )
        with closing(sqlite3.connect(lab.state / "journal.sqlite3")) as c:
            c.row_factory = sqlite3.Row
            c.execute("BEGIN")
            j = {
                t: [dict(row) for row in c.execute(f"SELECT * FROM {t} ORDER BY rowid")]
                for t in ("operations", "revoked_grants", "counter")
            }
        if case == "duplicate-settlement":
            # A replacement accepts a redelivery as a new logical increment.
            settlements.append(dict(settlements[0], seq=3))
            j["counter"][0]["value"] += 1
        j.update(
            settlements=settlements,
            commands=commands,
            bindings=bindings,
            recovery_acl=acl,
        )
        pending = materials["pending"]["binding"]
        state = "NOT_COMMITTED" if case == "false-reconciliation" else "UNRESOLVED"
        proof = sign_record(
            boot,
            dict(
                schema="wolfalibi.sovereign.recovery-proof.v1",
                binding=digest(pending),
                state=state,
                receipt=None,
            ),
        )
        disconnected = dict(state="DENIED", reason="QUORUM_UNAVAILABLE")
        if case == "unsafe-partition-recovery":
            disconnected = dict(result="COMMITTED", receipt=issued[-1])
        for n, v in (
            ("enrollment", e),
            ("materials", materials),
            ("oracle", j),
            ("quorum-audit", [records] * 3),
            ("pending", dict(state=state, receipt=None, proof=proof)),
            ("disconnected", disconnected),
        ):
            save(path / (n + ".json"), v)
        save(
            path / "provisioning.json",
            dict(
                enrollment=hashlib.sha256(
                    (path / "enrollment.json").read_bytes()
                ).hexdigest()
            ),
        )


def audit(path):
    _, expected, receipts = inspect(path, load(path, "provisioning")["enrollment"])
    e = load(path, "enrollment")
    b = load(path, "materials")["pending"]["binding"]
    outcome(
        load(path, "pending"),
        "pending",
        b,
        expected["pending"],
        receipts.get("pending"),
        e["boot"],
    )
    partition(load(path, "disconnected"))


def run(path, verify_only):
    if not verify_only:
        path.mkdir(parents=True, exist_ok=False)
    results = {}
    for case, wanted in CASES.items():
        directory = path / case
        if not verify_only:
            generate(directory, case)
        try:
            audit(directory)
            result = "ACCEPTED"
        except (AdapterError, Mismatch) as exc:
            result = exc.code if isinstance(exc, AdapterError) else str(exc)
        if result != wanted:
            raise ValueError((case, result, wanted))
        results[case] = result
    return results


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path)
    p.add_argument("--verify-only", action="store_true")
    a = p.parse_args()
    print(json.dumps(run(a.directory, a.verify_only), indent=2, sort_keys=True))
