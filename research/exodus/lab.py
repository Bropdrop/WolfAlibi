"""Fresh disposable destination enrollment and public transfer inspection."""

from copy import deepcopy
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.exodus.staging import source_snapshot, inspect
from research.wt_swarm.review import sha
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import sign_record
from tests.test_action_gate import GateFixture


def destination():
    with tempfile.TemporaryDirectory() as private:
        gate = GateFixture(Path(private) / "destination")
        print(json.dumps(gate.identity))


def run(root, out):
    out.mkdir(parents=True, exist_ok=False)
    profile = json.loads(
        subprocess.check_output(
            [sys.executable, "-B", "-m", "research.exodus.lab", "--destination"]
        )
    )
    pins = {
        k: sha(root / "native" / (k + ".json"))
        for k in ("profile", "reader", "anchors")
    }
    snapshot = source_snapshot(root, pins)
    assert profile["target_id"] == snapshot["logical_target"]
    assert profile["public_key"] != snapshot["source_gate_key"]
    exporter, authorizer = (Ed25519PrivateKey.generate() for _ in range(2))
    trusted = dict(
        source=pins,
        destination=profile,
        exporter=exporter.public_key().public_bytes_raw().hex(),
        authorizer=authorizer.public_key().public_bytes_raw().hex(),
    )
    auth = sign_record(
        authorizer,
        dict(
            schema="wolfalibi.exodus.inspect.v1",
            source=digest(snapshot),
            destination=profile,
            epoch=snapshot["epoch"],
            next_epoch=snapshot["epoch"] + 1,
        ),
    )
    manifest = sign_record(
        exporter,
        dict(
            schema="wolfalibi.exodus.transfer.v1",
            source=snapshot,
            destination=profile,
            authorization=digest(auth),
        ),
    )
    package = dict(authorization=auth, manifest=manifest)
    result = inspect(root, trusted, package)
    # Re-sign altered public transfers so signature validity cannot mask missing history.
    mutations = {}
    for field in (
        "revocations",
        "history",
        "recovery_bindings",
        "endorsements",
        "unresolved",
        "operations",
    ):
        changed = deepcopy(manifest["payload"])
        items = changed["source"][field]
        if isinstance(items, dict):
            items.pop(next(iter(items)))
        else:
            items.pop()
        altered = dict(package, manifest=sign_record(exporter, changed))
        try:
            inspect(root, trusted, altered)
        except ValueError as exc:
            if str(exc) != "TRANSFER_BINDING":
                raise
            mutations[field] = str(exc)
        else:
            raise ValueError("Undetected transfer omission")
    (out / "mutations.json").write_text(json.dumps(mutations, sort_keys=True) + "\n")
    for name, value in (("pins", trusted), ("transfer", package), ("review", result)):
        (out / (name + ".json")).write_text(json.dumps(value, sort_keys=True) + "\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--destination", action="store_true")
    p.add_argument("paths", nargs="*", type=Path)
    a = p.parse_args()
    if a.destination:
        destination()
    else:
        run(*a.paths)
