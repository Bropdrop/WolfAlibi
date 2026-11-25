"""Recompute like-for-like profiles from the pinned WT-SWARM-001 ZIP and new raw rows."""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile

from research.blackout.review import native_metrics

ARCHIVE_SHA = "a5366416830b4dbf861b468846c9692f200565caea0854b82fade7c9b032d24c"
PROFILES = ("contention", "duplicates", "overload")


def compare(archive, runs):
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA:
        raise ValueError("historical archive SHA-256")
    measurements = {}
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(archive) as z:
        root = Path(tmp)
        for run in ("standalone", "repeat"):
            for profile in PROFILES:
                for suffix in (".json", "-resources.json"):
                    name = profile + suffix
                    (root / name).write_bytes(z.read(f"evidence/{run}/{name}"))
            measurements["001-" + run] = {
                name: native_metrics(root, name) for name in PROFILES
            }
    for run in runs:
        measurements["002-" + run.name] = {
            name: native_metrics(run / "native", name) for name in PROFILES
        }
    return {
        "reference_archive_sha256": ARCHIVE_SHA,
        "profiles": measurements,
        "unavailable_in_001": [
            "CPU consumption",
            "journal size/growth",
            "recovery service latency",
        ],
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("baseline_zip", type=Path)
    p.add_argument("runs", type=Path, nargs="+")
    args = p.parse_args()
    print(json.dumps(compare(args.baseline_zip, args.runs), indent=2, sort_keys=True))
