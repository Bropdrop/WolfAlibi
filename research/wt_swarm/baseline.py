"""Recheck the pinned Git tree, retained manifests and PR 50's four historical audits."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from zipfile import ZipFile

from scripts.wt_alibi_human_verify import verify_effect

ROOT = Path(__file__).resolve().parents[2]
PIN = "c27556440b348fd8584fda4deaeacca0edb93004"
TREE = "042f7149d2acf0a442b0c5ca6f202c2e503dce5c"
ARCHIVE = "e6e13cdfd082d05193abdc48d3255f3d6f12d6e46c1c4f56e5b2794c881f1622"


def check(value, reason):
    if not value:
        raise ValueError(reason)


def history(read):
    def doc(path):
        return json.loads(read(path))
    result = {}
    for label in ("authorized", "lost-reply"):
        m = "materials/" + label + "/"
        for audit in ("audit-1", "audit-2"):
            a = m + audit + "/"
            verified = verify_effect(doc(m+"pins.json"), doc(a+"pins.json"), doc(m+"intent.json"),
                doc("owner-profile.json"), doc(m+"ready.json"), doc(m+"bundle.json"), read(m+"evidence.json"),
                doc(m+"request.json"), doc(a+"receipt.json"), doc(a+"before.json"), doc(a+"after.json"))
            check(verified == doc(a+"result.json"), "historical review result")
            result[label + "/" + audit] = verified
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path)
    source.add_argument("--public-subset", type=Path)
    args = parser.parse_args()
    tree = subprocess.check_output(["git", "rev-parse", PIN + "^{tree}"], cwd=ROOT, text=True).strip()
    check(tree == TREE, "baseline tree")
    subprocess.run(["git","diff","--exit-code",PIN,"--","shirudo_adapter","scripts","tests","docs",
                    ".github","pyproject.toml"], cwd=ROOT, check=True)
    manifests = {}
    for manifest in sorted((ROOT/"docs").rglob("preserved-file-manifest.json")):
        records = json.loads(manifest.read_bytes())["files"]
        for name, record in records.items():
            data = (manifest.parent / name).read_bytes()
            check(len(data) == record["bytes"] and hashlib.sha256(data).hexdigest() == record["sha256"], name)
        manifests[manifest.parent.name] = len(records)
    result = dict(commit=PIN, tree=TREE, preserved_files=manifests)
    if args.archive:
        check(hashlib.sha256(args.archive.read_bytes()).hexdigest() == ARCHIVE, "PR 50 archive")
        with ZipFile(args.archive) as z:
            files = {}
            for directory in ("evidence/prototype/", "evidence/lab/"):
                entries = json.loads(z.read(directory + "artifact-manifest.json"))["files"]
                for name, record in entries.items():
                    b = z.read(directory + name)
                    check(len(b) == record["bytes"] and hashlib.sha256(b).hexdigest() == record["sha256"], name)
                files[directory] = len(entries)
            result.update(archive_sha256=ARCHIVE, original_manifest_entries=files,
                          reviews=history(lambda name: z.read("evidence/prototype/" + name)))
    else:
        result["reviews"] = history(lambda name: (args.public_subset / name).read_bytes())
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
