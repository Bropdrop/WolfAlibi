#!/usr/bin/env python3
"""Challenge the standalone reviewer using temporary copies of genuine records.

The original artifact is first verified and snapshotted. All mutations are
local to disposable directories; no adapter, target or network is invoked.
Each altered file's manifest entry is recomputed to reach semantic checks.
"""

from __future__ import annotations

import argparse
import copy
import io
import json
from pathlib import Path
import tempfile
import zipfile

from review_action_artifact import Review, ReviewError, canonical, sha


def write(directory, name, raw):
    (directory / name).write_bytes(raw)
    manifest_path = directory / "artifact-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"][name] = {"bytes": len(raw), "sha256": sha(raw)}
    manifest_path.write_bytes(canonical(manifest) + b"\n")


def write_json(directory, name, value):
    write(directory, name, canonical(value) + b"\n")


def read(directory, name):
    return json.loads((directory / name).read_bytes())


def alter_case(directory, name, change):
    filename = f"cases/{name}/result.json"
    case = read(directory, filename)
    change(case)
    write_json(directory, filename, case)
    summary = read(directory, "summary.json")
    for index, item in enumerate(summary["cases"]):
        if item["case"] == name:
            summary["cases"][index] = copy.deepcopy(case)
    write_json(directory, "summary.json", summary)


def forged_grant(directory):
    filename = "materials/authorized/grant.json"
    grant = read(directory, filename)
    old = grant["signature"]
    grant["signature"] = old[:-1] + ("1" if old[-1] == "0" else "0")
    write_json(directory, filename, grant)


def forged_target(directory):
    filename = "materials/authorized/action-challenge.json"
    action = read(directory, filename)
    old = action["signature"]
    action["signature"] = old[:-1] + ("1" if old[-1] == "0" else "0")
    write_json(directory, filename, action)


def mismatched_ledger(directory):
    alter_case(directory, "authorized", lambda c:
               c["after"]["operation"].update(request_sha256="0" * 64))


def hidden_effect(directory):
    def change(case):
        case["after"]["counter"] += 1
        case["after"]["committed_operations"] += 1
    alter_case(directory, "forged-owner", change)


def boolean_counter(directory):
    alter_case(directory, "authorized", lambda c: c["after"].update(counter=True))


def omitted_control(directory):
    name = "cases/client-admin-denied/response.json"
    (directory / name).unlink()
    manifest = read(directory, "artifact-manifest.json")
    del manifest["files"][name]
    (directory / "artifact-manifest.json").write_bytes(canonical(manifest) + b"\n")


def altered_source(directory):
    filename = "shirudo_adapter/action_gate.py"
    packed = io.BytesIO()
    with zipfile.ZipFile(directory / "source/target-code.zip") as original:
        with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as changed:
            for info in original.infolist():
                raw = original.read(info)
                if info.filename == filename:
                    raw += b"\n# altered after the tested commit\n"
                    descriptor = {"bytes": len(raw), "sha256": sha(raw)}
                changed.writestr(info, raw)
    write(directory, "source/target-code.zip", packed.getvalue())
    manifest = read(directory, "source/manifest.json")
    manifest[filename] = descriptor
    write_json(directory, "source/manifest.json", manifest)
    installed = read(directory, "source/target-installation.json")
    installed["files"][filename] = descriptor
    write_json(directory, "source/target-installation.json", installed)


CASES = (
    ("forged-owner-signature", forged_grant, "authorized:grant:signature"),
    ("forged-target-signature", forged_target, "authorized:action:signature"),
    ("mismatched-oracle-request-binding", mismatched_ledger, "ORACLE:retained-authority-binding"),
    ("denial-concealing-an-extra-effect", hidden_effect, "forged-owner:ordered-counter-observations"),
    ("boolean-substituted-for-counter", boolean_counter, "ORACLE:counter"),
    ("omitted-required-control", omitted_control, "LAYOUT:exact-public-exports"),
    ("altered-source-with-matching-manifests", altered_source,
     "SOURCE:reviewed-commit:shirudo_adapter/action_gate.py"),
)


def run(directory):
    baseline = Review(directory)
    clean = baseline.run()
    results = []
    for name, mutate, expected_failure in CASES:
        with tempfile.TemporaryDirectory(prefix="wolfalibi-artifact-corruption-") as temp:
            destination = Path(temp)
            for path, body in baseline.raw.items():
                target = destination / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
            mutate(destination)
            try:
                Review(destination).run()
            except ReviewError as exc:
                if str(exc) != expected_failure:
                    raise ReviewError("Unexpected rejection for " + name + ": " + str(exc)) from exc
                results.append({"case": name, "result": "REJECTED", "failed_check": str(exc)})
            else:
                raise ReviewError("Corrupted artifact was accepted: " + name)
    return {"schema": "wolfalibi.shirudo.action-artifact-corruption-review.v1", "result": "PASS",
            "clean_artifact_result": clean["result"], "controls": results,
            "modified_file_manifest_entries_recomputed": True,
            "original_artifact_modified": False, "adapter_imported": False,
            "target_contact": False, "current_authorization": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        result, code = run(args.directory), 0
    except Exception as exc:
        result, code = {"result": "FAIL", "error_type": type(exc).__name__, "error": str(exc)}, 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
