#!/usr/bin/env python3
"""Challenge the prototype reviewer with disposable copies of genuine records.

The complete original must pass Review before its bounded byte snapshot is used.
Each mutation updates affected artifact-manifest entries, so rejection must reach
the named semantic check. No adapter, target, network, or private key is used.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import tempfile

from review_prototype_artifact import Review, ReviewError, canonical, digest, sha, strict


def read(directory, name):
    return strict((directory / name).read_bytes())


def write(directory, name, raw):
    (directory / name).write_bytes(raw)
    manifest = read(directory, "artifact-manifest.json")
    manifest["files"][name] = {"bytes": len(raw), "sha256": sha(raw)}
    (directory / "artifact-manifest.json").write_bytes(canonical(manifest) + b"\n")


def write_json(directory, name, value):
    write(directory, name, canonical(value) + b"\n")


def changed_hex(value):
    return value[:-1] + ("1" if value[-1] == "0" else "0")


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


def forged_owner(directory):
    filename = "materials/authorized/terminal.json"
    terminal = read(directory, filename)
    grant = terminal["events"][-1]["grant"]
    grant["signature"] = changed_hex(grant["signature"])
    write_json(directory, filename, terminal)
    request = read(directory, "materials/authorized/request.json")
    request["grant"] = grant
    write_json(directory, "materials/authorized/request.json", request)


def alter_bundle(directory, change):
    bundle = read(directory, "materials/authorized/bundle.json")
    change(bundle)
    for name in ("bundle.json", "submitted-bundle.json"):
        write_json(directory, "materials/authorized/" + name, bundle)


def forged_target(directory):
    def change(bundle):
        action = bundle["action_challenge"]
        action["signature"] = changed_hex(action["signature"])
    alter_bundle(directory, change)


def swapped_assessment(directory):
    # Both original signatures were already verified by the clean baseline run.
    other = read(directory, "materials/lost-reply/bundle.json")["assessment"]
    alter_bundle(directory, lambda bundle: bundle.update(assessment=other))


def mismatched_ledger(directory):
    def change(case):
        operation = case["oracle"]["operation"]
        operation["request_sha256"] = changed_hex(operation["request_sha256"])
    alter_case(directory, "authorized", change)


def boolean_counter(directory):
    alter_case(directory, "authorized", lambda case: case["oracle"].update(counter=True))


def missing_eio(directory):
    filename = "measurement/corrupt-read.txt"
    raw = (directory / filename).read_bytes()
    write(directory, filename, raw.replace(b"Input/output error", b"read failed (EIO text removed)"))


def falsely_claimed_human(directory):
    for filename in ("materials/authorized/terminal.json", "summary.json"):
        document = read(directory, filename)
        document["actual_human_approval"] = "PASS"
        write_json(directory, filename, document)


def altered_source(directory):
    filename = "measurement/source-manifest.json"
    source = read(directory, filename)
    selected = source["files"]["/opt/wolfalibi/shirudo_adapter/action_gate.py"]
    selected["sha256"] = changed_hex(selected["sha256"])
    raw = canonical(source) + b"\n"
    write(directory, filename, raw)
    observed = read(directory, "measurement/source-manifest-observation.json")
    observed.update(canonical_sha256=digest(source), raw_sha256=sha(raw), bytes=len(raw))
    write_json(directory, "measurement/source-manifest-observation.json", observed)
    for name in ("native-manifest.json", "witness-manifest.json"):
        manifest = read(directory, "measurement/" + name)
        manifest["source_manifest_sha256"] = digest(source)
        write_json(directory, "measurement/" + name, manifest)


CASES = (
    ("forged-owner-signature", forged_owner, "authorized:owner-grant:signature"),
    ("forged-target-signature", forged_target, "authorized:action:signature"),
    ("valid-assessment-from-another-operation", swapped_assessment, "authorized:assessment-bindings"),
    ("mismatched-ledger-request-binding", mismatched_ledger, "ORACLE:authority-effect-ledger-binding"),
    ("boolean-substituted-for-counter", boolean_counter, "ORACLE:counter"),
    ("missing-kernel-EIO-evidence", missing_eio, "BOOT:kernel-EIO-observation"),
    ("scripted-approval-relabelled-as-human", falsely_claimed_human, "authorized:scripted-terminal-record"),
    ("altered-source-with-coordinated-manifests", altered_source,
     "SOURCE:reviewed-commit:shirudo_adapter/action_gate.py"),
)


def run(directory):
    baseline = Review(directory)
    clean = baseline.run()
    results = []
    for name, mutate, expected in CASES:
        with tempfile.TemporaryDirectory(prefix="wolfalibi-prototype-corruption-") as temp:
            destination = Path(temp)
            for path, body in baseline.raw.items():
                target = destination / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
            mutate(destination)
            try:
                Review(destination).run()
            except ReviewError as exc:
                if str(exc) != expected:
                    raise ReviewError("Unexpected rejection for " + name + ": " + str(exc)) from exc
                results.append({"case": name, "result": "REJECTED", "failed_check": str(exc)})
            else:
                raise ReviewError("Corrupted artifact was accepted: " + name)
    return {"schema": "wolfalibi.shirudo.prototype-artifact-corruption-review.v1", "result": "PASS",
            "scope": "HISTORICAL_LAB_ARTIFACT_CONSISTENCY", "clean_artifact_result": clean["result"],
            "clean_artifact_manifest_sha256": sha(baseline.raw["artifact-manifest.json"]), "controls": results,
            "modified_file_manifest_entries_recomputed": True, "original_artifact_modified": False,
            "adapter_imported": False, "target_contact": False, "actual_human_approval": "NOT_RUN",
            "current_authorization": False, "external_provenance": "REQUIRES_SEPARATE_AUTHENTICATED_CHECK"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        result, code = run(args.directory), 0
    except Exception as exc:
        result, code = {"result": "FAIL", "error_type": type(exc).__name__, "error": str(exc)[:1024]}, 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
