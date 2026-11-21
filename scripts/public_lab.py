"""Verify the fixed WolfAlibi public lab cases locally and print a JSON report."""

import argparse
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
_SCHEMA = "WOLFALIBI_PUBLIC_LAB_VERIFICATION_V1"
_MANIFEST_SCHEMA = "QUORVANE_PUBLIC_LAB_MANIFEST_V1"
_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_FILE_LIMITS = {"pins.json": 32_768, "challenge.txt": 65, "genuine.json": 262_144, "tampered.json": 262_144}
_ASSURANCE = {
    "assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
    "confinement": "BLOCKED", "production": "BLOCKED", "certification": "NOT_ISSUED",
}
_CONDITIONS = {
    "education": "TESTED", "finance": "TESTED", "history": "TESTED", "tampering": "TESTED",
    "custody": "UNSUPPORTED", "witness": "NOT_ASSESSED", "freshness": "NOT_ASSESSED",
    "rollback": "NOT_ASSESSED", "power": "NOT_ASSESSED", "settlement": "NOT_ASSESSED",
    "confinement": "BLOCKED", "production": "BLOCKED", "certification": "NOT_ISSUED",
}


class LabInputError(ValueError):
    """The local manifest or a fixed artifact failed preflight."""


@dataclass(frozen=True)
class Experiment:
    module: str
    verifier: str
    operation: str
    claim: str
    change: tuple[str, ...]
    original: object
    replacement: object
    rejection: str
    effect: str | None = None
    settlement: str | None = None


_CASES = {
    "education": Experiment(
        "wolfalibi.education_verify", "verify_admission", "edu.student_record.read", "HISTORICAL_SYNTHETIC_ADMISSION",
        ("evidence", "response", "support_level"), "scheduled-check-in", "immediate-follow-up",
        "response differs from the expected fictional record",
    ),
    "finance": Experiment(
        "wolfalibi.finance_verify", "verify_admission", "fin.payment.initiate", "HISTORICAL_SYNTHETIC_PAYMENT_INTENT",
        ("evidence", "packet", "scope", "amount_minor"), 4500, 4600,
        "receipt differs from the exact payment scope", effect="PENDING_EXTERNAL_SETTLEMENT",
    ),
    "history": Experiment(
        "wolfalibi.history_verify", "verify_history", "fin.payment.history.inquire", "HISTORICAL_INTENT_DISCLOSURE",
        ("evidence", "request", "challenge"), None, "ee" * 32,
        "history inquiry differs from the expected scope or challenge",
        effect="PENDING_EXTERNAL_SETTLEMENT", settlement="UNESTABLISHED",
    ),
}


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _hex_digest(value):
    return type(value) is str and _HEX_256.fullmatch(value) is not None


def _read(path, maximum):
    relative = path.relative_to(ROOT)
    flags = os.O_RDONLY
    for flag in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_BINARY"):
        flags |= getattr(os, flag, 0)
    try:
        current = ROOT
        for name in relative.parts:
            current /= name
            if current.is_symlink():
                raise LabInputError(f"symbolic links are unsupported for lab artifact {relative}")
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise LabInputError(f"lab artifact is not a regular file: {relative}")
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise LabInputError(f"could not read lab artifact {relative}") from exc
    if len(data) > maximum:
        raise LabInputError(f"lab artifact exceeds its size limit: {relative}")
    return data


def _object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON field")
    return result


def _constant(_):
    raise ValueError("invalid JSON number")


def _json(data, label):
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_object,
                              parse_constant=_constant, parse_float=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise LabInputError(f"invalid JSON in {label}") from exc
    if type(document) is not dict:
        raise LabInputError(f"expected a JSON object in {label}")
    return document


def _check_conditions(conditions):
    if type(conditions) is not list:
        raise LabInputError("manifest must enumerate the fixed condition statuses")
    seen = set()
    for row in conditions:
        if type(row) is not dict or type(row.get("id")) is not str:
            raise LabInputError("invalid manifest condition")
        condition = row["id"]
        if condition not in _CONDITIONS or condition in seen:
            raise LabInputError("unknown or duplicate manifest condition")
        status = _CONDITIONS[condition]
        if row.get("status") != status:
            raise LabInputError(f"manifest condition {condition} requires status {status}")
        seen.add(condition)
    if missing := _CONDITIONS.keys() - seen:
        raise LabInputError(f"manifest omits conditions: {', '.join(sorted(missing))}")


def _manifest():
    raw = _read(ROOT / "public_lab" / "manifest.json", 65_536)
    manifest = _json(raw, "manifest.json")
    if manifest.get("schema") != _MANIFEST_SCHEMA or any(
        manifest.get(field) != value for field, value in _ASSURANCE.items()
        if field != "confinement" or "confinement" in manifest
    ):
        raise LabInputError("manifest schema or synthetic assurance differs from the public lab profile")
    _check_conditions(manifest.get("conditions"))
    experiments = manifest.get("experiments")
    if type(experiments) is not list:
        raise LabInputError("manifest must enumerate all fixed experiments")
    inventory = {}
    for item in experiments:
        if type(item) is not dict or type(item.get("id")) is not str:
            raise LabInputError("invalid manifest experiment")
        case = item["id"]
        if case not in _CASES or case in inventory:
            raise LabInputError("unknown or duplicate manifest experiment")
        files = item.get("files")
        if (type(files) is not dict or files.keys() != _FILE_LIMITS.keys()
                or not all(_hex_digest(value) for value in files.values())):
            raise LabInputError(f"invalid manifest file inventory for {case}")
        spec = _CASES[case]
        substitution = item.get("tamper")
        if (item.get("claim"), item.get("operation")) != (spec.claim, spec.operation):
            raise LabInputError(f"manifest claims differ from the fixed experiment {case}")
        if type(substitution) is not dict or substitution.get("path") != "/" + "/".join(spec.change):
            raise LabInputError(f"manifest substitution differs from the fixed experiment {case}")
        inventory[case] = files
    if inventory.keys() != _CASES.keys():
        raise LabInputError("manifest must enumerate all fixed experiments")
    return inventory, _sha256(raw)


def _artifacts(case, inventory):
    directory = ROOT / "public_lab" / "vectors" / case
    artifacts = {}
    for name, maximum in _FILE_LIMITS.items():
        data = _read(directory / name, maximum)
        if _sha256(data) != inventory[name]:
            raise LabInputError(f"SHA-256 mismatch for {case}/{name}")
        artifacts[name] = data
    return artifacts


def _challenge(case, data, pins):
    try:
        challenge = data.removesuffix(b"\n").decode("ascii")
        expected = pins["challenge"] if case == "history" else pins["scope"]["challenge"]
    except (KeyError, TypeError, UnicodeError) as exc:
        raise LabInputError(f"missing or invalid challenge for {case}") from exc
    if not _hex_digest(challenge) or expected != challenge:
        raise LabInputError(f"challenge differs from the external pins for {case}")
    return challenge


def _tamper_pair(genuine, tampered, spec, challenge):
    substituted = deepcopy(genuine)
    parent = substituted
    try:
        for field in spec.change[:-1]:
            parent = parent[field]
        field = spec.change[-1]
        original = parent[field]
    except (KeyError, TypeError) as exc:
        raise LabInputError("genuine artifact is missing its fixed variant field") from exc
    expected_original = challenge if spec.original is None else spec.original
    if type(original) is not type(expected_original) or original != expected_original or original == spec.replacement:
        raise LabInputError("genuine artifact differs from its fixed test value")
    parent[field] = spec.replacement
    if json.dumps(substituted, sort_keys=True) != json.dumps(tampered, sort_keys=True):
        raise LabInputError("tampered artifact differs from its fixed one-field substitution")


def _invoke(verifier, pins, evidence, options):
    try:
        result = verifier(pins, evidence, **options)
    except ValueError as exc:
        return {**_ASSURANCE, "outcome": "REJECTED", "reason": str(exc)}
    except Exception as exc:
        return {"outcome": "BLOCKED", "reason": "verifier could not run", "error_type": type(exc).__name__}
    if type(result) is not dict:
        return {"outcome": "BLOCKED", "reason": "verifier returned an invalid result"}
    return result


def _is_expected_verification(result, spec):
    return (
        result.get("outcome") == "VERIFIED" and result.get("verified") == spec.claim
        and result.get("effect") == spec.effect and result.get("settlement") == spec.settlement
        and all(result.get(field) == value for field, value in _ASSURANCE.items())
    )


def _verify_case(case, inventory):
    spec = _CASES[case]
    report = {"id": case, "outcome": "BLOCKED", "integrity": "UNVERIFIED",
              "genuine": {"outcome": "NOT_RUN"}, "tampered": {"outcome": "NOT_RUN"}}
    try:
        artifacts = _artifacts(case, inventory)
        report.update(integrity="VERIFIED", files=inventory)
        pins = _json(artifacts["pins.json"], f"{case}/pins.json")
        challenge = _challenge(case, artifacts["challenge.txt"], pins)
        genuine = _json(artifacts["genuine.json"], f"{case}/genuine.json")
        tampered = _json(artifacts["tampered.json"], f"{case}/tampered.json")
        if genuine.keys() != {"evidence"} or tampered.keys() != {"evidence"}:
            raise LabInputError("lab artifacts require one exact evidence wrapper")
        _tamper_pair(genuine, tampered, spec, challenge)
    except (LabInputError, RecursionError) as exc:
        return dict(report, reason=str(exc))
    try:
        verifier = getattr(importlib.import_module(spec.module), spec.verifier)
    except Exception as exc:
        return dict(report, reason="verifier could not load", error_type=type(exc).__name__)
    options = {"challenge": challenge} if case == "history" else {}
    report["genuine"] = _invoke(verifier, pins, genuine["evidence"], options)
    if not _is_expected_verification(report["genuine"], spec):
        return dict(report, reason="genuine artifact did not verify its exact historical claim")
    report["tampered"] = _invoke(verifier, pins, tampered["evidence"], options)
    expected_rejection = {**_ASSURANCE, "outcome": "REJECTED", "reason": spec.rejection}
    if report["tampered"] != expected_rejection:
        return dict(report, reason="tampered artifact did not produce its specified semantic rejection")
    return dict(report, outcome="PASS")


def verify(case=None):
    """Verify the selected fixed cases and return a machine-readable local report."""
    report = {"schema": _SCHEMA, "outcome": "BLOCKED", "selected_case": case or "all",
              "manifest_sha256": None, "cases": []}
    try:
        manifest, report["manifest_sha256"] = _manifest()
    except LabInputError as exc:
        return dict(report, reason=str(exc))
    selected = _CASES if case is None else (case,)
    if any(name not in _CASES for name in selected):
        return dict(report, reason="unknown experiment")
    report["cases"] = [_verify_case(name, manifest[name]) for name in selected]
    if all(item["outcome"] == "PASS" for item in report["cases"]):
        report["outcome"] = "PASS"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("verify", help="verify the fixed synthetic cases offline")
    run.add_argument("--case", choices=_CASES, help="verify one case (default: all cases)")
    args = parser.parse_args(argv)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    report = verify(args.case)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
