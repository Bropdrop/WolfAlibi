"""Emit exact-tree single-host controls and identify the outstanding independent trials."""

import json
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

from qualify_stage35 import run, unit_suite
from qualify_voidcell002 import _clean, _doctor, _environment, _status


BASE = "ac8fa4a3474e7edfe270ff63bcf15e731327050e"


def read_record(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if type(value) is dict else None


def cli_payload(record):
    try:
        value = json.loads(record["stdout"])
    except ValueError:
        return {}
    return value if type(value) is dict else {}


def single_account_control(directory):
    directories = {name: directory / name for name in
                   ("gateway", "target", "anchor", "qualification", "public", "endpoint")}
    for name, path in directories.items():
        path.mkdir(mode=0o700)
        if name in {"public", "endpoint"}:
            path.chmod(0o755)
    cli = (sys.executable, "-m", "wolfalibi.voidcell003_fixture")
    ref = directories["public"] / "gateway.json"
    gateway = run(*cli, "gateway-init", "--state-dir", str(directories["gateway"]), "--public-ref", str(ref))
    gateway_pub = cli_payload(gateway).get("gateway_pub")
    if gateway["exit_code"] or type(gateway_pub) is not str:
        return {"outcome": "BLOCKED", "gateway": gateway}
    owner = run(*cli, "owner-init", "--consent", "--target-state-dir", str(directories["target"]),
                "--anchor-dir", str(directories["anchor"]), "--qualification-dir", str(directories["qualification"]),
                "--gateway-ref", str(ref), "--expected-gateway-pub", gateway_pub,
                "--expected-gateway-uid", str(os.geteuid()), "--expected-gateway-gid", str(os.getegid()),
                "--socket-path", str(directories["endpoint"] / "target.sock"),
                "--handoff", str(directories["public"] / "owner.json"))
    owner_state_empty = all(not any(directories[name].iterdir()) for name in ("target", "anchor", "qualification"))
    refused = (owner["exit_code"] == 2 and cli_payload(owner).get("outcome") == "UNSUPPORTED"
               and owner_state_empty and not (directories["public"] / "owner.json").exists())
    return {"outcome": "REFUSED_SAME_UID" if refused else "BLOCKED", "gateway": gateway, "owner": owner,
            "owner_state_empty": owner_state_empty}


def qualify():
    revision = run("git", "rev-parse", "HEAD", "HEAD^{tree}")
    clean = _clean(_status())
    result = {
        "schema": "wolfalibi.voidcell003.local-qualification.v1", "base": BASE,
        "working_tree_clean_start": clean,
        "environment": _environment(), "preflight": _doctor(), "outcome": "BLOCKED",
        "independent_principal_qualification": "UNSUPPORTED",
        "host_scope": "local controls without separately provisioned target and gateway",
        "production": "BLOCKED", "independent_witness_custody": "BLOCKED", "formal_certification": "BLOCKED",
    }
    if revision["exit_code"]:
        result["reason"] = "Git revision unavailable"
        return result
    result["commit"], result["tree"] = revision["stdout"].splitlines()
    if not clean:
        result["reason"] = "exact-tree qualification requires a clean checkout"
        return result

    inherited = run("git", "ls-tree", "--name-only", BASE)
    inherited_files = [p for p in inherited["stdout"].splitlines() if p.startswith("test_") and p.endswith(".py")]
    if inherited["exit_code"] or not inherited_files:
        result["reason"] = "VOIDCELL 002 base tree required to identify inherited tests"
        return result
    preserved = run("git", "diff", "--exit-code", "--name-only", BASE, "HEAD", "--",
                    *inherited_files, "mutation_test.py")
    with TemporaryDirectory(prefix="wolfalibi-voidcell003-") as output:
        directory = Path(output)
        enrollment = single_account_control(directory)
        env = {
            "WOLFALIBI_VOIDCELL003_OWNER_EVIDENCE": output,
            "WOLFALIBI_VOIDCELL003_AVAILABILITY_FILE": str(directory / "availability.json"),
        }
        with patch.dict(os.environ, env):
            focused = unit_suite("discover", "-v", "-p", "test_voidcell003*.py")
        observations = {name: read_record(directory / (name + ".json"))
                        for name in ("owner", "crash", "availability")}
        with patch.dict(os.environ, {"WOLFALIBI_VOIDCELL002_EVIDENCE_FILE": str(directory / "reconciliation.json")}):
            full = unit_suite("discover", "-v")
        observations["reconciliation"] = read_record(directory / "reconciliation.json")
    mutations = run(sys.executable, "-u", "mutation_test.py")
    detected = sorted(set(re.findall(r"^CAUGHT\s+M(\d+)\b", mutations["stdout"], re.MULTILINE)))
    unchanged = _clean(_status()) and run("git", "rev-parse", "HEAD", "HEAD^{tree}") == revision
    count = (full["tests"] or 0) - (focused["tests"] or 0)
    passed = (preserved["exit_code"] == 0 and unchanged and count == 230
              and enrollment["outcome"] == "REFUSED_SAME_UID"
              and focused["outcome"] == full["outcome"] == "PASS" and all(observations.values())
              and mutations["exit_code"] == 0 and detected == list("12345678"))
    result.update(
        outcome="UNSUPPORTED" if passed and result["preflight"]["expected_here"] else "BLOCKED",
        local_controls="PASS" if passed else "BLOCKED",
        clean_and_same_revision_at_end=unchanged, inherited_test_sources=preserved, inherited_count=count,
        focused_tests=focused, full_suite=full, mutations=dict(mutations, detected=detected),
        local_observations=observations,
        same_uid_enrollment=enrollment,
        independent_trials={name: "UNEXECUTED" for name in (
            "authorized_gateway_increment", "unrelated_uid_denial", "gateway_file_exclusions",
            "target_restart_with_original_receipt", "lost_response_no_redispatch",
            "cross_uid_commit_checkpoint_interruption", "cross_uid_bounded_transport_availability",
        )},
    )
    return result


if __name__ == "__main__":
    print(json.dumps(qualify(), indent=2, sort_keys=True))
    # This local-only command never establishes independent principal custody.
    raise SystemExit(2)
