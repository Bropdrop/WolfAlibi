"""Measure the fixed, consented, offline BYOA trial on an externally pinned Git tree."""

import argparse
from importlib import metadata
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from qualify_financial_lab import check_effects, digest, git, head, process, require

BASE = {"commit": "5b0319e141dfc83b32a232399578096165b302af",
        "tree": "59d4af50af2a114bc0565a0e0499771c81e191dd"}
ARCHIVES = {
    "public_lab/quorvane-public-lab-001.zip": "0d14aeca661a8c01318ee55258e9198fb27cc1d8772e146b6dd296f7673342c7",
    "public_lab/quorvane-public-lab-002.zip": "6fb8f3396df397a0cd6e1c26a05ec85bce0e053b6002ed6e4c78ffb4ad10a29a",
}
INHERITED = 490
MANIFEST = "examples/qualification001/agent.json"


def clean():
    return git("status", "--porcelain=v1", "--untracked-files=all") == []


def json_run(*command):
    record = process(*command)
    try:
        payload = json.loads(record.pop("stdout"))
    except ValueError as exc:
        raise ValueError(f"command returned invalid JSON: {command[:3]}") from exc
    require(type(payload) is dict, "command returned a non-object JSON result")
    return dict(record, result=payload)


def cli(*args):
    return json_run(sys.executable, str(ROOT / "wolfalibi_cli.py"), *map(str, args))


def checkout(expected, report):
    require(all(re.fullmatch("[0-9a-f]{40}", s) for s in expected.values()), "invalid external Git object IDs")
    report["working_tree_clean_start"] = clean()
    require(report["working_tree_clean_start"], "qualification requires a clean checkout")
    revision = head()
    report["tested_revision"] = revision
    require(revision == expected, "checkout differs from external revision")
    require(git("rev-parse", BASE["commit"] + "^{tree}") == [BASE["tree"]]
            and git("show", "-s", "--format=%P", revision["commit"]) == [BASE["commit"]],
            "candidate must descend directly from the published PR #36 tree")
    inherited = sorted(p for p in git("ls-tree", "--name-only", BASE["commit"])
                       if p.startswith("test_") and p.endswith(".py"))
    focused = sorted(p for p in git("ls-tree", "--name-only", revision["commit"])
                     if p.startswith("test_") and p.endswith(".py") and p not in inherited)
    require(inherited and focused, "missing inherited or candidate test modules")
    fixed = ["alibi.py", "mutation_test.py", *inherited]
    for framework in ("langchain", "openai"):
        fixed.extend([f"examples/agent_{framework}_sample.py", f"examples/agent_{framework}_manifest.json"])
    # The published packages, all their existing source fixtures and the trusted
    # Stage 4 examples remain pinned. New research profiles may add new paths.
    changed = git("diff", "--no-renames", "--name-only", "--diff-filter=DMRTUXB",
                  BASE["commit"], revision["commit"], "--", "public_lab/", *fixed)
    report["preservation"] = {"inherited_modules": inherited, "new_modules": focused, "modified_pinned": changed,
                              "archives": {name: digest(ROOT / name) for name in ARCHIVES}}
    require(not changed and report["preservation"]["archives"] == ARCHIVES, "base evidence or fixtures changed")
    return inherited, focused


def tests(report, inherited, focused):
    from qualify_history_gate import _loader_counts
    from qualify_stage35 import unit_suite
    loader = _loader_counts(focused)
    report["focused_inventory"] = loader
    require(all(r["tests"] > 0 and not r["loader_errors"] for r in loader), "failed to load a focused module")
    count = sum(r["tests"] for r in loader)
    report["suites"] = {}
    for name, expected, args in (("inherited", INHERITED, ["-v", *inherited]), ("focused", count, ["-v", *focused]),
                                 ("full", INHERITED + count, ["discover", "-v"])):
        result = unit_suite(*args)
        for field in ("failures", "errors", "expected failures", "unexpected successes"):
            match = re.search(r"\b" + field + r"=(\d+)", result["stderr"])
            result[field.replace(" ", "_")] = int(match[1]) if match else 0
        result["expected_tests"] = expected
        report["suites"][name] = result
    mutations = process(sys.executable, "-u", "mutation_test.py")
    detected = re.findall(r"^CAUGHT\s+M([1-8])\b[^\n]+ -> (test_[^\n]+)$", mutations["stdout"], re.MULTILINE)
    report["mutations"] = dict(mutations, detected=dict(detected))
    require(all(r["outcome"] == "PASS" and not any(r[k] for k in ("skipped", "errors", "failures", "expected_failures", "unexpected_successes"))
                and r["tests"] == r["expected_tests"]
                for r in report["suites"].values()), "suite failed, was skipped or reported an unexpected count")
    require(mutations["exit_code"] == 0 and sorted(n for n, _ in detected) == list("12345678")
            and "8/8 mutants caught" in mutations["stdout"], "incomplete named mutation detections")


def framework_controls(directory):
    results = {}
    for name, adapter, version in (("langchain", "langchain", "1.5.2"), ("openai", "openai-agents", "0.25.0")):
        output = directory / (name + ".json")
        manifest = f"examples/agent_{name}_manifest.json"
        command = cli("agent", "test", "--manifest", manifest, "--consent", "--allow-local-code", "--output", output)
        results[name] = command
        if output.is_file():
            command["observations"] = json.loads(output.read_bytes())
            command["file_sha256"] = digest(output)
        observed = command.get("observations", {})
        expected = {"schema": "wolfalibi.agent_observation.v0", "assurance": "OBSERVATIONAL_ONLY",
                    "agent_type": adapter, "adapter": adapter, "adapter_version": version,
                    "coverage": "EXPLICITLY_WRAPPED_CALLS_ONLY", "runtime_scope": "IN_PROCESS_TOOL_OBSERVATION",
                    "events": 1, "complete_wrapped_calls": True, "counts": {"tool.invoke.success": 1},
                    "manual_events": 0, "inflight": 0, "network_upload": False, "nonaccess_proof": False}
        command["matched"] = (command["exit_code"] == 0 and command["result"].get("outcome") == "PASS"
                              and command["result"].get("manifest_sha256") == digest(ROOT / manifest)
                              and all(json.dumps(observed.get(k), sort_keys=True) == json.dumps(v, sort_keys=True)
                                      for k, v in expected.items()))
    return {"scope": "Trusted repository examples with local scripted models, outside the measured BYOA cell",
            "controls": results}


def environment():
    from qualify_voidcell002 import _environment
    record = _environment()
    record["optional_framework_versions"] = {}
    for dep in ("mcp", "langchain", "langchain-core", "openai-agents"):
        try:
            record["optional_framework_versions"][dep] = metadata.version(dep)
        except metadata.PackageNotFoundError:
            record["optional_framework_versions"][dep] = None
    return record


def run_trial(directory, report):
    """Exercise only the reviewed fixture and retain public records across process boundaries."""
    trial, owner, review, out = (directory / item for item in ("trial", "owner", "review", "out"))
    grant = directory / "owner-grant.json"
    independent = directory / "pre-run-expectations.json"
    run_id, challenge = secrets.token_hex(16), secrets.token_hex(32)
    demo = {"run_id": run_id, "challenge": challenge, "commands": {},
            "custody": "This local operator provisions all five roles; independent administration is untested."}
    report["measured_trial"] = demo

    def step(name, *args):
        record = cli("byoa", *args)
        demo["commands"][name] = record
        require(record["exit_code"] == 0, f"{name} failed: {record['result']}")
        return record["result"]

    step("provision_trial", "provision", "--role", "trial", "--output", trial)
    step("provision_owner", "provision", "--role", "owner", "--output", owner)
    step("enroll_owner", "enroll-owner", "--trial", trial, "--owner-pin", owner / "public.json", "--approve-owner")
    step("prepare", "prepare", "--manifest", MANIFEST, "--trial-pins", trial / "public.json",
         "--owner-pin", owner / "public.json", "--output", review, "--run-id", run_id, "--challenge", challenge)
    references = review / "expected.json"
    pinned_bytes = references.read_bytes()
    with independent.open("xb") as stream:
        stream.write(pinned_bytes)
    pins = json.loads(pinned_bytes)
    manifest = json.loads((ROOT / MANIFEST).read_bytes())
    bundle = pins["contract"]["profile"]["byoa"]
    require((pins["contract"]["challenge"], pins["contract"]["run_id"]) == (challenge, run_id),
            "prepared contract differs from verifier's selected run")
    require(bundle["manifest_sha256"] == digest(ROOT / MANIFEST) and bundle["files"] == manifest["files"]
            and bundle["source_sha256"] == digest((ROOT / MANIFEST).parent / manifest["package"] / "agent.py")
            and all(bundle[name] == manifest[name] for name in ("entrypoint", "policy", "dependencies", "tools")),
            "public expectation differs from the checked-out agent, dependencies or policy")
    public_trial = json.loads((trial / "public.json").read_bytes())
    public_owner = json.loads((owner / "public.json").read_bytes())
    public_inputs = {**public_trial, **public_owner}
    roles = ("broker_pub", "witness_pub", "supervisor_pub", "owner_pub", "target_pub")
    require(set(public_inputs) == {*roles, "expected_witness_state_digest"}
            and all(pins[key] == value for key, value in public_inputs.items())
            and len({pins[key] for key in roles}) == len(roles),
            "external role keys or witness digest differ from pre-launch pins")
    demo["retained_before_launch"] = {"expectations": pins, "sha256": digest(independent)}
    step("owner_grant", "grant-read", "--expect", independent, "--owner", owner, "--output", grant, "--approve-read")
    command = ("qualify", "--manifest", MANIFEST, "--trial", trial, "--review", review, "--grant", grant, "--consent")
    completed = step("run", *command, "--framework", "langchain", "--output", out)
    require(completed.get("outcome") == "COMPLETED", "selected agent did not complete")
    evidence = out / "report.json"
    signed = json.loads(evidence.read_bytes())
    framework = completed["framework_observation"]
    require(framework == json.loads((out / "framework-observation.json").read_bytes())
            and framework["inner_report_sha256"] == digest(evidence)
            and (framework["run_id"], framework["challenge"]) == (run_id, challenge)
            and framework["assurance"] == "OBSERVATIONAL_ONLY"
            and framework["runtime"] == "TRUSTED_HOST_SDK_OUTSIDE_MEASURED_CELL"
            and framework["framework"] == {"langchain": "1.5.2", "langchain-core": "1.8.4"}
            and framework["summary"]["counts"] == {"tool.invoke.success": 1}
            and framework["network_upload"] is False, "unlinked or incomplete LangChain observation")
    historical = step("verify", "verify-qualification", "--expect", independent, "--report", evidence)
    require(references.read_bytes() == independent.read_bytes() == pinned_bytes, "retained reference changed")
    require(historical.get("outcome") == "VERIFIED" and historical["claim"] == "HISTORICAL_AUTHORIZED_SYNTHETIC_TRIAL"
            and (historical["run_id"], historical["challenge"]) == (run_id, challenge), "historical claim differs")
    observed = historical["observation"]
    require(observed["outcome"] == "OBSERVED" and observed["assurance"] == "OBSERVATIONAL_ONLY"
            and observed["summary"]["complete_wrapped_calls"] is True
            and observed["summary"]["counts"] == {"filesystem.read.success": 1}, "observer coverage differs")
    execution = historical["execution"]
    require(execution["measurement"] == "SIGNED_SUPERVISOR_SNAPSHOT" and execution["bundle"] == bundle
            and execution["closure"] == {"launcher_reaped": True, "worker_pidfd_exited": True,
                                         "peer_hangup": True, "broker_drained": True}, "missing measured lifecycle")
    require(historical["authorization"]["read"]["outcome"] == "VERIFIED_HISTORICAL_READ_ADMISSION"
            and historical["authorization"]["present_authority"] == "NOT_ISSUED"
            and historical["effect"]["broker_read"] == {"actor": "TRUSTED_CELL_BOOTSTRAP",
                "claim": "HISTORICAL_BROKER_READ", "operation": "read", "resource": "protected.txt",
                "response_sha256": pins["contract"]["fixture_sha256"]}, "protected read evidence differs")
    require(historical["effect"]["financial"] == {"outcome": "NOT_DISPATCHED", "target_ledger": "NOT_OBSERVED",
                                                 "settlement": "UNESTABLISHED"}
            and historical["authorization"]["financial"] == {"outcome": "NOT_ISSUED",
                "operation": "fin.payment.initiate", "live_finance_caller": "NOT_ENROLLED"},
            "payment or settlement claim exceeds this read-only trial")
    assurance = historical["assurance"]
    require(assurance["cross_uid_custody"] == "UNSUPPORTED" and assurance["broker"] == "BROKER_ONLY"
            and assurance["independent_witness_custody"] == "NOT_ASSESSED"
            and assurance["production"] == assurance["confinement"] == "BLOCKED"
            and assurance["certification"] == "NOT_ISSUED", "an assurance boundary changed")
    demo["signed_report"] = {"sha256": digest(evidence), "record": signed}
    recovered = step("recover_read", "recover-read", "--trial", trial, "--expect", independent, "--grant", grant)
    require(recovered == {"outcome": "RECONCILED", "target_admission": signed["payload"]["authorization"]["target_admission"],
                          "delivery": "NOT_ESTABLISHED_BY_ADMISSION", "redispatched": False},
            "separate target recovery did not return the original admission without redispatch")
    substituted = directory / "different-supervisor.json"
    other = dict(pins, supervisor_pub=secrets.token_hex(32))
    substituted.write_text(json.dumps(other), encoding="utf-8")
    rejected = cli("byoa", "verify-qualification", "--expect", substituted, "--report", evidence)
    demo["commands"]["different_supervisor_pin"] = rejected
    require(rejected["exit_code"] != 0 and rejected["result"]["outcome"] == "REJECTED",
            "different supervisor pin did not produce a verifier rejection")
    replay = directory / "second-attempt"
    refused = cli("byoa", *command, "--output", replay)
    demo["commands"]["second_use"] = refused
    require(refused["exit_code"] != 0 and refused["result"]["outcome"] == "BLOCKED"
            and refused["result"].get("reason") == "witness state digest does not match the external expectation"
            and not (replay / "report.json").exists(), "second attempt did not refuse before terminal success")


def qualify(expected, report):
    from qualify_voidcell002 import _doctor
    from qualify_voidcell003 import single_account_control
    inherited, focused = checkout(expected, report)
    report["environment"] = environment()
    report["solitary_doctor"] = cli("byoa", "doctor")
    report["voidcell_host_controls"] = _doctor()
    with TemporaryDirectory(prefix="qb001-") as temp:
        scratch = Path(temp)
        report["sdk_examples_outside_cell"] = framework_controls(scratch)
        report["same_uid_voidcell_enrollment"] = single_account_control(scratch)
        report["separate_finance_controls"] = json_run(sys.executable, "-I", "scripts/financial_effect_controls.py")
        tests(report, inherited, focused)
        require(all(v["matched"] for v in report["sdk_examples_outside_cell"]["controls"].values()),
                "a fixed Stage 4 SDK example did not reproduce its expected wrapped callback")
        require(report["same_uid_voidcell_enrollment"]["outcome"] == "REFUSED_SAME_UID",
                "could not reproduce the independent principal enrollment refusal")
        target = report["separate_finance_controls"]
        check_effects(dict(target, report=target["result"]))
        doctor = report["solitary_doctor"]["result"]["outcome"]
        if doctor == "UNSUPPORTED":
            report["verdicts"]["B"] = "UNSUPPORTED"
        require(doctor == "READY", "Solitary preflight could not establish the fixture prerequisites")
        run_trial(scratch, report)
    report["unchanged_at_end"] = clean() and head() == expected
    require(report["unchanged_at_end"], "tree changed during qualification")
    report.update(outcome="PASS", verdicts={"A": "PASS", "B": "CONDITIONAL", "C": "BLOCKED"})
    report["verdict_scope"] = {
        "A": "Only the selected authorized package and its one wrapped callback in the measured cell.",
        "B": "Pre-release kernel snapshot, closure and an authorized broker read. Financial controls run separately.",
        "C": "Retained public anchors reproduce historical signatures. Independent role and witness custody remain open.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-commit", required=True)
    parser.add_argument("--expect-tree", required=True)
    parser.add_argument("--consent", action="store_true", help="run the checked-in local agent and fixed framework examples")
    args = parser.parse_args()
    expected = {"commit": args.expect_commit, "tree": args.expect_tree}
    report = {"schema": "quorvane.byoa001.local-qualification.v1", "outcome": "BLOCKED",
              "baseline": BASE, "expected_revision": expected, "consent": args.consent,
              "verdicts": {k: "BLOCKED" for k in "ABC"}, "operational_confinement": "BLOCKED",
              "production": "BLOCKED", "certification": "NOT_ISSUED", "independent_witness_custody": "NOT_ASSESSED",
              "scope": "Local engineering reproduction; independent third-party qualification remains blocked."}
    try:
        require(args.consent, "explicit execution consent required for this fixed trial")
        qualify(expected, report)
    except (ImportError, KeyError, OSError, TypeError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report.update(error_type=type(exc).__name__, reason=str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
