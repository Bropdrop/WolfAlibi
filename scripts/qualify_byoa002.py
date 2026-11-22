"""Reproduce an offline BYOA 002 protocol trial and qualify its exact Git tree."""

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))
from qualify_byoa001 import ARCHIVES, clean, environment, json_run
from qualify_financial_lab import digest, git, head, process, require


BASE = {"commit": "1e13380f881461bf459ab68d1e7726032515467f",
        "tree": "5d27e884bf38be50cf734cea168304f9ec51b19a"}
INHERITED = 545
DEMO = "scripts/byoa002_demo.py"
LIMITS = {"cross_uid_custody": "UNSUPPORTED", "independent_administration": "UNSUPPORTED",
          "production": "BLOCKED", "operational_confinement": "BLOCKED", "certification": "NOT_ISSUED"}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def host_details():
    """Only report public OS metadata. Distinct keys or account numbers do not establish custody."""
    import pwd
    wanted = {"Uid": "uid_set", "Gid": "gid_set", "Groups": "groups", "CapEff": "cap_eff",
              "CapPrm": "cap_prm", "CapAmb": "cap_amb", "Seccomp": "seccomp_mode",
              "Seccomp_filters": "seccomp_filter_count", "NoNewPrivs": "no_new_privs"}
    fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    return {**environment(), "kernel": platform.release(), "architecture": platform.machine(),
            **{name: fields.get(key, "").strip() for key, name in wanted.items()},
            "uid_map": Path("/proc/self/uid_map").read_text().strip(),
            "gid_map": Path("/proc/self/gid_map").read_text().strip(),
            "visible_local_uid_numbers_1000_to_65533": sorted(u.pw_uid for u in pwd.getpwall() if 1000 <= u.pw_uid < 65534),
            "kvm_device_present": Path("/dev/kvm").exists(),
            "cgroup_root_writable": os.access("/sys/fs/cgroup", os.W_OK),
            "topology": "one local operator; distinct signing keys, role stores and processes under that operator"}


def check_source(report, expected):
    require(all(re.fullmatch("[a-f0-9]{40}", s) for s in expected.values()), "invalid expected commit or tree")
    require(clean(), "exact-tree qualification requires a clean checkout")
    report["working_tree_clean_start"] = True
    report["tested_revision"] = head()
    require(report["tested_revision"] == expected, "checkout differs from external Git revision")
    require(git("show", "-s", "--format=%P", "HEAD") == [BASE["commit"]]
            and git("rev-parse", BASE["commit"] + "^{tree}") == [BASE["tree"]], "wrong direct PR #40 parent")
    def modules(ref):
        return {p for p in git("ls-tree", "--name-only", ref) if p.startswith("test_") and p.endswith(".py")}
    inherited = modules(BASE["commit"])
    focused = modules(expected["commit"]) - inherited
    changed = git("diff", "--no-renames", "--name-only", "--diff-filter=DMRTUXB", BASE["commit"], "HEAD",
                  "--", *sorted(inherited), "mutation_test.py", "alibi.py", "public_lab", "examples/qualification001")
    archives = {path: digest(ROOT / path) for path in ARCHIVES}
    require(not changed and archives == ARCHIVES and inherited and focused, "inherited fixture, archive or regression changed")
    report["preservation"] = {"archives": archives, "changed_inherited": changed, "inherited_modules": sorted(inherited)}
    return sorted(inherited), sorted(focused)


CORE_CONTROLS = {
    "test_byoa002_transport.SocketTests": (
        "kernel_enrolled_gateway_and_true_restart_on_ambiguous_delivery",
        "wrong_live_source_and_target_pin_are_refused_before_effect",
        "same_uid_is_unsupported_for_owned_files_without_open_attempts"),
    "test_byoa002_verifier.VerifierTests": (
        "verifier_rejects_an_unreserved_pair", "success_advance_replay_refusal_exact_retrieval",
        "competing_submissions_are_serialized_across_connections", "stale_issued_head_cannot_advance_and_fresh_successor_can",
        "process_death_after_sql_commit_prevents_ack_reissue", "db_rollback_and_joint_rollback_have_distinct_retention_limits",
        "checkpoint_absence_is_an_availability_failure"),
    "test_byoa002_target.TargetAuthorityTests": (
        "positive_commits_one_retained_target_record", "owner_signature_alternative_key_is_refused",
        "lost_reply_restart_recovers_only_original_receipt", "simultaneous_dispatch_has_one_commit_and_one_handoff",
        "revocation_while_verifier_retains_withholds_body", "expiration_then_target_clock_rollback_stays_blocked",
        "missing_witness_before_dispatch_refuses_commit", "target_commit_before_retention_withholds_body",
        "target_ledger_restore_without_checkpoint_is_fenced", "target_and_checkpoint_restore_still_need_live_pending_verifier",
        "process_death_before_sql_commit_rolls_back_decision", "process_death_after_sql_commit_before_anchor_is_fail_stop",
        "joint_store_restore_requires_a_separately_retained_head"),
    "test_byoa002_package.PortablePackageTests": (
        "original_verifies_offline_twice_without_dispatch", "each_signed_component_is_mandatory",
        "all_external_role_pins_must_match", "signed_event_must_match_externally_retained_history",
        "operator_observations_remain_attributed_statements")
}


def run_suites(report, inherited, focused):
    from qualify_history_gate import _loader_counts
    from qualify_stage35 import unit_suite
    loader = _loader_counts(focused)
    report["focused_inventory"] = loader
    require(loader and all(row["tests"] > 0 and not row["loader_errors"] for row in loader),
            "focused tests missing or unloadable")
    count = sum(row["tests"] for row in loader)
    report["suites"] = {}
    for name, expected, args in (("inherited", INHERITED, ["-v", *inherited]), ("focused", count, ["-v", *focused]),
                                 ("full", INHERITED + count, ["discover", "-v"])):
        result = unit_suite(*args)
        for field in ("errors", "failures", "unexpected successes", "expected failures"):
            value = re.search(r"\b" + field + r"=(\d+)", result["stderr"])
            result[field.replace(" ", "_")] = int(value[1]) if value else 0
        result["expected_tests"] = expected
        report["suites"][name] = result
    record = process(sys.executable, "-u", "mutation_test.py")
    caught = re.findall(r"^CAUGHT\s+M([1-8])\b[^\n]+ -> (test_[^\n]+)$", record["stdout"], re.MULTILINE)
    report["mutations"] = dict(record, detected=dict(caught))
    report["focused_mutations"] = json_run(sys.executable, "-I", "scripts/mutate_byoa002.py")
    require(all(row["outcome"] == "PASS" and row["tests"] == row["expected_tests"]
                and not any(row[field] for field in ("skipped", "errors", "failures", "unexpected_successes", "expected_failures"))
                for row in report["suites"].values()), "failed, skipped, partial or miscounted test suite")
    core = [f"{cls}.test_{method}" for cls, methods in CORE_CONTROLS.items() for method in methods]
    report["named_security_controls"] = {}
    for case in core:
        needle = case.split(".")[-1] + " (" + case + ") ... ok"
        matched = all(needle in report["suites"][suite]["stderr"].splitlines() for suite in ("focused", "full"))
        report["named_security_controls"][case] = "PASS" if matched else "MISSING"
    require(all(v == "PASS" for v in report["named_security_controls"].values()), "named adverse coverage incomplete")
    report["coordinated_rollback"] = {
        "test": "test_byoa002_target.TargetAuthorityTests.test_joint_store_restore_requires_a_separately_retained_head",
        "oracle": "Returned fictional records, target SQLite row, verifier head and cold-start decision",
        "scope": "Disposable policy fixture with an enrolled peer and restored owner and verifier state",
        "newer_reference_supplied": "REFUSED_AT_REOPEN",
        "newer_reference_absent": "SECOND_DISCLOSURE_REPRODUCED",
        "record_returns_across_branches": 2, "visible_target_rows_after_restore": 1,
        "interpretation": "Coordinated rollback defeats replay protection when all retained references roll back.",
    }
    require(not record["exit_code"] and sorted(n for n, _ in caught) == list("12345678")
            and "8/8 mutants caught" in record["stdout"], "inherited mutation detections incomplete")
    focused_result = report["focused_mutations"]
    mutation_rows = focused_result["result"]["cases"]
    expected_ids = [f"002-M{i}" for i in range(1, 7)]
    require(not focused_result["exit_code"] and focused_result["result"]["outcome"] == "PASS"
            and focused_result["result"]["detected"] == len(expected_ids)
            and sorted(row["id"] for row in mutation_rows) == expected_ids
            and all(row["detected"] is True for row in mutation_rows),
            "new mutation controls failed or omitted a designated oracle")


def check_demo(public, checked, *, lost):
    from wolfalibi.byoa002_enrollment import digest as record_digest

    pins = public["expectations.json"]
    package = public["package.json"]
    contract = pins["expected_trial"]["contract"]
    require(checked["claim"] == "HISTORICAL_MEASURED_TRIAL_AND_RETAINED_TARGET_RECORD"
            and checked["package_sha256"] == record_digest(package) and checked["expectations_sha256"] == record_digest(pins)
            and checked["revision"] == pins["enrollment"]["revision"]
            and (checked["run_id"], checked["challenge"]) == (contract["run_id"], contract["challenge"]),
            "historical verification does not match this package and challenge")
    require(checked["assurance"] == "SIMULATED_POLICY_ONLY" and checked["production"] == checked["confinement"] == "BLOCKED"
            and checked["independent_custody"] == checked["cross_uid_custody"] == "UNSUPPORTED"
            and checked["current_authority"] == checked["certification"] == "NOT_ISSUED"
            and checked["settlement"] == "UNESTABLISHED", "historical result overclaims authority or custody")
    observation, execution = checked["observation"], checked["execution"]
    require(observation["outcome"] == "OBSERVED" and observation["assurance"] == "OBSERVATIONAL_ONLY"
            and observation["summary"]["counts"] == {"filesystem.read.success": 1}
            and observation["summary"]["complete_wrapped_calls"] is True, "fixed agent callback control differs")
    require(execution["measurement"] == "SIGNED_SUPERVISOR_SNAPSHOT" and execution["scope"] == "PRE_RELEASE_SNAPSHOT_AND_EXIT"
            and execution["bundle"] == contract["profile"]["byoa"]
            and execution["closure"] == {"launcher_reaped": True, "worker_pidfd_exited": True,
                                         "broker_drained": True, "peer_hangup": True}, "measured lifecycle control differs")
    require(checked["bootstrap_read"]["authorization"]["outcome"] == "VERIFIED_HISTORICAL_READ_ADMISSION"
            and checked["bootstrap_read"]["effect"] == {"actor": "TRUSTED_CELL_BOOTSTRAP", "claim": "HISTORICAL_BROKER_READ",
                "operation": "read", "resource": "protected.txt", "response_sha256": contract["fixture_sha256"]},
            "bootstrap read lacks independent admission evidence")
    receipt_hash = record_digest(package["receipt"])
    target, history = checked["target"], checked["history"]
    require(target["outcome"] == "VERIFIED" and target["claim"] == "HISTORICAL_RETAINED_RELEASE_COMMITMENT"
            and target["operation_id"] == contract["run_id"] and target["recipient_delivery"] == "NOT_ESTABLISHED"
            and target["present_authority"] == "NOT_ISSUED" and target["receipt_sha256"] == receipt_hash
            and history["receipt_sha256"] == receipt_hash and history["ack_sha256"] == record_digest(package["ack"])
            and history["previous"] == pins["previous"] and history["head"] == pins["head"]
            and history["head"]["digest"] == receipt_hash, "receipt, independent history or target response differs")

    observed = public["result.json"]
    framework = observed["framework_observation"]
    require(observed["outcome"] == "COMPLETED" and observed["effect_count"] == 1
            and framework["inner_report_sha256"] == record_digest(package["report"])
            and (framework["run_id"], framework["challenge"]) == (checked["run_id"], checked["challenge"])
            and framework["framework"] == {"langchain": "1.5.2", "langchain-core": "1.8.4"}
            and framework["assurance"] == "OBSERVATIONAL_ONLY" and framework["network_upload"] is False
            and framework["runtime"] == "TRUSTED_HOST_SDK_OUTSIDE_MEASURED_CELL"
            and framework["summary"]["counts"] == {"tool.invoke.success": 1}, "LangChain did not drive this actual trial")
    controls = observed["controls"]
    replay = "NOT_ATTEMPTED" if lost else "DENIED"
    outcomes = {"wrong_peer": "DENIED", "custody": "UNSUPPORTED", "duplicate": replay,
                "accepted": "UNKNOWN" if lost else "RELEASED", "reconciled": "RECONCILED", "replacement_dispatch": replay}
    require(all(controls[k]["outcome"] == v for k, v in outcomes.items()),
            "target controls did not reproduce the observed authorization and replay outcomes")
    require(observed["gateway_dispatch_attempts"] == (1 if lost else 3) and observed["reconciliation_attempts"] == 1,
            "lost-response recovery cannot dispatch again")
    require(observed["administrators"] == 1 and observed["cross_uid_custody"] == observed["independent_verifier_custody"] == "UNSUPPORTED"
            and controls["custody"].get("file_opens") is None and observed["gateway_before"] == pins["enrollment"]["gateway"]
            and observed["gateway_before"]["pid"] != observed["gateway_after"]["pid"]
            and observed["target_before"]["pid"] != observed["target_after"]["pid"]
            and observed["verifier_pid_before"] != observed["verifier_pid_after"], "local role topology or restart evidence differs")
    require(controls["reconciled"] == {"outcome": "RECONCILED", "receipt": package["receipt"], "ack": package["ack"]}
            and observed["original_receipt_sha256"] == receipt_hash
            and all("record" not in controls[k] for k in ("reconciled", "wrong_peer", "duplicate", "replacement_dispatch")),
            "historical recovery differs from the one original target commitment")
    if lost:
        require("record" not in controls["accepted"] and "receipt" not in controls["accepted"],
                "lost reply spuriously confirmed delivery")
    else:
        require(controls["accepted"]["record"] == {"record": "fictional-record-002", "review_status": "available"}
                and controls["accepted"]["receipt"] == package["receipt"] and controls["accepted"]["ack"] == package["ack"],
                "ordinary synthetic response does not match the independently verified record")


def reverify(directory, report, expected, *, lost):
    public = {name: json.loads((directory / name).read_bytes()) for name in ("package.json", "expectations.json", "result.json")}
    checked = json_run(sys.executable, "-I", DEMO, "verify", "--package", str(directory / "package.json"),
                       "--expect", str(directory / "expectations.json"))
    report.update(verify=checked, public_sha256={name: digest(directory / name) for name in public},
                  observations=public["result.json"])
    require(checked["exit_code"] == 0 and checked["result"].get("outcome") == "VERIFIED"
            and checked["result"]["revision"] == expected,
            "offline invocation with detached references did not verify the tested revision")
    check_demo(public, checked["result"], lost=lost)
    return public


def qualification(expected, scratch, operator, report):
    inherited, focused = check_source(report, expected)
    report["host"] = host_details()
    run_suites(report, inherited, focused)
    demo = scratch / "demonstration"
    run = json_run(sys.executable, "-I", DEMO, "run", "--consent", "--expect-commit", expected["commit"],
                   "--expect-tree", expected["tree"], "--operator-state", str(operator), "--output", str(demo))
    report["demonstration"] = {"run": run}
    require(run["exit_code"] == 0, "measured role demonstration did not complete")
    public = reverify(demo, report["demonstration"], expected, lost=False)
    recovery = report["demonstration"]["lost_reply"] = {}
    recovered = reverify(demo / "lost-reply", recovery, expected, lost=True)
    require(public["expectations.json"]["expected_trial"]["contract"]["challenge"] !=
            recovered["expectations.json"]["expected_trial"]["contract"]["challenge"],
            "lost-reply demonstration reused the first ceremony's challenge")
    wrong_head = deepcopy(public["expectations.json"])
    observed = wrong_head["head"]["digest"]
    wrong_head["head"]["digest"] = ("1" if observed[0] == "0" else "0") + observed[1:]
    wrong_path = scratch / "wrong-retained-head.json"
    wrong_path.write_bytes(json_bytes(wrong_head))
    negative = json_run(sys.executable, "-I", DEMO, "verify", "--package", str(demo / "package.json"),
                        "--expect", str(wrong_path))
    report["demonstration"]["wrong_external_head"] = negative
    require(negative["exit_code"] != 0 and negative["result"].get("outcome") == "REJECTED"
            and "supplied prior or final head" in negative["result"].get("reason", ""),
            "changed external head was not rejected by its specific verification check")
    require(clean() and head() == expected, "worktree or revision changed during qualification")
    report.update(outcome="PASS", working_tree_clean_end=True, verdicts={
        "A": "PASS", "B": "UNSUPPORTED", "C": "UNSUPPORTED", "D": "CONDITIONAL", "E": "BLOCKED"
    }, verdict_scope={
        "A": "The installed LangChain runner drove the selected reviewed package in the measured Solitary profile.",
        "B": "The simulation uses distinct signing roles on one host under one operator.",
        "C": "Preselected public inputs and retained local witness state permit historical verification. Custody is unqualified.",
        "D": "Local recovery and one-store mismatches under the tested transaction and storage model.",
        "E": "Independent role administration, witness custody, general confinement and formal qualification remain open.",
    })
    return demo, public


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consent", action="store_true", help="run the reviewed local measured trial")
    parser.add_argument("--expect-commit", required=True)
    parser.add_argument("--expect-tree", required=True)
    parser.add_argument("--public-dir", type=Path, required=True, help="new directory outside checkout for public evidence")
    args = parser.parse_args()
    expected = {"commit": args.expect_commit, "tree": args.expect_tree}
    report = {"schema": "quorvane.byoa002.local-qualification.v1", "outcome": "BLOCKED",
              "baseline": BASE, "expected_revision": expected, "consent": args.consent,
              "verdicts": {"A": "BLOCKED", "B": "UNSUPPORTED", "C": "UNSUPPORTED", "D": "BLOCKED", "E": "BLOCKED"},
              **LIMITS, "qualification_scope": "offline synthetic, one locally controlled host"}
    try:
        require(args.consent, "explicit consent required before the qualification trial")
        destination = args.public_dir.absolute()
        require(destination == destination.resolve() and destination != ROOT and ROOT not in destination.parents
                and not destination.exists(), "supply a fresh absolute public evidence location outside the checkout")
        from wolfalibi.byoa002_package import sign_observations, verify_observations
        from wolfalibi.byoa_qualification_cli import _open_key
        with TemporaryDirectory(prefix="qb002-q-") as temp:
            scratch = Path(temp)
            operator = scratch / "operator"
            demo, public = qualification(expected, scratch, operator, report)
            package, pins = public["package.json"], public["expectations.json"]
            signed = sign_observations(package, pins, report, _open_key(operator, "operator"))
            verified = verify_observations(signed, package, pins, report)
            require(verified["outcome"] == "VERIFIED" and verified["claim"] == "OPERATOR_REPORTED_QUALIFICATION_RESULTS",
                    "operator qualification attachment did not verify")
            destination.mkdir(mode=0o700)
            (destination / "lost-reply").mkdir(mode=0o700)
            for prefix in (Path(), Path("lost-reply")):
                for name in public:
                    (destination / prefix / name).write_bytes((demo / prefix / name).read_bytes())
            (destination / "signed-qualification.json").write_bytes(json_bytes(signed))
            (destination / "qualification.json").write_bytes(json_bytes(report))
    except (ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError) as error:
        report.update(outcome="BLOCKED", error_type=type(error).__name__, reason=str(error))
        report["verdicts"]["A"] = report["verdicts"]["D"] = "BLOCKED"
    sys.stdout.buffer.write(json_bytes(report))
    return 0 if report["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
