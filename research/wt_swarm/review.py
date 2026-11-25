"""Offline qualification of public records. Requires the externally retained profile hash."""
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

from scripts.wt_alibi_human_verify import checked_observation
from shirudo_adapter.action_gate import CLOCK_SKEW_MS, make_grant_payload, verify_effect_receipt
from shirudo_adapter.model import AdapterError, digest
from shirudo_adapter.owner import MIN_REMAINING_MS, validate_bundle
from shirudo_adapter.receipt import verify_record


class Mismatch(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Mismatch(reason)


def load(path):
    return json.loads(path.read_bytes())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def response_is(value, status, reason):
    return value.get("status") == status and value.get("reason") == reason


class Review:
    def __init__(self, root, profile_hash):
        self.root = root
        require(sha(root / "profile.json") == profile_hash, "PROFILE_PIN")
        for key in ("profile", "materials", "journal", "inventory", "faults", "replies", "environment", "custody"):
            setattr(self, key, load(root / (key + ".json")))
        self.by_id = {m["request"]["operation_id"]: m for m in self.materials.values()}
        require(len(self.by_id) == len(self.materials), "OPERATION_UNIQUENESS")
        self.rows = {row["operation_id"]: row for row in self.journal["final"]["ledger"]}
        self.metrics = {}

    def separation(self):
        roles = self.custody
        require(len(set(self.profile[k + "_public_key"] for k in ("gate", "owner", "verifier"))) == 3,
                "ROLE_KEYS")
        for ns in ("pid_namespace", "mount_namespace"):
            require(len({r[ns] for r in roles.values()}) == 3, "ROLE_NAMESPACES")
        require(all(not roles[k]["socket_visible"] for k in ("owner", "verifier"))
                and not any(roles["executor"][k] for k in ("owner_state_visible", "host_gate_state_visible",
                                                            "fixture_verifier_file_visible"))
                and roles["executor"]["socket_mount_read_only"], "ROLE_MOUNTS")

    def authorities(self):
        votes = self.replies["votes"]
        withheld = self.materials["withheld"]["request"]
        keys = set()
        for v in votes["votes"]:
            keys.add(v["public_key"])
            require(verify_record(v["vote"], v["public_key"]) ==
                    {"operation_id": withheld["operation_id"], "approve": True}, "VOTE_BINDING")
        require(len(keys) == 3 and self.profile["owner_public_key"] not in keys, "VOTE_KEYS")
        require(response_is(votes["reply"], "DENIED", "INVALID_SCHEMA"), "CONSENSUS_AS_AUTHORITY")
        for name, reason in (("assessment_as_grant", "INVALID_SIGNATURE"), ("coordinator_admin", "UNKNOWN_OPERATION"),
                             ("coordinator_substitution", "INVALID_SIGNATURE")):
            require(response_is(self.replies[name], "DENIED", reason), name.upper())
        require(withheld["grant"] is None and withheld["operation_id"] not in self.rows, "WITHHELD_EFFECT")

    def batch(self, name):
        clients, total = {"contention": (1000, 1000), "overload": (64, 10000), "duplicates": (2, 2)}[name]
        data = load(self.root / (name + ".json"))
        rows = data["rows"]
        require(data["workers"] == clients and len(rows) == total, "WORKLOAD_SIZE")
        expected = {"contention": ["compete-" + str(i) for i in range(4)],
                    "duplicates": ["duplicates"], "overload": ["withheld"]}[name]
        ids = [self.materials[n]["request"]["operation_id"] for n in expected]
        require(data["request_ids"] == ids, "BATCH_BINDING")
        outcomes, reasons = Counter(), Counter()
        workers = {}
        events = []
        for r in rows:
            wid = r["worker"]
            require(0 <= wid < clients, "WORKER_RANGE")
            ready, tid, iterations = workers.setdefault(wid, (r["ready_ns"], r["tid"], set()))
            require((ready, tid) == (r["ready_ns"], r["tid"]) and r["iteration"] not in iterations,
                    "WORKER_IDENTITY")
            iterations.add(r["iteration"])
            require(ready <= data["release_ns"] <= r["start_ns"] <= r["connected_ns"] <= r["end_ns"],
                    "BARRIER_OR_CONNECTION")
            require(r["sent_ns"] is None or r["connected_ns"] <= r["sent_ns"] <= r["end_ns"], "SEND_CLOCK")
            events.extend([(r["start_ns"], 1), (r["end_ns"], -1)])
            outcome, reason = r["outcome"], r["reason"]
            outcomes[outcome] += 1
            reasons[reason or outcome] += 1
            require(r["slot"] == (wid + r["iteration"]) % len(ids), "REQUEST_SLOT")
            if outcome in ("COMMITTED", "ALREADY_COMMITTED"):
                row = self.rows[ids[r["slot"]]]
                require(name != "overload" and r["receipt_sha256"] == digest(row["receipt"]), "WIRE_RECEIPT")
            else:
                require((outcome == "DENIED" and (reason == "SERVER_BUSY" or
                        (name == "overload" and reason == "INVALID_SCHEMA"))) or
                        (outcome == "AMBIGUOUS" and reason == "TRANSPORT_LOST"), "WIRE_DECISION")
        require(len(workers) == clients == len({w[1] for w in workers.values()}), "CONCURRENT_WORKERS")
        for index, (_, _, iterations) in workers.items():
            count = (156 + int(index < 16)) if name == "overload" else 1
            require(iterations == set(range(count)), "ITERATIONS")
        active = high = 0
        for _, change in sorted(events):
            active += change
            high = max(active, high)
        require(high >= 2 and active == 0, "NO_OVERLAP")
        if name == "contention":
            window = self.faults["contention"]
            require(window["opened"]["count"] == 1000 and high == 1000
                    and window["paused_ns"] <= window["opened"]["ns"] <= window["resume_ns"]
                    and max(r["start_ns"] for r in rows) <= window["opened"]["ns"]
                    and min(r["end_ns"] for r in rows) >= window["resume_ns"], "CONTENTION_WINDOW")
        server = [json.loads(s) for s in (self.root / (name + "-admission.jsonl")).read_text().splitlines()]
        decisions = Counter(s["decision"] for s in server)
        require(len(server) == total and all(s["at"] ==
                ("_dispatch" if s["decision"] in ("COMMITTED", "ALREADY_COMMITTED") else "_denied")
                for s in server), "GATE_ADMISSION_COUNT")
        require(all(decisions[k] >= v for k, v in reasons.items() if k != "TRANSPORT_LOST"), "GATE_WIRE_COUNTS")
        if name == "overload":
            require(set(decisions) == {"SERVER_BUSY", "INVALID_SCHEMA"}, "OVERLOAD_ADMISSION")
        elif name == "duplicates":
            require(decisions == reasons == {"COMMITTED": 1, "ALREADY_COMMITTED": 1}, "DUPLICATE_DISPATCH")
        else:
            committed = self.journal["after_contention"]["ledger"]
            require(2 <= len(committed) <= len(ids) and {r["operation_id"] for r in committed} <= set(ids)
                    and decisions["COMMITTED"] == len(committed)
                    and set(decisions) <= {"COMMITTED", "ALREADY_COMMITTED", "SERVER_BUSY"}, "COMPETING_EFFECTS")
        samples = load(self.root / (name + "-resources.json"))
        peak = {k: max(s[k] for s in samples) for k in ("threads", "fds", "peak_rss_kib")}
        require(peak["threads"] <= 5 and peak["fds"] <= 64 and peak["peak_rss_kib"] <= 128 * 1024,
                "GATE_RESOURCE_BUDGET")
        health = self.replies[name + "-health"]
        snap = self.journal[{"contention":"after_contention","duplicates":"after_duplicates",
                             "overload":"after_overload"}[name]]
        require(health.get("status") == "STATUS" and health["result"]["policy_active"] is True
                and health["result"]["counter"] == snap["counter"], "SAME_PROCESS_HEALTH")
        self.metrics[name] = dict(workers=clients, attempts=total, peak_overlapping_attempts=high,
            connected=sum(r["connected_ns"] is not None for r in rows),
            complete_frames_written=sum(r["sent_ns"] is not None for r in rows), client=dict(reasons),
            gate=dict(decisions), sampled_and_kernel_peaks=peak,
            duration_ms=round((max(r["end_ns"] for r in rows) - data["release_ns"]) / 1e6, 2))

    def recovery(self):
        require(response_is(self.replies["changed_retry"], "DENIED", "OPERATION_CONFLICT"), "CHANGED_RETRY")
        for name in ["compete-" + str(i) for i in range(4)] + ["before", "after", "coordinator"]:
            op = self.materials[name]["request"]["operation_id"]
            status_name, retry_name = name + "-status", name + "-retry"
            if name.startswith("compete-"):
                i = name.split("-")[1]
                status_name, retry_name = "compete-status-" + i, "compete-retry-" + i
            reply = self.replies[status_name]
            require(reply["status"] == "STATUS", "RECOVERY_STATUS")
            seen = reply["result"]["operation"]
            prepared = name == "before" or (name.startswith("compete-") and op not in
                       {r["operation_id"] for r in self.journal["after_contention"]["ledger"]})
            require(seen["operation_id"] == op and seen["status"] == ("PREPARED" if prepared else "COMMITTED")
                    and seen["receipt"] == (None if prepared else self.rows[op]["receipt"]), "RECOVERY_STATE")
            retry = self.replies[retry_name]
            require(retry.get("result") == ("COMMITTED" if prepared else "ALREADY_COMMITTED"), "REPLAY_RESULT")
            require(retry["receipt"] == self.rows[op]["receipt"], "RECOVERY_RECEIPT")
        for name, code in (("before", 70), ("after", 71)):
            require(self.faults[name]["exit"] == code and
                    response_is(self.replies[name+"-interrupted"], "AMBIGUOUS", "TRANSPORT_LOST"), "GATE_EXIT")
        client = self.faults["coordinator"]
        require(client["exit"] == -9 and client["sent"]["phase"] == "sent_before_read"
                and client["sent"]["time_ns"] < client["killed_ns"], "COORDINATOR_EXIT")

    def revocation(self):
        for name, held, other in (("commit-first","gate","revoker"), ("revoke-first","revoker","gate")):
            timeline = self.faults[name]
            require([(e["source"], e["phase"]) for e in timeline] == [
                ("revoker", "armed"), (held, "begin_immediate"), (held, "writer_held"),
                (other, "begin_immediate"), ("controller", "release"), ("revoker", "revoked")],
                "WRITER_ORDER")
            times = [e["time_ns"] for e in timeline]
            require(times == sorted(times), "WRITER_CLOCK")
            req = self.materials[name]["request"]
            require(req["grant"]["payload"]["grant_id"] in self.inventory[name]["revocations"], "REVOCATION_ROW")
            for key in (name, name + "-retry"):
                reply = self.replies[key]
                if name == "commit-first":
                    require(reply["result"] == ("COMMITTED" if key == name else "ALREADY_COMMITTED")
                            and reply["receipt"] == self.rows[req["operation_id"]]["receipt"], "COMMIT_FIRST")
                else:
                    require(response_is(reply, "DENIED", "GRANT_REVOKED"), "REVOKE_FIRST")

    def ledger(self):
        previous = []
        stages = ("initial", "after_contention", "after_retries", "after_duplicates", "after_overload",
                  "coordinator", "before_restart", "before_retry", "after_restart", "after_retry",
                  "commit-first", "revoke-first", "final")
        counts = [0, None, 4, 5, 5, 6, 6, 7, 8, 8, 9, 9, 9]
        expected = {"compete-"+str(i) for i in range(4)} | {"duplicates", "coordinator", "before", "after", "commit-first"}
        require(set(self.rows) == {self.materials[n]["request"]["operation_id"] for n in expected}, "EFFECT_SET")
        last_time = 0
        for name, count in zip(stages, counts, strict=True):
            view = self.journal[name]
            rows = checked_observation(view, self.profile, digest(view))
            require(view["observed_at_ms"] >= last_time and rows[:len(previous)] == previous
                    and (count is None or len(rows) == count), "JOURNAL_TRANSITION")
            inv = self.inventory[name]["operations"]
            require({k for k, v in inv.items() if v == "COMMITTED"} == {r["operation_id"] for r in rows},
                    "INVENTORY_CONFLICT")
            for row in rows[len(previous):]:
                require(last_time <= row["receipt"]["payload"]["committed_at_ms"] <= view["observed_at_ms"],
                        "EFFECT_OBSERVATION_TIME")
            previous, last_time = rows, view["observed_at_ms"]
        require(set(self.inventory["final"]["operations"]) == set(self.by_id), "OPERATION_INVENTORY")
        for key in ("grant_id", "request_sha256", "assessment_sha256"):
            require(len({row[key] for row in previous}) == len(previous), "SPENT_BINDING")
        for row in previous:
            op = row["operation_id"]
            m = self.by_id[op]
            req, bundle = m["request"], m["bundle"]
            grant = verify_record(req["grant"], self.profile["owner_public_key"])
            validate_bundle(bundle, self.profile, intent=m["owner_review"]["intent"],
                ready_at_ms=m["owner_review"]["ready"]["ready_at_ms"], now_ms=grant["issued_at_ms"],
                min_remaining_ms=MIN_REMAINING_MS)
            expected_grant = make_grant_payload(bundle["action_challenge"], bundle["assessment"],
                grant_id=grant["grant_id"], issued_at_ms=grant["issued_at_ms"],
                expires_at_ms=bundle["action_challenge"]["payload"]["expires_at_ms"])
            require(grant == expected_grant and req["assessment"] == bundle["assessment"]
                    and digest(req) == row["request_sha256"], "REQUEST_BINDING")
            verify_effect_receipt(row["receipt"], self.profile["gate_public_key"],
                expected_target=self.profile["target_id"], expected_gate_instance_id=self.profile["gate_instance_id"],
                expected_operation_id=op, expected_grant_id=grant["grant_id"],
                expected_grant_sha256=digest(req["grant"]), expected_assessment_sha256=digest(req["assessment"]),
                expected_action_challenge=bundle["action_challenge"])
            committed = row["receipt"]["payload"]["committed_at_ms"]
            require(grant["issued_at_ms"] <= committed + CLOCK_SKEW_MS and committed < grant["expires_at_ms"],
                    "COMMIT_WINDOW")
        self.metrics["reconciled_increments"] = len(previous)

    def mutants(self):
        # Behavioral mutants consume public copies only. Each must fail at the
        # intended assertion after a valid unmodified review.
        def trial(method, code, edit):
            other = deepcopy(self)
            edit(other)
            try:
                getattr(other, method)()
            except (Mismatch, AdapterError) as exc:
                observed = exc.code if isinstance(exc, AdapterError) else str(exc)
                require(observed == code, "WRONG_MUTATION_DETECTOR")
                return observed
            raise Mismatch("MUTANT_SURVIVED")
        def duplicate_row(other):
            view = other.journal["final"]
            view["ledger"].append(deepcopy(view["ledger"][-1]))
            view["counter"] += 1
            view["committed_operations"] += 1

        def corrupt_owner_signature(other):
            record = other.materials["coordinator"]["request"]["grant"]
            record["signature"] = "0" * 128

        return {
            "unsigned_grant_in_effect_inputs": trial("ledger", "INVALID_SIGNATURE", corrupt_owner_signature),
            "same_operation_recorded_twice": trial("ledger", "ORACLE_LEDGER", duplicate_row),
            "votes_treated_as_owner": trial("authorities", "CONSENSUS_AS_AUTHORITY",
                lambda x: x.replies["votes"].update(reply=x.replies["commit-first"])),
            "exact_retry_claims_new_commit": trial("recovery", "REPLAY_RESULT",
                lambda x: x.replies["coordinator-retry"].update(result="COMMITTED")),
            "counter_persisted_without_row": trial("ledger", "ORACLE_COUNTER",
                lambda x: x.journal["final"].update(counter=x.journal["final"]["counter"] + 1)),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--profile-sha256", required=True)
    args = parser.parse_args()
    rev = Review(args.directory, args.profile_sha256)
    checks = {"role separation": rev.separation, "collusion and coordinator denials": rev.authorities,
              **{n: (lambda name=n: rev.batch(name)) for n in ("contention","duplicates","overload")},
              "restart and exact recovery": rev.recovery, "revocation serialization": rev.revocation,
              "all effects reconciled": rev.ledger}
    report = {k: [] for k in ("PASS","FAIL","BLOCKED","NOT_RUN")}
    for name, check in checks.items():
        try:
            check()
        except (ValueError, KeyError, TypeError, AdapterError, OSError) as exc:
            report["FAIL"].append({"check": name, "error": str(exc)})
        else:
            report["PASS"].append(name)
    if not report["FAIL"]:
        try:
            rev.metrics["behavioral_mutants_killed"] = rev.mutants()
            report["PASS"].append("behavioral mutation controls")
        except (Mismatch, AdapterError) as exc:
            report["FAIL"].append({"check": "behavioral mutation controls", "error": str(exc)})
    else:
        report["NOT_RUN"].append("mutations require a passing original")
    report["BLOCKED"] = ["HERCULES integration (no configured disposable integration)",
                         "fresh genuine Shirudo vTPM swarm (no provisioned VM)"]
    report["NOT_RUN"].append("actual human approval")
    print(json.dumps(dict(report, measurements=rev.metrics), indent=2, sort_keys=True))
    return int(bool(report["FAIL"]))


if __name__ == "__main__":
    sys.exit(main())
