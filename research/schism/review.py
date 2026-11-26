"""Read-only qualification from public evidence. No issuer, gate, or harness imports."""

import argparse
from collections import Counter
from copy import copy
import gzip
import json
from pathlib import Path
from types import SimpleNamespace

from research.blackout.review import Review as BlackoutReview, timing, quantiles
from research.wt_swarm.review import Mismatch, require, load, sha
from scripts.wt_alibi_human_verify import checked_observation
from shirudo_adapter.action_gate import verify_effect_receipt
from shirudo_adapter.model import AdapterError, digest
from shirudo_adapter.receipt import verify_record

NS = "wolfalibi.schism."
EFFECTS = [
    "old",
    "inflight",
    "current",
    "duplicates",
    "gap",
    "pair",
    *(f"mass{i}" for i in range(4)),
]


def denied(reply, reason):
    return (
        reply.get("status") == "DENIED"
        and reply.get("reason") == reason
        and "receipt" not in reply
    )


class Review(BlackoutReview):
    def __init__(self, root, trusted):
        self.root, self.rec = root, root / "native"
        for name in ("profile", "reader", "anchors"):
            require(
                sha(self.rec / (name + ".json")) == trusted[name], "PUBLIC_PIN_" + name
            )
        for name in (
            "faults",
            "replies",
            "transitions",
            "materials",
            "inventory",
            "events",
            "usage",
            "checkpoints",
            "permits",
            "anchors",
        ):
            setattr(self, name, load(self.rec / (name + ".json")))
        self.store = load(self.rec / "authority-store.json")
        self.history = load(self.rec / "ledger.json")
        self.native = SimpleNamespace(profile=load(self.rec / "profile.json"))
        self.views = load(self.rec / "journal.json")
        reader = load(self.rec / "reader.json")
        self.pins, self.bindings = reader["pins"], reader["bindings"]
        self.by_digest = {b["request_sha256"]: b for b in self.bindings.values()}
        self.budget = load(root / "budgets.json")
        require(
            self.budget == load(Path(__file__).with_name("budgets.json")),
            "PREDECLARED_BUDGETS",
        )
        self.metrics, self.breaches = {}, []

    def custody(self):
        self.enrollments()
        anchors, ab = self.anchors["pins"], self.anchors["executors"]
        profile = self.native.profile
        require(
            list(ab.values()) == anchors["executors"]
            and set(ab) == {"a", "b"}
            and (anchors["target"], anchors["gate"])
            == (profile["target_id"], profile["gate_instance_id"]),
            "AUTHORITY_ENROLLMENT",
        )
        keys = [
            anchors["issuer"],
            *ab.values(),
            self.pins["proof_key"],
            *(profile[n + "_public_key"] for n in ("gate", "owner", "verifier")),
        ]
        require(len(set(keys)) == len(keys), "KEY_SEPARATION")
        files = anchors["files"]
        require(
            set(files) == {"target", "control", "witness"}
            and len({v[0] for v in files.values()}) == 1
            and len({v[1] for v in files.values()}) == 3,
            "CANONICAL_STORAGE",
        )
        roles = load(self.rec / "custody.json")
        require(
            len({v["mount_namespace"] for v in roles.values()}) == 3
            and all(not roles[n]["socket_visible"] for n in ("owner", "verifier"))
            and roles["executor"]["socket_mount_read_only"]
            and all(
                not v for k, v in roles["executor"].items() if k.endswith("_visible")
            ),
            "ROLE_CUSTODY",
        )
        env = load(self.root / "environment.json")
        require(
            env["actual_human_approval"] == "NOT_RUN"
            and env["assessments"] == "FABRICATED"
            and env["paid_model_calls"] == 0
            and env["private_state_removed"],
            "LAB_SCOPE",
        )

    def authority(self):
        anchors = self.anchors["pins"]
        issuer, ab = anchors["issuer"], self.anchors["executors"]
        target = dict(gate=anchors["gate"], target=anchors["target"])
        approvals = [self.transitions[n]["record"] for n in ("genesis", "winner")]
        for index, (n, named) in enumerate(zip(("genesis", "winner"), "ab"), 1):
            record = approvals[index - 1]
            p = verify_record(record, issuer)
            require(
                p
                == dict(
                    target,
                    schema=NS + "transition.v1",
                    epoch=index,
                    previous=digest(approvals[0]) if index == 2 else "0" * 64,
                    executor=ab[named],
                )
                and self.transitions[n]["reply"]
                == dict(status="APPLIED", record=digest(record)),
                "EPOCH_CHAIN",
            )
        require(
            self.store["transitions"] == approvals
            and len(self.store["checkpoints"]) == 2,
            "AUTHORITY_STORE",
        )
        for i, (epoch, head, state) in enumerate(self.store["checkpoints"]):
            require(
                (epoch, head) == (i + 1, digest(approvals[i]))
                and state == self.checkpoints[("genesis", "epoch2")[i]]["local"][2],
                "INDEPENDENT_FLOOR",
            )
        require(
            self.transitions["crash-recovery"]
            == dict(epoch=1, head=digest(approvals[0]), executor=ab["a"]),
            "INTERRUPTED_TRANSITION",
        )
        require(
            self.transitions["transition-replay"]["record"] == approvals[1]
            and denied(self.transitions["transition-replay"]["reply"], "EPOCH_CAS"),
            "TRANSITION_REPLAY",
        )
        rival = verify_record(self.transitions["loser"]["record"], issuer)
        require(
            rival == dict(approvals[1]["payload"], executor=ab["a"])
            and denied(self.transitions["loser"]["reply"], "EPOCH_CAS"),
            "TRANSITION_CAS",
        )
        for n, code in (
            ("forged-higher", "TRANSITION_AUTHENTICATION"),
            ("self-election", "COORDINATOR_PROMOTION"),
        ):
            record = self.transitions[n]["record"]
            try:
                verify_record(record, issuer)
            except AdapterError as exc:
                require(exc.code == "INVALID_SIGNATURE", code)
            else:
                raise Mismatch(code)
            require(
                record["payload"]
                == dict(
                    target,
                    schema=NS + "transition.v1",
                    previous=digest(approvals[1]),
                    executor=ab["a"],
                    epoch=9000 if n == "forged-higher" else 3,
                )
                and denied(self.transitions[n]["reply"], "INVALID_SIGNATURE"),
                code,
            )
        require(
            set(self.permits) == set(self.bindings)
            and self.store["permits"]
            == {self.bindings[k]["operation_id"]: r for k, r in self.permits.items()},
            "PERMIT_SET",
        )
        for name, r in self.permits.items():
            epoch = (
                1
                if name in {"old", "inflight", "delayed", "rev-before", "rev-after"}
                else 2
            )
            b = self.bindings[name]
            expected = dict(
                target,
                schema=NS + "permit.v1",
                epoch=epoch,
                head=digest(approvals[epoch - 1]),
                executor=ab["ab"[epoch - 1]],
                op=b["operation_id"],
                request=b["request_sha256"],
                grant=b["grant_sha256"],
            )
            require(verify_record(r, issuer) == expected, "PERMIT_BINDING")
        require(
            verify_record(self.transitions["rebind"]["record"], issuer)
            == dict(
                self.permits["delayed"]["payload"],
                epoch=2,
                head=digest(approvals[1]),
                executor=ab["b"],
            )
            and denied(self.transitions["rebind"]["reply"], "CROSS_EPOCH_GRANT"),
            "CROSS_EPOCH_REPLAY",
        )

    def effects(self):
        final = self.views["final"]["ledger"]
        bound = {self.bindings[n]["operation_id"]: n for n in EFFECTS}
        epoch, head, holder = 0, "0" * 64, None
        committed = []
        for seq, event in enumerate(self.history, 1):
            require(event["seq"] == seq, "EVENT_SEQUENCE")
            r = event["record"]
            if event["kind"] == "transition":
                epoch += 1
                require(
                    epoch <= 2
                    and r == self.store["transitions"][epoch - 1]
                    and r["payload"]["previous"] == head,
                    "EVENT_TRANSITION",
                )
                head, holder = digest(r), r["payload"]["executor"]
                continue
            p = r["payload"]
            require(
                event["kind"] == "effect"
                and (p["epoch"], p["head"], p["executor"]) == (epoch, head, holder),
                "STALE_COMMIT",
            )
            require(verify_record(r, holder) == p and p["op"] in bound, "EFFECT_SIGNER")
            require(p["op"] not in committed, "DUPLICATE_SETTLEMENT")
            require(len(committed) < len(final), "EXTRA_EFFECT")
            row = final[len(committed)]
            n = bound[p["op"]]
            permit, b = self.permits[n], self.bindings[n]
            require(
                p
                == dict(
                    permit["payload"],
                    schema=NS + "effect.v1",
                    receipt=digest(row["receipt"]),
                    permit=digest(permit),
                )
                and all(
                    row[k] == b[k]
                    for k in (
                        "request_sha256",
                        "operation_id",
                        "grant_sha256",
                        "grant_id",
                        "assessment_sha256",
                    )
                ),
                "EXACT_EFFECT",
            )
            verify_effect_receipt(
                row["receipt"],
                self.native.profile["gate_public_key"],
                expected_target=b["target_id"],
                expected_gate_instance_id=b["gate_instance_id"],
                expected_operation_id=b["operation_id"],
                expected_grant_id=b["grant_id"],
                expected_grant_sha256=b["grant_sha256"],
                expected_assessment_sha256=b["assessment_sha256"],
                expected_action_challenge=self.materials[n]["bundle"][
                    "action_challenge"
                ],
            )
            committed.append(p["op"])
        require(
            epoch == 2
            and len(committed) == len(final) == len(bound)
            and set(committed) == set(bound),
            "EFFECT_SET",
        )
        for label, v in self.views.items():
            rows = checked_observation(v, self.native.profile, digest(v))
            require(
                rows == final[: len(rows)]
                and {
                    op
                    for op, state in self.inventory[label]["operations"].items()
                    if state == "COMMITTED"
                }
                == {r["operation_id"] for r in rows},
                "SNAPSHOT_LEDGER",
            )
        self.metrics["effects_per_epoch"] = dict(
            Counter(
                str(e["record"]["payload"]["epoch"])
                for e in self.history
                if e["kind"] == "effect"
            )
        )
        self.metrics["reconciled_increments"] = len(committed)

    def schedules(self):
        f, r, c = self.faults, self.replies, self.checkpoints
        require(
            f["interrupted-gate"] in (-9, 137) and f["interrupted-transition"] == -9,
            "INTERRUPTION",
        )
        order = f["writer_order"]
        require(
            [v["phase"] for v in order]
            == [
                "writer_held",
                "begin_immediate",
                "release_old",
                "writer_held",
                "begin_immediate",
                "release_transition",
            ]
            and all(x["ns"] < y["ns"] for x, y in zip(order, order[1:])),
            "WRITER_BOUNDARY",
        )
        require(
            f["buffered"]["phase"] == "buffered_disconnected"
            and f["buffered"]["digest"] == self.bindings["delayed"]["request_sha256"]
            and r["disconnect"]["status"] == "AMBIGUOUS"
            and f["buffered"]["ns"]
            < order[0]["ns"]
            < order[-1]["ns"]
            < f["delivery"]["ns"]
            and f["delivery"]["phase"] == "delivered"
            and denied(f["delivery"]["reply"], "CROSS_EPOCH_GRANT"),
            "PARTITION_DELIVERY",
        )
        claims = f["claims"]
        require(
            set(claims) == {"first", "rival", "resumed"}
            and f["coordinator_exit"] in (-9, 137),
            "COORDINATOR_REPLACEMENT",
        )
        for label, material in (
            ("first", "old"),
            ("rival", "delayed"),
            ("resumed", "old"),
        ):
            claim = claims[label]
            require(
                claim["claim"] == "LEADER"
                and claim["claimed_epoch"] == 1
                and claim["socket_readonly"]
                and claim["request"] == self.bindings[material]["request_sha256"]
                and claim["coordinator"] == ("rival" if label == "rival" else "first"),
                "COORDINATOR_CLAIM",
            )
        require(
            len({v["host_pid"] for v in claims.values()}) == 3
            and claims["first"]["mount"] != claims["rival"]["mount"]
            and max(claims[n]["ready_ns"] for n in ("first", "rival"))
            < order[0]["ns"]
            < order[-1]["ns"]
            < claims["resumed"]["ready_ns"]
            and denied(r["rival-after-transition"], "CROSS_EPOCH_GRANT"),
            "COORDINATOR_HISTORY",
        )
        for key in ("simultaneous-claim", "stale-restart"):
            require(denied(r[key], "STALE_EXECUTOR"), "LEADERSHIP_ONLY")
        require(
            denied(r["clone"], "TARGET_CLONE") and f["clone_unchanged"], "CLONE_EFFECT"
        )
        for name in ("old-epoch-restore", "same-epoch-restore"):
            q = c["at-" + name]
            require(
                denied(r[name], "ROLLBACK_DETECTED")
                and q["witness"] == c["pre_restore"]["witness"]
                and q["local"][2] != q["witness"][1]
                and q["local"][0] == (1 if name.startswith("old") else 2),
                "ROLLBACK_EXECUTION",
            )
        require(
            c["at-checkpoint-offline"]["control"] is None
            and f["gap-held"]["phase"] == "writer_held"
            and denied(r["checkpoint-loss"], "CHECKPOINT_UNAVAILABLE")
            and self.views["at-checkpoint-offline"]["ledger"]
            == self.views["pre_restore"]["ledger"],
            "UNAVAILABLE_EFFECT",
        )
        for label, q in c.items():
            if label != "at-checkpoint-offline":
                epoch, body = q["control"]
                require(
                    json.loads(body) == self.store["transitions"][epoch - 1],
                    "SNAPSHOT_HEAD",
                )
            if label not in (
                "at-old-epoch-restore",
                "at-same-epoch-restore",
                "at-checkpoint-offline",
            ):
                require(
                    q["local"][:2] == [epoch, digest(json.loads(body))]
                    and q["local"][2] == q["witness"][1],
                    "SNAPSHOT_FLOOR",
                )
        before, after = [
            self.bindings[n]["grant_id"] for n in ("rev-before", "rev-after")
        ]
        require(
            set(self.inventory["before_transition"]["revocations"]) == set()
            and set(self.inventory["epoch2"]["revocations"]) == {before}
            and set(self.inventory["pre_restore"]["revocations"]) == {before, after},
            "REVOCATION_ORDER",
        )
        for which in ("before", "after"):
            require(
                r["revocation-" + which]["status"] == "REVOKED"
                and denied(r["revoked-" + which], "GRANT_REVOKED"),
                "REVOCATION",
            )
        rows = {row["operation_id"]: row for row in self.views["final"]["ledger"]}
        for label, n in (
            ("original", "old"),
            ("inflight", "inflight"),
            ("current", "current"),
            ("gap-first", "duplicates"),
            ("healed", "gap"),
        ):
            require(
                r[label]
                == dict(
                    result="COMMITTED",
                    receipt=rows[self.bindings[n]["operation_id"]]["receipt"],
                ),
                "ORIGINAL_RECEIPT",
            )
        require(
            denied(r["read-proof-execute"], "INVALID_SCHEMA")
            and denied(r["conflicting-original"], "OPERATION_CONFLICT"),
            "RECOVERY_AUTHORITY",
        )
        require(
            f["expired_handshake"]["code"] == 10
            and f["expired_handshake"]["phase"] == "tls_rejected",
            "STALE_CERTIFICATE",
        )

    def outcomes(self):
        cases = {
            n: ("old", "UNRESOLVED")
            for n in (
                "old-epoch-restore",
                "same-epoch-restore",
                "checkpoint-offline",
                "cross-principal",
                "wrong-digest",
                "expired-certificate",
            )
        }
        cases.update(
            {
                "cross-epoch": ("old", "COMMITTED"),
                "durable-negative": ("rev-before", "NOT_COMMITTED"),
                "pending": ("pending", "UNRESOLVED"),
                "bob-own": ("duplicates", "COMMITTED"),
            }
        )
        cases.update({"final-" + n: (n, "COMMITTED") for n in EFFECTS})
        require(set(cases) == set(self.events), "RECOVERY_COVERAGE")
        times, distribution = [], Counter()
        for label, (n, state) in cases.items():
            event = self.events[label]
            require(
                event["role"]
                == (
                    "bob"
                    if label in ("cross-principal", "bob-own", "final-duplicates")
                    else "expired"
                    if label == "expired-certificate"
                    else "alice"
                ),
                "REQUESTER_IDENTITY",
            )
            t, counts = self.group(label, event, [n], [state])
            times.extend(t)
            distribution.update(counts)
            if label in (
                "old-epoch-restore",
                "same-epoch-restore",
                "checkpoint-offline",
            ):
                reply = next(iter(event["groups"][0]["proofs"].values()))
                require(
                    reply["proof"]["payload"]["reason"] == "JOURNAL_UNAVAILABLE",
                    "UNCERTAIN_CHECKPOINT",
                )
        self.metrics["individual_reconciliations"] = dict(
            counts=dict(distribution),
            unresolved_fraction=distribution["UNRESOLVED"] / len(times),
            **quantiles([e - s for s, e in times]),
        )

    def measure(self, name, services, stats):
        roles = {}
        for role, samples in services.items():
            profile = dict(
                seconds=stats["seconds"],
                peak_rss_kib=max(s["peak_rss_kib"] for s in samples),
                sampled_peak_fds=max(s["fds"] for s in samples),
                sampled_peak_threads=max(s["threads"] for s in samples),
            )
            self.resources(name + "/" + role, profile, samples)
            roles[role] = profile
        stats["services"] = roles
        stats.update(
            {
                k: max(v[k] for v in roles.values())
                for k in (
                    "peak_rss_kib",
                    "sampled_peak_fds",
                    "sampled_peak_threads",
                    "peak_sampled_database_bytes",
                )
            }
        )
        stats["service_cpu_seconds"] = sum(
            v["service_cpu_seconds"] for v in roles.values()
        )
        stats["journal_growth_bytes"] = next(iter(roles.values()))[
            "journal_growth_bytes"
        ]
        return stats

    def execution_profile(self, kind):
        contention = kind == "contention"
        rows, decisions = [], {}
        pair = kind == "duplicates"
        ledger = {r["operation_id"]: r for r in self.views["final"]["ledger"]}
        for route in "ab" if contention else "b":
            label = kind + "-" + route
            data = load(self.rec / (label + ".json"))
            group = data["rows"]
            audits = [
                json.loads(line)
                for line in (self.rec / (label + "-admission.jsonl"))
                .read_text()
                .splitlines()
            ]
            decisions[route] = dict(Counter(s for _, s in audits))
            require(
                len(audits)
                == len(group)
                == (500 if contention else (2 if pair else 10000)),
                "ADMISSION_COUNT",
            )
            if contention:
                opened = self.faults["sockets"][route]
                require(
                    opened["phase"] == "open"
                    and opened["sockets"] == 500
                    and len({r["tid"] for r in group}) == 500
                    and {r["worker"] for r in group} == set(range(500))
                    and max(r["start_ns"] for r in group)
                    <= opened["ns"]
                    <= self.faults["release"]
                    <= min(r["end_ns"] for r in group),
                    "CONCURRENT_WORKERS",
                )
                allowed = (
                    {"SERVER_BUSY", "STALE_EXECUTOR"}
                    if route == "a"
                    else {"SERVER_BUSY", "COMMITTED", "ALREADY_COMMITTED"}
                )
            elif pair:
                require(
                    data["workers"] == 2
                    and len({r["tid"] for r in group}) == 2
                    and data["request_ids"] == [self.bindings["pair"]["operation_id"]]
                    and max(r["start_ns"] for r in group)
                    < min(r["end_ns"] for r in group),
                    "DUPLICATE_PROFILE",
                )
                allowed = {"COMMITTED", "ALREADY_COMMITTED"}
                require(
                    decisions[route] == dict(COMMITTED=1, ALREADY_COMMITTED=1),
                    "DUPLICATE_RESULT",
                )
            else:
                require(
                    data["workers"] == 64
                    and len({r["tid"] for r in group}) == 64
                    and len({(r["worker"], r["iteration"]) for r in group}) == 10000
                    and data["request_ids"]
                    == [self.materials["withheld"]["request"]["operation_id"]],
                    "OVERLOAD_PROFILE",
                )
                allowed = {"SERVER_BUSY", "INVALID_SCHEMA"}
            require(
                set(decisions[route]) <= allowed
                and (pair or "SERVER_BUSY" in decisions[route])
                and len(decisions[route]) >= 2,
                "BOUNDED_ADMISSION",
            )
            visible = Counter()
            for r in group:
                require(
                    r["ready_ns"] <= r["start_ns"] <= r["end_ns"]
                    and r["slot"] == (r["worker"] % 4 if contention else 0),
                    "CLIENT_TIMING",
                )
                outcome = r["outcome"]
                if outcome in ("COMMITTED", "ALREADY_COMMITTED"):
                    op = self.bindings["pair" if pair else "mass" + str(r["slot"])][
                        "operation_id"
                    ]
                    require(
                        (contention or pair)
                        and route == "b"
                        and digest(ledger[op]["receipt"]) == r["receipt_sha256"],
                        "WORKER_RECEIPT",
                    )
                elif outcome == "AMBIGUOUS":
                    require(
                        r["reason"] == "TRANSPORT_LOST" and "receipt_sha256" not in r,
                        "TRANSPORT_OUTCOME",
                    )
                    continue
                else:
                    require(
                        outcome == "DENIED"
                        and r["reason"] in allowed
                        and "receipt_sha256" not in r,
                        "WORKER_DENIAL",
                    )
                visible[r["reason"] or outcome] += 1
            require(not (visible - Counter(decisions[route])), "ADMISSION_MISMATCH")
            rows.extend(group)
        initial = self.views[
            "healed" if contention else ("mass-settled" if pair else "duplicates")
        ]["ledger"]
        settled = self.views[kind]["ledger"]
        require(
            settled[: len(initial)] == initial
            and len(settled) - len(initial) == decisions["b"].get("COMMITTED", 0),
            "ADMISSION_EFFECTS",
        )
        if contention:
            for i in range(4):
                n = f"mass{i}"
                op = self.bindings[n]["operation_id"]
                result = (
                    "ALREADY_COMMITTED"
                    if any(x["operation_id"] == op for x in settled)
                    else "COMMITTED"
                )
                require(
                    self.replies["retry-" + n]
                    == dict(result=result, receipt=ledger[op]["receipt"]),
                    "EXACT_RETRY",
                )
        unresolved = sum(r["outcome"] == "AMBIGUOUS" for r in rows)
        stats = dict(
            **timing([(r["start_ns"], r["end_ns"]) for r in rows]),
            workers=1000 if contention else (2 if pair else 64),
            unresolved=unresolved,
            unresolved_fraction=unresolved / len(rows),
            gate_decisions=decisions,
        )
        return self.measure(kind, load(self.rec / (kind + "-usage.json")), stats)

    def performance(self):
        profiles = {
            k: self.execution_profile(k)
            for k in ("contention", "duplicates", "overload")
        }
        restarts = self.faults["recovery_restarts"]
        require(
            len(restarts) == 3 and len({r["serving"] for r in restarts}) == 3,
            "RESTART_COUNT",
        )
        for i, r in enumerate(restarts):
            name = f"storm-{i}"
            with gzip.open(self.rec / (name + ".json.gz")) as fp:
                data = json.load(fp)
            times, counts = self.group(
                name,
                data,
                ["old", "rev-before", "pending"],
                ["COMMITTED", "NOT_COMMITTED", "UNRESOLVED"],
                storm=True,
            )
            require(
                data["role"] == "alice"
                and counts
                == dict(COMMITTED=10000, NOT_COMMITTED=10000, UNRESOLVED=10000)
                and r["previous"] != r["serving"]
                and r["ready_ns"] < min(s for s, _ in times),
                "RESTART_STORM",
            )
            require(
                self.inventory["at-" + name] == self.inventory["final"]
                and self.views["at-" + name]["ledger"] == self.views["final"]["ledger"]
                and self.checkpoints["at-" + name] == self.checkpoints["final"],
                "READ_EFFECT",
            )
            services = dict(reader=self.usage[name], gate=self.usage[name + "-gate"])
            stats = dict(
                **timing(times),
                workers=4,
                outcomes=dict(counts),
                unresolved=counts["UNRESOLVED"],
                unresolved_fraction=counts["UNRESOLVED"] / len(times),
            )
            profiles[name] = self.measure(name, services, stats)
            if any(
                s["db_bytes"] != services["reader"][0]["db_bytes"]
                for s in services["reader"]
            ):
                self.breaches.append(
                    [name, "recovery_journal_growth", stats["journal_growth_bytes"], 0]
                )
        for label, q in self.checkpoints.items():
            size = sum(q["bytes"].get(k, 0) for k in ("control", "witness"))
            if size > self.budget["max_control_and_seal_bytes"]:
                self.breaches.append(
                    [
                        label,
                        "external_bytes",
                        size,
                        self.budget["max_control_and_seal_bytes"],
                    ]
                )
        self.metrics["measured_profiles"] = profiles
        self.metrics["cumulative_profile_requests"] = sum(
            v["count"] for v in profiles.values()
        )
        self.metrics["external_checkpoint_bytes"] = {
            k: v["bytes"]
            for k, v in self.checkpoints.items()
            if k in ("genesis", "healed", "contention", "overload", "final")
        }
        require(
            self.metrics["cumulative_profile_requests"] == 101002, "CUMULATIVE_VOLUME"
        )
        require(not self.breaches, "RESOURCE_BUDGET")

    def mutations(self):
        from research.schism.controls import variants, materialize

        detected = {}
        for name, field, behavior, check, expected in variants():
            variant = copy(self)
            setattr(variant, field, materialize(name, field, behavior, self))
            try:
                getattr(variant, check)()
            except (Mismatch, AdapterError) as exc:
                observed = getattr(exc, "code", str(exc))
                require(
                    observed == expected,
                    "WRONG_MUTATION_DETECTOR_" + name + "_" + observed,
                )
                detected[name] = observed
            else:
                raise Mismatch("SURVIVING_MUTATION_" + name)
        self.metrics["detected_behavioral_mutations"] = detected


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence", type=Path)
    for n in ("profile", "reader", "anchors"):
        p.add_argument("--" + n + "-sha256", required=True)
    args = p.parse_args()
    result = dict(
        PASS=[],
        FAIL=[],
        BLOCKED=["HERCULES integration", "genuine Shirudo vTPM qualification"],
        NOT_RUN=["actual human approval", "distributed consensus qualification"],
    )
    failed = False
    try:
        audit = Review(
            args.evidence,
            {n: getattr(args, n + "_sha256") for n in ("profile", "reader", "anchors")},
        )
        for n in (
            "custody",
            "authority",
            "effects",
            "schedules",
            "outcomes",
            "performance",
            "mutations",
        ):
            try:
                getattr(audit, n)()
                result["PASS"].append(n)
            except (
                ValueError,
                AdapterError,
                RuntimeError,
                KeyError,
                IndexError,
                TypeError,
                AssertionError,
                OSError,
            ) as e:
                result["FAIL"].append([n, getattr(e, "code", str(e))])
                failed = True
        result.update(measurements=audit.metrics, budget_exceedances=audit.breaches)
    except (ValueError, OSError, KeyError, AdapterError) as e:
        result["FAIL"].append(["inputs", str(e)])
        failed = True
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(int(failed))


if __name__ == "__main__":
    main()
