"""Offline review of WT-SWARM-002 using public records and externally pinned inputs."""

import argparse
from collections import Counter
from copy import deepcopy
import gzip
import json
import math
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from research.wt_swarm.review import (
    Review as NativeReview,
    require,
    Mismatch,
    sha,
    load,
)
from scripts.wt_alibi_human_verify import checked_observation
from shirudo_adapter.action_gate import verify_effect_receipt, make_grant_payload
from shirudo_adapter.model import AdapterError, digest
from shirudo_adapter.owner import validate_bundle, MIN_REMAINING_MS
from shirudo_adapter.receipt import verify_record

FIELDS = (
    "principal",
    "gate_instance_id",
    "target_id",
    "operation_id",
    "request_sha256",
)


def quantiles(ns):
    values = sorted(ns)
    return {
        f"p{p}_ms": round(values[math.ceil(p * len(values) / 100) - 1] / 1e6, 4)
        for p in (50, 95, 99)
    }


def timing(times):
    duration = (max(end for _, end in times) - min(start for start, _ in times)) / 1e9
    return dict(
        count=len(times),
        seconds=round(duration, 5),
        requests_per_second=round(len(times) / duration, 2),
        **quantiles([end - start for start, end in times]),
    )


def native_metrics(path, name):
    data = load(path / (name + ".json"))
    rows = data["rows"]
    samples = load(path / (name + "-resources.json"))
    return dict(
        **timing([(r["start_ns"], r["end_ns"]) for r in rows]),
        workers=data["workers"],
        unresolved=sum(r["outcome"] == "AMBIGUOUS" for r in rows),
        unresolved_fraction=sum(r["outcome"] == "AMBIGUOUS" for r in rows) / len(rows),
        peak_rss_kib=max(s["peak_rss_kib"] for s in samples),
        sampled_peak_fds=max(s["fds"] for s in samples),
        sampled_peak_threads=max(s["threads"] for s in samples),
    )


def audit_reply(reply, query, role, pins, b, view, inventory):
    # Denials and TLS failures carry no proof, receipt, or information about gate state.
    allowed = (
        b is not None and role == b["principal"] and query == {k: b[k] for k in FIELDS}
    )
    if not allowed:
        require(
            reply
            in (
                {"outcome": "UNRESOLVED", "reason": "RECOVERY_DENIED"},
                {"outcome": "UNRESOLVED", "reason": "TRANSPORT"},
            ),
            "RECEIPT_AUTHORIZATION",
        )
        return "UNRESOLVED"
    if "proof" not in reply:
        require(
            reply == {"outcome": "UNRESOLVED", "reason": "TRANSPORT"},
            "AMBIGUITY_PROMOTED",
        )
        return "UNRESOLVED"
    require(set(reply) == {"proof", "receipt"}, "REPLY_SHAPE")
    p = verify_record(reply["proof"], pins["proof_key"])
    require(
        set(p)
        == set(FIELDS)
        | {
            "schema",
            "grant_id",
            "outcome",
            "authority",
            "reason",
            "receipt_sha256",
            "revoked_at_ms",
        }
        and all(p[k] == v for k, v in query.items())
        and p["grant_id"] == b["grant_id"]
        and p["schema"] == "wolfalibi.blackout.reconciliation.v1"
        and p["authority"] == "READ_ONLY",
        "REQUEST_BINDING",
    )
    rows = [r for r in view["ledger"] if r["operation_id"] == b["operation_id"]]
    outcome = p["outcome"]
    if outcome == "COMMITTED":
        require(
            len(rows) == 1
            and rows[0]["request_sha256"] == b["request_sha256"]
            and p["revoked_at_ms"] is None
            and p["reason"] == "ORIGINAL_RECEIPT"
            and reply["receipt"] == rows[0]["receipt"]
            and p["receipt_sha256"] == digest(reply["receipt"]),
            "COMMIT_WITHOUT_ORIGINAL",
        )
        verify_effect_receipt(
            reply["receipt"],
            pins["gate_public_key"],
            expected_target=b["target_id"],
            expected_gate_instance_id=b["gate_instance_id"],
            expected_operation_id=b["operation_id"],
            expected_grant_id=b["grant_id"],
            expected_grant_sha256=b["grant_sha256"],
            expected_assessment_sha256=b["assessment_sha256"],
        )
    else:
        require(
            reply["receipt"] is None and p["receipt_sha256"] is None,
            "NONCOMMIT_DISCLOSURE",
        )
        if outcome == "NOT_COMMITTED":
            require(
                not rows
                and inventory["operations"].get(b["operation_id"]) == "PREPARED"
                and b["grant_id"] in inventory["revocations"]
                and p["revoked_at_ms"]
                == inventory["revocations"][b["grant_id"]]
                <= view["observed_at_ms"]
                and p["reason"] == "DURABLE_GRANT_REVOCATION",
                "NO_DURABLE_SETTLEMENT",
            )
        else:
            require(
                outcome == "UNRESOLVED"
                and p["revoked_at_ms"] is None
                and p["reason"]
                in (
                    "NO_TERMINAL_EVIDENCE",
                    "NO_ROW",
                    "JOURNAL_IDENTITY",
                    "JOURNAL_BINDING",
                    "JOURNAL_UNAVAILABLE",
                ),
                "UNKNOWN_OUTCOME",
            )
    return outcome


class Review:
    def __init__(self, root, profile_sha, reader_sha):
        self.root = root
        self.rec = root / "recovery"
        self.native = NativeReview(root / "native", profile_sha)
        require(sha(self.rec / "reader.json") == reader_sha, "READER_PIN")
        reader = load(self.rec / "reader.json")
        self.pins = reader["pins"]
        self.bindings = reader["bindings"]
        self.by_digest = {b["request_sha256"]: b for b in self.bindings.values()}
        self.materials = load(self.rec / "materials.json")
        self.views = load(self.rec / "journal.json")
        self.inventory = load(self.rec / "inventory.json")
        self.events = load(self.rec / "events.json")
        self.faults = load(self.rec / "faults.json")
        self.replies = load(self.rec / "replies.json")
        self.metrics = {}
        self.usage = load(root / "usage.json")
        self.budget = load(root / "budgets.json")
        require(
            self.budget == load(Path(__file__).with_name("budgets.json")),
            "PREDECLARED_BUDGETS",
        )
        self.breaches = []
        self.single_times = []

    def inherited(self):
        n = self.native
        n.separation()
        n.authorities()
        for name in ("contention", "duplicates", "overload"):
            n.batch(name)
        n.recovery()
        n.revocation()
        n.ledger()
        self.metrics["inherited_mutations"] = n.mutants()

    def enrollments(self):
        profile = self.native.profile
        require(self.pins["gate_public_key"] == profile["gate_public_key"], "GATE_PIN")
        ca = x509.load_pem_x509_certificate((self.rec / "ca.pem").read_bytes())
        custody = load(self.rec / "reader.json")["custody"]
        require(
            custody
            == dict(
                proof_key=self.pins["proof_key"],
                db_mount_readonly=True,
                gate_key_visible=False,
                native_socket_visible=False,
            ),
            "READER_CUSTODY",
        )
        start = self.views["native_complete"]["observed_at_ms"] / 1000
        for role in ("reader", "alice", "bob", "expired"):
            cert = x509.load_pem_x509_certificate(
                (self.rec / (role + ".pem")).read_bytes()
            )
            cert.verify_directly_issued_by(ca)
            require(
                cert.fingerprint(hashes.SHA256()).hex() == self.pins[role], "CERT_PIN"
            )
            require(
                (
                    cert.not_valid_before_utc.timestamp()
                    <= start
                    < cert.not_valid_after_utc.timestamp()
                )
                == (role != "expired"),
                "CERT_LIFETIME",
            )
        require(len(set(self.pins.values())) == len(self.pins), "DISTINCT_IDENTITIES")
        require(
            set(self.bindings)
            == {k for k, m in self.materials.items() if m["request"]["grant"]},
            "ENROLLMENT_SET",
        )
        for name, b in self.bindings.items():
            m = self.materials[name]
            req = m["request"]
            bundle = m["bundle"]
            g = verify_record(req["grant"], profile["owner_public_key"])
            validate_bundle(
                bundle,
                profile,
                intent=m["owner_review"]["intent"],
                ready_at_ms=m["owner_review"]["ready"]["ready_at_ms"],
                now_ms=g["issued_at_ms"],
                min_remaining_ms=MIN_REMAINING_MS,
            )
            require(
                g
                == make_grant_payload(
                    bundle["action_challenge"],
                    bundle["assessment"],
                    grant_id=g["grant_id"],
                    issued_at_ms=g["issued_at_ms"],
                    expires_at_ms=bundle["action_challenge"]["payload"][
                        "expires_at_ms"
                    ],
                )
                and req["assessment"] == bundle["assessment"]
                and req["operation_id"] == g["operation_id"],
                "ORIGINAL_GRANT",
            )
            expected = dict(
                operation_id=g["operation_id"],
                request_sha256=digest(req),
                target_id=profile["target_id"],
                gate_instance_id=profile["gate_instance_id"],
                grant_id=g["grant_id"],
                grant_sha256=digest(req["grant"]),
                assessment_sha256=digest(req["assessment"]),
                challenge_sha256=digest(bundle["action_challenge"]),
                principal=self.pins["bob" if name == "duplicates" else "alice"],
            )
            require(b == expected, "ENROLLMENT_BINDING")

    def ledger(self):
        require(
            self.views["native_complete"]["ledger"]
            == self.native.journal["final"]["ledger"],
            "BASE_CONTINUITY",
        )
        prev = []
        for name, v in sorted(
            self.views.items(),
            key=lambda item: (item[1]["observed_at_ms"], item[1]["counter"]),
        ):
            rows = checked_observation(v, self.native.profile, digest(v))
            require(rows[: len(prev)] == prev, "LEDGER_HISTORY")
            prev = rows
            inv = self.inventory[name]["operations"]
            require(
                {op for op, state in inv.items() if state == "COMMITTED"}
                == {r["operation_id"] for r in rows},
                "JOURNAL_INVENTORY",
            )
        expected = set(self.native.rows) | {
            self.bindings[n]["operation_id"]
            for n in ("late", "replacement", "interrupted")
        }
        final = self.views["final"]["ledger"]
        require(
            len(final) == len(expected) == 12
            and {r["operation_id"] for r in final} == expected,
            "PROTECTED_EFFECT_SET",
        )
        for row in final:
            b = self.by_digest[row["request_sha256"]]
            require(
                all(
                    row[k] == b[k]
                    for k in (
                        "operation_id",
                        "grant_id",
                        "grant_sha256",
                        "assessment_sha256",
                    )
                ),
                "EXACT_EFFECT",
            )
            m = self.materials[next(n for n, v in self.bindings.items() if v == b)]
            verify_effect_receipt(
                row["receipt"],
                self.pins["gate_public_key"],
                expected_target=b["target_id"],
                expected_gate_instance_id=b["gate_instance_id"],
                expected_operation_id=b["operation_id"],
                expected_grant_id=b["grant_id"],
                expected_grant_sha256=b["grant_sha256"],
                expected_assessment_sha256=b["assessment_sha256"],
                expected_action_challenge=m["bundle"]["action_challenge"],
            )
        for k in ("grant_id", "operation_id", "request_sha256", "assessment_sha256"):
            require(len({r[k] for r in final}) == len(final), "DUPLICATE_EFFECT")
        self.metrics["reconciled_increments"] = len(final)

    def group(self, name, record, names, states, storm=False):
        require(
            not record["native_socket_visible"] and not record["journal_visible"],
            "CLIENT_CUSTODY",
        )
        queries = record["queries"]
        role = self.pins[record["role"]]
        require(len(queries) == len(names) == len(states), "QUERY_COUNT")
        for q, n in zip(queries, names, strict=True):
            expected = {k: self.bindings[n][k] for k in FIELDS}
            for label, field in (
                ("wrong-digest", "request_sha256"),
                ("wrong-target", "target_id"),
                ("wrong-gate", "gate_instance_id"),
            ):
                if name == label:
                    require(q[field] != expected[field], "CONTROL_NOT_APPLIED")
                    expected[field] = q[field]
            require(q == expected, "QUERY_SUBSTITUTION")
        require(len(record["groups"]) == (4 if storm else 1), "WORKER_COUNT")
        times = []
        counts = Counter()
        threads = set()
        for worker, g in enumerate(record["groups"]):
            threads.add(g["thread"])
            require(len(g["rows"]) == (7500 if storm else 1), "REQUEST_COUNT")
            examined = set()
            last = 0
            for i, row in enumerate(g["rows"]):
                start, end, idx, ref = row[:4]
                require(
                    idx == (i + worker) % len(names) and last <= start <= end,
                    "REQUEST_ORDER",
                )
                last = end
                reply = g["proofs"][ref]
                require(
                    len(row) == 4
                    or (
                        name == "expired-certificate"
                        and len(row) == 6
                        and row[4]
                        in (
                            "SSLError",
                            "BrokenPipeError",
                            "ConnectionResetError",
                            "ConnectionError",
                        )
                    ),
                    "CLIENT_ERROR",
                )
                if (idx, ref) not in examined:
                    require(digest(reply) == ref, "WIRE_DIGEST")
                    state = audit_reply(
                        reply,
                        queries[idx],
                        role,
                        self.pins,
                        self.by_digest.get(queries[idx]["request_sha256"]),
                        self.views["at-" + name],
                        self.inventory["at-" + name],
                    )
                    require(state == states[idx], "OUTCOME")
                    if name in (
                        "cross-principal",
                        "wrong-digest",
                        "wrong-gate",
                        "wrong-target",
                    ):
                        require(
                            reply.get("reason") == "RECOVERY_DENIED", "DENIAL_REQUIRED"
                        )
                    elif name == "expired-certificate":
                        require(
                            reply.get("reason") == "TRANSPORT" and len(row) == 6,
                            "TLS_REJECTION_REQUIRED",
                        )
                    else:
                        require("proof" in reply, "SIGNED_REPLY_REQUIRED")
                    examined.add((idx, ref))
                times.append((start, end))
                counts[states[idx]] += 1
            require(
                set(g["proofs"]) == {r[3] for r in g["rows"]}, "UNREFERENCED_WIRE_DATA"
            )
        require(len(threads) == len(record["groups"]), "WORKER_IDENTITIES")
        return times, counts

    def outcomes(self):
        cases = {
            "late-before": ("late", "UNRESOLVED"),
            "late-after": ("late", "COMMITTED"),
            "cancel-before": ("cancel", "UNRESOLVED"),
            "cancel-revoked": ("cancel", "NOT_COMMITTED"),
            "cancel-after": ("cancel", "NOT_COMMITTED"),
            "replacement-after": ("replacement", "COMMITTED"),
            "settlement-pending": ("interrupted", "UNRESOLVED"),
            "settlement-committed": ("interrupted", "COMMITTED"),
            "cross-principal": ("replacement", "UNRESOLVED"),
            "wrong-digest": ("replacement", "UNRESOLVED"),
            "wrong-target": ("replacement", "UNRESOLVED"),
            "wrong-gate": ("replacement", "UNRESOLVED"),
            "expired-certificate": ("replacement", "UNRESOLVED"),
            "bob-own": ("duplicates", "COMMITTED"),
            "still-pending": ("waiting", "UNRESOLVED"),
        }
        for row in self.views["final"]["ledger"]:
            name = next(
                n
                for n, b in self.bindings.items()
                if b["operation_id"] == row["operation_id"]
            )
            cases["final-" + name] = (name, "COMMITTED")
        require(set(cases) == set(self.events), "CASE_SET")
        handshake = self.faults["expired_handshake"]
        s, e, *_ = self.events["expired-certificate"]["groups"][0]["rows"][0]
        require(
            handshake["phase"] == "tls_rejected"
            and handshake["code"] == 10
            and s <= handshake["ns"] <= e + 100_000_000,
            "TLS_EXPIRED_CERTIFICATE",
        )
        distribution = Counter()
        for label, (name, state) in cases.items():
            role = (
                "bob"
                if label in ("cross-principal", "bob-own", "final-duplicates")
                else ("expired" if label == "expired-certificate" else "alice")
            )
            require(self.events[label]["role"] == role, "REQUESTER_IDENTITY")
            times, counts = self.group(label, self.events[label], [name], [state])
            self.single_times.extend(times)
            distribution.update(counts)
        self.metrics["individual_reconciliations"] = dict(
            counts=dict(distribution),
            unresolved_fraction=distribution["UNRESOLVED"] / sum(distribution.values()),
            **quantiles([e - s for s, e in self.single_times]),
        )
        for name in ("late", "cancel"):
            require(
                self.replies[name + "-disconnect"]["status"] == "AMBIGUOUS",
                "DISCONNECT",
            )
            f = self.faults[name]
            require(
                f["first"]["phase"] == "buffered_disconnected"
                and f["first"]["digest"] == self.bindings[name]["request_sha256"]
                and f["delivery"]["phase"] == "delivered",
                "PARTITION",
            )
            for when in ["before", "revoked"] if name == "cancel" else ["before"]:
                s, e, *_ = self.events[name + "-" + when]["groups"][0]["rows"][0]
                require(f["first"]["ns"] < s <= e < f["delivery"]["ns"], "DELAY_ORDER")
        require(
            self.faults["cancel"]["delivery"]["reply"].get("reason") == "GRANT_REVOKED"
            and self.faults["late"]["delivery"]["reply"].get("result") == "COMMITTED",
            "DELAY_DELIVERY",
        )
        require(
            self.faults["replacement"]["coordinator_exit"] == -9
            and self.faults["replacement"]["first"]["reply"]["result"] == "COMMITTED",
            "REPLACEMENT",
        )
        require(
            self.faults["settlement_exit"] == 70
            and self.replies["settlement-loss"]["status"] == "AMBIGUOUS"
            and self.replies["settlement-retry"]["result"] == "COMMITTED",
            "SETTLEMENT_INTERRUPTION",
        )
        require(
            self.replies["read-proof-as-execute"].get("reason") == "INVALID_SCHEMA",
            "READ_ONLY_AUTHORITY",
        )

    def resources(self, name, stats, samples):
        ticks = samples[-1]["cpu_ticks"] - samples[0]["cpu_ticks"]
        stats.update(
            service_cpu_seconds=ticks / samples[-1]["clock_ticks"],
            journal_start_bytes=samples[0]["db_bytes"],
            journal_end_bytes=samples[-1]["db_bytes"],
            journal_growth_bytes=samples[-1]["db_bytes"] - samples[0]["db_bytes"],
        )
        stats["peak_sampled_sqlite_sidecar_bytes"] = max(
            s["sqlite_sidecar_bytes"] for s in samples
        )
        stats["peak_sampled_database_bytes"] = max(s["db_bytes"] for s in samples)
        for key, limit in (
            ("peak_rss_kib", "max_service_rss_kib"),
            ("sampled_peak_threads", "max_service_threads"),
            ("sampled_peak_fds", "max_service_fds"),
            ("service_cpu_seconds", "max_service_cpu_seconds_per_wave"),
            ("seconds", "max_wall_seconds_per_wave"),
            ("peak_sampled_database_bytes", "max_database_bytes"),
        ):
            if stats[key] > self.budget[limit]:
                self.breaches.append([name, key, stats[key], self.budget[limit]])

    def performance(self):
        stats = {}
        for name in ("contention", "duplicates", "overload"):
            stats[name] = native_metrics(self.root / "native", name)
            wave_samples = load(self.root / "native" / (name + "-resources.json"))
            first, last = self.usage[name]
            self.resources(name, stats[name], [first, *wave_samples, last])
        for i in range(3):
            name = f"storm-{i}"
            with gzip.open(self.rec / (name + ".json.gz")) as stream:
                data = json.load(stream)
            times, counts = self.group(
                name,
                data,
                ["replacement", "cancel", "waiting"],
                ["COMMITTED", "NOT_COMMITTED", "UNRESOLVED"],
                True,
            )
            require(data["role"] == "alice", "STORM_PRINCIPAL")
            f = self.faults[name]
            require(
                f["stopped_pid"] != f["ready_pid"]
                and f["ready_ns"] < min(s for s, _ in times),
                "RESTART_BARRIER",
            )
            require(
                self.views[name]["ledger"] == self.views["before_storms"]["ledger"]
                and self.inventory[name] == self.inventory["before_storms"],
                "READ_EFFECT",
            )
            samples = self.usage[name]
            st = dict(
                **timing(times),
                workers=4,
                outcomes=dict(counts),
                unresolved=counts["UNRESOLVED"],
                unresolved_fraction=counts["UNRESOLVED"] / len(times),
                peak_rss_kib=max(s["peak_rss_kib"] for s in samples),
                sampled_peak_fds=max(s["fds"] for s in samples),
                sampled_peak_threads=max(s["threads"] for s in samples),
            )
            self.resources(name, st, samples)
            idle = self.usage[name + "-gate"]
            st["native_gate_cpu_seconds_during_reads"] = (
                idle[-1]["cpu_ticks"] - idle[0]["cpu_ticks"]
            ) / idle[0]["clock_ticks"]
            if any(s["db_bytes"] != samples[0]["db_bytes"] for s in samples):
                self.breaches.append(
                    [name, "journal_growth", st["journal_growth_bytes"], 0]
                )
            stats[name] = st
        self.metrics["measured_profiles"] = stats
        self.metrics["cumulative_profile_requests"] = sum(
            s["count"] for s in stats.values()
        )
        require(
            self.metrics["cumulative_profile_requests"] == 101002, "CUMULATIVE_VOLUME"
        )
        require(not self.breaches, "RESOURCE_BUDGET")

    def mutations(self):
        detected = {}

        def one(name, code, fn):
            try:
                fn()
            except (Mismatch, AdapterError) as exc:
                observed = exc.code if isinstance(exc, AdapterError) else str(exc)
                require(observed == code, "WRONG_MUTATION_DETECTOR")
                detected[name] = observed
                return
            raise Mismatch("MUTATION_SURVIVED")

        def record(label):
            e = self.events[label]
            q = e["queries"][0]
            g = e["groups"][0]
            return (
                g["proofs"][g["rows"][0][3]],
                q,
                self.pins[e["role"]],
                self.pins,
                self.by_digest[q["request_sha256"]],
                self.views["at-" + label],
                deepcopy(self.inventory["at-" + label]),
            )

        committed = record("replacement-after")
        other = record("late-after")
        one(
            "wrong original digest",
            "REQUEST_BINDING",
            lambda: audit_reply(committed[0], *other[1:]),
        )
        one(
            "cross-principal disclosure",
            "RECEIPT_AUTHORIZATION",
            lambda: audit_reply(*committed[:2], self.pins["bob"], *committed[3:]),
        )
        view = deepcopy(self.views["final"])
        view["ledger"].append(view["ledger"][-1])
        view["counter"] += 1
        view["committed_operations"] += 1
        one(
            "second effect on same operation",
            "ORACLE_LEDGER",
            lambda: checked_observation(view, self.native.profile, digest(view)),
        )
        revoked = record("cancel-revoked")
        revoked[-1]["revocations"].pop(revoked[4]["grant_id"])
        one(
            "negative without durable settlement",
            "NO_DURABLE_SETTLEMENT",
            lambda: audit_reply(*revoked),
        )
        one(
            "transport absence reported definitive",
            "AMBIGUITY_PROMOTED",
            lambda: audit_reply(
                {"outcome": "NOT_COMMITTED", "reason": "TRANSPORT"},
                *record("late-before")[1:],
            ),
        )
        self.metrics["detected_mutations"] = detected


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path)
    p.add_argument("--profile-sha256", required=True)
    p.add_argument("--reader-sha256", required=True)
    args = p.parse_args()
    report = {
        "PASS": [],
        "FAIL": [],
        "BLOCKED": ["HERCULES integration", "genuine Shirudo vTPM qualification"],
        "NOT_RUN": ["actual human approval"],
    }
    r = Review(args.directory, args.profile_sha256, args.reader_sha256)
    for name in (
        "inherited",
        "enrollments",
        "ledger",
        "outcomes",
        "performance",
        "mutations",
    ):
        try:
            getattr(r, name)()
        except (
            ValueError,
            KeyError,
            TypeError,
            AdapterError,
            OSError,
            IndexError,
        ) as exc:
            report["FAIL"].append([name, str(exc)])
        else:
            report["PASS"].append(name)
    print(
        json.dumps(
            dict(report, measurements=r.metrics, budget_exceedances=r.breaches),
            indent=2,
            sort_keys=True,
        )
    )
    return int(bool(report["FAIL"]))


if __name__ == "__main__":
    sys.exit(main())
