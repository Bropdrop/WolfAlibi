"""Offline qualification from public artifacts and an explicitly retained custody hash."""

import argparse, gzip, hashlib, json
from collections import Counter
from pathlib import Path
from research.sovereign.review import load, outcome
from research.sovereign.resurrection.audit import chain, history
from research.wt_swarm.review import require
from shirudo_adapter.model import digest
from shirudo_adapter.receipt import verify_record

PHASES = ["RECOVERING", "STATE_VERIFIED", "AUTHORITY_RECONCILED", "ACTIVE"]
LIMIT = json.loads(Path(__file__).with_name("budgets.json").read_bytes())
PINNED = (
    "commission",
    "enrollment",
    "observer-pins",
    "auditor",
    "resurrection",
    "activations",
    "faults",
    "historical",
)


def anchors(root):
    return {
        name: hashlib.sha256((root / (name + ".json")).read_bytes()).hexdigest()
        for name in PINNED
    }


def transition(events, auth, current_boot, epoch, observed, seal, actual):
    require(events == PHASES, "RECONCILIATION_REQUIRED")
    require(auth["epoch"] == epoch, "STALE_EPOCH")
    require(auth["boot"] == current_boot, "INCARNATION")
    require(auth["snapshot"] == digest(observed) and seal == actual, "RESTORED_STATE")


def retained(replies, expected, receipt):
    require(replies["state"] == expected, "FALSE_OUTCOME")
    require(replies.get("receipt") == receipt, "ORIGINAL_RECEIPT")


def revocations(j, required):
    require({r["id"] for r in j["revoked_grants"]} == required, "OFFLINE_REVOCATION")


def semantic(root):
    e = load(root, "enrollment")
    commission = load(root, "commission")
    context = load(root, "resurrection")
    pin = context["pin"]
    public = context["public"]
    records = context["records"]
    require(
        pin == commission["pin"]
        and public == commission["public"]
        and pin["enrollment"] == digest(e),
        "CUSTODY",
    )
    j = load(root, "oracle")
    m = load(root, "materials")
    copies = load(root, "quorum-audit")
    require(len(copies) == 3 and all(v == copies[0] for v in copies), "QUORUM")
    orders = copies[0]
    audit = load(root, "auditor")
    summary, expected, receipts = history(
        **context, enrollment=e, materials=m, journal=j, commands=orders
    )
    require(
        summary["effects"] == audit["effects"] == 3
        and audit["witness_head"] == digest(records[-1])
        and audit["durable_seal"] == records[-1]["payload"]["seal"],
        "DURABLE_OBSERVATION",
    )
    initial = commission["initial"]
    wave = load(root, "activations")
    require(len(wave) == 2 and initial == wave[0]["before"], "COMMISSION_SNAPSHOT")
    proof = commission["proof"]
    outcome(
        proof,
        "lost",
        m["lost"]["binding"],
        "COMMITTED",
        receipts["lost"],
        pin["origin"],
    )
    byhash = {digest(r): i for i, r in enumerate(records)}
    mutations = [r for r in records if r["payload"]["auth"]]
    require(len(mutations) == len(wave), "ACTIVATION_COUNT")
    budget_fail = []
    for jump, reservation in zip(wave, mutations):
        cert = jump["auth"]
        a = verify_record(cert, pin["owner"])
        cut = byhash[a["parent"]] + 1
        require(
            reservation == jump["result"]["anchor"]
            and reservation["payload"]["auth"] == cert
            and reservation["payload"]["version"] == cut,
            "ACTIVATION_CAS",
        )
        before = jump["before"]
        ids = {row["id"] for row in before["operations"]}
        materials = {
            k: v for k, v in m.items() if v["frame"]["request"]["operation_id"] in ids
        }
        history(
            pin, public, records[:cut], e, materials, before, orders[: a["first"] - 1]
        )
        # The signed reservation preceding this activation names the verified
        # floor. The fixture kept the protected writer locked during transition.
        transition(
            jump["result"]["events"],
            a,
            reservation["payload"]["boot"],
            orders[a["last"] - 1]["payload"]["epoch"],
            before,
            records[cut - 1]["payload"]["seal"],
            jump["before_seal"],
        )
        for row in before["operations"]:
            if row["receipt"]:
                final = next(r for r in j["operations"] if r["id"] == row["id"])
                require(
                    final["receipt"] == row["receipt"]
                    and final["request"] == row["request"],
                    "ORIGINAL_BYTES",
                )
        if jump["cold_ns"] / 1e9 > LIMIT["cold_start_seconds"]:
            budget_fail.append("cold_start_seconds")
    revoked = {
        doc["payload"]["revoked"]
        for doc in orders
        if doc["payload"]["kind"] == "revoke"
    }
    revocations(j, revoked)
    h = load(root, "historical")
    f = load(root, "faults")
    responses = load(root, "replies")
    for name in ("lost", "new-lost", "crash", "revoked", "uncertain"):
        retained(h["alice/" + name], expected[name], receipts.get(name))
    require(
        h["bob/new-lost"] == dict(state="UNRESOLVED")
        and responses["outsider"] == dict(state="UNRESOLVED", reason="ACCESS_DENIED"),
        "DISCLOSURE",
    )
    require(
        f["leader-downtime"][0] != f["leader-downtime"][1]
        and f["partition"].get("reason") == "QUORUM_UNAVAILABLE"
        and f["replayed-activation"]["state"] == "RECOVERY_UNRESOLVED",
        "AUTHORITY_FAILURE",
    )
    for k, code in (
        ("concurrent", "WRITER_HELD"),
        ("cloned-credentials", "VOLUME_IDENTITY"),
        ("outdated-epoch", "TARGET_ROLLBACK"),
        ("missing-settlement", "TARGET_ROLLBACK"),
        ("reservation-gap", "TARGET_ROLLBACK"),
        ("missing-volume", "STORAGE_UNAVAILABLE"),
        ("all-unavailable", "STORAGE_UNAVAILABLE"),
        ("witness-unavailable", "WITNESS_UNAVAILABLE"),
    ):
        require(
            f[k] == dict(startup="RECOVERY_UNRESOLVED", reason=code), "UNSAFE_RESTART"
        )
    chain(pin, public, records + [f["unsettled-intent"]])
    require(
        f["unsettled-intent"]["payload"]["seal"] != audit["durable_seal"]
        and expected["uncertain"] == "UNRESOLVED",
        "INTENT_IS_NOT_RECEIPT",
    )
    require(
        all(f[k]["state"] == "DENIED" for k in ("retired-first", "retired-second")),
        "STALE_INCARNATION",
    )
    return summary, expected, receipts, budget_fail


def measured(root, expect, receipts, failures):
    w = load(root, "overlap")
    rows = w["rows"]
    samples = [w["resources"], load(root, "storm")["resources"]]
    require(
        len({r[0] for r in rows}) == len(rows) == LIMIT["attempts"]
        and max(r[1] for r in rows) <= min(r[2] for r in rows),
        "WORKER_OVERLAP",
    )
    outcomes = Counter(r[3] for r in rows)
    require(
        outcomes == w["outcomes"]
        and outcomes["RECOVERY_CLOSED"] > 0
        and set(outcomes) <= {"RECOVERY_CLOSED", "NO_ACK"},
        "PREMATURE_EFFECT",
    )
    delays = []
    tally = Counter()
    boot = load(root, "resurrection")["records"][-1]["payload"]["boot"]
    m = load(root, "materials")
    for i in range(LIMIT["sessions"]):
        docs = load(root, f"proofs-{i}")
        checked = set()
        with gzip.open(root / f"lane-{i}.json.gz", "rt") as f:
            raw = json.load(f)
        require(len(raw) == LIMIT["queries_per_session"], "VOLUME")
        for n, (start, end, name, h) in enumerate(raw):
            require(
                name == ("new-lost", "revoked", "crash")[(i + n) % 3] and end >= start,
                "QUERY_BINDING",
            )
            if (h, name) not in checked:
                require(digest(docs[h]) == h, "RESPONSE_HASH")
                outcome(
                    docs[h],
                    name,
                    m[name]["binding"],
                    expect[name],
                    receipts.get(name),
                    boot,
                )
                checked.add((h, name))
            delays.append(end - start)
            tally[expect[name]] += 1
    metrics = []
    for before, after in samples:
        wall = (after["ns"] - before["ns"]) / 1e9
        cpu = after["target"]["cpu"] - before["target"]["cpu"]
        for name, value in (
            ("per_wave_wall_seconds", wall),
            ("target_cpu_seconds_per_wave", cpu),
            ("target_peak_rss_kib", after["target"]["rss_kib"]),
            ("target_storage_bytes", after["target_bytes"]),
            ("per_member_storage_bytes", max(after["member_bytes"])),
        ):
            if value > LIMIT[name]:
                failures.append(name)
        metrics.append(
            dict(
                seconds=wall,
                target_cpu_s=cpu,
                rss_kib=after["target"]["rss_kib"],
                journal_growth_bytes=after["target_bytes"] - before["target_bytes"],
            )
        )
    delays.sort()
    return dict(
        peak_overlapping=1000,
        attempts=dict(outcomes),
        queries=len(delays),
        responses=dict(tally),
        recovery_qps=len(delays) / metrics[1]["seconds"],
        query_ms={
            f"p{q}": delays[(len(delays) - 1) * q // 100] / 1e6 for q in (50, 95, 99)
        },
        waves=metrics,
    )


def verify(root, trust):
    require(anchors(root) == trust, "EXTERNAL_PINS")
    for n, h in load(root, "observer-pins").items():
        require(
            hashlib.sha256((root / (n + ".json")).read_bytes()).hexdigest() == h,
            "OBSERVER_PINS",
        )
    summary, expect, receipts, failures = semantic(root)
    perf = measured(root, expect, receipts, failures)
    from research.sovereign.resurrection.controls import controls

    jumps = load(root, "activations")
    return dict(
        status="FAIL" if failures else "PASS",
        budget_failures=failures,
        **summary,
        **perf,
        mutations=controls(root),
        cold_ms=[x["cold_ns"] / 1e6 for x in jumps],
        reconcile_ms=[x["result"]["ns"] / 1e6 for x in jumps],
        unavailable_ms=[x["unavailable_ns"] / 1e6 for x in jumps],
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("output", type=Path)
    p.add_argument("custody_pins", type=Path)
    a = p.parse_args()
    print(
        json.dumps(
            verify(a.output, json.loads(a.custody_pins.read_bytes())),
            sort_keys=True,
            indent=2,
        )
    )
