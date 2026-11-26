"""Compare historical archive profiles, a fresh baseline, Schism and the crossover."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from statistics import mean
import zipfile

from research.blackout.review import native_metrics
from research.wt_swarm.review import load, require

BLACKOUT = "42b03dba0381abdff1fd01fbaa1a913446671822b637748f56778821f4a07eb1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    root = parser.parse_args().evidence
    zpath = root / "inherited" / "WT-SWARM-002-evidence.zip"
    require(
        hashlib.sha256(zpath.read_bytes()).hexdigest() == BLACKOUT, "HISTORICAL_ARCHIVE"
    )
    profiles = {}
    with zipfile.ZipFile(zpath) as z:
        comparisons = json.loads(z.read("evidence/comparison.json"))["profiles"]
        for n in ("standalone", "repeat"):
            profiles["001-" + n] = comparisons["001-" + n]
            old = json.loads(z.read(f"evidence/{n}/qualification.json"))
            profiles["002-" + n] = old["measurements"]["measured_profiles"]
    new = {}
    for n, path in (
        ("002-reproduced", root / "inherited" / "live"),
        ("003-standalone", root / "standalone"),
        ("003-repeat", root / "repeat"),
    ):
        q = load(path / "qualification.json")
        require(not q["FAIL"], "PROFILE_QUALIFICATION")
        profiles[n] = q["measurements"]["measured_profiles"]
        if n.startswith("003"):
            new[n] = {
                k: load(path / "native" / (k + ".json"))
                for k in ("profile", "anchors", "reader")
            }
    a, b = new.values()
    for k in ("gate_public_key", "owner_public_key", "verifier_public_key"):
        require(a["profile"][k] != b["profile"][k], "FRESH_NATIVE_KEYS")
    require(
        set(a["anchors"]["pins"]["executors"]).isdisjoint(
            b["anchors"]["pins"]["executors"]
        )
        and a["anchors"]["pins"]["issuer"] != b["anchors"]["pins"]["issuer"]
        and set(a["reader"]["pins"].values()).isdisjoint(b["reader"]["pins"].values()),
        "FRESH_ROLE_KEYS",
    )
    crossover = []
    cross = root / "crossover"
    reported = load(cross / "results.json")
    budget = load(root / "standalone" / "budgets.json")
    for i, variant in enumerate(("light", "blackout", "blackout", "light")):
        run = cross / f"{i}-{variant}"
        stats = native_metrics(run, "overload")
        usage = load(run / "usage.json")
        row = dict(
            variant=variant,
            **stats,
            cpu_seconds=(usage[-1]["cpu_ticks"] - usage[0]["cpu_ticks"])
            / usage[0]["clock_ticks"],
        )
        row["gate_decisions"] = dict(
            Counter(
                json.loads(x)["decision"]
                for x in (run / "overload-admission.jsonl").read_text().splitlines()
            )
        )
        row["samples"] = len(load(run / "overload-resources.json"))
        require(
            row == reported[i]
            and row["count"] == sum(row["gate_decisions"].values()) == 10000
            and set(row["gate_decisions"]) == {"INVALID_SCHEMA", "SERVER_BUSY"}
            and load(run / "journal.json")["after"]["counter"] == 5,
            "CROSSOVER_RAW",
        )
        require(
            row["peak_rss_kib"] <= budget["max_service_rss_kib"]
            and row["sampled_peak_fds"] <= budget["max_service_fds"]
            and row["sampled_peak_threads"] <= budget["max_service_threads"]
            and row["cpu_seconds"] <= budget["max_service_cpu_seconds_per_wave"]
            and row["seconds"] <= budget["max_wall_seconds_per_wave"],
            "CROSSOVER_BUDGET",
        )
        crossover.append(row)
    means = {
        v: round(
            mean(r["requests_per_second"] for r in crossover if r["variant"] == v), 2
        )
        for v in ("light", "blackout")
    }
    print(
        json.dumps(
            dict(
                profiles=profiles,
                crossover=crossover,
                crossover_mean_attempts_per_second=means,
                independent_keys=True,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
