"""Within-host ABBA crossover of WT-SWARM-001 and Blackout supervisor sampling."""

from collections import Counter
from contextlib import ExitStack
from pathlib import Path
import argparse
import json
import tempfile

from research.wt_swarm.run import Run, save
from research.blackout.experiment import Experiment
from research.blackout.review import native_metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    with (
        tempfile.TemporaryDirectory(prefix="wt003-crossover-") as temp,
        ExitStack() as stack,
    ):
        lab = Experiment(Path(temp), out, stack)
        lab.setup()
        # Match Blackout's overload entry with five committed and one withheld.
        for i in range(5):
            req = lab.material(str(i))
            lab.submit(str(i), req)
            if lab.replies[str(i)].get("result") != "COMMITTED":
                raise RuntimeError("fixture settlement")
        withheld = lab.material("withheld", False)
        summary = []
        for i, variant in enumerate(("light", "blackout", "blackout", "light")):
            lab.out = out / f"{i}-{variant}"
            lab.out.mkdir()
            (Run.batch if variant == "light" else Experiment.batch)(
                lab, "overload", [withheld]
            )
            lab.snapshot("after")
            if lab.snapshots["after"]["counter"] != 5:
                raise RuntimeError("unexpected overload effect")
            first, last = lab.trace["overload"]
            stats = native_metrics(lab.out, "overload")
            stats["cpu_seconds"] = (last["cpu_ticks"] - first["cpu_ticks"]) / first[
                "clock_ticks"
            ]
            stats["gate_decisions"] = dict(
                Counter(
                    json.loads(line)["decision"]
                    for line in (lab.out / "overload-admission.jsonl")
                    .read_text()
                    .splitlines()
                )
            )
            stats["samples"] = len(
                json.loads((lab.out / "overload-resources.json").read_bytes())
            )
            save(lab.out / "usage.json", [first, last])
            summary.append(dict(variant=variant, **stats))
        save(out / "results.json", summary)


if __name__ == "__main__":
    main()
