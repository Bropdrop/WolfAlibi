"""Collect public outputs of the single-account decision fixture in a new directory."""
import json
from contextlib import closing
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_byoa002_custody import CustodyTests
from wolfalibi.byoa002_custody import inspect_history


def collect(directory):
    directory.mkdir(mode=0o700)
    CustodyTests.setUpClass()
    case = CustodyTests("test_detached_expectation")
    try:
        case.setUp()
        with case.open(journal=case.journal) as service:
            result = case.dispatch(service)
        if result["outcome"] != "RELEASED":
            raise ValueError(result)
        with case.open(journal=case.journal) as service:
            inquiry = case.recover(service)
        if (inquiry != {"outcome": "RECONCILED", "receipt": result["receipt"], "ack": result["ack"]}
                or case.count() != 1 or result["ack"]["payload"]["head"] != case.verifier.head()):
            raise ValueError("historical reconciliation disagrees with target or verifier")
        with closing(case.journal.connect()) as db:
            history = [json.loads(raw) for raw, in db.execute("SELECT record FROM history ORDER BY seq")]
        head = inspect_history(history, case.journal.enrollment, case.target_key.pub)
        documents = {"history": history, "expect": {"enrollment": case.journal.enrollment,
                     "public_key": case.target_key.pub.hex(), "head": head},
                     "decision": {"enrollment": case.enrollment, "dispatch": result, "inquiry": inquiry,
                                  "target_rows": case.count(), "verifier_head": case.verifier.head()}}
        for name, data in documents.items():
            (directory / (name + ".json")).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    finally:
        case.doCleanups()
        CustodyTests.doClassCleanups()


if __name__ == "__main__":
    collect(Path(sys.argv[1]))
