"""Check a reviewer's local copy of a fictional financial envelope against the Lab 001 pins."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))

from scripts.finance_challenge import BASE_COMMIT, BASE_TREE, LABELS, MAX_BYTES, trusted_baseline


class CheckUnavailable(ValueError):
    """A diagnostic that contains no submitted fields or local paths."""


def _read_file(path):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise CheckUnavailable("supply one regular local evidence file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CheckUnavailable("input is not a regular file")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise CheckUnavailable("submitted envelope exceeds the byte limit")
    return data


def check(profile, path, *, root=ROOT):
    report = {"schema": "QUORVANE_SUBMITTED_RECEIPT_V1", "profile": profile,
              "pin_source": {"commit": BASE_COMMIT, "tree": BASE_TREE},
              "outcome": "BLOCKED", "settlement": "UNESTABLISHED",
              "operational_authority": "NOT_ISSUED", **LABELS}
    phase = "preflight"
    try:
        from scripts.finance_challenge_cases import observe

        trusted = trusted_baseline(root)
        control = trusted[profile]
        case = {"profile": profile, "mode": "verify", "input_kind": "evidence"}
        positive = observe(case, json.dumps(control["genuine"]).encode("utf-8"), trusted)
        details = positive.get("details", {})
        if (positive.get("outcome") != "VERIFIED" or details.get("canonical") != control["canonical"]
                or details.get("operational_authority") != "NOT_ISSUED" or details.get("settlement") != "UNESTABLISHED"):
            raise CheckUnavailable("the pinned genuine positive control did not verify")
        phase = "local_input"
        raw = _read_file(path)
        report["submitted_sha256"] = sha256(raw).hexdigest()
        phase = "verification"
        observation = observe(case, raw, trusted)
        outcome = observation["outcome"]
        if outcome == "UNEXPECTED_RESULT":
            return dict(report, outcome="REVIEW_REQUIRED", observation=observation)
        if outcome not in {"VERIFIED", "REJECTED", "INPUT_REFUSED"}:
            raise CheckUnavailable("unknown verification result")
        return dict(report, outcome=outcome, observation=observation)
    except Exception as exc:
        # Operational failure is a distinct exit status. Omit submitted data and private paths.
        return dict(report, phase=phase, error_type=type(exc).__name__,
                    reason=str(exc) if isinstance(exc, CheckUnavailable) else "the check could not complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=("finance", "history"))
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    report = check(args.profile, args.file)
    print(json.dumps(report, sort_keys=True, indent=2))
    return {"VERIFIED": 0, "INPUT_REFUSED": 1, "REJECTED": 1, "BLOCKED": 2, "REVIEW_REQUIRED": 3}[report["outcome"]]


if __name__ == "__main__":
    raise SystemExit(main())
