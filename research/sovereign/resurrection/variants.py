"""Replay eight disposable faulty output behaviors through the complete semantic auditor.

Archive checksum checks are deliberately external to this test: the signed inputs
stay intact and the independent semantic check must reject the resulting history.
"""

from pathlib import Path
import json, tempfile
from research.sovereign.review import load
from research.sovereign.resurrection.verify import semantic
from research.wt_swarm.review import Mismatch
from shirudo_adapter.model import AdapterError


def replay(root):
    files = (
        "enrollment",
        "commission",
        "resurrection",
        "oracle",
        "materials",
        "quorum-audit",
        "auditor",
        "activations",
        "historical",
        "faults",
        "replies",
    )
    cases = {
        "automatic activation": "RECONCILIATION_REQUIRED",
        "stale epoch": "ACTIVATION_CAS",
        "missing incarnation fence": "STALE_INCARNATION",
        "restored state": "RESTORED_STATE",
        "duplicate settlement": "DUPLICATE_SETTLEMENT",
        "false exclusion": "FALSE_OUTCOME",
        "receipt substitution": "ORIGINAL_RECEIPT",
        "ignored offline revocation": "REVOKED_SET",
    }
    semantic(root)
    result = {}
    with tempfile.TemporaryDirectory() as t:
        for case, reason in cases.items():
            altered = Path(t) / case
            altered.mkdir()
            docs = {n: load(root, n) for n in files}
            jumps = docs["activations"]
            archive = docs["historical"]
            journal = docs["oracle"]
            faults = docs["faults"]
            if case == "automatic activation":
                jumps[-1]["result"]["events"] = ["RECOVERING", "ACTIVE"]
            elif case == "stale epoch":
                jumps[-1]["auth"] = jumps[0]["auth"]
            elif case == "missing incarnation fence":
                faults["retired-second"] = docs["replies"]["fresh"]
            elif case == "restored state":
                jumps[-1]["before_seal"] = jumps[0]["before_seal"]
            elif case == "duplicate settlement":
                seq = journal["counter"][0]["value"] + 1
                journal["settlements"].append(dict(journal["settlements"][0], seq=seq))
                journal["counter"][0]["value"] = seq
            elif case == "false exclusion":
                archive["alice/uncertain"] = dict(state="NOT_COMMITTED")
            elif case == "receipt substitution":
                archive["alice/lost"] = archive["alice/new-lost"]
            else:
                journal["revoked_grants"] = jumps[0]["before"]["revoked_grants"]
            for k, v in docs.items():
                (altered / (k + ".json")).write_text(json.dumps(v))
            try:
                semantic(altered)
            except (Mismatch, AdapterError, KeyError) as exc:
                actual = getattr(exc, "code", str(exc))
                # Responses from retired actors must be explicitly denied.
                if actual != reason:
                    raise AssertionError((case, actual, reason))
                result[case] = actual
            else:
                raise AssertionError("accepted " + case)
    return result
