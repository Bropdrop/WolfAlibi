"""Public negative controls. A faulty exporter can produce fresh, correctly signed transfers."""

from copy import deepcopy
from shirudo_adapter.model import AdapterError, digest
from shirudo_adapter.receipt import sign_record
from research.continuity.history import verify


def omissions(roots, package, observer):
    controls = {}

    def exercise(label, change):
        r, p = deepcopy(roots), deepcopy(package)
        change(r, p["journal"])
        old = p["checkpoint"]["payload"]
        p["checkpoint"] = sign_record(observer, dict(old, journal=digest(p["journal"])))
        r["checkpoint_sha256"] = digest(p["checkpoint"])
        try:
            verify(r, p)
        except (ValueError, AdapterError, KeyError) as exc:
            controls[label] = getattr(exc, "code", str(exc))
        else:
            raise AssertionError("accepted " + label)

    exercise(
        "historical identity replaced",
        lambda r, j: r["enrollment"].update(gate="0" * 32),
    )
    exercise(
        "unauthorized native signing key",
        lambda r, j: r["enrollment"].update(key="0" * 64),
    )
    exercise(
        "target substitution", lambda r, j: r["source"].update(target="other-counter")
    )

    def delayed_effect(r, j):
        event = next(e for e in j["events"] if e["kind"] == "effect")
        j["events"].remove(event)
        j["events"].append(event)
        for i, e in enumerate(j["events"], 1):
            e["seq"] = i

    exercise("valid signature under wrong epoch", delayed_effect)
    exercise(
        "forked transition",
        lambda r, j: j["events"][0]["record"]["payload"].update(previous="1" * 64),
    )
    exercise("retirement missing", lambda r, j: j["events"].pop())
    exercise(
        "retirement authorization altered",
        lambda r, j: j["events"][-1]["record"]["payload"]["authorization"][
            "payload"
        ].update(destination="0" * 64),
    )
    exercise("destination identity missing", lambda r, j: r.update(destination=None))
    exercise("revocation omitted", lambda r, j: j["revocations"].clear())
    exercise(
        "consumption omitted",
        lambda r, j: next(x for x in j["rows"] if x["status"] == "COMMITTED").update(
            grant_id=None
        ),
    )
    exercise(
        "receipt replaced",
        lambda r, j: next(x for x in j["rows"] if x["status"] == "COMMITTED").update(
            receipt="{}"
        ),
    )
    exercise("duplicate settlement", lambda r, j: j["rows"].append(j["rows"][0]))
    return controls
