"""ABBA read-only microprofile on the same live source row and identical request mix."""

import time
from contextlib import closing
from research.blackout.reader import database, observation
from research.schism.storage import attach, guard
from research.blackout.review import timing
from shirudo_adapter.model import digest


def matched(paths, pins, fixture, requests):
    bindings = [
        dict(
            gate_instance_id=pins["gate"],
            target_id=pins["target"],
            operation_id=r["operation_id"],
            request_sha256=digest(r),
            grant_id=r["grant"]["payload"]["grant_id"],
            grant_sha256=digest(r["grant"]),
            assessment_sha256=digest(r["assessment"]),
            challenge_sha256=r["grant"]["payload"]["action_challenge_sha256"],
        )
        for r in requests
    ]
    profile = dict(
        gate_public_key=fixture.identity["public_key"], policy=fixture.policy
    )
    result = []
    for variant in ("blackout", "schism", "schism", "blackout"):
        with closing(database(paths["target"])) as c:
            attach(c, paths, pins, "ro", "ro")
            c.execute("BEGIN")
            guard(c, paths, pins)
            c.rollback()
            # An unchanged database with a warm connection is the fast path
            # in Schism. Measure just the extra authoritative-floor work.
            checks = 0

            def floor(con, b):
                nonlocal checks
                start = time.thread_time_ns()
                guard(con, paths, pins, full=False)
                checks += time.thread_time_ns() - start

            raw = []
            start = time.thread_time_ns()
            for i in range(900):
                s = time.monotonic_ns()
                outcome = observation(
                    c, bindings[i % 3], profile, floor if variant == "schism" else None
                )[0]
                e = time.monotonic_ns()
                assert outcome == ("COMMITTED", "UNRESOLVED", "NOT_COMMITTED")[i % 3]
                raw.append((s, e))
            cpu = time.thread_time_ns() - start
        result.append(
            dict(
                variant=variant,
                timing=timing(raw),
                thread_cpu_ns=cpu,
                floor_cpu_ns=checks,
                raw=raw,
            )
        )
    return result
