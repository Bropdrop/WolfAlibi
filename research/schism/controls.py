"""Disposable public-transcript models. Inputs are completed, already signed lab records.

These fixtures have no gate connection, private signing key or execution interface.
Each models the observable result of one weakened rule, using original wire replies
or signed effects wherever possible. The normal reviewer receives the resulting view.
"""

from shirudo_adapter.model import digest


def without_commit_fence(history, audit):
    # Complete the pending old-holder write after the replacement becomes effective.
    inflight = audit.bindings["inflight"]["operation_id"]
    pending = next(e for e in history if e["record"]["payload"].get("op") == inflight)
    history.remove(pending)
    transition = next(
        i
        for i, e in enumerate(history)
        if e["kind"] == "transition" and e["record"]["payload"]["epoch"] == 2
    )
    history.insert(transition + 1, pending)
    for index, event in enumerate(history, 1):
        event["seq"] = index
    return history


def unconditional_apply(name):
    def apply(actions, audit):
        proposal = actions[name]["record"]
        actions[name]["reply"] = {"status": "APPLIED", "record": digest(proposal)}
        return actions

    return apply


def execute_against_local_copy(name):
    def apply(replies, audit):
        # All three trials submit the same frozen operation. This policy answers
        # from its local accepted copy even when the independent floor is lost.
        replies[name] = replies["healed"].copy()
        return replies

    return apply


def settle_after_replacement(history, audit):
    last = next(e for e in reversed(history) if e["kind"] == "effect")
    history.append(dict(last, seq=len(history) + 1))
    return history


def variants():
    return [
        (
            "missing commit-time epoch fence",
            "history",
            without_commit_fence,
            "effects",
            "STALE_COMMIT",
        ),
        (
            "unauthenticated higher transition",
            "transitions",
            unconditional_apply("forged-higher"),
            "authority",
            "TRANSITION_AUTHENTICATION",
        ),
        (
            "rolled-back authority accepted",
            "replies",
            execute_against_local_copy("same-epoch-restore"),
            "schedules",
            "ROLLBACK_EXECUTION",
        ),
        (
            "coordinator self-promotion",
            "transitions",
            unconditional_apply("self-election"),
            "authority",
            "COORDINATOR_PROMOTION",
        ),
        (
            "cross-epoch grant replay",
            "transitions",
            unconditional_apply("rebind"),
            "authority",
            "CROSS_EPOCH_REPLAY",
        ),
        (
            "checkpoint outage permits execution",
            "replies",
            execute_against_local_copy("checkpoint-loss"),
            "schedules",
            "UNAVAILABLE_EFFECT",
        ),
        (
            "replacement settles twice",
            "history",
            settle_after_replacement,
            "effects",
            "DUPLICATE_SETTLEMENT",
        ),
    ]


def materialize(name, field, transform, audit):
    """Drive a fixed, in-memory decision fixture and export its observable history.

    The seven facts below are a completed schedule, not gate input. The fixture
    models a lookup or a write in an independent SQLite transaction. No fixture
    accepts paths, external requests, code, private keys or enrollment material.
    """
    import sqlite3
    from contextlib import closing
    from copy import deepcopy

    from shirudo_adapter.model import AdapterError
    from shirudo_adapter.receipt import verify_record

    holder = audit.store["transitions"][-1]["payload"]
    op = audit.bindings["duplicates"]["operation_id"]
    head = audit.checkpoints["final"]["local"]
    witness = audit.checkpoints["final"]["witness"][1]
    proposed = audit.transitions["winner"]["record"]
    local_epoch = holder["epoch"]
    source_epoch = local_epoch
    coordinator_claim = False
    checkpoint = witness
    expected_seal = head[2]
    rules = {
        "missing commit-time epoch fence": ("effect", "writer_epoch=current_epoch"),
        "unauthenticated higher transition": ("transition", "authenticated=1"),
        "rolled-back authority accepted": ("effect", "local_hash=checkpoint_hash"),
        "coordinator self-promotion": ("transition", "election=0 OR authenticated=1"),
        "cross-epoch grant replay": ("permit", "grant_epoch=current_epoch"),
        "checkpoint outage permits execution": (
            "effect",
            "checkpoint_hash IS NOT NULL",
        ),
        "replacement settles twice": (
            "effect",
            "NOT EXISTS (SELECT 1 FROM settled WHERE settled.op=inputs.op)",
        ),
    }
    kind, predicate = rules[name]
    if name == "missing commit-time epoch fence":
        local_epoch = audit.permits["inflight"]["payload"]["epoch"]
    elif name == "unauthenticated higher transition":
        proposed = audit.transitions["forged-higher"]["record"]
    elif name == "rolled-back authority accepted":
        restored = audit.checkpoints["at-same-epoch-restore"]
        expected_seal, checkpoint = restored["local"][2], restored["witness"][1]
    elif name == "coordinator self-promotion":
        proposed = audit.transitions["self-election"]["record"]
        coordinator_claim = audit.faults["claims"]["rival"]["claim"] == "LEADER"
    elif name == "cross-epoch grant replay":
        source_epoch = audit.permits["delayed"]["payload"]["epoch"]
    elif name == "checkpoint outage permits execution":
        checkpoint = audit.checkpoints["at-checkpoint-offline"]["control"]
    try:
        verify_record(proposed, audit.anchors["pins"]["issuer"])
        authenticated = True
    except AdapterError:
        authenticated = False
    with closing(sqlite3.connect(":memory:")) as c:
        c.execute(
            "CREATE TABLE inputs(op, writer_epoch, current_epoch, grant_epoch, authenticated, election, local_hash, checkpoint_hash)"
        )
        c.execute(
            "INSERT INTO inputs VALUES(?,?,?,?,?,?,?,?)",
            (
                op,
                local_epoch,
                holder["epoch"],
                source_epoch,
                authenticated,
                coordinator_claim,
                expected_seal,
                checkpoint,
            ),
        )
        c.execute("CREATE TABLE settled(op PRIMARY KEY)")
        c.executemany(
            "INSERT INTO settled VALUES(?)",
            ((r["operation_id"],) for r in audit.views["final"]["ledger"]),
        )
        c.execute("CREATE TABLE accepted(kind,trial)")
        for trial, condition in (("reference", predicate), ("weakened", "1")):
            c.execute(
                f"INSERT INTO accepted SELECT ?,? FROM inputs WHERE ({condition})",
                (kind, trial),
            )
            c.commit()
        if c.execute("SELECT kind,trial FROM accepted").fetchall() != [
            (kind, "weakened")
        ]:
            raise ValueError("mutation fixture did not distinguish the two behaviors")
    return transform(deepcopy(getattr(audit, field)), audit)
