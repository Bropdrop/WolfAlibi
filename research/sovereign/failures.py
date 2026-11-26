"""Bounded failure schedules for a private local trial."""

import os
import shutil
import signal
import sqlite3
import subprocess
import time
from contextlib import closing
from research.sovereign.cluster import read, write, key, rpc


def backup(source, destination):
    with (
        closing(sqlite3.connect(source)) as src,
        closing(sqlite3.connect(destination)) as dst,
    ):
        src.backup(dst)


def exercise(lab):
    c = lab.c
    ids = [c.status(i)["header"]["member_id"] for i in range(3)]
    leader = ids.index(c.status(0)["leader"])
    os.kill(c.pids[leader], signal.SIGKILL)
    c.procs[leader].wait(6)
    survivors = [i for i in range(3) if i != leader]
    c.wait(survivors)
    new = c.status(survivors[0])["leader"]
    assert new != ids[leader]
    c.start(leader)
    deadline = time.monotonic() + 12
    while True:
        try:
            c.ctx.token = rpc(
                c.clients[leader],
                c.ctx,
                "auth/authenticate",
                dict(name="root", password=c.passwords["root"]),
            )["token"]
            break
        except (OSError, RuntimeError):
            if time.monotonic() > deadline:
                raise
            time.sleep(0.1)
    c.wait(survivors + [leader])
    lab.faults["leader-crash"] = [
        ids[leader],
        new,
        c.status(leader)["header"]["member_id"],
    ]
    for name, ctx in (("root", c.ctx), ("publisher", c.writer), ("auditor", c.auditor)):
        ctx.token = rpc(
            c.clients[leader],
            ctx,
            "auth/authenticate",
            dict(name=name, password=c.passwords[name]),
        )["token"]
    for h in "ab":
        lab.order(h)
    call = lambda: lab.call(
        "alice", dict(op="recover", binding=lab.ops["lost"]["binding"])
    )
    f = lab.state / "journal.sqlite3"
    tmp = lab.base / "present.sqlite3"
    backup(f, tmp)
    backup(lab.base / "early.sqlite3", f)
    try:
        rollback = call()
        assert rollback == dict(state="UNRESOLVED", reason="TARGET_ROLLBACK"), rollback
    finally:
        backup(tmp, f)
    lab.faults["restored"] = rollback
    hidden = lab.base / "offline.sqlite3"
    f.rename(hidden)
    try:
        offline = call()
        assert offline["state"] == "UNRESOLVED" and "receipt" not in offline, offline
    finally:
        hidden.rename(f)
    lab.faults["storage-offline"] = offline
    assert call()["receipt"] == lab.replies["retry"]["receipt"]
    clone = lab.base / "clone"
    shutil.copytree(lab.state, clone)
    args = [str(clone) if a == str(lab.state) else a for a in lab.target_args]
    result = subprocess.run(args, input=b"", capture_output=True, timeout=6)
    assert result.returncode and b"TARGET_RESTART_UNRESOLVED" in result.stderr, (
        result.stderr
    )
    lab.faults["clone"] = "TARGET_RESTART_UNRESOLVED"
    # Exercise loss of the quorum's recorded floor, independently and together
    # with local target rollback. This uses fixture administrator privileges.
    last = read(c.clients[0], c.auditor, lab.idx)
    rpc(c.clients[0], c.ctx, "kv/deleterange", dict(key=key(lab.idx)))
    try:
        floor = lab.call("coordinator", dict(op="sync"))
        assert floor == dict(state="DENIED", reason="AUTHORITY_FLOOR")
        backup(lab.base / "early.sqlite3", f)
        try:
            both = call()
            assert both == rollback
            refusal = lab.execute("lost", "b")
            assert refusal.get("reason") in (
                "TARGET_ROLLBACK",
                "AUTHORITY_FLOOR",
                "COMMAND_BINDING",
            ), refusal
        finally:
            backup(tmp, f)
        lab.faults["coordinated-rollback"] = dict(
            authority=floor, recovery=both, submission=refusal
        )
    finally:
        assert write(c.clients[0], c.writer, lab.idx, last)
    # Inserting an ineligible record in quorum can obstruct progress only.
    fake = dict(lab.proposal("a"), signature="0" * 128)
    assert write(c.clients[1], c.writer, lab.idx + 1, fake)
    denial = lab.call("coordinator", dict(op="sync"))
    assert denial["state"] == "DENIED", denial
    lab.faults["unsigned-succession"] = dict(command=fake, denial=denial)
