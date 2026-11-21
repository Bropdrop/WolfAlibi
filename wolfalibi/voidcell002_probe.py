"""Ordinary local Linux permission checks for a separately provisioned target.

The probe requires operator-supplied process and path references. It never
reads key contents, opens process memory, changes permissions or writes to
the target ledger. A successful result only describes the measured fixture.
"""

import errno
import os
from pathlib import Path
import select
import socket
import stat
import sys


_CAPABILITIES = ("CapEff", "CapPrm", "CapAmb")
_ZERO_CAPS = {field: "0000000000000000" for field in _CAPABILITIES}
_STATUS_FIELDS = {"Uid", "Gid", *_CAPABILITIES}
_UNGRANTED_REASON = "INVALID_GATEWAY_DISPATCH"
_INVENTORY_DOMAIN = b"wolfalibi/voidcell002/private-inventory/v1"
_PERMISSION_FAILURES = (errno.EACCES, errno.EPERM)


def _linux():
    return sys.platform.startswith("linux")


def _status(pid):
    fields = {}
    with Path(f"/proc/{pid}/status").open(encoding="ascii", errors="replace") as stream:
        for line in stream:
            key, _, value = line.partition(":")
            if key in _STATUS_FIELDS:
                fields[key] = value.strip()
    if fields.keys() != _STATUS_FIELDS:
        raise ValueError("process credential fields unavailable")
    ids = {key: tuple(int(value, 10) for value in fields[key].split()) for key in ("Uid", "Gid")}
    if any(len(values) != 4 or any(not 0 <= value < 2**32 for value in values)
           for values in ids.values()):
        raise ValueError("invalid process credential fields")
    caps = {key: fields[key] for key in _CAPABILITIES}
    if any(len(value) != 16 or any(char not in "0123456789abcdef" for char in value)
           for value in caps.values()):
        raise ValueError("invalid process capability fields")
    return {**ids, "capabilities": caps}


def _result(outcome, reason, state, **observations):
    return {"outcome": outcome, "custody": outcome, "reason": reason, **state, **observations}


def preflight():
    """Report this process's credentials and the need for a second principal."""
    state = {
        "linux": _linux(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "gid": os.getgid() if hasattr(os, "getgid") else None,
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "egid": os.getegid() if hasattr(os, "getegid") else None,
        "capabilities": None,
    }
    if not state["linux"]:
        return _result("UNSUPPORTED", "Linux process credentials required", state)
    try:
        state["capabilities"] = _status("self")["capabilities"]
    except (OSError, ValueError):
        return _result("UNSUPPORTED", "caller capability fields unavailable", state)
    return _result("UNSUPPORTED", "separately provisioned target and authorized gateway required", state)


def _ordinary(status):
    return (
        len(set(status["Uid"])) == len(set(status["Gid"])) == 1
        and status["Uid"][0] > 0
        and status["Gid"][0] > 0
        and status["capabilities"] == _ZERO_CAPS
    )


def _fingerprint(entry):
    return entry.st_dev, entry.st_ino, entry.st_mode, entry.st_uid, entry.st_gid, entry.st_nlink


def _target_file(directory, name, target_uid):
    entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(entry.st_mode) or entry.st_uid != target_uid or entry.st_nlink != 1:
        raise ValueError("target file is not a target-owned regular file")
    return _fingerprint(entry)


def _open_denied(directory, name, access):
    try:
        fd = os.open(name, access | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
    except OSError as exc:
        if exc.errno not in _PERMISSION_FAILURES:
            raise
        return True
    os.close(fd)
    return False


def _check_inventory(inventory, target_pub, state, directory_entry):
    from alibi import canon, verify_sig
    from .stage3_evidence import _hex

    if (type(target_pub) is not bytes or len(target_pub) != 32
            or type(inventory) is not dict or inventory.keys() != {"payload", "signature"}):
        raise ValueError("target inventory and an independent target key are required")
    expected = {
        "type": "WOLFALIBI_VOIDCELL002_INVENTORY_V1", "pid": state["target_pid"],
        "target_uid": state["target_uid"], "gateway_uid": state["uid"],
        "state_device": str(directory_entry.st_dev), "state_inode": str(directory_entry.st_ino),
        "key_mode": 0o600, "ledger_mode": 0o600,
    }
    payload = canon(inventory["payload"])
    signature = _hex(inventory["signature"], 64, "target inventory signature")
    if payload != canon(expected) or not verify_sig(target_pub, _INVENTORY_DOMAIN, payload, signature):
        raise ValueError("target inventory does not match the pinned peer and state directory")


def _file_observations(state_dir, state, *, inventory, target_pub):
    target_uid = state["target_uid"]
    directory = os.open(state_dir, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        entry = os.fstat(directory)
        if entry.st_uid != target_uid or entry.st_mode & 0o022:
            raise ValueError("target state directory is not controlled by the target")
        names = ("target.key", "ledger.sqlite")
        try:
            before = tuple(_target_file(directory, name, target_uid) for name in names)
        except OSError as exc:
            if exc.errno not in _PERMISSION_FAILURES or stat.S_IMODE(entry.st_mode) != 0o700:
                raise
            _check_inventory(inventory, target_pub, state, entry)
            before = None
        observations = {
            "target_key_read_denied": _open_denied(directory, names[0], os.O_RDONLY),
            "ledger_write_denied": _open_denied(directory, names[1], os.O_WRONLY),
            "file_existence_basis": "OWNER_ATTESTED" if before is None else "INDEPENDENT_STAT",
        }
        if before is not None and tuple(_target_file(directory, name, target_uid) for name in names) != before:
            raise ValueError("target file changed during observation")
        if _fingerprint(os.stat(state_dir, follow_symlinks=False)) != _fingerprint(entry):
            raise ValueError("target state directory changed during observation")
        return observations
    finally:
        os.close(directory)


def probe(target_uid, *, target_pid, state_dir, socket_path, inventory=None, target_pub=None):
    """Measure ordinary file-open denials against the operator's pinned target.

    When a private directory hides file metadata, require a signed owner
    inventory and a separately supplied target public key for file existence.
    """
    state = {key: value for key, value in preflight().items() if key not in {"outcome", "custody", "reason"}}
    if not state["linux"] or not all((
            hasattr(os, "pidfd_open"), hasattr(os, "O_PATH"), hasattr(socket, "SO_PEERCRED"),
    )):
        return _result("UNSUPPORTED", "required Linux process and socket controls unavailable", state)
    if type(target_uid) is not int or not 0 <= target_uid < 2**32 - 1:
        return _result("BLOCKED", "expected target UID is unavailable", state)
    if target_uid == state["uid"] or target_uid == 0 or state["uid"] == 0:
        return _result("UNSUPPORTED", "distinct nonroot Linux UIDs are required", state)
    if type(target_pid) is not int or not 0 < target_pid < 2**31:
        return _result("BLOCKED", "expected target PID is unavailable", state)
    try:
        caller = _status("self")
    except (OSError, ValueError):
        return _result("BLOCKED", "caller credentials could not be established", state)
    if (not _ordinary(caller) or caller["Uid"][0] != state["uid"]
            or caller["Uid"][1] != state["euid"] or caller["Gid"][0] != state["gid"]
            or caller["Gid"][1] != state["egid"]):
        return _result("UNSUPPORTED", "caller does not have ordinary nonroot credentials", state)

    state["capabilities"] = caller["capabilities"]
    state.update(target_uid=target_uid, target_pid=target_pid)
    try:
        target = os.pidfd_open(target_pid)
    except OSError:
        return _result("BLOCKED", "expected target process unavailable", state)
    try:
        return _probe_live(target, state_dir, socket_path, state, caller,
                           inventory=inventory, target_pub=target_pub)
    finally:
        os.close(target)


def _probe_live(target, state_dir, socket_path, state, caller, *, inventory, target_pub):
    target_uid, target_pid = state["target_uid"], state["target_pid"]
    poller = select.poll()
    poller.register(target, select.POLLIN)
    try:
        before = _status(target_pid)
        endpoint = os.stat(socket_path, follow_symlinks=False)
    except (OSError, ValueError, TypeError):
        return _result("BLOCKED", "target credentials or endpoint could not be established", state)
    if (poller.poll(0) or not _ordinary(before) or before["Uid"][0] != target_uid
            or not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != target_uid):
        return _result("BLOCKED", "target process or endpoint differs from the custody requirements", state)

    try:
        from .voidcell002_transport import request

        response = request(socket_path, "dispatch", None, expected_target_uid=target_uid,
                           expected_target_pid=target_pid)
    except (ImportError, OSError, RuntimeError, ValueError, TypeError):
        return _result("BLOCKED", "peer-pinned no-grant request could not be checked", state)
    if (type(response) is not dict or response.get("outcome") != "DENIED"
            or response.get("reason") != _UNGRANTED_REASON or "receipt" in response):
        return _result("BLOCKED", "authorized peer denial of a no-grant request was not established", state)
    observations = {"peer_pinned": True, "ungranted_request_denied": True}

    try:
        observations.update(_file_observations(state_dir, state, inventory=inventory, target_pub=target_pub))
        if (_status(target_pid) != before or _status("self") != caller
                or _fingerprint(os.stat(socket_path, follow_symlinks=False)) != _fingerprint(endpoint)
                or poller.poll(0)):
            raise ValueError("credentials or endpoint changed during observation")
    except (ImportError, OSError, ValueError, TypeError, RecursionError):
        return _result("BLOCKED", "target file metadata or stable process references were unavailable",
                       state, observations=observations)
    if not observations["target_key_read_denied"] or not observations["ledger_write_denied"]:
        return _result("BLOCKED", "an ordinary file-open exclusion was not observed",
                       state, observations=observations)
    return _result("MEASURED_CANDIDATE", "ordinary principal exclusions observed for the pinned fixture",
                   state, target_gid=before["Gid"][0], target_capabilities=before["capabilities"],
                   observations=observations)
