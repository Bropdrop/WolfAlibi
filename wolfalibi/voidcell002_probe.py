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
_INVENTORY_V2_DOMAIN = b"wolfalibi/voidcell002/private-inventory/v2"
_INVENTORY_V1_TYPE = "WOLFALIBI_VOIDCELL002_INVENTORY_V1"
_INVENTORY_V2_TYPE = "WOLFALIBI_VOIDCELL002_INVENTORY_V2"
_PERMISSION_FAILURES = (errno.EACCES, errno.EPERM)
_ACCESS_TRIALS = (
    ("target_key", "target.key", "read", os.O_RDONLY),
    ("target_key", "target.key", "write", os.O_WRONLY),
    ("ledger", "ledger.sqlite", "read", os.O_RDONLY),
    ("ledger", "ledger.sqlite", "write", os.O_WRONLY),
)


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


def _start_ticks(pid):
    with Path(f"/proc/{pid}/stat").open(encoding="ascii", errors="replace") as stream:
        # The process name can contain spaces and right parentheses.
        _, delimiter, fields = stream.read(65_536).rpartition(")")
    fields = fields.split()
    if not delimiter or len(fields) < 20 or not _unsigned_decimal(fields[19]):
        raise ValueError("target process start time unavailable")
    return fields[19]


def _unsigned_decimal(value):
    return (type(value) is str and 1 <= len(value) <= 20 and value.isascii() and value.isdecimal()
            and str(int(value)) == value and int(value) < 2**64)


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


def _observe_open(directory, name, access):
    try:
        fd = os.open(name, access | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
    except OSError as exc:
        if exc.errno not in _PERMISSION_FAILURES:
            raise
        return {"outcome": "DENIED", "errno": errno.errorcode[exc.errno]}
    os.close(fd)
    return {"outcome": "OPENED", "errno": None}


def _check_inventory(inventory, target_pub, state, directory_entry):
    from alibi import canon, verify_sig
    from .stage3_evidence import _hex

    if (type(target_pub) is not bytes or len(target_pub) != 32
            or type(inventory) is not dict or inventory.keys() != {"payload", "signature"}):
        raise ValueError("target inventory and an independent target key are required")
    expected = {
        "type": _INVENTORY_V1_TYPE, "pid": state["target_pid"],
        "target_uid": state["target_uid"], "gateway_uid": state["uid"],
        "state_device": str(directory_entry.st_dev), "state_inode": str(directory_entry.st_ino),
        "key_mode": 0o600, "ledger_mode": 0o600,
    }
    payload = inventory["payload"]
    if type(payload) is not dict:
        raise ValueError("invalid target inventory payload")
    domain = _INVENTORY_DOMAIN
    if payload.get("type") == _INVENTORY_V2_TYPE:
        refs = ("key_device", "key_inode", "ledger_device", "ledger_inode")
        values = [payload.get(name) for name in refs]
        if any(not _unsigned_decimal(value) for value in values) or values[1] == "0" or values[3] == "0":
            raise ValueError("invalid target inventory object identities")
        identities = {
            (expected["state_device"], expected["state_inode"]),
            tuple(values[:2]), tuple(values[2:]),
        }
        if len(identities) != 3:
            raise ValueError("target inventory object identities are aliased")
        started = state.get("target_start_ticks")
        if not _unsigned_decimal(started):
            raise ValueError("target process start time unavailable")
        expected.update(type=_INVENTORY_V2_TYPE, target_start_ticks=started, **dict(zip(refs, values)))
        domain = _INVENTORY_V2_DOMAIN
    if payload.keys() != expected.keys() or any(type(payload[name]) is not type(value)
                                                for name, value in expected.items()):
        raise ValueError("invalid target inventory payload")
    signature = _hex(inventory["signature"], 64, "target inventory signature")
    if payload != expected or not verify_sig(target_pub, domain, canon(expected), signature):
        raise ValueError("target inventory does not match the pinned peer and state directory")
    return expected


def _file_stat_pair(directory, target_uid):
    return (_target_file(directory, "target.key", target_uid),
            _target_file(directory, "ledger.sqlite", target_uid))


def _match_inventory_files(inventory, before):
    if inventory["type"] != _INVENTORY_V2_TYPE:
        return
    for name, entry in zip(("key", "ledger"), before):
        if ((inventory[f"{name}_device"], inventory[f"{name}_inode"]) != tuple(map(str, entry[:2]))
                or inventory[f"{name}_mode"] != stat.S_IMODE(entry[2])):
            raise ValueError("independently visible target files differ from the signed inventory")


def _file_observations(state_dir, state, *, inventory, target_pub):
    target_uid = state["target_uid"]
    directory = os.open(state_dir, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        entry = os.fstat(directory)
        if entry.st_uid != target_uid or entry.st_mode & 0o022:
            raise ValueError("target state directory is not controlled by the target")
        attested = _check_inventory(inventory, target_pub, state, entry) if inventory is not None else None
        try:
            before = _file_stat_pair(directory, target_uid)
        except OSError as exc:
            if (exc.errno not in _PERMISSION_FAILURES or stat.S_IMODE(entry.st_mode) != 0o700
                    or attested is None):
                raise
            before = None
        if before is not None:
            if before[0][:2] == before[1][:2]:
                raise ValueError("target files share the same object identity")
            if attested is not None:
                _match_inventory_files(attested, before)
        opened = {f"{object_name}_{access}": _observe_open(directory, filename, flags)
                  for object_name, filename, access, flags in _ACCESS_TRIALS}
        if before is not None and _file_stat_pair(directory, target_uid) != before:
            raise ValueError("target files changed during observation")
        if _fingerprint(os.stat(state_dir, follow_symlinks=False)) != _fingerprint(entry):
            raise ValueError("target state directory changed during observation")
        if before is not None:
            existence = identities = "INDEPENDENT_STAT"
        else:
            existence = "OWNER_ATTESTED"
            identities = ("OWNER_ATTESTED_DEVICE_INODE" if attested["type"] == _INVENTORY_V2_TYPE
                          else "OWNER_ATTESTED_DIRECTORY_ONLY")
        return {
            **{f"{trial}_denied": result["outcome"] == "DENIED" for trial, result in opened.items()},
            "file_open_results": opened,
            "file_open_scope": "ORDINARY_OPEN_WITHOUT_CREATE_OR_TRUNCATE",
            "file_existence_basis": existence, "file_identity_basis": identities,
        }
    finally:
        os.close(directory)


def probe(target_uid, *, target_pid, state_dir, socket_path, inventory=None, target_pub=None):
    """Measure ordinary read and write open denials for each pinned target file.

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
        state["target_start_ticks"] = _start_ticks(target_pid)
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
        if (_status(target_pid) != before or _start_ticks(target_pid) != state["target_start_ticks"]
                or _status("self") != caller
                or _fingerprint(os.stat(socket_path, follow_symlinks=False)) != _fingerprint(endpoint)
                or poller.poll(0)):
            raise ValueError("credentials or endpoint changed during observation")
    except (ImportError, OSError, ValueError, TypeError, RecursionError):
        return _result("BLOCKED", "target file metadata or stable process references were unavailable",
                       state, observations=observations)
    if not all(result["outcome"] == "DENIED" for result in observations["file_open_results"].values()):
        return _result("BLOCKED", "an ordinary file-open exclusion was not observed",
                       state, observations=observations)
    return _result("MEASURED_CANDIDATE", "ordinary principal exclusions observed for the pinned fixture",
                   state, target_gid=before["Gid"][0], target_capabilities=before["capabilities"],
                   observations=observations)
