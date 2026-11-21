"""Point-in-time supervisor measurements for the fixed Linux worker."""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import re
import select
import stat
import time


RECORD_TYPE = "WOLFALIBI_STAGE35_PROC_SNAPSHOT_V1"
_NS = ("user", "mnt", "pid", "net", "ipc", "uts")
_CAPS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
_PROC = Path("/proc")
_PYTHON_FLAGS = ("-I", "-S", "-B", "-c")


class MeasurementBlocked(RuntimeError):
    """The supervisor could not substantiate the required worker observations."""


def _require(condition, reason):
    if not condition:
        raise MeasurementBlocked(reason)


def _shape(obj, fields):
    return type(obj) is dict and obj.keys() == set(fields.split())


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _identity_pair(value):
    return type(value) is list and len(value) == 2 and all(_integer(x) for x in value)


def _expected_mounts(profile):
    return {m["destination"]: m["source"] for m in profile["readonly_mounts"]}


def verify_measurement_record(record, contract):
    """Validate the signed record's claims against the pinned launch profile.

    This pure schema and consistency check relies on the supervisor for the
    reported measurements. Verify that supervisor's detached signature
    separately against a pinned key.
    """
    try:
        _validate_record(record, contract)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise MeasurementBlocked("invalid supervisor measurement record") from error


def _validate_record(record, contract):
    profile = contract["profile"]
    _require(_shape(record, "type identity executable credentials namespaces mounts descriptors "
                    "protected_root_visible cwd invocation"), "unexpected measurement fields")
    _require(record["type"] == RECORD_TYPE, "unsupported measurement type")
    _require(record["protected_root_visible"] is False and record["cwd"] == "/work",
             "worker root or working directory differs from the profile")

    identity = record["identity"]
    identity_numbers = ("launcher_pid", "launcher_start_ticks", "worker_pid",
                        "worker_start_ticks", "worker_parent_pid", "worker_namespace_pid")
    _require(_shape(identity, " ".join((*identity_numbers, "stability")))
             and all(_integer(identity[k], 1) for k in identity_numbers)
             and identity["stability"] == "procdir+pidfd"
             and identity["worker_namespace_pid"] == 1
             and identity["worker_pid"] != identity["launcher_pid"]
             and identity["worker_parent_pid"] == identity["launcher_pid"]
             and identity["worker_start_ticks"] >= identity["launcher_start_ticks"],
             "worker identity or launcher ancestry differs from the profile")

    executable = record["executable"]
    _require(_shape(executable, "path sha256 argv_source_sha256 flags")
             and executable["path"] == profile["python"]
             and executable["sha256"] == profile["python_sha256"]
             and executable["argv_source_sha256"] == profile["worker_sha256"]
             and executable["flags"] == list(_PYTHON_FLAGS),
             "observed executable or command line differs from the profile")
    invocation = record["invocation"]
    _require(_shape(invocation, "fixture_key run_id challenge canary_fd mode")
             and invocation["fixture_key"] == contract["key"]
             and invocation["run_id"] == contract["run_id"]
             and invocation["challenge"] == contract["challenge"]
             and _integer(invocation["canary_fd"], 64)
             and invocation["mode"] == "normal",
             "observed invocation differs from the run contract")

    creds = record["credentials"]
    _require(_shape(creds, "uid gid uid_map gid_map capabilities no_new_privs "
                    "groups seccomp_mode threads tracer_pid"), "unexpected credential fields")
    for name in ("uid", "gid"):
        ids, mapping = creds[name], creds[f"{name}_map"]
        _require(type(ids) is list and len(ids) == 4 and all(_integer(x) for x in ids)
                 and len(set(ids)) == 1 and type(mapping) is list and len(mapping) == 3
                 and all(_integer(x) for x in mapping) and mapping == [1000, ids[0], 1],
                 f"worker {name} mapping differs from the profile")
    caps = creds["capabilities"]
    _require(type(caps) is dict and caps.keys() == set(_CAPS)
             and all(_integer(v) and v == 0 for v in caps.values())
             and creds["groups"] == [] and type(creds["groups"]) is list
             and _integer(creds["no_new_privs"]) and creds["no_new_privs"] == 1
             and _integer(creds["threads"], 1) and creds["threads"] == 1
             and _integer(creds["tracer_pid"]) and creds["tracer_pid"] == 0
             and _integer(creds["seccomp_mode"]) and creds["seccomp_mode"] in (0, 1, 2),
             "worker privileges, threads or tracer differ from the profile")

    namespaces = record["namespaces"]
    _require(type(namespaces) is dict and namespaces.keys() == set(_NS),
             "namespace inventory differs from the profile")
    for name, observed in namespaces.items():
        _require(_shape(observed, "supervisor worker")
                 and all(type(v) is str and re.fullmatch(rf"{name}:\[\d+\]", v)
                         for v in observed.values())
                 and observed["supervisor"] != observed["worker"],
                 f"worker {name} namespace is not distinct")

    expected = _expected_mounts(profile)
    _require(type(record["mounts"]) is list and len(record["mounts"]) == len(expected) + 1,
             "unexpected number of worker mounts")
    seen = set()
    for mount in record["mounts"]:
        _require(_shape(mount, "destination fs_type flags private source "
                        "expected_identity observed_identity"), "unexpected mount fields")
        target, flags = mount["destination"], mount["flags"]
        _require(type(target) is str and target not in seen and type(flags) is list
                 and all(type(flag) is str for flag in flags)
                 and flags == sorted(set(flags))
                 and {"nosuid", "nodev"}.issubset(flags)
                 and mount["private"] is True and type(mount["fs_type"]) is str
                 and bool(mount["fs_type"]) and _identity_pair(mount["observed_identity"]),
                 "invalid mount record")
        seen.add(target)
        if target == "/":
            _require(mount["fs_type"] == "tmpfs" and mount["source"] is None
                     and mount["expected_identity"] is None
                     and "rw" in flags and "ro" not in flags, "worker root is not private tmpfs")
        else:
            _require(target in expected and mount["source"] == expected[target]
                     and _identity_pair(mount["expected_identity"])
                     and mount["expected_identity"] == mount["observed_identity"]
                     and "ro" in flags and "rw" not in flags,
                     "worker runtime mount identity or flags differ from the profile")
    _require(seen == set(expected) | {"/"}, "mount destinations differ from the profile")

    fds = record["descriptors"]
    _require(_shape(fds, "0 1 2"), "unexpected worker descriptors")
    endpoint = fds["0"]
    _require(_shape(endpoint, "kind inode expected_inode") and endpoint["kind"] == "socket"
             and _integer(endpoint["inode"], 1) and _integer(endpoint["expected_inode"], 1)
             and endpoint["inode"] == endpoint["expected_inode"],
             "worker descriptor 0 is not the per-run endpoint")
    for name in ("1", "2"):
        device = fds[name]
        _require(_shape(device, "kind major minor") and device["kind"] == "character_device"
                 and _integer(device["major"]) and _integer(device["minor"])
                 and [device["major"], device["minor"]] == [1, 3],
                 "worker output is not directed to the null device")


def _read_at(directory, filename, *, binary=False):
    fd = os.open(filename, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        data = stream.read()
    return data if binary else os.fsdecode(data)


def _process_fields(data):
    # The comm field can contain whitespace and right parentheses.
    fields = data.rsplit(")", 1)[1].split()
    return fields[0], int(fields[1]), int(fields[19])


def _children(parent):
    child_list = _PROC / str(parent) / "task" / str(parent) / "children"
    try:
        return [int(pid) for pid in child_list.read_text().split()]
    except FileNotFoundError:
        # Some kernels omit CONFIG_CHECKPOINT_RESTORE. Read minimal PPID
        # metadata from the supervisor's proc view on those hosts.
        pass
    children = []
    for entry in _PROC.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            _, ppid, _ = _process_fields(os.fsdecode((entry / "stat").read_bytes()))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if ppid == parent:
            children.append(int(entry.name))
    return children


def _open_proc(stack, pid):
    handle = os.pidfd_open(pid)
    stack.callback(os.close, handle)
    proc = os.open(_PROC / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    stack.callback(os.close, proc)
    return proc, handle


def _alive(handle):
    poller = select.poll()
    poller.register(handle, select.POLLIN)
    return not poller.poll(0)


def _proc_executable(directory, contract, protected_root, canary_fd):
    observed_path = os.readlink("exe", dir_fd=directory)
    hasher = hashlib.sha256()
    fd = os.open("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            hasher.update(block)
    argv = _read_at(directory, "cmdline", binary=True).split(b"\0")
    _require(len(argv) == 13 and argv[-1] == b"" and os.fsdecode(argv[0]) == observed_path,
             "worker command line has unexpected layout")
    fixture, key, run_id, challenge, descriptor, mode = map(os.fsdecode, argv[6:12])
    _require(fixture == str(Path(protected_root).resolve(strict=True) / contract["key"])
             and descriptor == str(canary_fd), "worker fixture path or canary argument changed")
    executable = {
        "path": observed_path, "sha256": hasher.hexdigest(),
        "flags": [os.fsdecode(flag) for flag in argv[1:5]],
        "argv_source_sha256": hashlib.sha256(argv[5]).hexdigest(),
    }
    return executable, {
        "fixture_key": key, "run_id": run_id, "challenge": challenge,
        "canary_fd": int(descriptor), "mode": mode,
    }


def _status(directory):
    return dict(line.split(":\t", 1) for line in _read_at(directory, "status").splitlines()
                if ":\t" in line)


def _credentials(directory, status):
    return {
        "uid": [int(i) for i in status["Uid"].split()],
        "gid": [int(i) for i in status["Gid"].split()],
        "uid_map": [int(i) for i in _read_at(directory, "uid_map").split()],
        "gid_map": [int(i) for i in _read_at(directory, "gid_map").split()],
        "groups": [int(i) for i in status["Groups"].split()],
        "capabilities": {name: int(status[name], 16) for name in _CAPS},
        "no_new_privs": int(status["NoNewPrivs"]), "seccomp_mode": int(status["Seccomp"]),
        "threads": int(status["Threads"]), "tracer_pid": int(status["TracerPid"]),
    }


def _mount_path(encoded):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), encoded)


def _stat_identity(stat_result):
    return [stat_result.st_dev, stat_result.st_ino]


def _mounts(directory, profile, root_fd):
    expected = _expected_mounts(profile)
    rows = []
    for line in _read_at(directory, "mountinfo").splitlines():
        lhs, rhs = line.split(" - ", 1)
        fields = lhs.split()
        target = _mount_path(fields[4])
        _require(target.startswith("/") and target in ({"/"} | set(expected)),
                 "unexpected mount destination in worker namespace")
        source = expected.get(target)
        rows.append({
            "destination": target, "fs_type": rhs.split()[0],
            "flags": sorted(fields[5].split(",")),
            "private": not any(f.startswith(("shared:", "master:", "propagate_from:"))
                               for f in fields[6:]),
            "source": source,
            "expected_identity": _stat_identity(os.stat(source)) if source else None,
            "observed_identity": _stat_identity(os.stat(target.lstrip("/") or ".", dir_fd=root_fd)),
        })
    return sorted(rows, key=lambda row: row["destination"])


def _descriptors(stack, directory, expected_inode):
    fd_dir = os.open("fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=directory)
    stack.callback(os.close, fd_dir)
    _require(set(os.listdir(fd_dir)) == {"0", "1", "2"}, "unexpected worker descriptors")
    result = {}
    for name in ("0", "1", "2"):
        entry = os.stat(name, dir_fd=fd_dir)
        if name == "0":
            _require(stat.S_ISSOCK(entry.st_mode), "worker endpoint is not a socket")
            result[name] = {"kind": "socket", "inode": entry.st_ino,
                            "expected_inode": expected_inode}
        else:
            _require(stat.S_ISCHR(entry.st_mode), "worker output is not a character device")
            result[name] = {"kind": "character_device", "major": os.major(entry.st_rdev),
                            "minor": os.minor(entry.st_rdev)}
    return result


def _protected_visible(root_fd, protected_root):
    relative = Path(protected_root).resolve(strict=True).relative_to("/")
    try:
        os.stat(relative, dir_fd=root_fd)
    except FileNotFoundError:
        return False
    return True


def measure_worker(proc, contract, worker_endpoint_inode, protected_root, *, canary_fd, deadline):
    """Observe the single waiting worker from the trusted supervisor.

    A proc directory plus a live pidfd protect the copy from numeric PID
    substitution. The worker protocol must keep it waiting for the entire
    measurement. This snapshot does not cover other instants or attest the
    provenance of the interpreter's command-line source.
    """
    _require(hasattr(os, "pidfd_open"), "Linux pidfd_open is unavailable")
    try:
        profile = contract["profile"]
        _require(time.monotonic() < deadline, "worker measurement deadline expired")
        with ExitStack() as stack:
            launcher_dir, launcher_handle = _open_proc(stack, proc.pid)
            _require(_alive(launcher_handle), "worker launcher already exited")
            launcher_identity = _process_fields(_read_at(launcher_dir, "stat"))[1:]
            _require(launcher_identity[0] == os.getpid(), "unrelated worker launcher")
            candidates = _children(proc.pid)
            _require(len(candidates) == 1, "worker launcher has no unique direct child")
            worker_pid = candidates[0]
            worker_dir, worker_handle = _open_proc(stack, worker_pid)
            _require(_alive(worker_handle), "worker exited before measurement")
            worker_identity = _process_fields(_read_at(worker_dir, "stat"))[1:]
            status = _status(worker_dir)
            nspid = [int(n) for n in status["NSpid"].split()]
            _require(nspid == [worker_pid, 1], "worker is not the init of the new PID namespace")
            root_fd = os.open("root", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
                              dir_fd=worker_dir)
            stack.callback(os.close, root_fd)
            executable, invocation = _proc_executable(worker_dir, contract, protected_root,
                                                      canary_fd)
            record = {
                "type": RECORD_TYPE,
                "identity": {
                    "launcher_pid": proc.pid, "launcher_start_ticks": launcher_identity[1],
                    "worker_pid": worker_pid, "worker_start_ticks": worker_identity[1],
                    "worker_parent_pid": worker_identity[0], "worker_namespace_pid": nspid[-1],
                    "stability": "procdir+pidfd",
                },
                "executable": executable,
                "invocation": invocation,
                "credentials": _credentials(worker_dir, status),
                "namespaces": {
                    name: {
                        "supervisor": os.readlink(_PROC / "self" / "ns" / name),
                        "worker": os.readlink(f"ns/{name}", dir_fd=worker_dir),
                    }
                    for name in _NS
                },
                "mounts": _mounts(worker_dir, profile, root_fd),
                "descriptors": _descriptors(stack, worker_dir, worker_endpoint_inode),
                "protected_root_visible": _protected_visible(root_fd, protected_root),
                "cwd": os.readlink("cwd", dir_fd=worker_dir),
            }
            _require(_children(proc.pid) == [worker_pid] and not _children(worker_pid)
                     and _process_fields(_read_at(launcher_dir, "stat"))[1:] == launcher_identity
                     and _process_fields(_read_at(worker_dir, "stat"))[1:] == worker_identity
                     and _alive(launcher_handle) and _alive(worker_handle),
                     "worker process identity or ancestry changed during measurement")
            _require(time.monotonic() < deadline, "worker measurement deadline expired")
            verify_measurement_record(record, contract)
            return record
    except (OSError, AttributeError, IndexError, KeyError, TypeError, ValueError) as error:
        raise MeasurementBlocked(f"worker proc measurements unavailable: {error}") from error
