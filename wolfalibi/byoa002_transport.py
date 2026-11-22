"""Linux sender authentication for the second, gateway-originated synthetic read."""

import hashlib
import os
from pathlib import Path
import socket
import stat
import time

from alibi import canon, verify_sig
from . import education_transport as wire
from .education_records import validate_peer
from .stage3_evidence import _hex
from .voidcell002_probe import _fingerprint, _observe_open, _ordinary, _status


GATEWAY = Path(__file__).resolve().parents[1] / "scripts" / "byoa002_gateway.py"
PROFILE = wire.TransportProfile(
    label="BYOA002", wire_type="quorvane.byoa002.gateway-rpc.v1",
    actions=frozenset({"dispatch", "reconcile"}), caller_path=GATEWAY, peer_validator=validate_peer,
)
_INVENTORY_DOMAIN = b"quorvane/byoa002/private-file-inventory/v1"
_FILENAMES = {"target_key": "target.seed", "ledger": "ledger.sqlite"}
_DENIED = {"outcome": "DENIED", "reason": "UNENROLLED_LIVE_GATEWAY"}
_UNKNOWN = {"outcome": "UNKNOWN", "reason": "RECONCILE_ORIGINAL_DISPATCH"}


def _ordinary_peer(pid):
    status = _status(pid)
    if not _ordinary(status):
        raise ValueError("an ordinary unprivileged identity is required")
    return status


def measure_gateway(pid, socket_path):
    """Sample the actual fixed gateway interpreter, argv, source and kernel identity."""
    _ordinary_peer(pid)
    with wire._PinnedProcess(pid, profile=PROFILE, endpoint=os.fspath(socket_path)) as pinned:
        return pinned.current()


def _same_recovery_role(expected, sample):
    return all(sample[k] == v for k, v in expected.items() if k not in {"pid", "start_ticks"})


def _socket_request(channel, expected, path, target):
    from .voidcell002_transport import _credentials, _expect_eof, _peer_credentials, _recv

    submitted = False
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        channel.settimeout(wire.CONNECTION_TIMEOUT_SECONDS)
        deadline = time.monotonic() + wire.CONNECTION_TIMEOUT_SECONDS
        cred = _peer_credentials(channel)
        if cred[1:] != (expected["uid"], expected["gid"]):
            return dict(_DENIED)
        _ordinary_peer(cred[0])
        with wire._PinnedProcess(cred[0], profile=PROFILE, endpoint=os.fspath(path)) as pinned:
            measured = pinned.match_credentials(cred)
            if not _same_recovery_role(expected, measured):
                return dict(_DENIED)
            wire._safe_send(channel, wire._ready(PROFILE), close_write=False)
            data, ancillary, _ = _recv(channel)
            _credentials(ancillary, cred)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("local frame deadline elapsed")
            channel.settimeout(remaining)
            _expect_eof(channel)
            action, packet = wire._decode_request(data, profile=PROFILE)
            if action == "dispatch" and measured != expected:
                return dict(_DENIED)

            def live():
                _ordinary_peer(cred[0])
                pinned.match_credentials(cred)
                return True

            live()
            submitted = True
            method = target.dispatch if action == "dispatch" else target.reconcile
            result = method(packet, peer=dict(measured), live=live)
            live()
            return result
    except PermissionError:
        if not submitted:
            return {"outcome": "UNSUPPORTED", "reason": "required peer measurements unavailable"}
        return dict(_UNKNOWN)
    except (OSError, RuntimeError, ValueError, TypeError):
        if submitted:
            return dict(_UNKNOWN)
        return {"outcome": "DENIED", "reason": "LOCAL_PEER_OR_FRAME_REFUSED"}


def serve(target, socket_path, *, gateway_peer, on_ready=None, stop_event=None):
    """Serve canonical one-frame RPCs serially with bounded input size and timeouts.

    The owner supplies the enrolled gateway. A replacement with identical
    boot, credential, executable, argv and source pins may only reconcile.
    """
    from .voidcell002_transport import _endpoint_inventory

    wire._linux_controls()
    _ordinary_peer(os.getpid())
    expected = validate_peer(gateway_peer)
    path = Path(socket_path).absolute()
    directory = wire._endpoint_directory(path, expected["uid"])
    if os.path.lexists(path):
        raise FileExistsError("the socket path must be new")
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        listener.bind(str(path))
        identity = path.lstat()
        try:
            os.chmod(path, 0o666)
            _endpoint_inventory(directory, path.name)
            listener.listen(wire.LISTEN_BACKLOG)
            listener.settimeout(0.2)
            if on_ready is not None:
                on_ready()
            while stop_event is None or not stop_event.is_set():
                try:
                    channel, _ = listener.accept()
                except (InterruptedError, TimeoutError):
                    continue
                with channel:
                    result = _socket_request(channel, expected, path, target)
                    wire._safe_terminal(channel, result, profile=PROFILE)
        finally:
            try:
                item = path.lstat()
                if stat.S_ISSOCK(item.st_mode) and (item.st_dev, item.st_ino) == (identity.st_dev, identity.st_ino):
                    path.unlink()
            except FileNotFoundError:
                pass


def request(socket_path, action, packet, *, expected_target_pid, expected_target_uid):
    """One authenticated local request. Delivery ambiguity permits reconciliation only."""
    if action not in {"dispatch", "lose-reply", "reconcile"}:
        raise ValueError("unknown gateway action")
    if type(expected_target_uid) is not int or expected_target_uid <= 0:
        raise ValueError("supply a provisioned non-root target UID")
    try:
        with wire._PinnedProcess(expected_target_pid) as target:
            if target.current()["uid"] != expected_target_uid:
                return {"outcome": "DENIED", "reason": "UNEXPECTED_TARGET_IDENTITY"}
            with wire._open_client_session(socket_path, expected_target_pid=expected_target_pid, profile=PROFILE) as session:
                target.current()
                try:
                    session.send("dispatch" if action == "lose-reply" else action, packet)
                    if action == "lose-reply":
                        return dict(_UNKNOWN)
                    response = session.receive()
                    target.current()
                    return response
                except (OSError, RuntimeError):
                    return dict(_UNKNOWN)
    except wire._TerminalResult as exc:
        return exc.result
    except PermissionError:
        return {"outcome": "UNSUPPORTED", "reason": "required target measurements unavailable"}
    except (OSError, RuntimeError):
        return {"outcome": "BLOCKED", "reason": "pinned local target unavailable"}


def _object_info(entry):
    return {"dev": str(entry.st_dev), "ino": str(entry.st_ino), "uid": entry.st_uid,
            "mode": stat.S_IMODE(entry.st_mode)}


def make_inventory(key_path, ledger_path, target_signer, gateway_peer):
    """Owner signs the two actual private files and their immediate directory identities."""
    from .byoa_qualification_cli import _open_key
    from .voidcell002 import _private_directory

    gateway = validate_peer(gateway_peer)
    _ordinary_peer(os.getpid())
    files = {}
    for label, path in (("target_key", key_path), ("ledger", ledger_path)):
        path = Path(path).absolute()
        _private_directory(path.parent)
        directory, item = path.parent.lstat(), path.lstat()
        if (path != path.resolve(strict=True) or path.name != _FILENAMES[label]
                or not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
                or stat.S_IMODE(directory.st_mode) != 0o700 or not stat.S_ISREG(item.st_mode)
                or item.st_uid != os.geteuid() or item.st_nlink != 1 or stat.S_IMODE(item.st_mode) != 0o600):
            raise ValueError("private owner file inventory does not match the custody profile")
        if label == "target_key" and _open_key(path.parent, "target").pub != target_signer.pub:
            raise ValueError("inventory seed does not identify the target signing key")
        chain = [_object_info(parent.lstat()) for parent in reversed(path.parents)]
        files[label] = {"path": str(path), "directories": chain, "file": _object_info(item)}
    with wire._PinnedProcess(os.getpid()) as target:
        payload = {"type": "quorvane.byoa002.private-files.v1", "target": target.current(),
                   "gateway": gateway, "target_pub": target_signer.pub.hex(), "files": files}
    return {"payload": payload, "signature": target_signer.sign(_INVENTORY_DOMAIN, canon(payload)).hex()}


def _gateway_file_opens(record, label, target_uid):
    path = Path(record["path"])
    parents = list(reversed(path.parents))
    chain = record["directories"]
    if (not path.is_absolute() or ".." in path.parts or path.name != _FILENAMES[label]
            or len(parents) != len(chain) or chain[-1]["uid"] != target_uid or chain[-1]["mode"] != 0o700
            or record["file"]["uid"] != target_uid or record["file"]["mode"] != 0o600):
        raise ValueError("wrong inventory file scope")
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    try:
        anchor = parents[0]
        if _object_info(os.fstat(directory)) != chain[0]:
            raise ValueError("kernel root differs from inventory")
        for parent, expected in zip(parents[1:], chain[1:]):
            try:
                child = os.open(parent.name, flags, dir_fd=directory)
            except PermissionError:
                break
            os.close(directory)
            directory = child
            anchor = parent
            if _object_info(os.fstat(directory)) != expected:
                raise ValueError("kernel directory differs from inventory")
        identity = _fingerprint(os.fstat(directory))
        suffix = str(path.relative_to(anchor))
        rows = {}
        for operation, access in (("read", os.O_RDONLY), ("write", os.O_WRONLY)):
            rows[f"{label}.{operation}"] = {
                **_observe_open(directory, suffix, access),
                "pinned_ancestor": str(anchor), "requested_suffix": suffix,
            }
        if _fingerprint(os.fstat(directory)) != identity:
            raise ValueError("pinned directory changed during custody check")
        return rows
    finally:
        os.close(directory)


def custody(socket_path, *, expected_target_uid, expected_target_pid, target_pub, inventory):
    """Measure one split-role kernel exclusion. Never write or truncate either file."""
    if not expected_target_uid or os.geteuid() == expected_target_uid:
        return {"outcome": "UNSUPPORTED", "cross_uid_custody": "UNSUPPORTED",
                "reason": "requires two distinct ordinary non-root UIDs"}
    gateway_status = _ordinary_peer(os.getpid())
    owner_status = _ordinary_peer(expected_target_pid)
    key = _hex(target_pub, 32, "target public key")
    if type(inventory) is not dict or inventory.keys() != {"payload", "signature"}:
        raise ValueError("invalid signed owner inventory")
    payload = inventory["payload"]
    if (not verify_sig(key, _INVENTORY_DOMAIN, canon(payload), _hex(inventory["signature"], 64, "inventory signature"))
            or payload.keys() != {"type", "target", "gateway", "target_pub", "files"}
            or payload["type"] != "quorvane.byoa002.private-files.v1" or payload["target_pub"] != target_pub
            or payload["files"].keys() != _FILENAMES.keys()):
        raise ValueError("invalid signed owner inventory")
    if measure_gateway(os.getpid(), socket_path) != payload["gateway"]:
        raise ValueError("inventory does not specify this live gateway")
    with wire._PinnedProcess(expected_target_pid) as target:
        before = target.current()
        if before["uid"] != expected_target_uid or before != payload["target"]:
            raise ValueError("inventory does not specify the live owner process")
        checks = {}
        for label, record in payload["files"].items():
            checks.update(_gateway_file_opens(record, label, expected_target_uid))
        target.current()
        if (_ordinary_peer(os.getpid()) != gateway_status or
                _ordinary_peer(expected_target_pid) != owner_status):
            raise ValueError("process credentials changed during custody check")
    observed = all(row["outcome"] == "DENIED" for row in checks.values())
    return {"outcome": "OBSERVED" if observed else "BLOCKED", "file_opens": checks,
            "cross_uid_custody": "FOUR_FILE_OPENS_ONLY" if observed else "BLOCKED",
            "gateway": payload["gateway"], "target": before,
            "gateway_status": gateway_status, "owner_status": owner_status,
            "inventory_sha256": hashlib.sha256(canon(inventory)).hexdigest()}
