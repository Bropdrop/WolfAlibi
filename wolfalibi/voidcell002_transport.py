"""Fixed local Unix transport for the synthetic VOIDCELL002 authority.

The endpoint accepts exactly one canonical request per connection. Kernel
credentials choose the narrow local role; they do not turn this experiment into
a production network transport or a substitute for signed authority records.
"""
from __future__ import annotations

from array import array
import os
from pathlib import Path
import socket
import stat
import struct
import time

from .voidcell_service import MAX_PACKET_BYTES, _canonical, _decode, _snapshot


MAX_FRAME_BYTES = 65_536
CONNECT_TIMEOUT_SECONDS = 2.0
CONNECTION_TIMEOUT_SECONDS = 2.0
_TYPE = "wolfalibi.voidcell002.local-transport.v1"
_ACTIONS = frozenset({"dispatch", "reconcile", "revoke", "status"})
_GATEWAY_ACTIONS = frozenset({"dispatch", "reconcile"})
_TARGET_ACTIONS = frozenset({"revoke", "status"})
_CREDENTIAL_SIZE = struct.calcsize("3i")
_INT_SIZE = array("i").itemsize
_ANCILLARY_SPACE = socket.CMSG_SPACE(_CREDENTIAL_SIZE) + socket.CMSG_SPACE(32 * _INT_SIZE)
_REJECTED = {"outcome": "BLOCKED", "reason": "VOIDCELL002_TRANSPORT_REJECTED"}
_UNAVAILABLE = {"outcome": "BLOCKED", "reason": "VOIDCELL002_TRANSPORT_UNAVAILABLE"}


class Voidcell002TransportError(RuntimeError):
    """The fixed local VOIDCELL002 endpoint cannot be used safely."""


def _close_rights(ancillary) -> None:
    """Close delivered rights before rejecting their unexpected control message."""
    for level, kind, value in ancillary:
        if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            continue
        descriptors = array("i")
        descriptors.frombytes(value[:len(value) - len(value) % _INT_SIZE])
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _credentials(ancillary, expected) -> None:
    if [(level, kind, len(value)) for level, kind, value in ancillary] != [
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, _CREDENTIAL_SIZE)]:
        raise Voidcell002TransportError("missing local credentials")
    pid, uid, gid = struct.unpack("3i", ancillary[0][2])
    if (pid, uid, gid) != expected:
        raise Voidcell002TransportError("local credentials differ from peer credentials")


def _peer_credentials(channel) -> tuple[int, int, int]:
    raw = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIAL_SIZE)
    if len(raw) != _CREDENTIAL_SIZE:
        raise Voidcell002TransportError("peer credentials are unavailable")
    return struct.unpack("3i", raw)


def _recv(channel) -> tuple[bytes, list, int]:
    data, ancillary, flags, _ = channel.recvmsg(
        MAX_FRAME_BYTES,
        _ANCILLARY_SPACE,
        socket.MSG_CMSG_CLOEXEC,
    )
    _close_rights(ancillary)
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise Voidcell002TransportError("truncated or ancillary transport frame")
    return data, ancillary, flags


def _decode_request(raw: bytes) -> tuple[str, object]:
    try:
        frame = _decode(raw, maximum=MAX_FRAME_BYTES)
    except Exception as exc:
        raise Voidcell002TransportError("invalid request frame") from exc
    if type(frame) is not dict or frozenset(frame) != {"type", "action", "packet"}:
        raise Voidcell002TransportError("invalid request frame")
    action, packet = frame["action"], frame["packet"]
    if type(action) is not str or action not in _ACTIONS:
        raise Voidcell002TransportError("unsupported request action")
    if action == "status" and packet is not None:
        raise Voidcell002TransportError("status accepts no packet")
    return action, packet


def _encode_request(action, packet) -> bytes:
    if type(action) is not str or action not in _ACTIONS:
        raise ValueError("unsupported VOIDCELL002 action")
    if action == "status" and packet is not None:
        raise ValueError("status accepts no packet")
    try:
        copied = _snapshot(packet, maximum=MAX_PACKET_BYTES)
        raw = _canonical({"type": _TYPE, "action": action, "packet": copied})
    except Exception as exc:
        raise ValueError("invalid VOIDCELL002 request") from exc
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError("VOIDCELL002 request exceeds the transport bound")
    return raw


def _encode_response(result: dict) -> bytes:
    try:
        copied = _snapshot(result, maximum=MAX_FRAME_BYTES // 2)
        if type(copied) is not dict:
            raise ValueError
        raw = _canonical({"type": _TYPE, "result": copied})
    except Exception:
        raw = _canonical({"type": _TYPE, "result": _REJECTED})
    if len(raw) > MAX_FRAME_BYTES:
        return _canonical({"type": _TYPE, "result": _REJECTED})
    return raw


def _decode_response(raw: bytes) -> dict:
    try:
        frame = _decode(raw, maximum=MAX_FRAME_BYTES)
    except Exception as exc:
        raise Voidcell002TransportError("invalid response frame") from exc
    if type(frame) is not dict or frozenset(frame) != {"type", "result"} or frame["type"] != _TYPE:
        raise Voidcell002TransportError("invalid response frame")
    if type(frame["result"]) is not dict:
        raise Voidcell002TransportError("invalid response result")
    return frame["result"]


def _expect_eof(channel) -> None:
    data, ancillary, _ = _recv(channel)
    if data or ancillary:
        raise Voidcell002TransportError("connection carried more than one frame")


def _directory(path: Path) -> tuple[Path, str]:
    if path.name in ("", ".", "..") or path.name != Path(path.name).name:
        raise Voidcell002TransportError("invalid endpoint name")
    directory = path.parent.absolute()
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise Voidcell002TransportError("endpoint directory is unavailable") from exc
    try:
        entry = os.fstat(fd)
    finally:
        os.close(fd)
    mode = stat.S_IMODE(entry.st_mode)
    if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or
            mode not in (0o711, 0o755) or mode & 0o022):
        raise Voidcell002TransportError("endpoint directory is not a dedicated traversable owner directory")
    for parent in directory.parents:
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not sticky_root)):
            raise Voidcell002TransportError("endpoint ancestors must exclude non-owner writes")
    return directory, path.name


def _endpoint_inventory(directory: Path, endpoint_name: str) -> None:
    try:
        with os.scandir(directory) as entries:
            observed = [(entry.name, stat.S_ISSOCK(entry.stat(follow_symlinks=False).st_mode))
                        for entry in entries]
    except OSError as exc:
        raise Voidcell002TransportError("endpoint inventory is unavailable") from exc
    if observed != [(endpoint_name, True)]:
        raise Voidcell002TransportError("endpoint inventory does not contain exactly one socket")


def _check_gateway_uid(gateway_uid) -> int:
    if (os.geteuid() == 0 or type(gateway_uid) is not int
            or not 0 < gateway_uid < (1 << 31) or gateway_uid == os.geteuid()):
        raise Voidcell002TransportError("a distinct nonroot gateway UID is required")
    return gateway_uid


def _check_authority(authority) -> None:
    if any(not callable(getattr(authority, name, None))
           for name in ("dispatch", "reconcile", "revoke", "status")):
        raise Voidcell002TransportError("fixed VOIDCELL002 authority methods are required")


def _bound_gateway_uid(authority, gateway_uid: int) -> None:
    """Do not silently detach the kernel gate from the authority's policy."""
    if getattr(authority, "gateway_uid", None) != gateway_uid:
        raise Voidcell002TransportError("transport gateway UID differs from authority policy")


def _safe_send(channel, result: dict) -> None:
    try:
        raw = _encode_response(result)
        if channel.send(raw) != len(raw):
            raise OSError("short response")
        channel.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _serve_connection(channel, authority, gateway_uid: int, target_uid: int) -> None:
    """Serve one connection; all malformed or unauthorized paths are opaque."""
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        channel.settimeout(CONNECTION_TIMEOUT_SECONDS)
        peer = _peer_credentials(channel)
        data, ancillary, _ = _recv(channel)
        if not data:
            raise Voidcell002TransportError("empty request frame")
        _credentials(ancillary, peer)
        _expect_eof(channel)
        action, packet = _decode_request(data)
        if action in _GATEWAY_ACTIONS:
            if peer[1] != gateway_uid:
                raise Voidcell002TransportError("gateway peer is not authorized")
        elif peer[1] != target_uid:
            raise Voidcell002TransportError("target peer is not authorized")
        if action == "dispatch":
            result = authority.dispatch(packet)
        elif action == "reconcile":
            result = authority.reconcile(packet)
        elif action == "revoke":
            result = authority.revoke(packet)
        else:
            result = authority.status()
        if type(result) is not dict:
            raise Voidcell002TransportError("authority result is invalid")
    except Exception:
        result = _REJECTED
    _safe_send(channel, result)


def serve(authority, *, socket_path, gateway_uid, on_ready=None) -> None:
    """Run one local UID-gated endpoint until interrupted.

    The directory must already be a dedicated, owner-controlled 0711 or 0755
    directory. Existing entries are never unlinked or overwritten.
    """
    _check_authority(authority)
    gateway_uid = _check_gateway_uid(gateway_uid)
    _bound_gateway_uid(authority, gateway_uid)
    if on_ready is not None and not callable(on_ready):
        raise TypeError("on_ready must be callable")
    try:
        path = Path(os.fspath(socket_path)).absolute()
    except (TypeError, OSError) as exc:
        raise Voidcell002TransportError("invalid endpoint path") from exc
    directory, _ = _directory(path)
    if os.path.lexists(path):
        raise Voidcell002TransportError("endpoint path already exists")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    bound = None
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        listener.bind(str(path))
        os.chmod(path, 0o666)
        entry = path.lstat()
        if (not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != os.geteuid()
                or stat.S_IMODE(entry.st_mode) != 0o666):
            raise Voidcell002TransportError("endpoint binding is unsafe")
        bound = (entry.st_dev, entry.st_ino)
        _endpoint_inventory(directory, path.name)
        listener.listen(16)
        listener.settimeout(0.25)
        if on_ready is not None:
            on_ready()
        while True:
            try:
                channel, _ = listener.accept()
            except socket.timeout:
                continue
            except InterruptedError:
                continue
            with channel:
                _serve_connection(channel, authority, gateway_uid, os.geteuid())
    except KeyboardInterrupt:
        return
    finally:
        try:
            listener.close()
        finally:
            if bound is not None:
                try:
                    entry = path.lstat()
                    if (stat.S_ISSOCK(entry.st_mode)
                            and (entry.st_dev, entry.st_ino) == bound):
                        path.unlink()
                except OSError:
                    pass


def request(socket_path, action, packet=None, *, expected_target_uid=None,
            expected_target_pid=None) -> dict:
    """Send one canonical request to the local endpoint and return its result."""
    if expected_target_uid is not None and (
            type(expected_target_uid) is not int or not 0 <= expected_target_uid < (1 << 31)):
        raise ValueError("expected target UID must be a local UID")
    if expected_target_pid is not None and (
            type(expected_target_pid) is not int or not 0 < expected_target_pid < (1 << 31)):
        raise ValueError("expected target PID must be a live local PID")
    try:
        path = Path(os.fspath(socket_path)).absolute()
        entry = path.lstat()
        if not stat.S_ISSOCK(entry.st_mode):
            raise Voidcell002TransportError("endpoint is not a socket")
        raw = _encode_request(action, packet)
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            channel.settimeout(CONNECT_TIMEOUT_SECONDS)
            channel.connect(str(path))
            peer = _peer_credentials(channel)
            if expected_target_uid is not None and peer[1] != expected_target_uid:
                raise Voidcell002TransportError("unexpected target UID")
            if expected_target_pid is not None and peer[0] != expected_target_pid:
                raise Voidcell002TransportError("unexpected target PID")
            if channel.send(raw) != len(raw):
                raise Voidcell002TransportError("short request")
            channel.shutdown(socket.SHUT_WR)
            data, ancillary, _ = _recv(channel)
            if not data:
                raise Voidcell002TransportError("empty response")
            _credentials(ancillary, peer)
            _expect_eof(channel)
            return _decode_response(data)
    except ValueError:
        raise
    except (OSError, TimeoutError, RuntimeError, Voidcell002TransportError):
        return dict(_UNAVAILABLE)


__all__ = ("Voidcell002TransportError", "request", "serve")
