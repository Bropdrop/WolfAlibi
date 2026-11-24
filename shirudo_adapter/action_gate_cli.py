"""Bounded local transport for the laboratory counter action gate.

One connection carries one four-byte, big-endian length followed by one strict
JSON document. Clients finish their write side before awaiting the response.
Only prepare, execute, and status are RPCs. State administration and the two
process-interruption fixtures require local access as the state's owner.
"""

from __future__ import annotations

import argparse
import errno
import math
import os
import signal
import socket
import stat
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .model import (AdapterError, MAX_RECORD_BYTES, canonical_json, exact_keys,
                    read_bounded_file, require_hex, strict_json)

MAX_REQUEST_BYTES = MAX_RECORD_BYTES + 32_768
MAX_RESPONSE_BYTES = MAX_RECORD_BYTES
MAX_WORKERS = 4
DEFAULT_TIMEOUT = 10.0
EXIT_BEFORE_COMMIT = 70
EXIT_AFTER_COMMIT = 71


def _timeout(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(result) or not 0.05 <= result <= 30:
        raise argparse.ArgumentTypeError("timeout must be between 0.05 and 30 seconds")
    return result


def _workers(value: str) -> int:
    result = int(value)
    if not 1 <= result <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"workers must be between 1 and {MAX_WORKERS}")
    return result


def _gid(value: str) -> int:
    result = int(value)
    if not 0 <= result < 2 ** 31:
        raise argparse.ArgumentTypeError("socket group must be a nonnegative numeric GID")
    return result


def _socket_path(value: str) -> Path:
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts or "\0" in value
            or path.name in ("", ".", "..") or len(os.fsencode(str(path))) > 107):
        raise AdapterError("SOCKET_PATH", "Socket path must be an absolute bounded Unix pathname")
    return path


def _trusted_parent(path: Path) -> None:
    """Reject symlink or replaceable directories before binding a pathname.

    A root-owned sticky ancestor, such as /tmp, protects an owned child from
    other users' replacement. The immediate socket parent must still disallow
    all group and other writes; socket group permission only permits clients
    to connect, never to replace the endpoint.
    """
    try:
        for directory in (path.parent, *path.parent.parents):
            info = directory.lstat()
            mode = stat.S_IMODE(info.st_mode)
            sticky_ancestor = (directory != path.parent and info.st_uid == 0
                               and bool(mode & stat.S_ISVTX))
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or (mode & 0o022 and not sticky_ancestor)):
                raise AdapterError("SOCKET_PARENT", "Socket parent chain must be trusted and nonreplaceable")
    except OSError as exc:
        raise AdapterError("SOCKET_PARENT", "Cannot inspect the socket parent") from exc


def _same_inode(first, second) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _bind_socket(path: Path, *, socket_gid: int | None, replace_stale: bool):
    _trusted_parent(path)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    listener = None
    created = None
    try:
        try:
            existing = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.geteuid()
                    or existing.st_nlink != 1):
                raise AdapterError("SOCKET_EXISTS", "Existing endpoint is not an owned socket")
            if not replace_stale:
                raise AdapterError("SOCKET_EXISTS", "Existing socket requires explicit stale-socket replacement")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.5)
                try:
                    probe.connect(str(path))
                except OSError as exc:
                    if exc.errno != errno.ECONNREFUSED:
                        raise AdapterError("SOCKET_NOT_STALE", "Existing socket could not be proven refused") from exc
                else:
                    raise AdapterError("SOCKET_IN_USE", "Refusing to replace a live socket")
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (not _same_inode(existing, current) or not stat.S_ISSOCK(current.st_mode)
                    or current.st_uid != os.geteuid() or current.st_nlink != 1):
                raise AdapterError("SOCKET_CHANGED", "Existing socket changed during inspection")
            os.unlink(path.name, dir_fd=parent_fd)

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)
        try:
            listener.bind(str(path))
        finally:
            os.umask(old_umask)
        created = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISSOCK(created.st_mode) or created.st_uid != os.geteuid():
            raise AdapterError("SOCKET_CHANGED", "Created endpoint is not the expected owned socket")
        if socket_gid is not None:
            os.chown(path.name, -1, socket_gid, dir_fd=parent_fd, follow_symlinks=False)
            os.chmod(path.name, 0o660, dir_fd=parent_fd, follow_symlinks=False)
        else:
            os.chmod(path.name, 0o600, dir_fd=parent_fd, follow_symlinks=False)
        listener.listen(MAX_WORKERS)
        listener.settimeout(0.2)
        return listener, parent_fd, created
    except BaseException:
        if listener is not None:
            listener.close()
        if created is not None:
            _unlink_own_socket(path, parent_fd, created)
        os.close(parent_fd)
        raise


def _unlink_own_socket(path: Path, parent_fd: int, created) -> None:
    try:
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (stat.S_ISSOCK(current.st_mode) and current.st_uid == os.geteuid()
                and _same_inode(current, created)):
            os.unlink(path.name, dir_fd=parent_fd)
    except OSError:
        pass


def _remaining(sock: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Connection deadline expired")
    sock.settimeout(remaining)


def _read_exact(sock: socket.socket, count: int, deadline: float) -> bytes:
    parts = []
    remaining = count
    while remaining:
        _remaining(sock, deadline)
        part = sock.recv(min(remaining, 65_536))
        if not part:
            raise AdapterError("FRAME_TRUNCATED", "Connection ended before the declared frame")
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def _read_frame(sock: socket.socket, limit: int, deadline: float) -> dict:
    size = struct.unpack("!I", _read_exact(sock, 4, deadline))[0]
    if not 0 < size <= limit:
        raise AdapterError("FRAME_SIZE", "Frame length is outside the supported bound")
    body = _read_exact(sock, size, deadline)
    # Requiring EOF makes trailing data and additional frames unambiguous, and
    # ensures no action is dispatched before the entire request is admitted.
    _remaining(sock, deadline)
    if sock.recv(1):
        raise AdapterError("FRAME_TRAILING", "Only one frame is permitted per connection")
    return strict_json(body, limit)


def _write_frame(sock: socket.socket, body: bytes, deadline: float) -> None:
    _remaining(sock, deadline)
    sock.sendall(struct.pack("!I", len(body)) + body)


def _denied(exc: AdapterError) -> dict:
    return {"status": "DENIED", "reason": str(exc.code)[:128],
            "message": str(exc.message)[:512]}


def _ambiguous(reason: str = "TRANSPORT_LOST") -> dict:
    return {"status": "AMBIGUOUS", "reason": reason,
            "message": "No effect outcome can be inferred; query the operation before retrying"}


def _dispatch(gate, request: dict) -> dict:
    if type(request) is not dict or type(request.get("op")) is not str:
        raise AdapterError("INVALID_REQUEST", "Request must name one operation")
    operation = request["op"]
    if operation == "prepare":
        exact_keys(request, {"op", "attestation_challenge"}, "prepare request")
        return {"status": "PREPARED", "action_challenge": gate.prepare(request["attestation_challenge"])}
    if operation == "execute":
        exact_keys(request, {"op", "request"}, "execute request")
        exact_keys(request["request"], {"operation_id", "grant", "assessment"}, "execution body")
        require_hex(request["request"]["operation_id"], 32, "operation ID")
        return gate.execute(request["request"])
    if operation == "status":
        exact_keys(request, {"op", "operation_id"}, "status request")
        if request["operation_id"] is not None:
            require_hex(request["operation_id"], 32, "operation ID")
        return {"status": "STATUS", "result": gate.status(request["operation_id"])}
    raise AdapterError("UNKNOWN_OPERATION", "Only prepare, execute, and status are client operations")


def _connection(gate, conn: socket.socket, timeout: float, exit_after_commit: bool) -> None:
    deadline = time.monotonic() + timeout
    with conn:
        try:
            request = _read_frame(conn, MAX_REQUEST_BYTES, deadline)
            response = _dispatch(gate, request)
            if exit_after_commit and response.get("result") == "COMMITTED":
                os._exit(EXIT_AFTER_COMMIT)
        except AdapterError as exc:
            response = _denied(exc)
        except TimeoutError:
            response = _denied(AdapterError("FRAME_TIMEOUT", "Connection exceeded its time limit"))
        except OSError:
            return
        except Exception:
            response = _ambiguous("INTERNAL_ERROR")
        try:
            body = canonical_json(response)
            if len(body) > MAX_RESPONSE_BYTES:
                body = canonical_json(_ambiguous("RESPONSE_TOO_LARGE"))
            _write_frame(conn, body, deadline)
        except (AdapterError, OSError, TimeoutError):
            # A caller cannot infer whether a transaction committed from a
            # failed reply. Recovery uses the durable operation identifier.
            return


def serve(gate, path: Path, *, socket_gid: int | None = None,
          replace_stale: bool = False, workers: int = MAX_WORKERS,
          timeout: float = DEFAULT_TIMEOUT, exit_before_commit: bool = False,
          exit_after_commit: bool = False) -> None:
    listener, parent_fd, created = _bind_socket(path, socket_gid=socket_gid,
                                                replace_stale=replace_stale)
    stopped = threading.Event()
    capacity = threading.BoundedSemaphore(workers)
    previous_handlers = {}
    if exit_before_commit:
        gate._before_commit = lambda: os._exit(EXIT_BEFORE_COMMIT)

    def stop(_signum, _frame):
        stopped.set()

    def handle(conn):
        try:
            _connection(gate, conn, timeout, exit_after_commit)
        finally:
            capacity.release()

    try:
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.signal(signum, stop)
        sys.stdout.buffer.write(canonical_json({"status": "READY", "socket": str(path),
                                               "workers": workers}) + b"\n")
        sys.stdout.buffer.flush()
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="action-gate") as pool:
            while not stopped.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                if not capacity.acquire(blocking=False):
                    # Do not create an unbounded executor queue or wait on an
                    # untrusted peer in the accept loop.
                    with conn:
                        try:
                            _write_frame(conn, canonical_json(_denied(AdapterError(
                                "SERVER_BUSY", "All bounded workers are occupied"))),
                                time.monotonic() + 0.05)
                        except OSError:
                            pass
                    continue
                try:
                    pool.submit(handle, conn)
                except BaseException:
                    capacity.release()
                    conn.close()
                    raise
    finally:
        listener.close()
        _unlink_own_socket(path, parent_fd, created)
        os.close(parent_fd)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def _validate_response(response: dict) -> None:
    if type(response) is not dict:
        raise AdapterError("INVALID_RESPONSE", "Response is not an object")
    if response.get("result") in ("COMMITTED", "ALREADY_COMMITTED"):
        exact_keys(response, {"result", "receipt"}, "effect response")
        record = response["receipt"]
    elif response.get("status") == "PREPARED":
        exact_keys(response, {"status", "action_challenge"}, "prepare response")
        record = response["action_challenge"]
    elif response.get("status") == "STATUS":
        exact_keys(response, {"status", "result"}, "status response")
        if type(response["result"]) is not dict:
            raise AdapterError("INVALID_RESPONSE", "Status result is not an object")
        return
    elif response.get("status") in ("DENIED", "AMBIGUOUS"):
        exact_keys(response, {"status", "reason", "message"}, "error response")
        if (type(response["reason"]) is not str or not 1 <= len(response["reason"]) <= 128
                or type(response["message"]) is not str or len(response["message"]) > 512):
            raise AdapterError("INVALID_RESPONSE", "Invalid error response")
        return
    else:
        raise AdapterError("INVALID_RESPONSE", "Unknown response outcome")
    exact_keys(record, {"schema", "payload", "signature"}, "signed response")
    if record["schema"] != "wolfalibi.signed-record.v1" or type(record["payload"]) is not dict:
        raise AdapterError("INVALID_RESPONSE", "Invalid signed response structure")
    require_hex(record["signature"], 128, "response signature")
    # The transport checks framing and structure. Cryptographic verification
    # still requires the independently pinned target key and expected bindings.


def request(path: Path, document: dict, *, timeout: float = DEFAULT_TIMEOUT) -> tuple[dict, int]:
    body = canonical_json(document)
    if not 0 < len(body) <= MAX_REQUEST_BYTES:
        raise AdapterError("FRAME_SIZE", "Request exceeds the supported byte limit")
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            _remaining(conn, deadline)
            conn.connect(str(path))
            _write_frame(conn, body, deadline)
            conn.shutdown(socket.SHUT_WR)
            response = _read_frame(conn, MAX_RESPONSE_BYTES, deadline)
        _validate_response(response)
        return response, 2 if response.get("status") == "AMBIGUOUS" else 0
    except (AdapterError, OSError, TimeoutError):
        return _ambiguous(), 2


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = root.add_subparsers(dest="command", required=True)
    for command in ("init", "serve", "request", "status", "revoke-grant", "revoke-policy"):
        p = commands.add_parser(command, allow_abbrev=False)
        if command in ("init", "serve", "revoke-grant", "revoke-policy"):
            p.add_argument("--state", required=True)
        if command == "init":
            p.add_argument("--trust", required=True)
        if command in ("serve", "request"):
            p.add_argument("--socket", required=True)
        if command == "serve":
            p.add_argument("--socket-gid", type=_gid)
            p.add_argument("--replace-stale-socket", action="store_true")
            p.add_argument("--workers", type=_workers, default=MAX_WORKERS)
            p.add_argument("--connection-timeout", type=_timeout, default=DEFAULT_TIMEOUT)
            fault = p.add_mutually_exclusive_group()
            fault.add_argument("--exit-before-commit-once", action="store_true")
            fault.add_argument("--exit-after-commit-once", action="store_true")
        if command in ("request", "status"):
            p.add_argument("--timeout", type=_timeout, default=DEFAULT_TIMEOUT)
        if command == "request":
            p.add_argument("--request", default="-", help="JSON input file, or - for stdin")
        if command == "status":
            source = p.add_mutually_exclusive_group(required=True)
            source.add_argument("--state")
            source.add_argument("--socket")
            p.add_argument("--operation-id")
        if command == "revoke-grant":
            p.add_argument("--grant-id", required=True)
    return root


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "request":
            raw = (sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1) if args.request == "-"
                   else read_bounded_file(args.request, MAX_REQUEST_BYTES))
            document = strict_json(raw, MAX_REQUEST_BYTES)
            result, code = request(_socket_path(args.socket), document, timeout=args.timeout)
        elif args.command == "status" and args.socket:
            if args.operation_id is not None:
                require_hex(args.operation_id, 32, "operation ID")
            result, code = request(_socket_path(args.socket),
                                   {"op": "status", "operation_id": args.operation_id}, timeout=args.timeout)
        else:
            from .action_gate import Gate

            if args.command == "init":
                trust = strict_json(read_bounded_file(args.trust, MAX_RECORD_BYTES), MAX_RECORD_BYTES)
                gate = Gate.initialize(args.state, trust)
                result = {"status": "INITIALIZED", "identity": gate.public_identity()}
            else:
                # Gate checks private file ownership before opening local
                # state. There is no local-owner bypass in the RPC protocol.
                gate = Gate(args.state)
                if args.command == "serve":
                    serve(gate, _socket_path(args.socket), socket_gid=args.socket_gid,
                          replace_stale=args.replace_stale_socket, workers=args.workers,
                          timeout=args.connection_timeout, exit_before_commit=args.exit_before_commit_once,
                          exit_after_commit=args.exit_after_commit_once)
                    return 0
                if args.command == "status":
                    result = {"status": "STATUS", "result": gate.status(args.operation_id)}
                elif args.command == "revoke-grant":
                    gate.revoke_grant(args.grant_id)
                    result = {"status": "REVOKED", "grant_id": args.grant_id}
                else:
                    gate.revoke_policy()
                    result = {"status": "REVOKED", "scope": "POLICY"}
            code = 0
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        return code
    except AdapterError as exc:
        sys.stdout.buffer.write(canonical_json({"status": "BLOCKED", "reason": exc.code,
                                              "message": exc.message}) + b"\n")
        return 2
    except OSError:
        sys.stdout.buffer.write(canonical_json({"status": "BLOCKED", "reason": "LOCAL_IO",
                                              "message": "Local state or socket operation failed"}) + b"\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
