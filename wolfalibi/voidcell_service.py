"""One-shot local pipe transport for the synthetic VOIDCELL effect vault.

The parent sends a private bootstrap and one fixed RPC over stdin. The child
returns only a bounded canonical result on stdout and exits. There are no
listeners, sockets, arbitrary command arguments, or credential-bearing output.
This is transport separation for a local synthetic fixture, not an independent
attestation boundary.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


MAX_PACKET_BYTES = 262_144
MAX_BOOTSTRAP_BYTES = 131_072
MAX_REQUEST_BYTES = 524_288
MAX_RESPONSE_BYTES = 262_144
MAX_HEAD_BYTES = 256
RPC_TIMEOUT_SECONDS = 5
_TYPE = "wolfalibi.voidcell.service.v1"
_ACTIONS = frozenset({"dispatch", "reconcile", "revoke", "count"})
_HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
_BOOTSTRAP_FIELDS = frozenset({
    "path", "target_seed", "owner_pub", "gateway_pub", "broker_pub", "witness_pub",
    "supervisor_pub", "contract", "operation_id", "expected_witness_state_digest",
    "witness_head_path",
})
_REQUEST_FIELDS = frozenset({"action", "packet"})


class VaultProcessError(RuntimeError):
    """The local VOIDCELL subprocess transport could not produce a safe result."""


class _ProtocolError(ValueError):
    """A private bootstrap, retained head, or child response is malformed."""


def _object_without_duplicates(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise _ProtocolError("duplicate field")
        result[name] = value
    return result


def _reject_constant(_value):
    raise _ProtocolError("non-finite JSON value")


def _reject_float(_value):
    raise _ProtocolError("floating-point JSON value")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _snapshot(value: object, *, maximum: int) -> object:
    """Return a bounded plain-JSON copy without retaining caller containers."""
    try:
        raw = _canonical(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise _ProtocolError("invalid JSON value") from exc
    if len(raw) > maximum:
        raise _ProtocolError("JSON value exceeds transport bound")
    return _decode(raw, maximum=maximum)


def _decode(raw: bytes, *, maximum: int) -> object:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise _ProtocolError("invalid JSON frame size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError,
            OverflowError, RecursionError) as exc:
        raise _ProtocolError("invalid JSON frame") from exc
    try:
        if _canonical(value) != raw:
            raise _ProtocolError("JSON frame is not canonical")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise _ProtocolError("invalid JSON frame") from exc
    return value


def _fixed_hex(value: object, label: str) -> bytes:
    if type(value) is not str or _HEX_32.fullmatch(value) is None:
        raise _ProtocolError(f"invalid {label}")
    return bytes.fromhex(value)


def _private_path(value: object, label: str) -> str:
    if type(value) is not str or not value or "\0" in value or len(value) > 4096:
        raise _ProtocolError(f"invalid {label}")
    return str(Path(value).absolute())


def _head_from_file(path: str) -> bytes:
    """Read one bounded retained head without following a symlink.

    The head value is canonical lowercase hex. The locally retained JSON file
    itself may be pretty-printed by the create-only artifact writer.
    """
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        initial = os.fstat(fd)
        if (not stat.S_ISREG(initial.st_mode) or initial.st_size > MAX_HEAD_BYTES or
                initial.st_mode & 0o022 or initial.st_nlink != 1):
            raise _ProtocolError("invalid retained head file")
        data = b""
        while len(data) <= MAX_HEAD_BYTES:
            chunk = os.read(fd, MAX_HEAD_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
        final = os.fstat(fd)
    finally:
        os.close(fd)
    if (len(data) > MAX_HEAD_BYTES or initial.st_dev != final.st_dev or
            initial.st_ino != final.st_ino or initial.st_size != final.st_size):
        raise _ProtocolError("retained head changed during read")
    if not 0 < len(data) <= MAX_HEAD_BYTES:
        raise _ProtocolError("invalid retained head")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError,
            OverflowError, RecursionError) as exc:
        raise _ProtocolError("invalid retained head") from exc
    if type(value) is not dict or frozenset(value) != {"head"}:
        raise _ProtocolError("invalid retained head")
    return _fixed_hex(value["head"], "retained head")


def _contains_private_value(value: object, private: tuple[str, ...]) -> bool:
    if type(value) is str:
        return any(marker and marker in value for marker in private)
    if type(value) is list:
        return any(_contains_private_value(item, private) for item in value)
    if type(value) is dict:
        return any(_contains_private_value(item, private) for item in value.values())
    return False


def _response(result: object, *, bootstrap: dict[str, object]) -> bytes:
    """Encode a result only when it cannot reflect private bootstrap values."""
    result = _snapshot(result, maximum=MAX_RESPONSE_BYTES // 2)
    private = (
        str(bootstrap["target_seed"]),
        str(bootstrap["path"]),
        str(bootstrap["witness_head_path"]),
    )
    if _contains_private_value(result, private):
        raise _ProtocolError("private bootstrap value reflected by vault")
    raw = _canonical({"type": _TYPE, "ok": True, "result": result})
    if len(raw) > MAX_RESPONSE_BYTES:
        raise _ProtocolError("response exceeds transport bound")
    return raw


def _error_response() -> bytes:
    return _canonical({"type": _TYPE, "ok": False, "reason": "VOIDCELL_CHILD_REJECTED"})


def _child_request(raw: bytes) -> tuple[dict[str, object], str, object]:
    frame = _decode(raw, maximum=MAX_REQUEST_BYTES)
    if type(frame) is not dict or frozenset(frame) != {"type", "bootstrap", "request"}:
        raise _ProtocolError("invalid bootstrap frame")
    if frame["type"] != _TYPE or type(frame["bootstrap"]) is not dict or type(frame["request"]) is not dict:
        raise _ProtocolError("invalid bootstrap frame")
    bootstrap = frame["bootstrap"]
    request = frame["request"]
    if frozenset(bootstrap) != _BOOTSTRAP_FIELDS or frozenset(request) != _REQUEST_FIELDS:
        raise _ProtocolError("invalid bootstrap fields")
    if (len(_canonical(bootstrap)) > MAX_BOOTSTRAP_BYTES or
            len(_canonical(request["packet"])) > MAX_PACKET_BYTES):
        raise _ProtocolError("bootstrap or packet exceeds transport bound")
    for field in ("path", "witness_head_path"):
        bootstrap[field] = _private_path(bootstrap[field], field)
    for field in (
            "target_seed", "owner_pub", "gateway_pub", "broker_pub", "witness_pub",
            "supervisor_pub", "expected_witness_state_digest"):
        _fixed_hex(bootstrap[field], field)
    if type(bootstrap["contract"]) is not dict:
        raise _ProtocolError("invalid vault contract")
    if (type(bootstrap["operation_id"]) is not str or not bootstrap["operation_id"] or
            len(bootstrap["operation_id"]) > 256 or not bootstrap["operation_id"].isprintable()):
        raise _ProtocolError("invalid operation identifier")
    action = request["action"]
    if type(action) is not str or action not in _ACTIONS:
        raise _ProtocolError("unsupported vault action")
    if action == "count" and request["packet"] is not None:
        raise _ProtocolError("count does not take a packet")
    return bootstrap, action, request["packet"]


def _child_result(raw: bytes) -> bytes:
    """Create one EffectVault in the child and perform one allowlisted RPC."""
    bootstrap, action, packet = _child_request(raw)
    # Deliberately import the evolving vault only in the fixed child entrypoint.
    from alibi import Signer
    from .voidcell import EffectVault

    def observe_witness_head():
        return _head_from_file(bootstrap["witness_head_path"])

    with EffectVault(
            bootstrap["path"],
            signer=Signer(_fixed_hex(bootstrap["target_seed"], "target seed")),
            owner_pub=_fixed_hex(bootstrap["owner_pub"], "owner key"),
            gateway_pub=_fixed_hex(bootstrap["gateway_pub"], "gateway key"),
            broker_pub=_fixed_hex(bootstrap["broker_pub"], "broker key"),
            witness_pub=_fixed_hex(bootstrap["witness_pub"], "witness key"),
            supervisor_pub=_fixed_hex(bootstrap["supervisor_pub"], "supervisor key"),
            contract=bootstrap["contract"],
            operation_id=bootstrap["operation_id"],
            expected_witness_state_digest=_fixed_hex(
                bootstrap["expected_witness_state_digest"], "expected witness head"),
            observe_witness_head=observe_witness_head,
    ) as vault:
        if action == "dispatch":
            result = vault.dispatch(packet)
        elif action == "reconcile":
            result = vault.reconcile(packet)
        elif action == "revoke":
            result = vault.revoke(packet)
        else:
            result = vault.effect_count()
    if action == "count":
        if type(result) is not int or result < 0:
            raise _ProtocolError("invalid vault count")
    elif type(result) is not dict:
        raise _ProtocolError("invalid vault result")
    return _response(result, bootstrap=bootstrap)


def _child_main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise _ProtocolError("oversized bootstrap")
        response = _child_result(raw)
    except (Exception, SystemExit):
        response = _error_response()
    try:
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
    except OSError:
        return 2
    return 0


def _child_command() -> list[str]:
    """Launch this exact source module under isolated Python import settings."""
    repository = str(Path(__file__).resolve().parents[1])
    bootstrap = (
        "import runpy,sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "sys.argv=['wolfalibi.voidcell_service',*sys.argv[2:]];"
        "runpy.run_module('wolfalibi.voidcell_service',run_name='__main__')"
    )
    return [sys.executable, "-I", "-c", bootstrap, repository, "--voidcell-child"]


class VaultProcess:
    """Per-RPC private-pipe client for one synthetic VOIDCELL authority."""

    def __init__(self, path, *, target_seed: bytes, owner_pub, gateway_pub, broker_pub,
                 witness_pub, supervisor_pub, contract, operation_id,
                 expected_witness_state_digest, witness_head_path):
        if type(target_seed) is not bytes or len(target_seed) != 32:
            raise ValueError("target seed must be exactly 32 bytes")
        keys = {
            "owner_pub": owner_pub, "gateway_pub": gateway_pub, "broker_pub": broker_pub,
            "witness_pub": witness_pub, "supervisor_pub": supervisor_pub,
            "expected_witness_state_digest": expected_witness_state_digest,
        }
        if any(type(value) is not bytes or len(value) != 32 for value in keys.values()):
            raise ValueError("VOIDCELL pins must be exactly 32 bytes")
        try:
            stored_contract = _snapshot(contract, maximum=MAX_BOOTSTRAP_BYTES)
            if type(stored_contract) is not dict:
                raise _ProtocolError("contract must be an object")
            stored_path = _private_path(os.fspath(path), "path")
            stored_head_path = _private_path(os.fspath(witness_head_path), "witness head path")
            if (type(operation_id) is not str or not operation_id or len(operation_id) > 256 or
                    not operation_id.isprintable()):
                raise _ProtocolError("invalid operation identifier")
        except (OSError, TypeError, ValueError, _ProtocolError) as exc:
            raise ValueError("invalid local VOIDCELL configuration") from exc
        self._bootstrap = {
            "path": stored_path,
            "target_seed": target_seed.hex(),
            **{name: value.hex() for name, value in keys.items() if name != "expected_witness_state_digest"},
            "contract": stored_contract,
            "operation_id": operation_id,
            "expected_witness_state_digest": expected_witness_state_digest.hex(),
            "witness_head_path": stored_head_path,
        }
        self._closed = False

    def __enter__(self):
        if self._closed:
            raise VaultProcessError("VOIDCELL process handle is closed")
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        self._closed = True

    def call(self, action, packet=None):
        """Perform exactly one fixed vault operation in a fresh local child."""
        if self._closed:
            raise VaultProcessError("VOIDCELL process handle is closed")
        if type(action) is not str or action not in _ACTIONS:
            raise ValueError("unsupported VOIDCELL action")
        if action == "count" and packet is not None:
            raise ValueError("count does not take a packet")
        try:
            request = _snapshot(packet, maximum=MAX_PACKET_BYTES)
            frame = {
                "type": _TYPE,
                "bootstrap": _snapshot(self._bootstrap, maximum=MAX_BOOTSTRAP_BYTES),
                "request": {"action": action, "packet": request},
            }
            raw = _canonical(frame)
            if len(raw) > MAX_REQUEST_BYTES:
                raise _ProtocolError("request exceeds transport bound")
        except (TypeError, ValueError, OverflowError, RecursionError, _ProtocolError) as exc:
            raise ValueError("invalid local VOIDCELL request") from exc
        environment = {"PATH": os.defpath, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
        try:
            child = subprocess.Popen(
                _child_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                close_fds=True, start_new_session=True, env=environment,
                cwd=str(Path(__file__).resolve().parents[1]),
            )
            try:
                stdout, _ = child.communicate(raw, timeout=RPC_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise VaultProcessError("VOIDCELL subprocess timed out") from None
        except VaultProcessError:
            raise
        except OSError as exc:
            raise VaultProcessError("VOIDCELL subprocess could not start") from exc
        if child.returncode != 0:
            raise VaultProcessError("VOIDCELL subprocess failed")
        try:
            response = _decode(stdout, maximum=MAX_RESPONSE_BYTES)
            if type(response) is not dict or response.get("type") != _TYPE:
                raise _ProtocolError("invalid child response")
            if response.get("ok") is not True or frozenset(response) != {"type", "ok", "result"}:
                raise _ProtocolError("child rejected request")
            result: Any = response["result"]
            if action == "count":
                if type(result) is not int or result < 0:
                    raise _ProtocolError("invalid child count")
            elif type(result) is not dict:
                raise _ProtocolError("invalid child result")
            private = (
                str(self._bootstrap["target_seed"]),
                str(self._bootstrap["path"]),
                str(self._bootstrap["witness_head_path"]),
            )
            if _contains_private_value(result, private):
                raise _ProtocolError("private bootstrap value reflected")
            return result
        except (TypeError, ValueError, OverflowError, RecursionError, _ProtocolError) as exc:
            raise VaultProcessError("VOIDCELL subprocess returned an invalid response") from exc


if __name__ == "__main__":
    if sys.argv[1:] != ["--voidcell-child"]:
        raise SystemExit(2)
    raise SystemExit(_child_main())


__all__ = (
    "MAX_PACKET_BYTES", "MAX_REQUEST_BYTES", "MAX_RESPONSE_BYTES",
    "VaultProcess", "VaultProcessError",
)
