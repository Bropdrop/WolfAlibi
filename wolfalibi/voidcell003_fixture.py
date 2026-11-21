"""Split-role provisioning fixture for the synthetic VOIDCELL counter.

This module deliberately does not create accounts, call privileged programs,
or pretend that two same-UID processes establish key custody.  It prepares
public, signed handoffs for an operator who has already provisioned ordinary,
distinct non-root gateway and target-owner accounts on Linux.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import time
from typing import Any, Mapping, Optional

from alibi import DurableWitness, H, Signer, canon, verify_sig
from .agent_solitary import agent_solitary_contract, run_agent_solitary
from .solitary_evidence import verify_solitary
from .stage3_evidence import _hex
from .stage3_worker import UnsupportedWorker
from .voidcell002 import AuthorityError, init_key, initialize
from .voidcell003_revision import source_revision
from .voidcell_records import check_grant, grant, make_scope


GATEWAY_KEY_FILE = "gateway.key"
OWNER_KEY_FILE = "owner.key"
GATEWAY_REFERENCE_SCHEMA = "wolfalibi.voidcell003.gateway-reference.v1"
OWNER_HANDOFF_SCHEMA = "wolfalibi.voidcell003.owner-handoff.v1"
GATEWAY_REFERENCE_DOMAIN = b"wolfalibi/voidcell003/gateway-reference/v1"
OWNER_HANDOFF_DOMAIN = b"wolfalibi/voidcell003/owner-handoff/v1"
MAX_PUBLIC_BYTES = 512 * 1024
DEFAULT_OPERATION_ID = "voidcell003-counter-increment-001"

_GATEWAY_PAYLOAD_FIELDS = frozenset({"gateway_uid", "gateway_gid", "gateway_pub"})
_TARGET_STATE_FIELDS = frozenset({
    "authority_config_sha256", "state_device", "state_inode", "state_mode",
    "anchor_device", "anchor_inode", "anchor_mode", "key_mode", "ledger_mode",
})
_HANDOFF_PAYLOAD_FIELDS = frozenset({
    "source_revision", "created_at", "gateway_reference_sha256",
    "gateway_uid", "gateway_gid", "gateway_pub", "target_uid", "target_gid", "target_pub",
    "socket_path", "target_state", "owner_pub", "broker_pub", "witness_pub",
    "supervisor_pub", "contract", "qualification", "owner_grant", "scope",
    "operation_id", "expected_witness_state_digest", "initial_witness_head",
    "terminal_witness_state_digest",
})


class FixtureError(RuntimeError):
    """A split-role fixture prerequisite or signed handoff is invalid."""


def _freeze(value: Any, *, maximum: int = MAX_PUBLIC_BYTES) -> Any:
    try:
        encoded = canon(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise FixtureError("record is not canonically serializable") from exc
    if len(encoded) > maximum:
        raise FixtureError("record exceeds the fixture size bound")
    try:
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise FixtureError("record cannot be frozen") from exc


def _absolute(path: object, label: str) -> Path:
    try:
        candidate = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as exc:
        raise FixtureError(f"invalid {label} path") from exc
    if candidate.name in ("", ".", ".."):
        raise FixtureError(f"invalid {label} path")
    return candidate


def _private_directory(path: object, label: str, *, empty: bool = False) -> Path:
    directory = _absolute(path, label)
    uid = os.geteuid()
    if uid == 0:
        raise FixtureError("split-role fixture refuses to run as root")
    try:
        entry = directory.lstat()
    except OSError as exc:
        raise FixtureError(f"{label} directory is unavailable") from exc
    if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != uid
            or stat.S_IMODE(entry.st_mode) != 0o700):
        raise FixtureError(f"{label} directory must be target-owned mode 0700")
    for ancestor in directory.parents:
        try:
            info = ancestor.lstat()
        except OSError as exc:
            raise FixtureError(f"{label} directory ancestors are unavailable") from exc
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid)
                or (info.st_mode & 0o022 and not sticky_root)):
            raise FixtureError(f"{label} directory ancestors permit unsafe writes")
    if empty:
        try:
            if any(directory.iterdir()):
                raise FixtureError(f"{label} directory must be empty for a new run")
        except OSError as exc:
            raise FixtureError(f"{label} directory cannot be inspected") from exc
    return directory


def _public_output(path: object, label: str, *, private_roots: tuple[Path, ...] = ()) -> Path:
    output = _absolute(path, label)
    if any(output == root or root in output.parents for root in private_roots):
        raise FixtureError(f"{label} must not be placed under a private role directory")
    try:
        parent = output.parent.lstat()
    except OSError as exc:
        raise FixtureError(f"{label} parent is unavailable") from exc
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) not in (0o711, 0o755)):
        raise FixtureError(f"{label} parent must be a role-owned public mode-0711 or mode-0755 directory")
    if os.path.lexists(output):
        raise FixtureError(f"{label} must be a new file")
    return output


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if not isinstance(written, int) or written <= 0:
            raise OSError("fixture write made no progress")
        view = view[written:]


def _sync_parent(path: Path) -> None:
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _sync_parent(path)


def _read_canonical_public(path: object, label: str) -> dict[str, Any]:
    candidate = _absolute(path, label)
    try:
        descriptor = os.open(
            candidate,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise FixtureError(f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o644):
            raise FixtureError(f"{label} must be a regular public mode-0644 file")
        raw = os.read(descriptor, MAX_PUBLIC_BYTES + 1)
        while len(raw) <= MAX_PUBLIC_BYTES:
            more = os.read(descriptor, MAX_PUBLIC_BYTES + 1 - len(raw))
            if not more:
                break
            raw += more
    finally:
        os.close(descriptor)
    if not raw or len(raw) > MAX_PUBLIC_BYTES:
        raise FixtureError(f"{label} has an invalid size")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON field")
                result[key] = value
            return result
        record = json.loads(raw, object_pairs_hook=unique)
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise FixtureError(f"{label} is not canonical JSON") from exc
    if type(record) is not dict or canon(record) != raw:
        raise FixtureError(f"{label} is not canonical JSON")
    return record


def _key_hex(value: object, label: str) -> bytes:
    """Accept an in-process key or a canonical public hexadecimal encoding."""
    if type(value) is bytes:
        if len(value) != 32:
            raise FixtureError(f"invalid {label}")
        return value
    try:
        return _hex(value, 32, label)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise FixtureError(f"invalid {label}") from exc


def _sig_hex(value: object, label: str) -> bytes:
    try:
        return _hex(value, 64, label)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise FixtureError(f"invalid {label}") from exc


def _uid(value: object, label: str) -> int:
    if type(value) is not int or not 0 < value < (1 << 31):
        raise FixtureError(f"invalid {label}")
    return value


def _digest_hex(value: object, label: str) -> str:
    if type(value) is not str:
        raise FixtureError(f"invalid {label}")
    try:
        return _hex(value, 32, label).hex()
    except (TypeError, ValueError, RuntimeError) as exc:
        raise FixtureError(f"invalid {label}") from exc


def _message(schema: str, payload: Mapping[str, Any]) -> bytes:
    return canon({"schema": schema, "payload": payload})


def _signed(schema: str, payload: Mapping[str, Any], signer: Signer, domain: bytes) -> dict[str, Any]:
    return {
        "schema": schema,
        "payload": _freeze(payload),
        "signature": signer.sign(domain, _message(schema, payload)).hex(),
    }


def handoff_sha256(record: Mapping[str, Any]) -> str:
    """Return the canonical public handoff fingerprint for out-of-band pinning."""
    return H(canon(record)).hex()


def make_gateway_reference(signer: Signer, *, gateway_uid: int, gateway_gid: int) -> dict[str, Any]:
    """Make a public, self-signed gateway enrollment reference."""
    if not isinstance(getattr(signer, "pub", None), bytes) or len(signer.pub) != 32:
        raise FixtureError("gateway signer is invalid")
    payload = {
        "gateway_uid": _uid(gateway_uid, "gateway UID"),
        "gateway_gid": _uid(gateway_gid, "gateway GID"),
        "gateway_pub": signer.pub.hex(),
    }
    return _signed(GATEWAY_REFERENCE_SCHEMA, payload, signer, GATEWAY_REFERENCE_DOMAIN)


def verify_gateway_reference(
        record: Mapping[str, Any], *, expected_gateway_uid: int,
        expected_gateway_gid: int, expected_gateway_pub: bytes) -> dict[str, Any]:
    """Verify a public gateway ref against operator-supplied identity pins."""
    frozen = _freeze(record)
    if type(frozen) is not dict or frozenset(frozen) != {"schema", "payload", "signature"}:
        raise FixtureError("gateway reference shape is invalid")
    if frozen["schema"] != GATEWAY_REFERENCE_SCHEMA or type(frozen["payload"]) is not dict:
        raise FixtureError("gateway reference schema is invalid")
    payload = frozen["payload"]
    if frozenset(payload) != _GATEWAY_PAYLOAD_FIELDS:
        raise FixtureError("gateway reference fields are invalid")
    gateway_pub = _key_hex(payload["gateway_pub"], "gateway public key")
    uid = _uid(payload["gateway_uid"], "gateway UID")
    gid = _uid(payload["gateway_gid"], "gateway GID")
    if (uid != _uid(expected_gateway_uid, "expected gateway UID")
            or gid != _uid(expected_gateway_gid, "expected gateway GID")
            or gateway_pub != _key_hex(expected_gateway_pub, "expected gateway public key")):
        raise FixtureError("gateway reference differs from the independently supplied gateway identity")
    signature = _sig_hex(frozen["signature"], "gateway reference signature")
    if not verify_sig(gateway_pub, GATEWAY_REFERENCE_DOMAIN,
                      _message(GATEWAY_REFERENCE_SCHEMA, payload), signature):
        raise FixtureError("gateway reference signature is invalid")
    return _freeze(payload)


def load_gateway_signer(state_dir: object) -> Signer:
    """Load only the gateway's raw private seed from its private role directory."""
    state = _private_directory(state_dir, "gateway state")
    key = state / GATEWAY_KEY_FILE
    try:
        descriptor = os.open(
            key,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise FixtureError("gateway signing key is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
            raise FixtureError("gateway signing key is not private")
        seed = os.read(descriptor, 33)
        if os.read(descriptor, 1):
            raise FixtureError("gateway signing key has an invalid size")
    finally:
        os.close(descriptor)
    if len(seed) != 32:
        raise FixtureError("gateway signing key has an invalid size")
    return Signer(seed)


def gateway_init(state_dir: object, public_ref: object) -> dict[str, Any]:
    """Generate the gateway key and a public ref; no owner or target key exists here."""
    state = _private_directory(state_dir, "gateway state")
    output = _public_output(public_ref, "gateway public reference", private_roots=(state,))
    if os.path.lexists(state / GATEWAY_KEY_FILE):
        raise FixtureError("gateway signing key already exists; never replace it automatically")
    seed = secrets.token_bytes(32)
    signer = Signer(seed)
    try:
        _write_new(state / GATEWAY_KEY_FILE, seed, 0o600)
    except OSError as exc:
        raise FixtureError("could not persist gateway signing key") from exc
    reference = make_gateway_reference(signer, gateway_uid=os.geteuid(), gateway_gid=os.getegid())
    _write_new(output, canon(reference), 0o644)
    return {
        "outcome": "PROVISIONED", "gateway_pub": signer.pub.hex(),
        "gateway_uid": os.geteuid(), "gateway_gid": os.getegid(),
        "public_ref": str(output), "public_ref_sha256": handoff_sha256(reference),
    }


def split_role_preflight(gateway_uid: int, gateway_gid: int, *, target_uid: Optional[int] = None,
                         target_gid: Optional[int] = None) -> dict[str, Any]:
    """Check declared ordinary account identities without creating or changing users."""
    target_uid = os.geteuid() if target_uid is None else target_uid
    target_gid = os.getegid() if target_gid is None else target_gid
    try:
        gateway_uid = _uid(gateway_uid, "gateway UID")
        gateway_gid = _uid(gateway_gid, "gateway GID")
        target_uid = _uid(target_uid, "target UID")
        target_gid = _uid(target_gid, "target GID")
    except FixtureError as exc:
        return {"outcome": "UNSUPPORTED", "custody": "UNSUPPORTED", "reason": str(exc)}
    if target_uid == 0 or gateway_uid == 0:
        return {"outcome": "UNSUPPORTED", "custody": "UNSUPPORTED",
                "reason": "split-role fixture requires ordinary non-root accounts"}
    if target_uid == gateway_uid:
        return {"outcome": "UNSUPPORTED", "custody": "UNSUPPORTED",
                "reason": "target and gateway UIDs must be distinct"}
    try:
        gateway_account = pwd.getpwuid(gateway_uid)
    except KeyError:
        return {"outcome": "UNSUPPORTED", "custody": "UNSUPPORTED",
                "reason": "declared gateway UID is not a provisioned local account"}
    if gateway_account.pw_gid != gateway_gid:
        return {"outcome": "UNSUPPORTED", "custody": "UNSUPPORTED",
                "reason": "declared gateway GID does not match its provisioned account"}
    return {
        "outcome": "READY", "custody": "UNMEASURED",
        "target_uid": target_uid, "target_gid": target_gid,
        "gateway_uid": gateway_uid, "gateway_gid": gateway_gid,
        "shared_gid": target_gid == gateway_gid,
    }


def _endpoint_path(path: object, target_uid: int) -> str:
    endpoint = _absolute(path, "target socket")
    if not endpoint.is_absolute() or "\x00" in str(endpoint):
        raise FixtureError("target socket path is invalid")
    try:
        parent = endpoint.parent.lstat()
    except OSError as exc:
        raise FixtureError("target socket parent is unavailable") from exc
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != target_uid
            or stat.S_IMODE(parent.st_mode) not in (0o711, 0o755) or parent.st_mode & 0o022):
        raise FixtureError("target socket parent must be target-owned and safely traversable")
    if os.path.lexists(endpoint):
        raise FixtureError("target socket path must be absent before owner provisioning")
    return str(endpoint)


def _source(value: object) -> dict[str, str]:
    if type(value) is not dict or frozenset(value) != {"commit", "tree"}:
        raise FixtureError("source revision is invalid")
    result = {}
    for field in ("commit", "tree"):
        item = value[field]
        if type(item) is not str or len(item) != 40 or any(char not in "0123456789abcdef" for char in item):
            raise FixtureError("source revision is invalid")
        result[field] = item
    return result


def _target_state_metadata(target_state: Path, anchor_dir: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    try:
        state = target_state.lstat()
        anchor = anchor_dir.lstat()
        key = (target_state / "target.key").lstat()
        ledger = (target_state / "ledger.sqlite").lstat()
    except OSError as exc:
        raise FixtureError("target authority files are unavailable after initialization") from exc
    if (stat.S_IMODE(state.st_mode) != 0o700 or stat.S_IMODE(anchor.st_mode) != 0o700
            or stat.S_IMODE(key.st_mode) != 0o600 or stat.S_IMODE(ledger.st_mode) != 0o600):
        raise FixtureError("target authority file modes differ from the fixed custody profile")
    return {
        "authority_config_sha256": H(canon(config)).hex(),
        "state_device": str(state.st_dev), "state_inode": str(state.st_ino), "state_mode": 0o700,
        "anchor_device": str(anchor.st_dev), "anchor_inode": str(anchor.st_ino), "anchor_mode": 0o700,
        "key_mode": 0o600, "ledger_mode": 0o600,
    }


def _run_stage5(qualification_dir: Path, *, now: int) -> dict[str, Any]:
    """Create a fresh fixed callback qualification under owner custody."""
    contract = agent_solitary_contract(
        "voidcell003-" + secrets.token_hex(12), secrets.token_bytes(32), now + 120,
    )
    broker, supervisor = Signer(), Signer()
    with DurableWitness(qualification_dir / "witness.json", Signer()) as witness:
        expected = witness.state_digest
        result = run_agent_solitary(
            qualification_dir, contract=contract, signer=broker, witness=witness,
            supervisor=supervisor, expected_witness_state_digest=expected,
        )
        terminal = witness.state_digest
        witness_pub = witness.signer.pub
    if result.get("outcome") != "COMPLETED" or type(result.get("envelope")) is not dict:
        raise FixtureError("fixed Stage 5 qualification did not complete")
    return {
        "contract": contract, "qualification": result["envelope"],
        "broker_pub": broker.pub, "witness_pub": witness_pub, "supervisor_pub": supervisor.pub,
        "expected_witness_state_digest": expected, "terminal_witness_state_digest": terminal,
    }


def _check_owner_payload(payload: Mapping[str, Any], *, owner_pub: bytes,
                         expected_source_revision: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
    payload = _freeze(payload)
    if type(payload) is not dict or frozenset(payload) != _HANDOFF_PAYLOAD_FIELDS:
        raise FixtureError("owner handoff fields are invalid")
    if payload["owner_pub"] != _key_hex(owner_pub, "expected owner public key").hex():
        raise FixtureError("owner handoff differs from the externally pinned owner key")
    source = _source(payload["source_revision"])
    if expected_source_revision is not None and source != _source(expected_source_revision):
        raise FixtureError("owner handoff source revision differs from the expected checkout")
    created_at = payload["created_at"]
    if type(created_at) is not int or not 0 <= created_at < (1 << 63):
        raise FixtureError("owner handoff creation time is invalid")
    gateway_uid = _uid(payload["gateway_uid"], "gateway UID")
    gateway_gid = _uid(payload["gateway_gid"], "gateway GID")
    target_uid = _uid(payload["target_uid"], "target UID")
    target_gid = _uid(payload["target_gid"], "target GID")
    if gateway_uid == target_uid:
        raise FixtureError("owner handoff does not bind distinct target and gateway UIDs")
    keys = {
        field: _key_hex(payload[field], field.replace("_", " "))
        for field in ("gateway_pub", "target_pub", "owner_pub", "broker_pub", "witness_pub", "supervisor_pub")
    }
    if len(set(keys.values())) != len(keys):
        raise FixtureError("owner handoff signing roles are not distinct")
    expected = _key_hex(payload["expected_witness_state_digest"], "expected witness state digest")
    terminal = _key_hex(payload["terminal_witness_state_digest"], "terminal witness state digest")
    if _key_hex(payload["initial_witness_head"], "initial witness head") != terminal:
        raise FixtureError("target witness head does not equal the completed qualification head")
    operation_id = payload["operation_id"]
    if type(operation_id) is not str or not operation_id or len(operation_id) > 256 or not operation_id.isprintable():
        raise FixtureError("owner handoff operation identifier is invalid")
    socket_path = payload["socket_path"]
    if (type(socket_path) is not str or not socket_path.startswith("/") or "\x00" in socket_path
            or len(socket_path) > 4096):
        raise FixtureError("owner handoff target socket path is invalid")
    if _digest_hex(payload["gateway_reference_sha256"], "gateway reference digest") != payload["gateway_reference_sha256"]:
        raise FixtureError("owner handoff gateway reference digest is not canonical")
    target_state = payload["target_state"]
    if type(target_state) is not dict or frozenset(target_state) != _TARGET_STATE_FIELDS:
        raise FixtureError("owner handoff target state metadata is invalid")
    _digest_hex(target_state["authority_config_sha256"], "target authority configuration digest")
    for field in ("state_device", "state_inode", "anchor_device", "anchor_inode"):
        value = target_state[field]
        if type(value) is not str or not value.isdecimal() or len(value) > 32:
            raise FixtureError("owner handoff target state identity is invalid")
    if (target_state["state_mode"], target_state["anchor_mode"], target_state["key_mode"],
            target_state["ledger_mode"]) != (0o700, 0o700, 0o600, 0o600):
        raise FixtureError("owner handoff target state modes are invalid")
    contract = _freeze(payload["contract"])
    scope = make_scope(
        contract, gateway_pub=keys["gateway_pub"], target_pub=keys["target_pub"],
        operation_id=operation_id, expected_witness_state_digest=expected,
    )
    if canon(scope) != canon(payload["scope"]):
        raise FixtureError("owner handoff scope does not match the exact contract and role keys")
    try:
        owner_grant = check_grant(payload["owner_grant"], owner_pub=keys["owner_pub"],
                                  scope=scope, now=created_at)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise FixtureError("owner handoff grant is invalid at creation time") from exc
    if owner_grant["expires_at"] > contract["expires_at"]:
        raise FixtureError("owner handoff grant outlives its fixed qualification contract")
    verified = verify_solitary(
        payload["qualification"], contract=contract, broker_pub=keys["broker_pub"],
        witness_pub=keys["witness_pub"], supervisor_pub=keys["supervisor_pub"],
        expected_witness_state_digest=expected, now=created_at,
    )
    if verified.get("outcome") != "VERIFIED" or verified.get("witness_state_digest") != terminal.hex():
        raise FixtureError("owner handoff qualification does not bind the completed retained witness head")
    return _freeze(payload)


def make_owner_handoff(
        owner: Signer, *, source: Mapping[str, str], created_at: int,
        gateway_reference_sha256: str, gateway_uid: int, gateway_gid: int, gateway_pub: bytes,
        target_uid: int, target_gid: int, target_pub: bytes, socket_path: str,
        target_state: Mapping[str, Any], contract: Mapping[str, Any], qualification: Mapping[str, Any],
        broker_pub: bytes, witness_pub: bytes, supervisor_pub: bytes,
        expected_witness_state_digest: bytes, terminal_witness_state_digest: bytes,
        operation_id: str, owner_grant: Mapping[str, Any]) -> dict[str, Any]:
    """Build one owner-signed public handoff after all target-side staging succeeds."""
    if not isinstance(getattr(owner, "pub", None), bytes) or len(owner.pub) != 32:
        raise FixtureError("owner signer is invalid")
    payload = {
        "source_revision": _source(source), "created_at": created_at,
        "gateway_reference_sha256": _digest_hex(gateway_reference_sha256, "gateway reference digest"),
        "gateway_uid": _uid(gateway_uid, "gateway UID"), "gateway_gid": _uid(gateway_gid, "gateway GID"),
        "gateway_pub": _key_hex(gateway_pub, "gateway public key").hex(),
        "target_uid": _uid(target_uid, "target UID"), "target_gid": _uid(target_gid, "target GID"),
        "target_pub": _key_hex(target_pub, "target public key").hex(), "socket_path": socket_path,
        "target_state": _freeze(target_state), "owner_pub": owner.pub.hex(),
        "broker_pub": _key_hex(broker_pub, "broker public key").hex(),
        "witness_pub": _key_hex(witness_pub, "witness public key").hex(),
        "supervisor_pub": _key_hex(supervisor_pub, "supervisor public key").hex(),
        "contract": _freeze(contract), "qualification": _freeze(qualification),
        "owner_grant": _freeze(owner_grant), "scope": None,
        "operation_id": operation_id,
        "expected_witness_state_digest": _key_hex(expected_witness_state_digest, "expected witness state digest").hex(),
        "initial_witness_head": _key_hex(terminal_witness_state_digest, "completed witness state digest").hex(),
        "terminal_witness_state_digest": _key_hex(terminal_witness_state_digest, "completed witness state digest").hex(),
    }
    payload["scope"] = make_scope(
        payload["contract"], gateway_pub=bytes.fromhex(payload["gateway_pub"]),
        target_pub=bytes.fromhex(payload["target_pub"]), operation_id=operation_id,
        expected_witness_state_digest=bytes.fromhex(payload["expected_witness_state_digest"]),
    )
    # Validate every cross-reference before the owner signature is emitted.
    _check_owner_payload(payload, owner_pub=owner.pub)
    return _signed(OWNER_HANDOFF_SCHEMA, payload, owner, OWNER_HANDOFF_DOMAIN)


def verify_owner_handoff(
        record: Mapping[str, Any], *, owner_pub: bytes, expected_sha256: Optional[str] = None,
        expected_source_revision: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
    """Verify a public handoff using an owner key and optional out-of-band pins."""
    frozen = _freeze(record)
    if type(frozen) is not dict or frozenset(frozen) != {"schema", "payload", "signature"}:
        raise FixtureError("owner handoff shape is invalid")
    if frozen["schema"] != OWNER_HANDOFF_SCHEMA or type(frozen["payload"]) is not dict:
        raise FixtureError("owner handoff schema is invalid")
    if expected_sha256 is not None and handoff_sha256(frozen) != _digest_hex(expected_sha256, "expected handoff digest"):
        raise FixtureError("owner handoff differs from the independently pinned handoff digest")
    public = _key_hex(owner_pub, "expected owner public key")
    signature = _sig_hex(frozen["signature"], "owner handoff signature")
    if not verify_sig(public, OWNER_HANDOFF_DOMAIN,
                      _message(OWNER_HANDOFF_SCHEMA, frozen["payload"]), signature):
        raise FixtureError("owner handoff signature is invalid")
    return _check_owner_payload(frozen["payload"], owner_pub=public,
                                expected_source_revision=expected_source_revision)


def load_owner_handoff(
        path: object, *, owner_pub: bytes, expected_sha256: Optional[str] = None,
        expected_source_revision: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
    """Read and verify an owner public handoff without opening target private state."""
    return verify_owner_handoff(_read_canonical_public(path, "owner handoff"), owner_pub=owner_pub,
                                expected_sha256=expected_sha256,
                                expected_source_revision=expected_source_revision)


def _write_owner_seed(state: Path) -> Signer:
    seed = secrets.token_bytes(32)
    _write_new(state / OWNER_KEY_FILE, seed, 0o600)
    return Signer(seed)


def owner_init(
        *, target_state_dir: object, anchor_dir: object, qualification_dir: object,
        gateway_ref: object, handoff: object, socket_path: object, consent: bool,
        expected_gateway_uid: int, expected_gateway_gid: int, expected_gateway_pub: bytes,
        operation_id: str = DEFAULT_OPERATION_ID) -> dict[str, Any]:
    """Prepare a fresh target and public handoff under the actual owner account.

    This does not serve the target.  The owner starts ``voidcell002 serve``
    later; the gateway sees only this signed public record and its own key.
    """
    if not consent:
        raise FixtureError("explicit consent is required for the fixed Stage 5 qualification")
    target_state = _private_directory(target_state_dir, "target state", empty=True)
    anchor = _private_directory(anchor_dir, "target anchor", empty=True)
    qualification = _private_directory(qualification_dir, "qualification state", empty=True)
    if len({target_state, anchor, qualification}) != 3:
        raise FixtureError("target, anchor and qualification directories must be separate")
    output = _public_output(handoff, "owner handoff", private_roots=(target_state, anchor, qualification))
    reference_record = _read_canonical_public(gateway_ref, "gateway public reference")
    gateway = verify_gateway_reference(
        reference_record, expected_gateway_uid=expected_gateway_uid,
        expected_gateway_gid=expected_gateway_gid, expected_gateway_pub=expected_gateway_pub,
    )
    roles = split_role_preflight(gateway["gateway_uid"], gateway["gateway_gid"])
    if roles["outcome"] != "READY":
        return roles
    endpoint = _endpoint_path(socket_path, roles["target_uid"])
    # Refuse a dirty/untracked source before the 120-second fixed trial begins.
    source = _source(source_revision())
    now = int(time.time())
    stage5 = _run_stage5(qualification, now=now)
    owner = _write_owner_seed(target_state)
    target_pub_hex = init_key(target_state)
    target_pub = _key_hex(target_pub_hex, "target public key")
    all_keys = {owner.pub, target_pub, _key_hex(gateway["gateway_pub"], "gateway public key"),
                stage5["broker_pub"], stage5["witness_pub"], stage5["supervisor_pub"]}
    if len(all_keys) != 6:
        raise FixtureError("split-role fixture generated non-distinct signing identities")
    config = {
        "gateway_uid": gateway["gateway_uid"], "owner_pub": owner.pub.hex(),
        "gateway_pub": gateway["gateway_pub"], "broker_pub": stage5["broker_pub"].hex(),
        "witness_pub": stage5["witness_pub"].hex(), "supervisor_pub": stage5["supervisor_pub"].hex(),
        "contract": stage5["contract"], "operation_id": operation_id,
        "expected_witness_state_digest": stage5["expected_witness_state_digest"].hex(),
        "initial_witness_head": stage5["terminal_witness_state_digest"].hex(),
    }
    status = initialize(target_state, anchor, config)
    if status.get("outcome") != "READY" or status.get("target_pub") != target_pub.hex():
        raise FixtureError("target authority did not initialize its pinned synthetic counter")
    scope = make_scope(
        stage5["contract"], gateway_pub=_key_hex(gateway["gateway_pub"], "gateway public key"),
        target_pub=target_pub, operation_id=operation_id,
        expected_witness_state_digest=stage5["expected_witness_state_digest"],
    )
    owner_grant = grant(
        owner, scope=scope, grant_id="voidcell003-" + secrets.token_hex(12),
        not_before=now, expires_at=stage5["contract"]["expires_at"],
    )
    metadata = _target_state_metadata(target_state, anchor, config)
    record = make_owner_handoff(
        owner, source=source, created_at=now,
        gateway_reference_sha256=handoff_sha256(reference_record),
        gateway_uid=gateway["gateway_uid"], gateway_gid=gateway["gateway_gid"],
        gateway_pub=_key_hex(gateway["gateway_pub"], "gateway public key"),
        target_uid=roles["target_uid"], target_gid=roles["target_gid"], target_pub=target_pub,
        socket_path=endpoint, target_state=metadata, contract=stage5["contract"],
        qualification=stage5["qualification"], broker_pub=stage5["broker_pub"],
        witness_pub=stage5["witness_pub"], supervisor_pub=stage5["supervisor_pub"],
        expected_witness_state_digest=stage5["expected_witness_state_digest"],
        terminal_witness_state_digest=stage5["terminal_witness_state_digest"],
        operation_id=operation_id, owner_grant=owner_grant,
    )
    _write_new(output, canon(record), 0o644)
    return {
        "outcome": "PREPARED", "custody": "UNMEASURED", "confinement": "BLOCKED",
        "handoff": str(output), "handoff_sha256": handoff_sha256(record),
        "owner_pub": owner.pub.hex(), "target_pub": target_pub.hex(),
        "gateway_pub": gateway["gateway_pub"], "gateway_uid": gateway["gateway_uid"],
        "target_uid": roles["target_uid"], "socket_path": endpoint,
        "source_revision": source,
    }


def _result_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "gateway-init":
        return gateway_init(args.state_dir, args.public_ref)
    return owner_init(
        target_state_dir=args.target_state_dir, anchor_dir=args.anchor_dir,
        qualification_dir=args.qualification_dir, gateway_ref=args.gateway_ref,
        handoff=args.handoff, socket_path=args.socket_path, consent=args.consent,
        expected_gateway_uid=args.expected_gateway_uid, expected_gateway_gid=args.expected_gateway_gid,
        expected_gateway_pub=_key_hex(args.expected_gateway_pub, "expected gateway public key"),
        operation_id=args.operation_id,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    gateway = commands.add_parser("gateway-init", help="create only the gateway private key and public reference")
    gateway.add_argument("--state-dir", required=True, type=Path)
    gateway.add_argument("--public-ref", required=True, type=Path)
    owner = commands.add_parser("owner-init", help="run a fresh fixed qualification and provision target handoff")
    owner.add_argument("--target-state-dir", required=True, type=Path)
    owner.add_argument("--anchor-dir", required=True, type=Path)
    owner.add_argument("--qualification-dir", required=True, type=Path)
    owner.add_argument("--gateway-ref", required=True, type=Path)
    owner.add_argument("--expected-gateway-uid", required=True, type=int)
    owner.add_argument("--expected-gateway-gid", required=True, type=int)
    owner.add_argument("--expected-gateway-pub", required=True)
    owner.add_argument("--handoff", required=True, type=Path)
    owner.add_argument("--socket-path", required=True, type=Path)
    owner.add_argument("--operation-id", default=DEFAULT_OPERATION_ID)
    owner.add_argument("--consent", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = _result_from_args(args)
    except UnsupportedWorker as exc:
        result = {"outcome": "UNSUPPORTED", "custody": "UNSUPPORTED", "reason": str(exc)}
    except (AuthorityError, FixtureError, OSError, ValueError, TypeError, RuntimeError) as exc:
        result = {"outcome": "BLOCKED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in {"PROVISIONED", "PREPARED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "DEFAULT_OPERATION_ID", "FixtureError", "GATEWAY_KEY_FILE", "GATEWAY_REFERENCE_DOMAIN",
    "GATEWAY_REFERENCE_SCHEMA", "OWNER_HANDOFF_DOMAIN", "OWNER_HANDOFF_SCHEMA", "gateway_init",
    "handoff_sha256", "load_gateway_signer", "load_owner_handoff", "make_gateway_reference",
    "make_owner_handoff", "owner_init", "split_role_preflight", "verify_gateway_reference",
    "verify_owner_handoff",
)
