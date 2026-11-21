"""Owner-provisioned target authority for the offline VOIDCELL counter."""

import argparse
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
from threading import Lock

from alibi import Signer, canon
from .clearance_records import _document
from .solitary_cli import _read, _unique_object, _write_new
from .stage3_evidence import _hex
from .voidcell import EffectVault
from .voidcell002_anchor import LedgerAnchor


KEY_FILE = "target.key"
LEDGER_FILE = "ledger.sqlite"
_CONFIG_FILE = "authority.json"
_WITNESS_FILE = "witness-head.json"
_INVENTORY_DOMAIN = b"wolfalibi/voidcell002/private-inventory/v1"
_KEY_FIELDS = ("owner_pub", "gateway_pub", "broker_pub", "witness_pub", "supervisor_pub")
_CONFIG_FIELDS = {
    *_KEY_FIELDS, "gateway_uid", "contract", "operation_id", "expected_witness_state_digest",
    "initial_witness_head",
}


class AuthorityError(RuntimeError):
    """The owner-controlled target state could not be verified."""


def _private_directory(path):
    path = Path(path).absolute()
    uid = os.geteuid()
    entry = path.lstat()
    if uid == 0 or not stat.S_ISDIR(entry.st_mode) or entry.st_uid != uid or stat.S_IMODE(entry.st_mode) != 0o700:
        raise AuthorityError("a private directory owned by a non-root target UID is required")
    for parent in path.parents:
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid)
                or (info.st_mode & 0o022 and not sticky_root)):
            raise AuthorityError("target state ancestors must exclude non-owner writes")
    return path


def _owner_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise AuthorityError("target state file must be regular, private and owner-controlled")
    return info


def _read_private(path, maximum):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        _owner_file(os.fstat(stream.fileno()))
        data = stream.read(maximum + 1)
    if not data or len(data) > maximum:
        raise AuthorityError("invalid target state file size")
    return data


def _json_private(path, maximum):
    return json.loads(_read_private(path, maximum), object_pairs_hook=_unique_object)


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def init_key(state_dir):
    """Generate the private target seed under the actual owner UID."""
    state = _private_directory(state_dir)
    seed = secrets.token_bytes(32)
    fd = os.open(state / KEY_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(seed)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(state)
    return Signer(seed).pub.hex()


def _checked_config(value):
    config = _document(value, "target authority configuration", max_bytes=65536)
    if config.keys() != _CONFIG_FIELDS:
        raise AuthorityError("exact target authority configuration required")
    uid = config["gateway_uid"]
    if type(uid) is not int or not 0 < uid < 2**31 or uid == os.geteuid():
        raise AuthorityError("a distinct non-root gateway UID is required")
    for name in (*_KEY_FIELDS, "expected_witness_state_digest", "initial_witness_head"):
        _hex(config[name], 32, name)
    return config


def _file_id(path):
    info = _owner_file(path.lstat())
    return (info.st_dev, info.st_ino)


def _static_file_state(path):
    info = _owner_file(path.lstat())
    return (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns)


def initialize(state_dir, anchor_dir, config):
    """Enroll a new counter with separately retained witness and ledger state."""
    with TargetAuthority(state_dir, anchor_dir, _new_config=config) as authority:
        return authority.status()


class TargetAuthority:
    """Keep target keys, effect ledger and retained checkpoint in the owner role."""

    def __init__(self, state_dir, anchor_dir, *, _new_config=None):
        self._state = _private_directory(state_dir)
        self._anchor_dir = _private_directory(anchor_dir)
        if (self._state == self._anchor_dir or self._state in self._anchor_dir.parents
                or self._anchor_dir in self._state.parents):
            raise AuthorityError("retain the anchor outside the target ledger directory")
        self._lock = Lock()
        self._resources = ExitStack()
        self._blocked = False
        try:
            self._open_state(_new_config)
        except BaseException:
            self._resources.close()
            raise

    def _open_state(self, new_config):
        lease = os.open(self._state / "authority.lock",
                        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        self._resources.callback(os.close, lease)
        _owner_file(os.fstat(lease))
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        seed = _read_private(self._state / KEY_FILE, 32)
        if len(seed) != 32:
            raise AuthorityError("invalid provisioned target key")
        signer = self._signer = Signer(seed)
        config_path = self._state / _CONFIG_FILE
        ledger = self._state / LEDGER_FILE
        witness = self._anchor_dir / _WITNESS_FILE
        config = (_checked_config(new_config) if new_config is not None
                  else _checked_config(_json_private(config_path, 65536)))
        self._anchor = self._resources.enter_context(LedgerAnchor(
            self._anchor_dir, signer=signer, authority_policy=canon(config),
        ))
        if new_config is not None:
            if any(os.path.lexists(path) for path in
                   (config_path, ledger, witness, self._anchor_dir / "ledger-anchor.json")):
                raise AuthorityError("initialization is create-only")
            _write_new(config_path, config)
            _write_new(witness, {"head": config["initial_witness_head"]})
        else:
            _file_id(ledger)
        self._gateway_uid = config["gateway_uid"]
        self._target_pub = signer.pub.hex()
        self._vault = self._resources.enter_context(EffectVault(
            ledger, signer=signer, contract=config["contract"], operation_id=config["operation_id"],
            expected_witness_state_digest=bytes.fromhex(config["expected_witness_state_digest"]),
            observe_witness_head=self._witness_head,
            **{name: bytes.fromhex(config[name]) for name in _KEY_FIELDS},
        ))
        self._ledger_id = _file_id(ledger)
        self._key_state = _static_file_state(self._state / KEY_FILE)
        self._config_state = _static_file_state(config_path)
        if new_config is None:
            self._anchor.verify(self._vault)
        else:
            self._anchor.initialize(self._vault)

    @property
    def gateway_uid(self):
        return self._gateway_uid

    @property
    def scope(self):
        return self._vault.scope

    def _witness_head(self):
        value = _json_private(self._anchor_dir / _WITNESS_FILE, 256)
        if type(value) is not dict or value.keys() != {"head"}:
            raise AuthorityError("invalid retained witness reference")
        return _hex(value["head"], 32, "witness head")

    def _files_unchanged(self):
        if (_file_id(self._state / LEDGER_FILE) != self._ledger_id
                or _static_file_state(self._state / KEY_FILE) != self._key_state
                or _static_file_state(self._state / _CONFIG_FILE) != self._config_state):
            raise AuthorityError("target ledger, signing key or authority configuration changed")

    def _inventory(self):
        directory = self._state.lstat()
        payload = {
            "type": "WOLFALIBI_VOIDCELL002_INVENTORY_V1", "pid": os.getpid(),
            "target_uid": os.geteuid(), "gateway_uid": self._gateway_uid,
            "state_device": str(directory.st_dev), "state_inode": str(directory.st_ino),
            "key_mode": stat.S_IMODE((self._state / KEY_FILE).lstat().st_mode),
            "ledger_mode": stat.S_IMODE((self._state / LEDGER_FILE).lstat().st_mode),
        }
        return {"payload": payload, "signature": self._signer.sign(_INVENTORY_DOMAIN, canon(payload)).hex()}

    def _invoke(self, action, packet=None):
        with self._lock:
            if not self._blocked:
                try:
                    self._files_unchanged()
                    self._anchor.verify(self._vault)
                    if action == "status":
                        return {
                            "outcome": "READY", "effect_count": self._vault.effect_count(),
                            "target_pub": self._target_pub, "target_uid": os.geteuid(), "pid": os.getpid(),
                            "gateway_uid": self._gateway_uid, "anchor": self._anchor.public_summary(),
                            "inventory": self._inventory(),
                        }
                    operation = {"dispatch": self._vault.dispatch, "reconcile": self._vault.reconcile,
                                 "revoke": self._vault.revoke}[action]
                    result = operation(packet)
                    self._files_unchanged()
                    self._anchor.advance(self._vault)
                    return result
                except (OSError, sqlite3.Error, ValueError, RuntimeError):
                    self._blocked = True
            return {"outcome": "BLOCKED", "reason": "TARGET_AUTHORITY_UNAVAILABLE", "effect_count": None}

    def dispatch(self, packet):
        return self._invoke("dispatch", packet)

    def reconcile(self, packet):
        return self._invoke("reconcile", packet)

    def revoke(self, packet):
        return self._invoke("revoke", packet)

    def status(self):
        return self._invoke("status")

    def close(self):
        with self._lock:
            self._blocked = True
            self._resources.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="report local custody prerequisites")
    probe = commands.add_parser("probe", help="exercise permissions from the provisioned gateway account")
    probe.add_argument("--target-uid", type=int, required=True)
    probe.add_argument("--target-pid", type=int, required=True)
    probe.add_argument("--state-dir", type=Path, required=True)
    probe.add_argument("--socket", type=Path, required=True)
    probe.add_argument("--target-pub", help="separately retained target public key")
    probe.add_argument("--inventory", type=Path, help="signed inventory from the owner-role ready record")
    key = commands.add_parser("init-key", help="generate a target key locally and print only the public key")
    key.add_argument("--state-dir", type=Path, required=True)
    for command in ("initialize", "status", "serve"):
        child = commands.add_parser(command)
        child.add_argument("--state-dir", type=Path, required=True)
        child.add_argument("--anchor-dir", type=Path, required=True)
        if command == "initialize":
            child.add_argument("--config", type=Path, required=True)
        if command == "serve":
            child.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = _command(args)
    except KeyboardInterrupt:
        return 0
    except (OSError, sqlite3.Error, ValueError, TypeError, RuntimeError):
        result = {"outcome": "BLOCKED", "reason": "TARGET_AUTHORITY_UNAVAILABLE"}
    if result is None:
        return 0
    print(json.dumps(result, sort_keys=True))
    return 2 if result["outcome"] in {"BLOCKED", "UNSUPPORTED"} else 0


def _command(args):
    if args.command == "doctor":
        from .voidcell002_probe import preflight
        return preflight()
    if args.command == "probe":
        from .voidcell002_probe import probe
        inventory = _read(args.inventory, 16384) if args.inventory is not None else None
        if isinstance(inventory, dict) and "inventory" in inventory:
            inventory = inventory["inventory"]
        target_pub = _hex(args.target_pub, 32, "target key") if args.target_pub is not None else None
        return probe(args.target_uid, target_pid=args.target_pid, state_dir=args.state_dir, socket_path=args.socket,
                     inventory=inventory, target_pub=target_pub)
    if args.command == "init-key":
        return {"outcome": "PROVISIONED", "target_pub": init_key(args.state_dir)}
    if args.command == "initialize":
        return initialize(args.state_dir, args.anchor_dir, _json_private(args.config, 65536))
    with TargetAuthority(args.state_dir, args.anchor_dir) as authority:
        if args.command == "status":
            return authority.status()
        from .voidcell002_transport import serve
        serve(authority, socket_path=args.socket, gateway_uid=authority.gateway_uid,
              on_ready=lambda *_: print(json.dumps(authority.status(), sort_keys=True), flush=True))
        return None


if __name__ == "__main__":
    raise SystemExit(main())
