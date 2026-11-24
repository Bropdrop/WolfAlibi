#!/usr/bin/env python3
"""Disposable CI provisioning and public IPC for the Shirudo prototype.

This is a trusted laboratory administrator, not a confined agent. It may use
sudo to start separate Unix accounts. It never loads an owner or verifier
private key. The role programs alone create and use their private state.
"""

from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import pty
import re
import selectors
import signal
import subprocess
import sys
import termios
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shirudo_adapter.action_gate import ACTION  # noqa: E402
from shirudo_adapter.model import (  # noqa: E402
    UPSTREAM_COMMIT, canonical_json, read_bounded_file, strict_json,
)
from scripts.shirudo_real_lab import (  # noqa: E402
    EnvironmentFailure, VERIFIER_SHA256, bounded_command, require,
)

USERS = {"owner": "wolfproto-owner", "verifier": "wolfproto-verifier",
         "client": "wolfproto-client"}
MODULES = {"owner": "shirudo_adapter.owner_cli", "verifier": "shirudo_adapter.cli"}
MAX_PUBLIC = 1_048_576


def selected_run() -> str:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("WOLFALIBI_DISPOSABLE_CI") == "1",
            "DISPOSABLE_CI_REQUIRED", "host role provisioning", environment=True)
    run, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run) is not None
            and re.fullmatch(r"[1-9][0-9]{0,5}", attempt) is not None,
            "CI_RUN_ID", "host role provisioning", environment=True)
    return f"{run}-{attempt}"


def command(argv, *, accepted=(0,), timeout=30):
    code, out, err = bounded_command(argv, ROOT, timeout=timeout,
                                     stdout_limit=MAX_PUBLIC)
    if code not in accepted:
        # All commands here contain only public file paths and fixed programs.
        # Never dump environment, key files or process descriptors on failure.
        print(err[-4096:].decode("utf-8", "replace"), file=sys.stderr)
        raise EnvironmentFailure("ROLE_COMMAND_EXIT", str(argv[0]))
    return code, out


class Roles:
    def __init__(self, *, provision=False):
        self.run = selected_run()
        self.base = Path("/var/lib/wolfalibi-prototype") / self.run
        self.verifier = self.base / "official-shirudo"
        self.exchange = Path("/var/tmp") / f"wolfalibi-prototype-{self.run}"
        self.python = str(Path(sys.executable).resolve())
        if provision:
            require(not os.path.lexists(self.base) and not os.path.lexists(self.exchange),
                    "ROLE_STATE_EXISTS", "fresh laboratory roles", environment=True)
            command(["sudo", "-n", "install", "-d", "-m", "0755", "-o", "root", "-g", "root",
                     str(self.base)])
            self.exchange.mkdir(mode=0o755)
            for role, user in USERS.items():
                command(["sudo", "-n", "useradd", "--system", "--user-group", "--no-create-home",
                         "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", user])
                command(["sudo", "-n", "install", "-d", "-m", "0700", "-o", user, "-g", user,
                         str(self.base / role)])

    def argv(self, role, args):
        require(role in MODULES, "ROLE_NAME", "role invocation", environment=True)
        # Raise the limit after sudo's PAM session, then drop the UID without
        # a second PAM reset. The pinned upstream verifier needs this memlock
        # limit even though it performs evidence verification on the host.
        return ["sudo", "-n", "prlimit", "--memlock=unlimited:unlimited", "--",
                "setpriv", "--reuid=" + USERS[role], "--regid=" + USERS[role], "--init-groups",
                self.python, "-I", "-B", "-m",
                MODULES[role], *args, "--state", str(self.base / role / "state")]

    def invoke(self, role, args, *, accepted=(0,)):
        code, raw = command(self.argv(role, args), accepted=accepted)
        value = strict_json(raw, MAX_PUBLIC)
        require(type(value) is dict, "ROLE_OUTPUT", role, environment=True)
        return code, value

    def public(self, name, value):
        require(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", name) is not None,
                "PUBLIC_FILENAME", "role exchange", environment=True)
        data = value if isinstance(value, bytes) else canonical_json(value) + b"\n"
        require(len(data) <= MAX_PUBLIC, "PUBLIC_SIZE", "role exchange", environment=True)
        path = self.exchange / name
        fd, temporary = tempfile.mkstemp(prefix="public-", dir=self.exchange)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o644)
            # A completed regular file appears atomically, with no replace of
            # any preexisting intent or fresh bundle. Consumers never read a
            # partly written JSON document.
            os.link(temporary, path, follow_symlinks=False)
        finally:
            os.unlink(temporary)
        return path

    def identity(self):
        records = {}
        for role, user in USERS.items():
            _, uid = command(["id", "-u", user])
            _, gid = command(["id", "-g", user])
            records[role] = {"user": user, "uid": int(uid), "gid": int(gid)}
        require(len({r["uid"] for r in records.values()}) == 3
                and all(r["uid"] > 0 for r in records.values()),
                "ROLE_SEPARATION", "distinct non-root host accounts")
        return records

    def custody_controls(self):
        """Actual peer-UID EACCES probes, with no private file contents read."""
        probe = (
            "import errno,json,os,sys; results=[]\n"
            "for p in sys.argv[1:]:\n"
            " try:\n"
            "  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);os.close(fd);"
            "results.append({'path_role':p.split('/')[-3],'denied':False})\n"
            " except OSError as e:\n"
            "  results.append({'path_role':p.split('/')[-3],'denied':"
            "isinstance(e,PermissionError) and e.errno==errno.EACCES,'errno':e.errno})\n"
            "print(json.dumps({'uid':os.geteuid(),'probes':results},sort_keys=True))"
        )
        results = {}
        # Directory traversal itself must fail, independently of key filename.
        for reader, destinations in (("client", ("owner", "verifier")),
                                     ("verifier", ("owner",)), ("owner", ("verifier",))):
            paths = [str(self.base / dest / "state" / "signing.key") for dest in destinations]
            _, raw = command(["sudo", "-n", "-u", USERS[reader], "--", self.python,
                              "-I", "-c", probe, *paths])
            result = strict_json(raw, 16_384)
            require(result["uid"] > 0 and all(x["denied"] for x in result["probes"]),
                    "PRIVATE_KEY_ACCESS", reader)
            results[reader] = result
        return results


class OwnerTerminal:
    """A scripted controlling terminal for CI, explicitly not a human decision.

    stdout remains a bounded JSON-lines pipe. Prompts and typed input belong to
    the separate controlling terminal; nothing from stdin approves an action.
    """

    def __init__(self, argv):
        self.master, slave = pty.openpty()

        def terminal_session():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        try:
            self.process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=slave,
                close_fds=True, pass_fds=(slave,), preexec_fn=terminal_session,
                env=os.environ.copy(),
            )
        finally:
            os.close(slave)
        os.set_blocking(self.process.stdout.fileno(), False)
        os.set_blocking(self.master, False)
        self.buffer = bytearray()
        self.transcript = bytearray()
        self.records = []

    def send(self, text):
        require(type(text) is str and "\n" not in text and len(text) <= 128,
                "TTY_INPUT", "scripted owner terminal")
        os.write(self.master, (text + "\n").encode("ascii"))

    def event(self, *, timeout=30):
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(self.master, selectors.EVENT_READ, "terminal")
            while time.monotonic() < deadline:
                if b"\n" in self.buffer:
                    line, _, remaining = self.buffer.partition(b"\n")
                    self.buffer = bytearray(remaining)
                    value = strict_json(bytes(line), MAX_PUBLIC)
                    require(type(value) is dict, "OWNER_EVENT", "scripted terminal")
                    self.records.append(value)
                    return value
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    try:
                        data = os.read(key.fd, 16_384)
                    except OSError as exc:
                        if key.data == "terminal" and exc.errno == 5:
                            data = b""
                        else:
                            raise
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    dest = self.buffer if key.data == "stdout" else self.transcript
                    require(len(dest) + len(data) <= MAX_PUBLIC,
                            "OWNER_OUTPUT_LIMIT", "scripted terminal")
                    dest.extend(data)
                if not selector.get_map() and b"\n" not in self.buffer:
                    break
        raise EnvironmentFailure("OWNER_EVENT_TIMEOUT", "scripted terminal")

    def wait_prompt(self, text, *, timeout=10):
        deadline = time.monotonic() + timeout
        needle = text.encode("ascii")
        with selectors.DefaultSelector() as selector:
            selector.register(self.master, selectors.EVENT_READ)
            while needle not in self.transcript and time.monotonic() < deadline:
                for key, _ in selector.select(0.05):
                    try:
                        data = os.read(key.fd, 16_384)
                    except OSError:
                        data = b""
                    if not data:
                        raise EnvironmentFailure("OWNER_TTY_CLOSED", "scripted terminal prompt")
                    require(len(self.transcript) + len(data) <= MAX_PUBLIC,
                            "OWNER_OUTPUT_LIMIT", "scripted terminal prompt")
                    self.transcript.extend(data)
        require(needle in self.transcript, "OWNER_PROMPT_TIMEOUT", "scripted terminal", environment=True)

    def close(self):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        self.process.stdout.close()
        os.close(self.master)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def provision(verifier, output):
    roles = Roles(provision=True)
    _, owner = roles.invoke("owner", ["init"])
    _, verification = roles.invoke("verifier", ["init"])
    # The same immutable official verifier pin is enforced again by Service.
    import hashlib
    raw = read_bounded_file(verifier, 64 * 1024 * 1024)
    require(hashlib.sha256(raw).hexdigest() == VERIFIER_SHA256,
            "VERIFIER_DIGEST", "host bootstrap authorities")
    command(["sudo", "-n", "install", "-m", "0555", "-o", "root", "-g", "root",
             str(verifier.absolute()), str(roles.verifier)])
    require(hashlib.sha256(read_bounded_file(roles.verifier, 64 * 1024 * 1024)).hexdigest() == VERIFIER_SHA256,
            "VERIFIER_COPY_DIGEST", "public role-readable pinned executable")
    _, version_raw = command([str(roles.verifier), "version", "--version-id"])
    version = version_raw.decode("ascii").strip()
    require(re.fullmatch(r"[0-9a-f]{64}", version) is not None,
            "VERIFIER_VERSION", "host bootstrap authorities")
    owner_identity = owner.get("identity", owner)
    anchors = {
        "schema": "wolfalibi.shirudo.bootstrap-anchors.v1",
        "target_id": f"wolfalibi-prototype-{roles.run}",
        "owner_public_key": owner_identity["public_key"],
        "verifier_public_key": verification["public_key"],
        "verifier_instance_id": verification["instance_id"],
        "verifier": {"source_commit": UPSTREAM_COMMIT, "sha256": VERIFIER_SHA256,
                     "version_id": version},
        "assurance": "LAB_VTPM", "action": dict(ACTION),
        "max_challenge_ttl_seconds": 30, "config_pcr": 14,
    }
    output.mkdir(mode=0o755, parents=True, exist_ok=False)
    records = {"anchors.json": anchors, "owner-identity.json": owner_identity,
               "verifier-identity.json": verification, "role-identities.json": roles.identity()}
    for name, value in records.items():
        (output / name).write_bytes(canonical_json(value) + b"\n")
    print(canonical_json({"status": "PROVISIONED", "target_id": anchors["target_id"],
                          "role_separation": "SEPARATE_UID_AND_PROCESS",
                          "coordinator_authority": "TRUSTED_CI_ADMINISTRATOR",
                          "actual_human_approval": "NOT_RUN"}).decode("ascii"))


def cleanup():
    roles = Roles()
    # These exact fresh per-run directories were created by this helper. No
    # VM disk, unrelated directory, user account or external service is removed.
    command(["sudo", "-n", "rm", "-rf", "--", str(roles.base), str(roles.exchange)])
    require(not os.path.lexists(roles.base) and not os.path.lexists(roles.exchange),
            "PRIVATE_STATE_CLEANUP", "host roles")
    print('{"status":"REMOVED","secure_erasure_qualified":false}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("provision")
    init.add_argument("--verifier", type=Path, required=True)
    init.add_argument("--output", type=Path, required=True)
    commands.add_parser("cleanup")
    args = parser.parse_args()
    if args.command == "provision":
        provision(args.verifier, args.output)
    else:
        cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
