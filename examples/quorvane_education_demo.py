"""Run the fixed fictional education service with separate local processes."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from alibi import Signer, canon
from wolfalibi import education_records, education_transport
from wolfalibi.education_records import digest, verify_receipt
from wolfalibi.stage3_evidence import _hex


FICTIONAL_RESPONSE = {"student_ref": "fictional-aster", "support_level": "scheduled-check-in"}
_ROOT = Path(__file__).resolve().parents[1]
_PYTHON = Path(sys.executable).absolute()
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
_MAX_RECORD = 65_536
_INIT_KEY = (
    "from importlib import import_module; from pathlib import Path; from sys import argv; "
    "print(import_module(argv[1]).init_key(Path(argv[2])))"
)
_REVOKE = (
    "from importlib import import_module; from pathlib import Path; from sys import argv; import json\n"
    "with getattr(import_module(argv[1]), argv[2])(Path(argv[3]), Path(argv[4])) as target:\n"
    "    print(json.dumps(target.revoke(argv[5])))\n"
)
_STATUS = (
    "from importlib import import_module; from pathlib import Path; from sys import argv; import json\n"
    "with getattr(import_module(argv[1]), argv[2])(Path(argv[3]), Path(argv[4])) as target:\n"
    "    print(json.dumps(target.status()))\n"
)


class FixtureError(RuntimeError):
    """The owner-controlled local demonstration could not establish a control."""


def write_new(path, data):
    """Create one private fixture file without replacing an existing entry."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags, 0o600), "wb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _private_dir(path, mode=0o700):
    path.mkdir(mode=mode)
    path.chmod(mode)


def _read_json_line(stream):
    readable, _, _ = select.select((stream,), (), (), 8)
    if not readable:
        raise FixtureError("fixture child did not return a record")
    raw = stream.readline(_MAX_RECORD + 1)
    if not raw.endswith(b"\n") or len(raw) > _MAX_RECORD:
        raise FixtureError("fixture child record is unavailable")
    return json.loads(raw)


def _admin(snippet, *args):
    return subprocess.check_output(
        [str(_PYTHON), "-I", "-c", "import sys; sys.path.insert(0, sys.argv.pop(1)); " + snippet,
         str(_ROOT), *(str(arg) for arg in args)],
        cwd=_ROOT, env=_ENV, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8,
    )


def _stop(process, *, interrupt):
    if process is None:
        return
    if process.poll() is None and interrupt:
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=4)


class LocalFixture:
    """Provision, measure and supervise the caller and target of one local run."""

    extra_expectations = {}

    def __init__(self, root, *, challenge=None):
        if challenge is not None:
            _hex(challenge, 32, "controller challenge")
        self.challenge = secrets.token_hex(32) if challenge is None else challenge
        self.root = Path(root).resolve()
        self.target_state = self.root / "target"
        self.anchor = self.root / "anchor"
        self.control = self.root / "control"
        endpoint_dir = self.root / "endpoint"
        for directory in (self.target_state, self.anchor, self.control):
            _private_dir(directory)
        _private_dir(endpoint_dir, 0o711)
        self.endpoint = endpoint_dir / "target.sock"
        self.head_file = self.control / "witness-head"
        self.target = self.caller = None
        self.owner = Signer()
        self.supervisor = Signer()
        self.witness = Signer()

    def target_scope(self):
        return self.scope

    def start(self):
        target_pub = _admin(_INIT_KEY, self.target_module, self.target_state).decode("ascii").strip()
        command = [str(_PYTHON), "-I", str(self.caller_source), str(self.endpoint)]
        expected_source = hashlib.sha256(self.caller_source.read_bytes()).hexdigest()
        expected_executable = hashlib.sha256(_PYTHON.resolve().read_bytes()).hexdigest()
        self.caller = subprocess.Popen(
            command, cwd=_ROOT, env=_ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        announced = _read_json_line(self.caller.stdout)
        peer = self.transport.measure_peer(self.caller.pid)
        observed_argv = Path(f"/proc/{self.caller.pid}/cmdline").read_bytes()
        expected_argv = b"\0".join(os.fsencode(item) for item in command) + b"\0"
        expected_argv_sha256 = hashlib.sha256(expected_argv).hexdigest()
        observed_source = hashlib.sha256(self.caller_source.read_bytes()).hexdigest()
        if (peer["pid"] != self.caller.pid or peer["exe_sha256"] != expected_executable
                or observed_source != expected_source or peer["source_sha256"] != expected_source
                or observed_argv != expected_argv or peer["argv_sha256"] != expected_argv_sha256):
            raise FixtureError("fixed caller executable or source differs from the controller's expectation")
        self.caller_preflight = {
            "expected_executable_sha256": expected_executable, "observed_executable_sha256": peer["exe_sha256"],
            "expected_source_sha256": expected_source, "observed_source_sha256": peer["source_sha256"],
            "expected_argv_sha256": expected_argv_sha256, "observed_argv_sha256": peer["argv_sha256"],
            "fixed_argv_matched": True, "provenance": "TRUSTED_CONTROLLER_LAUNCH_SNAPSHOT",
        }
        self.scope = self.records.validate_scope({
            **self.scope_fields, "target_pub": target_pub,
            "run_id": secrets.token_hex(16), "challenge": self.challenge,
            "caller_pub": announced["caller_pub"], "request_id": secrets.token_hex(16),
        })
        now = int(time.time())
        self.approval = self.make_grant(start=now, end=now + 90)
        self.qualification = self.records.qualify(self.supervisor, self.witness, self.scope, peer, now, now + 90)
        head = self.records.digest(self.qualification)
        write_new(self.head_file, head.encode("ascii"))
        self.expectations = {
            "scope": self.scope, "owner_pub": self.owner.pub.hex(),
            "supervisor_pub": self.supervisor.pub.hex(), "witness_pub": self.witness.pub.hex(),
            "target_pub": target_pub, "peer": peer, "witness_head": head,
            **self.extra_expectations,
        }
        config = {
            **{key: self.expectations[key] for key in
               ("owner_pub", "supervisor_pub", "witness_pub", "peer")},
            "scope": self.target_scope(),
            "witness_head_path": str(self.head_file),
        }
        write_new(self.target_state / "config.json", canon(config))
        self.start_target(create=True)

    def start_target(self, *, create=False):
        if self.target is not None:
            raise FixtureError("target already started")
        command = [
            str(_PYTHON), "-m", self.transport.__name__, str(self.target_state),
            str(self.anchor), str(self.endpoint),
        ]
        if create:
            command.append("--create")
        self.target = subprocess.Popen(command, cwd=_ROOT, env=_ENV, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and self.target.poll() is None:
            if self.endpoint.is_socket():
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
                    channel.settimeout(0.25)
                    try:
                        channel.connect(str(self.endpoint))
                    except OSError:
                        pass
                    else:
                        return
            time.sleep(0.01)
        raise FixtureError("target did not open the dedicated local endpoint")

    def stop_target(self):
        target, self.target = self.target, None
        _stop(target, interrupt=True)

    def restart_target(self):
        self.stop_target()
        self.start_target()

    def revoke(self):
        """Run local target-owner administration with the service stopped."""
        if self.target is not None:
            raise FixtureError("stop the target before revoking a fixture grant")
        return json.loads(_admin(_REVOKE, self.target_module, self.target_class, self.target_state,
                                 self.anchor, self.grant_id))

    def offline_status(self):
        if self.target is not None:
            raise FixtureError("stop the target before checking its durable ledger")
        return json.loads(_admin(_STATUS, self.target_module, self.target_class, self.target_state, self.anchor))

    def retained_anchor(self):
        return (self.anchor / "ledger-anchor.json").read_bytes()

    def wait_for_checkpoint_change(self, previous):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and self.target is not None and self.target.poll() is None:
            if self.retained_anchor() != previous:
                return
            time.sleep(0.01)
        raise FixtureError("target checkpoint did not advance")

    def make_grant(self, *, signer=None, scope=None, start=None, end=None):
        now = int(time.time())
        return self.records.owner_grant(
            self.owner if signer is None else signer, self.scope if scope is None else scope,
            self.grant_id, now if start is None else start, now + 90 if end is None else end,
        )

    def invoke(self, mode=None, *, packet=None, grant=None, qualification=None, scope=None):
        if self.target is None or self.caller is None:
            raise FixtureError("caller or target not running")
        if self.caller.poll() is not None:
            raise FixtureError("original caller process exited and its enrollment is unusable")
        instruction = {
            "mode": self.action if mode is None else mode, "target_pid": self.target.pid,
            "scope": self.scope if scope is None else scope,
            "grant": self.approval if grant is None else grant,
            "qualification": self.qualification if qualification is None else qualification,
            "packet": packet,
        }
        try:
            self.caller.stdin.write(canon(instruction) + b"\n")
            self.caller.stdin.flush()
        except BrokenPipeError as error:
            raise FixtureError("original caller process exited and its enrollment is unusable") from error
        return _read_json_line(self.caller.stdout)

    def direct(self, packet):
        """Issue a fixture control from the controller's unauthorized PID."""
        if self.target is None:
            raise FixtureError("target not running")
        return self.transport.request(self.endpoint, self.action, packet, expected_target_pid=self.target.pid)

    def close(self):
        try:
            self.stop_target()
        finally:
            if self.caller is not None:
                try:
                    self.caller.stdin.close()
                finally:
                    _stop(self.caller, interrupt=False)
                    self.caller.stdout.close()
                    self.caller = None


class EducationFixture(LocalFixture):
    """Trusted controller for one measured run and one fictional record."""

    caller_source = _ROOT / "wolfalibi" / "education_fixture_caller.py"
    records = education_records
    transport = education_transport
    target_module = "wolfalibi.education_target"
    target_class = "EducationTarget"
    action = "read"
    grant_id = "fictional-support-grant"
    scope_fields = {
        "tenant": "fictional-school", "student": "fictional-aster", "purpose": "approved-support",
        "operation": "edu.student_record.read", "policy_version": "edu-gate-002.v1",
    }
    extra_expectations = {"response_sha256": digest(FICTIONAL_RESPONSE)}

    def verify(self, packet, response, receipt):
        return verify_receipt(
            receipt, target_pub=bytes.fromhex(self.expectations["target_pub"]),
            scope=self.scope, packet=packet, response=response,
        )


@contextmanager
def fixture(root, *, challenge=None, fixture_type=EducationFixture):
    resource = fixture_type(root, challenge=challenge)
    try:
        resource.start()
        yield resource
    finally:
        resource.close()


def _denial(value, reason):
    if value != {"outcome": "DENIED", "reason": reason}:
        raise FixtureError(f"a negative control did not return DENIED/{reason}")
    return value


def demo(root, *, expectations_out=None, challenge=None):
    with fixture(root, challenge=challenge) as resource:
        if expectations_out is not None:
            write_new(expectations_out, canon(resource.expectations) + b"\n")
        signed = resource.invoke("sign")["packet"]
        other_student_grant = resource.make_grant(scope=dict(resource.scope, student="fictional-other"))
        observed = {
            "wrong_peer": _denial(resource.direct(signed), "PEER_IDENTITY_MISMATCH"),
            "unsigned": _denial(resource.invoke("unsigned")["result"], "INVALID_TARGET_REQUEST"),
            "wrong_owner": _denial(
                resource.invoke("read", grant=resource.make_grant(signer=Signer()))["result"],
                "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED",
            ),
            "other_student_grant": _denial(
                resource.invoke("read", grant=other_student_grant)["result"],
                "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED",
            ),
        }
        delivered = resource.invoke()
        result, packet = delivered["result"], delivered["packet"]
        if result["outcome"] != "RELEASED" or result["response"] != FICTIONAL_RESPONSE:
            raise FixtureError("expected one fictional record release")
        receipt = result["receipt"]
        resource.verify(packet, result["response"], receipt)
        observed["authorized_read"] = result["outcome"]
        observed["replay"] = _denial(resource.invoke()["result"], "READ_ALREADY_RECORDED")
        resource.restart_target()
        reconciliation = resource.invoke("reconcile", packet=packet)["result"]
        if (reconciliation["outcome"] != "RECONCILED" or reconciliation["receipt"] != receipt
                or "response" in reconciliation):
            raise FixtureError("target did not reconcile to the original historical receipt")
        observed["restart_reconciliation"] = "SAME_RECEIPT_WITHOUT_RESPONSE"
        resource.stop_target()
        observed["committed_read_count"] = resource.offline_status()["release_count"]
        expected = {
            "wrong_peer": {"outcome": "DENIED", "reason": "PEER_IDENTITY_MISMATCH"},
            "unsigned": {"outcome": "DENIED", "reason": "INVALID_TARGET_REQUEST"},
            "wrong_owner": {"outcome": "DENIED", "reason": "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED"},
            "other_student_grant": {
                "outcome": "DENIED", "reason": "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED",
            },
            "authorized_read": "RELEASED",
            "replay": {"outcome": "DENIED", "reason": "READ_ALREADY_RECORDED"},
            "restart_reconciliation": "SAME_RECEIPT_WITHOUT_RESPONSE", "committed_read_count": 1,
        }
        if observed != expected:
            raise FixtureError("synthetic service controls did not match")
        return {
            "schema": "QUORVANE_EDUCATION_DEMO_V1", "outcome": "PASS",
            "assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
            "certification": "NOT_ISSUED", "confinement": "BLOCKED", "production": "BLOCKED",
            "caller_preflight": resource.caller_preflight,
            "expected": expected, "observed": observed,
            "evidence": {"packet": packet, "response": result["response"], "receipt": receipt},
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations-out", type=Path,
                        help="create-only file for separately retained pre-dispatch public pins")
    parser.add_argument("--challenge", help="optional controller-pinned 32-byte lowercase hex challenge")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or not hasattr(socket, "SCM_CREDENTIALS") or not hasattr(os, "pidfd_open"):
        result = {"outcome": "UNSUPPORTED", "reason": "LINUX_PEER_AND_PIDFD_REQUIRED"}
    else:
        try:
            with TemporaryDirectory(prefix="wolfalibi-education-") as root:
                result = demo(root, expectations_out=args.expectations_out, challenge=args.challenge)
        except (KeyError, ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
            result = {
                "outcome": "BLOCKED", "reason": "LOCAL_EDUCATION_FIXTURE_UNAVAILABLE",
                "diagnostic": str(error) if isinstance(error, FixtureError) else type(error).__name__,
            }
    print(canon(result).decode("ascii"))
    return 0 if result["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
