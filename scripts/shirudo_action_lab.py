#!/usr/bin/env python3
"""Qualify the fixed counter action inside an approved disposable Shirudo VM.

The owner key and verifier key are separate, ephemeral host authorities. Every
assessment used here comes from genuine collected evidence and the pinned
official upstream verifier. The root-owned target gate and its private SQLite
state are trusted; they are installed after boot, not measured by the boot
quote. An unprivileged guest client can request only the bounded gate protocol.
"""

from __future__ import annotations

import argparse
import base64
import copy
import io
import os
from pathlib import Path
import secrets
import shlex
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from shirudo_adapter.action_gate import (  # noqa: E402
    ACTION, make_grant_payload, verify_effect_receipt,
)
from shirudo_adapter.model import (  # noqa: E402
    AdapterError, UPSTREAM_COMMIT, canonical_json, digest, strict_json, validate_policy,
)
from shirudo_adapter.receipt import sign_record, verify_record, verify_receipt  # noqa: E402
from shirudo_adapter.service import Service  # noqa: E402
from scripts.shirudo_real_lab import (  # noqa: E402
    ARCHIVE_SHA256, VERIFIER_SHA256, EnvironmentFailure, LabFailure, RealLab,
    bounded_command, check_receipt_bindings, expect_receipt, parse_input, read_input,
    require, sha256,
)

CODE = "/opt/wolfalibi-action-code"
PYTHON = "/opt/wolfalibi-action-venv/bin/python"
STATE = "/var/lib/wolfalibi-action"
SOCKET = "/run/wolfalibi-action/gate.sock"
CLIENT = "wolfalibi-action-client"
MAX_BUNDLE = 65_536
GATE_RUNNER = (
    f"import sys; sys.path.insert(0,{CODE!r}); "
    "from shirudo_adapter.action_gate_cli import main; raise SystemExit(main())"
)

# These fixed guest programs receive only public inputs. No submitted request
# is interpolated as Python or shell code. Host SSH arguments use shlex.join.
INSTALLER = r'''
import base64, hashlib, io, json, os, pathlib, re, sys, zipfile
destination = pathlib.Path('/opt/wolfalibi-action-code')
raw = base64.b64decode(sys.argv[1], validate=True)
assert len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == sys.argv[2]
assert os.geteuid() == 0 and not os.path.lexists(destination)
with zipfile.ZipFile(io.BytesIO(raw)) as archive:
    infos = archive.infolist()
    assert 2 <= len(infos) <= 32
    names = [item.filename for item in infos]
    assert len(names) == len(set(names)) and 'trust.json' in names
    assert 'shirudo_adapter/action_gate.py' in names
    assert 'shirudo_adapter/action_gate_cli.py' in names
    assert sum(item.file_size for item in infos) <= 1048576
    for item in infos:
        assert (item.filename == 'trust.json' or
                re.fullmatch(r'shirudo_adapter/[a-z_]+[.]py', item.filename))
        assert not item.is_dir() and item.file_size <= 262144
        assert ((item.external_attr >> 16) & 0o170000) in (0, 0o100000)
    os.umask(0o022)
    destination.mkdir(mode=0o755)
    (destination / 'shirudo_adapter').mkdir(mode=0o755)
    result = {}
    for item in infos:
        body = archive.read(item)
        path = destination / item.filename
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
        result[item.filename] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
import cryptography
print(json.dumps({'uid': os.geteuid(), 'files': result,
                  'python_version': sys.version.split()[0],
                  'cryptography_version': cryptography.__version__}, sort_keys=True))
'''

RPC_RUNNER = r'''
import base64, hashlib, json, subprocess, sys
body = base64.b64decode(sys.argv[1], validate=True)
assert len(body) <= 294912
run = subprocess.run([
    'runuser', '-u', 'wolfalibi-action-client', '--',
    '/opt/wolfalibi-action-venv/bin/python', '-I', '-c', sys.argv[2],
    'request', '--socket', '/run/wolfalibi-action/gate.sock', '--timeout', '5',
], input=body, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False)
assert len(run.stdout) <= 262145 and len(run.stderr) <= 65536
document = json.loads(run.stdout)
print(json.dumps({'client_exit_code': run.returncode, 'document': document,
                  'stderr_bytes': len(run.stderr),
                  'stderr_sha256': hashlib.sha256(run.stderr).hexdigest()}, sort_keys=True))
'''

ORACLE = r'''
import json, os, pathlib, sqlite3, stat, sys, time
directory = pathlib.Path('/var/lib/wolfalibi-action')
path = directory / 'journal.sqlite3'
conn = sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True)
conn.execute('BEGIN')
counter = conn.execute('SELECT value FROM counter WHERE id=1').fetchone()[0]
committed = conn.execute("SELECT COUNT(*) FROM operations WHERE status='COMMITTED'").fetchone()[0]
result = {'counter': counter, 'committed_operations': committed,
          'observed_at_ms': time.time_ns() // 1000000, 'reader_uid': os.geteuid(),
          'state_uid': directory.stat().st_uid, 'state_mode': stat.S_IMODE(directory.stat().st_mode),
          'database_uid': path.stat().st_uid, 'database_mode': stat.S_IMODE(path.stat().st_mode)}
if len(sys.argv) == 2:
    row = conn.execute('SELECT status,request_sha256,grant_id,assessment_sha256,receipt,'
                       'counter_before,counter_after FROM operations WHERE id=?',
                       (sys.argv[1],)).fetchone()
    result['operation'] = None if row is None else dict(zip(
        ('status','request_sha256','grant_id','assessment_sha256','receipt','counter_before','counter_after'), row))
    if row is not None and row[4] is not None:
        result['operation']['receipt'] = json.loads(row[4])
conn.close()
print(json.dumps(result, sort_keys=True))
'''

DIRECT_ACCESS = r'''
import errno, json, os
try:
    fd = os.open('/var/lib/wolfalibi-action/journal.sqlite3', os.O_WRONLY | os.O_APPEND)
except OSError as exc:
    result = {'uid': os.geteuid(), 'write_access': False, 'errno': exc.errno,
              'permission_denied': isinstance(exc, PermissionError) and exc.errno == errno.EACCES}
else:
    os.close(fd)
    result = {'uid': os.geteuid(), 'write_access': True, 'permission_denied': False}
print(json.dumps(result, sort_keys=True))
'''

CHECK_UNITS = r'''
import json, re, subprocess, sys
units = json.loads(sys.argv[1])
assert type(units) is list and len(units) <= 10
result = {}
for unit in units:
    assert re.fullmatch(r'wolfalibi-action-gate-[1-9][0-9]?[.]service', unit)
    proc = subprocess.run(['systemctl', 'show', unit, '--property=LoadState',
                           '--property=ActiveState', '--property=MainPID'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    fields = dict(line.split('=', 1) for line in proc.stdout.decode('ascii').splitlines() if '=' in line)
    fields['query_exit_code'] = proc.returncode
    result[unit] = fields
print(json.dumps(result, sort_keys=True))
'''

LIMITATIONS = [
    "LAB_VTPM: builder, hypervisor, vTPM state and operator remain trusted.",
    "LAB_OWNER_GRANT uses an ephemeral test signer; no human approval ceremony is implemented.",
    "Owner and verifier use distinct keys in the same trusted host harness; independent key custody is not qualified.",
    "The gate and Python dependencies are installed after boot and are not measured into the approved boot image.",
    "Gate root, private state, trusted signers and local clocks remain trusted; no coordinated rollback resistance is claimed.",
    "Freshness is bounded to 30 seconds with 2 seconds of clock skew; continuous state and quote-to-effect atomicity are not proved.",
    "The only effect is one SQLite counter increment; process-exit tests do not establish power-loss durability.",
    "Grants are bearer capabilities for a named operation; socket group membership restricts access but does not identify a particular agent process.",
    "Existing assessment and new effect receipts remain historical records, not current authorization.",
    "No production shield, general command runner, hardware identity or complete agent confinement is qualified.",
]

REQUIRED_CASES = frozenset({
    "authorized", "exact-retry", "attestation-reuse", "completed-operation-conflict",
    "assessment-alone", "grant-alone", "forged-owner", "forged-verifier",
    "widened-action", "wrong-target", "wrong-policy", "different-valid-assessment",
    "grant-revoked", "grant-expired", "operation-expired", "concurrent",
    "direct-database-access", "client-admin-denied", "before-commit-interruption",
    "before-commit-retry", "after-commit-lost-reply", "lost-reply-status-recovery",
    "lost-reply-exact-retry", "policy-revoked", "prepare-after-revocation",
    "historical-retry-after-revocation",
})


def bundle_source(trust: dict) -> tuple[bytes, dict]:
    """Select bounded public source explicitly; never archive a state tree."""
    entries = {f"shirudo_adapter/{path.name}": read_input(path, 262_144, "gate source")
               for path in sorted((ROOT / "shirudo_adapter").glob("*.py"))}
    entries["trust.json"] = canonical_json(trust) + b"\n"
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in entries.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, body)
    raw = stream.getvalue()
    require(len(raw) <= MAX_BUNDLE, "SOURCE_BUNDLE_LIMIT", "public source bundle")
    manifest = {name: {"sha256": sha256(body), "bytes": len(body)}
                for name, body in entries.items()}
    return raw, manifest


class ActionLab(RealLab):
    def __init__(self, upstream, vm_name, verifier, output):
        super().__init__(upstream, vm_name, verifier, output)
        self.units: list[str] = []
        self.current_unit: str | None = None
        self.daemons_stopped = True
        self.fresh_assessments = 0
        self.last_oracle = None
        self.client_uid = None
        self.client_gid = None
        self.identity = None
        self.owner = Ed25519PrivateKey.generate()
        self.policy = None
        self.policy_sha = None

    def guest(self, args, stage, *, timeout=60):
        """Known public commands only; retain bounded diagnostics on failure."""
        self.target_contact = True
        started = time.time_ns() // 1_000_000
        try:
            code, stdout, stderr = bounded_command([
                "make", "--silent", "--no-print-directory", "-C", "testing", "vm-ssh",
                f"VM_NAME={self.vm_name}", "VM_SSH_COMMAND=" + shlex.join(args),
            ], self.upstream, timeout=timeout)
        except EnvironmentFailure as exc:
            raise EnvironmentFailure(exc.code, stage) from exc
        record = {"stage": stage, "started_at_ms": started,
                  "completed_at_ms": time.time_ns() // 1_000_000,
                  "exit_code": code, "stdout_bytes": len(stdout), "stdout_sha256": sha256(stdout),
                  "stderr_bytes": len(stderr), "stderr_sha256": sha256(stderr)}
        if code != 0:
            # Our static programs handle only public records. No state file or
            # secret value is ever formatted in these diagnostics.
            record["public_error"] = stderr[-4096:].decode("utf-8", "replace")
        self.commands.append(record)
        require(code == 0, "GUEST_COMMAND_EXIT", stage, environment=True)
        return stdout

    def guest_json(self, args, stage):
        return parse_input(self.guest(args, stage), 262_144, stage)

    def admin(self, args, stage):
        return self.guest_json([PYTHON, "-I", "-c", GATE_RUNNER, *args], stage)

    def rpc(self, document, stage):
        wrapper = self.guest_json([
            PYTHON, "-I", "-c", RPC_RUNNER,
            base64.b64encode(canonical_json(document)).decode("ascii"), GATE_RUNNER,
        ], stage)
        require(set(wrapper) == {"client_exit_code", "document", "stderr_bytes", "stderr_sha256"}
                and wrapper["client_exit_code"] in (0, 2)
                and type(wrapper["document"]) is dict and wrapper["stderr_bytes"] == 0,
                "CLIENT_RESPONSE", stage)
        response = wrapper["document"]
        require((wrapper["client_exit_code"] == 2) == (response.get("status") == "AMBIGUOUS"),
                "TRANSPORT_STATUS", stage)
        return wrapper

    def setup_target(self, service):
        owner_public = self.owner.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        trust = {"schema": "wolfalibi.shirudo.action-trust.v1", "target_id": self.vm_name,
                 "owner_public_key": owner_public, "verifier_public_key": service.public_key_hex(),
                 "verifier_instance_id": service.instance_id, "policy": self.policy}
        self.artifacts.json("trust.json", trust)
        self.artifacts.json("policy.json", self.policy)
        raw, manifest = bundle_source(trust)
        self.artifacts.write("source/target-code.zip", raw)
        self.artifacts.json("source/manifest.json", manifest)
        observed = self.guest_json([
            PYTHON, "-I", "-c", INSTALLER, base64.b64encode(raw).decode("ascii"), sha256(raw)
        ], "install selected public gate source")
        require(observed.get("files") == manifest and observed.get("uid") == 0
                and observed.get("cryptography_version") == "50.0.0",
                "TARGET_SOURCE_OR_RUNTIME", "target source install")
        self.artifacts.json("source/target-installation.json", observed)
        self.guest(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir",
                    "/nonexistent", "--shell", "/usr/sbin/nologin", CLIENT], "create isolated client")
        self.client_uid = int(self.guest(["id", "-u", CLIENT], "client uid"))
        self.client_gid = int(self.guest(["id", "-g", CLIENT], "client gid"))
        require(self.client_uid > 0 and self.client_gid > 0, "CLIENT_PRIVILEGE", "client identity")
        self.guest(["install", "-d", "-m", "0755", "-o", "root", "-g", "root",
                    "/run/wolfalibi-action"], "create trusted socket parent")
        initialized = self.admin(["init", "--state", STATE, "--trust", CODE + "/trust.json"],
                                 "initialize private target state")
        require(initialized.get("status") == "INITIALIZED", "TARGET_INITIALIZATION", "target state")
        self.identity = initialized["identity"]
        require(self.identity["target_id"] == self.vm_name
                and self.identity["policy_sha256"] == self.policy_sha
                and self.identity["policy_generation"] == 1,
                "TARGET_IDENTITY", "pin target identity before grants")
        self.artifacts.json("target-identity.json", self.identity)
        self.artifacts.json("client-identity.json", {"user": CLIENT, "uid": self.client_uid,
                                                    "gid": self.client_gid})
        self.start()
        initial = self.oracle()
        require(initial["counter"] == 0, "COUNTER_BASELINE", "initial target counter")
        self.artifacts.json("initial-oracle.json", initial)

    def stop(self):
        if self.current_unit is not None:
            self.guest(["systemctl", "stop", self.current_unit], "stop owned gate daemon")
            self.current_unit = None

    def start(self, fault=None):
        self.stop()
        unit = f"wolfalibi-action-gate-{len(self.units) + 1}.service"
        self.units.append(unit)
        self.current_unit = unit
        self.daemons_stopped = False
        args = ["systemd-run", "--quiet", "--unit", unit, "--property=Type=exec",
                "--property=UMask=0077", "--property=NoNewPrivileges=yes",
                PYTHON, "-I", "-c", GATE_RUNNER, "serve", "--state", STATE,
                "--socket", SOCKET, "--socket-gid", str(self.client_gid),
                "--replace-stale-socket"]
        if fault is not None:
            require(fault in ("before", "after"), "FAULT_SELECTION", "harness")
            args.append(f"--exit-{fault}-commit-once")
        self.guest(args, "start owned gate daemon")
        for _ in range(20):
            response = self.rpc({"op": "status", "operation_id": None}, "gate readiness")
            if response["document"].get("status") == "STATUS":
                require(response["document"]["result"]["gate_instance_id"] == self.identity["gate_instance_id"],
                        "GATE_INSTANCE", "daemon restart")
                return
            time.sleep(0.1)
        raise EnvironmentFailure("GATE_START_TIMEOUT", "gate readiness")

    def oracle(self, operation_id=None):
        args = [PYTHON, "-I", "-c", ORACLE]
        if operation_id is not None:
            args.append(operation_id)
        observed = self.guest_json(args, "independent readonly database observation")
        require(observed["reader_uid"] == 0 and observed["state_uid"] == 0
                and observed["database_uid"] == 0 and observed["state_mode"] == 0o700
                and observed["database_mode"] == 0o600,
                "PRIVATE_TARGET_STATE", "independent database observation")
        require(type(observed["counter"]) is int and observed["counter"] >= 0
                and observed["counter"] == observed["committed_operations"],
                "COUNTER_JOURNAL_CONSISTENCY", "independent database observation")
        self.last_oracle = observed
        return observed

    def material(self, service, name, *, grant_ttl_ms=30_000):
        challenge = service.issue_challenge(self.policy_sha)
        prepared = self.rpc({"op": "prepare", "attestation_challenge": challenge}, f"prepare {name}")
        require(prepared["document"].get("status") == "PREPARED", "PREPARE_DENIED", name)
        action = prepared["document"]["action_challenge"]
        payload = verify_record(action, self.identity["public_key"])
        expected = {"schema": "wolfalibi.shirudo.action-challenge.v1",
                    "gate_instance_id": self.identity["gate_instance_id"], "target_id": self.vm_name,
                    "policy_sha256": self.policy_sha, "policy_generation": 1, "action": ACTION,
                    "attestation_challenge_sha256": digest(challenge),
                    "attestation_challenge_id": challenge["payload"]["challenge_id"],
                    "attestation_nonce": challenge["payload"]["nonce"]}
        require(all(payload.get(key) == value for key, value in expected.items()),
                "ACTION_CHALLENGE_BINDING", name)
        self.artifacts.json(f"materials/{name}/attestation-challenge.json", challenge)
        self.artifacts.json(f"materials/{name}/action-challenge.json", action)
        evidence = self.collect(challenge, "action-" + name)
        path = self.artifacts.write(f"materials/{name}/evidence.json", evidence)
        assessment = service.assess_file(challenge["payload"]["challenge_id"], path, str(self.verifier))
        expect_receipt(assessment, outcome="EVIDENCE_ACCEPTED", reason="REQUIRED_CHECKS_PASSED")
        check_receipt_bindings(assessment, self.policy, challenge, evidence)
        check = verify_receipt(assessment, service.public_key_hex(), expected_target=self.vm_name,
                               expected_policy_sha256=self.policy_sha,
                               expected_challenge_id=challenge["payload"]["challenge_id"])
        require(check["signature_valid"] and not check["current_authorization"]
                and service.get_receipt(challenge["payload"]["challenge_id"]) == assessment,
                "ASSESSMENT_VERIFICATION", name)
        self.artifacts.json(f"materials/{name}/assessment.json", assessment)
        self.artifacts.json(f"materials/{name}/assessment-verification.json", check)
        now = time.time_ns() // 1_000_000
        expires = min(payload["expires_at_ms"], now + grant_ttl_ms)
        require(expires > now, "AUTHORITY_EXPIRED_DURING_COLLECTION", name, environment=True)
        grant = sign_record(self.owner, make_grant_payload(action, assessment,
            grant_id=secrets.token_hex(16), issued_at_ms=now, expires_at_ms=expires))
        request = {"operation_id": payload["operation_id"], "grant": grant, "assessment": assessment}
        self.artifacts.json(f"materials/{name}/grant.json", grant)
        self.artifacts.json(f"materials/{name}/request.json", request)
        self.fresh_assessments += 1
        self.positive_accepted = True
        return {"name": name, "challenge": challenge, "action": action, "request": request}

    def verify_effect(self, response, material, oracle):
        request = material["request"]
        receipt = response["receipt"]
        result = verify_effect_receipt(receipt, self.identity["public_key"],
            expected_target=self.vm_name, expected_gate_instance_id=self.identity["gate_instance_id"],
            expected_operation_id=request["operation_id"],
            expected_grant_id=request["grant"]["payload"]["grant_id"],
            expected_grant_sha256=digest(request["grant"]),
            expected_assessment_sha256=digest(request["assessment"]),
            expected_action_challenge=material["action"])
        operation = oracle.get("operation")
        require(operation is not None and operation["status"] == "COMMITTED"
                and operation["receipt"] == receipt and operation["request_sha256"] == digest(request)
                and operation["grant_id"] == request["grant"]["payload"]["grant_id"]
                and operation["assessment_sha256"] == digest(request["assessment"])
                and operation["counter_before"] == result["counter_before"]
                and operation["counter_after"] == result["counter_after"],
                "EFFECT_DATABASE_BINDING", material["name"])
        return result

    def record_case(self, name, before, after, *, delta, detail):
        require(after["counter"] - before["counter"] == delta
                and after["committed_operations"] - before["committed_operations"] == delta,
                "UNEXPECTED_COUNTER_DELTA", name)
        result = {"case": name, "result": "PASS", "expected_counter_delta": delta,
                  "observed_counter_delta": after["counter"] - before["counter"],
                  "before": before, "after": after, **detail}
        self.cases.append(result)
        self.artifacts.json(f"cases/{name}/result.json", result)
        return result

    def case(self, name, material, *, document=None, denial=None, outcome=None,
             delta=0, same_receipt=None, after_response=None):
        document = document if document is not None else {"op": "execute", "request": material["request"]}
        operation_id = material["request"]["operation_id"]
        before = self.oracle(operation_id)
        self.artifacts.json(f"cases/{name}/request.json", document)
        response = self.rpc(document, name)
        self.artifacts.json(f"cases/{name}/response.json", response)
        recovery = after_response() if after_response is not None else None
        after = self.oracle(operation_id)
        public = response["document"]
        detail = {"material": material["name"], "client_exit_code": response["client_exit_code"],
                  "response": public}
        if recovery is not None:
            detail["recovery_before_oracle"] = recovery
        if denial is not None:
            require(response["client_exit_code"] == 0 and public.get("status") == "DENIED"
                    and public.get("reason") == denial, "UNEXPECTED_DENIAL", name)
        elif outcome == "AMBIGUOUS":
            require(response["client_exit_code"] == 2 and public.get("status") == "AMBIGUOUS"
                    and public.get("reason") == "TRANSPORT_LOST", "EXPECTED_AMBIGUITY", name)
        else:
            require(response["client_exit_code"] == 0 and public.get("result") == outcome,
                    "UNEXPECTED_EXECUTION_RESULT", name)
            detail["receipt_verification"] = self.verify_effect(public, material, after)
            if delta == 1:
                require(public["receipt"]["payload"]["counter_before"] == before["counter"]
                        and public["receipt"]["payload"]["counter_after"] == after["counter"],
                        "EFFECT_COUNTER_DELTA", name)
            if same_receipt is not None:
                require(public["receipt"] == same_receipt, "RETRY_RECEIPT_CHANGED", name)
        self.record_case(name, before, after, delta=delta, detail=detail)
        return public

    def altered(self, material, *, grant_change=None, assessment=None, owner=None):
        changed = copy.deepcopy(material)
        if assessment is not None:
            changed["request"]["assessment"] = assessment
            changed["request"]["grant"]["payload"]["attestation_receipt_sha256"] = digest(assessment)
        if grant_change:
            grant_change(changed["request"]["grant"]["payload"])
        changed["request"]["grant"] = sign_record(owner or self.owner, changed["request"]["grant"]["payload"])
        return changed

    def wait_expiry(self, timestamp):
        for _ in range(40):
            observed = self.oracle()
            if observed["observed_at_ms"] >= timestamp:
                return observed
            time.sleep(min(1, (timestamp - observed["observed_at_ms"]) / 1000 + 0.02))
        raise EnvironmentFailure("CLOCK_EXPIRY_TIMEOUT", "actual target clock")

    def fault_status(self, expected):
        raw = self.guest(["systemctl", "show", self.current_unit, "--property=ActiveState",
                          "--property=ExecMainCode", "--property=ExecMainStatus"], "owned daemon process exit")
        status = dict(line.split("=", 1) for line in raw.decode("ascii").splitlines() if "=" in line)
        require(status.get("ActiveState") == "failed" and status.get("ExecMainCode") == "1"
                and status.get("ExecMainStatus") == str(expected), "FAULT_EXIT_STATUS", "owned daemon fault")
        self.artifacts.json(f"faults/exit-{expected}.json", {"unit": self.current_unit, **status})

    def run_action_cases(self, service):
        # Hold one genuinely assessed operation until real target time expires.
        expiring = self.material(service, "operation-expiry")
        positive = self.material(service, "authorized")
        committed = self.case("authorized", positive, outcome="COMMITTED", delta=1)
        self.case("exact-retry", positive, outcome="ALREADY_COMMITTED", same_receipt=committed["receipt"])
        self.case("attestation-reuse", positive, denial="ATTESTATION_REUSED",
                  document={"op": "prepare", "attestation_challenge": positive["challenge"]})
        changed = self.altered(positive, grant_change=lambda p: p.update(grant_id=secrets.token_hex(16)))
        self.case("completed-operation-conflict", changed, denial="OPERATION_CONFLICT")

        missing = self.material(service, "missing-authority")
        for field, name in (("grant", "assessment-alone"), ("assessment", "grant-alone")):
            request = copy.deepcopy(missing["request"])
            del request[field]
            self.case(name, missing, denial="INVALID_SCHEMA", document={"op": "execute", "request": request})

        signatures = self.material(service, "signatures")
        wrong_owner = self.altered(signatures, owner=Ed25519PrivateKey.generate())
        self.case("forged-owner", wrong_owner, denial="INVALID_SIGNATURE")
        forged = sign_record(Ed25519PrivateKey.generate(), signatures["request"]["assessment"]["payload"])
        self.case("forged-verifier", self.altered(signatures, assessment=forged), denial="INVALID_SIGNATURE")

        bounded = self.material(service, "bounded-action")
        self.case("widened-action", self.altered(bounded, grant_change=lambda p: p["action"].update(delta=2)),
                  denial="INVALID_SCHEMA")
        self.case("wrong-target", self.altered(bounded, grant_change=lambda p: p.update(target_id="other-lab-target")),
                  denial="GRANT_MISMATCH")
        self.case("wrong-policy", self.altered(bounded, grant_change=lambda p: p.update(policy_sha256="0" * 64)),
                  denial="GRANT_MISMATCH")

        other = self.material(service, "different-assessment")
        self.case("different-valid-assessment", self.altered(other, assessment=positive["request"]["assessment"]),
                  denial="RECEIPT_SCOPE_MISMATCH")

        revoked = self.material(service, "grant-revocation")
        admin = self.admin(["revoke-grant", "--state", STATE, "--grant-id",
                            revoked["request"]["grant"]["payload"]["grant_id"]], "revoke owner grant")
        self.artifacts.json("cases/grant-revoked/admin-result.json", admin)
        self.case("grant-revoked", revoked, denial="GRANT_REVOKED")

        short = self.material(service, "grant-expiry", grant_ttl_ms=1000)
        waited = self.wait_expiry(short["request"]["grant"]["payload"]["expires_at_ms"])
        self.artifacts.json("cases/grant-expired/expiry-observation.json", waited)
        self.case("grant-expired", short, denial="GRANT_EXPIRED")
        waited = self.wait_expiry(expiring["action"]["payload"]["expires_at_ms"])
        self.artifacts.json("cases/operation-expired/expiry-observation.json", waited)
        self.case("operation-expired", expiring, denial="OPERATION_EXPIRED")

        concurrent = self.material(service, "concurrent")
        before = self.oracle(concurrent["request"]["operation_id"])
        document = {"op": "execute", "request": concurrent["request"]}
        self.artifacts.json("cases/concurrent/request.json", document)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.rpc, document, f"concurrent request {index}") for index in range(2)]
            responses = [future.result() for future in futures]
        after = self.oracle(concurrent["request"]["operation_id"])
        require(all(item["client_exit_code"] == 0 for item in responses)
                and sorted(item["document"].get("result", "") for item in responses) ==
                    ["ALREADY_COMMITTED", "COMMITTED"]
                and responses[0]["document"]["receipt"] == responses[1]["document"]["receipt"],
                "CONCURRENT_SINGLE_EFFECT", "concurrent requests")
        verification = self.verify_effect(responses[0]["document"], concurrent, after)
        self.record_case("concurrent", before, after, delta=1,
                         detail={"material": concurrent["name"], "responses": responses,
                                 "receipt_verification": verification})

        before = self.oracle()
        denied = self.guest_json(["runuser", "-u", CLIENT, "--", PYTHON, "-I", "-c", DIRECT_ACCESS],
                                 "unprivileged direct database access")
        after = self.oracle()
        require(denied.get("uid") == self.client_uid and denied.get("write_access") is False
                and denied.get("permission_denied") is True,
                "DIRECT_DATABASE_ACCESS", "client privilege boundary")
        self.record_case("direct-database-access", before, after, delta=0, detail={"observation": denied})
        self.case("client-admin-denied", positive, document={"op": "revoke-policy"}, denial="UNKNOWN_OPERATION")

        self.start(fault="before")
        interrupted = self.material(service, "before-commit")
        def recover_before_commit():
            self.fault_status(70)
            # Opening the trusted gate performs SQLite's normal hot-journal
            # rollback if needed. The subsequent oracle remains read-only;
            # opening a hot journal in read-only mode can itself fail.
            self.start()
            return "DAEMON_RESTART_AND_SQLITE_CRASH_RECOVERY; NO_EXECUTION_REQUEST"
        self.case("before-commit-interruption", interrupted, outcome="AMBIGUOUS", delta=0,
                  after_response=recover_before_commit)
        self.case("before-commit-retry", interrupted, outcome="COMMITTED", delta=1)

        self.start(fault="after")
        lost = self.material(service, "after-commit")
        self.case("after-commit-lost-reply", lost, outcome="AMBIGUOUS", delta=1)
        self.fault_status(71)
        self.start()
        before = self.oracle(lost["request"]["operation_id"])
        status = self.rpc({"op": "status", "operation_id": lost["request"]["operation_id"]},
                          "recover committed receipt after lost reply")
        after = self.oracle(lost["request"]["operation_id"])
        require(status["document"].get("status") == "STATUS", "RECOVERY_STATUS", "lost reply")
        operation = status["document"]["result"]["operation"]
        require(operation["status"] == "COMMITTED", "RECOVERY_COMMITTED", "lost reply")
        recovered = operation["receipt"]
        verification = self.verify_effect({"receipt": recovered}, lost, after)
        self.record_case("lost-reply-status-recovery", before, after, delta=0,
                         detail={"material": lost["name"], "response": status,
                                 "receipt_verification": verification})
        self.case("lost-reply-exact-retry", lost, outcome="ALREADY_COMMITTED", same_receipt=recovered)

        final = self.material(service, "policy-revocation")
        result = self.admin(["revoke-policy", "--state", STATE], "revoke target action policy")
        self.artifacts.json("cases/policy-revoked/admin-result.json", result)
        self.case("policy-revoked", final, denial="POLICY_REVOKED")
        challenge = service.issue_challenge(self.policy_sha)
        self.case("prepare-after-revocation", final, denial="POLICY_REVOKED",
                  document={"op": "prepare", "attestation_challenge": challenge})
        self.case("historical-retry-after-revocation", positive, outcome="ALREADY_COMMITTED",
                  same_receipt=committed["receipt"])

    def run(self):
        require(os.environ.get("GITHUB_ACTIONS") == "true"
                and os.environ.get("WOLFALIBI_DISPOSABLE_CI") == "1",
                "DISPOSABLE_CI_REQUIRED", "action lab arguments", environment=True)
        self.policy = self.prepare()
        self.policy["policy_id"] = "lab-counter-policy"
        self.policy["challenge_ttl_seconds"] = 30
        self.policy = validate_policy(self.policy)
        private_path = None
        try:
            with tempfile.TemporaryDirectory(prefix="wolfalibi-action-private-") as private:
                private_path = Path(private)
                private_path.chmod(0o700)
                self.state_removed = False
                service = Service.initialize(private_path / "verifier")
                self.policy_sha = service.register_policy(self.policy)
                self.setup_target(service)
                self.run_action_cases(service)
        finally:
            if private_path is not None:
                self.state_removed = not private_path.exists()
            if self.current_unit is not None:
                self.stop()
            if self.units:
                status = self.guest_json([PYTHON, "-I", "-c", CHECK_UNITS,
                                          canonical_json(self.units).decode("ascii")],
                                         "verify all owned daemons stopped")
                self.artifacts.json("cleanup/daemon-status.json", status)
                require(set(status) == set(self.units)
                        and all(item.get("MainPID") == "0"
                                and item.get("ActiveState") in ("inactive", "failed")
                                for item in status.values()),
                        "DAEMON_CLEANUP", "owned target processes")
            self.daemons_stopped = True
        require(self.state_removed, "PRIVATE_STATE_CLEANUP", "host verifier state")
        require(self.positive_accepted and self.fresh_assessments == 12
                and len(self.cases) == len(REQUIRED_CASES)
                and {case["case"] for case in self.cases} == REQUIRED_CASES
                and all(case["result"] == "PASS" for case in self.cases)
                and self.last_oracle is not None and self.last_oracle["counter"] == 4
                and self.last_oracle["committed_operations"] == 4,
                "INCOMPLETE_QUALIFICATION", "action cases")
        return self.finish("PASS")

    def finish(self, result, *, code=None, stage=None):
        summary = {"schema": "wolfalibi.shirudo.action-lab.v1", "result": result,
                   "assurance": "LAB_VTPM", "owner_authority": "LAB_OWNER_GRANT",
                   "source_commit": UPSTREAM_COMMIT, "verifier_sha256": VERIFIER_SHA256,
                   "verifier_archive_sha256": ARCHIVE_SHA256,
                   "positive_evidence_accepted": self.positive_accepted,
                   "fresh_genuine_assessments": self.fresh_assessments,
                   "target_contact": self.target_contact,
                   "target_state_changes": "LAB_SETUP_AND_COUNTER",
                   "protected_effect": "SQLITE_COUNTER_INCREMENT_BY_ONE",
                   "private_adapter_state_removed": self.state_removed,
                   "gate_daemons_stopped": self.daemons_stopped,
                   "target_identity": self.identity, "final_oracle": self.last_oracle,
                   "action": ACTION, "cases": self.cases, "limitations": LIMITATIONS,
                   "current_authorization": False, "hardware_qualification": False,
                   "gate_measured_into_boot_image": False, "human_approval_implemented": False}
        if code is not None:
            summary.update(failure_code=code, failure_stage=stage)
        self.artifacts.json("commands.json", self.commands)
        self.artifacts.json("summary.json", summary)
        self.artifacts.json("artifact-manifest.json", {
            "schema": "wolfalibi.shirudo.public-artifacts.v1", "files": dict(self.artifacts.files),
            "private_state_exported": False})
        return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    lab = None
    try:
        lab = ActionLab(args.upstream, args.vm_name, args.verifier, args.output)
        summary, code = lab.run(), 0
    except LabFailure as exc:
        code = exc.exit_code
        summary = lab.finish(exc.result, code=exc.code, stage=exc.stage) if lab else {
            "schema": "wolfalibi.shirudo.action-lab.v1", "result": exc.result,
            "failure_code": exc.code, "failure_stage": exc.stage}
    except (AdapterError, OSError, UnicodeError, KeyError, TypeError, ValueError) as exc:
        code = 2
        failure = exc.code if isinstance(exc, AdapterError) else type(exc).__name__
        summary = lab.finish("BLOCKED_ENVIRONMENT", code=failure, stage="action harness") if lab else {
            "schema": "wolfalibi.shirudo.action-lab.v1", "result": "BLOCKED_ENVIRONMENT",
            "failure_code": failure}
    print(canonical_json(summary).decode("ascii"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
