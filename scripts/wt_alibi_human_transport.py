"""Fixed public transports to the selected disposable lab roles and VM."""

from __future__ import annotations

from base64 import b64decode
import os
from pathlib import Path
import shlex

from scripts.shirudo_prototype_host import selected_run
from scripts.shirudo_real_lab import LabFailure, bounded_command, require
from shirudo_adapter.model import (
    AdapterError, MAX_EVIDENCE_BYTES, MAX_RECORD_BYTES, UPSTREAM_COMMIT, canonical_json,
    exact_keys, read_bounded_file, require_hex, strict_json,
)
from shirudo_adapter.runner import MAX_REPORT_BYTES

ROOT = Path(__file__).resolve().parents[1]

# The remote shell sees constant commands. One bounded public JSON document
# travels on stdin. Fields in that document never enter a shell command.
GUEST_CLIENT = """
from pathlib import Path
import sys
sys.path.insert(0, '/run/wolfalibi/image/opt/wolfalibi')
from shirudo_adapter.action_gate_cli import MAX_REQUEST_BYTES, request
from shirudo_adapter.model import canonical_json, strict_json
document = strict_json(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1), MAX_REQUEST_BYTES)
operations = ('prepare',) if sys.argv[1] == 'prepare' else ('execute', 'status')
if type(document) is not dict or document.get('op') not in operations:
    raise SystemExit(2)
socket = Path('/var/lib/wolfalibi-prototype/socket/gate.sock')
result, code = request(socket, document, timeout=4)
sys.stdout.buffer.write(canonical_json(result) + b'\\n')
raise SystemExit(code)
"""
GUEST_COLLECTOR = """
import json, os, re, subprocess, sys
document = json.loads(sys.stdin.buffer.read(257))
if (type(document) is not dict or set(document) != {'nonce', 'challenge_id'}
        or not re.fullmatch('[0-9a-f]{64}', document['nonce'])
        or not re.fullmatch('[0-9a-f]{32}', document['challenge_id'])):
    raise SystemExit(2)
path = '/mnt/shirudo-out/wolfalibi-' + document['challenge_id'] + '.json'
if os.path.lexists(path):
    raise SystemExit(2)
subprocess.run(['/usr/local/bin/shirudo-runtime', 'attest', '--nonce=' + document['nonce'],
    '--output=' + path], check=True, timeout=20, stdin=subprocess.DEVNULL)
"""
GUEST_CLIENT_ARGV = ("/usr/sbin/runuser", "-u", "wolfproto-client", "--",
                     "/usr/bin/python3", "-I", "-B", "-c", GUEST_CLIENT)
GUEST_COMMANDS = {
    "prepare": shlex.join((*GUEST_CLIENT_ARGV, "prepare")),
    "client": shlex.join((*GUEST_CLIENT_ARGV, "control")),
    "collect": shlex.join(("/usr/bin/python3", "-I", "-B", "-c", GUEST_COLLECTOR)),
    "observe": "/usr/bin/python3 -I -B - /var/lib/wolfalibi-prototype/state/gate/journal.sqlite3",
}


class LabGuest:
    """Fixed loopback SSH entrypoints on the selected, pinned disposable VM."""

    def __init__(self, upstream, vm_name):
        self.upstream = Path(upstream).resolve(strict=True)
        self.vm_name = vm_name
        require(vm_name == f"wolfalibi-prototype-{selected_run()}",
                "CI_TARGET", "handoff target", environment=True)
        for args, expected in ((["rev-parse", "HEAD"], UPSTREAM_COMMIT.encode()),
                               (["status", "--porcelain", "--untracked-files=no"], b"")):
            code, raw, _ = bounded_command(["git", "--no-replace-objects", "-c", "core.fsmonitor=false", *args],
                                           self.upstream, timeout=5)
            require(code == 0 and raw.strip() == expected, "SOURCE_REVISION",
                    "pinned Shirudo checkout", environment=True)

    def invoke(self, name, data, timeout, *, stdout_limit=MAX_RECORD_BYTES):
        argv = ["/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C",
                f"VM_NAME={self.vm_name}", "VM_SSH_COMMAND=" + GUEST_COMMANDS[name],
                str(self.upstream / "testing/vm/run.sh"), "--ssh"]
        return bounded_command(argv, self.upstream, timeout=timeout, stdout_limit=stdout_limit, input_data=data)

    def client(self, document, *, timeout=8, endpoint="client"):
        try:
            code, raw, _ = self.invoke(endpoint, canonical_json(document), timeout)
            reply = strict_json(raw, MAX_RECORD_BYTES)
            if code == 0 and type(reply) is dict:
                return reply
            if code == 2 and type(reply) is dict and reply.get("status") == "AMBIGUOUS":
                return reply
        except (AdapterError, LabFailure):
            pass
        return {"status": "AMBIGUOUS", "reason": "TRANSPORT_LOST"}

    def observe(self):
        source = read_bounded_file(ROOT / "scripts/wt_alibi_human_oracle.py", 16_384)
        code, raw, _ = self.invoke("observe", source, 8, stdout_limit=1_048_576)
        require(code == 0, "JOURNAL_OBSERVATION", "independent guest SQLite query", environment=True)
        return strict_json(raw, 1_048_576)


class LabCollection:
    """Invoke the verifier CLI under its own UID and the target through its lab client."""

    def __init__(self, guest, roles):
        self.guest = guest
        self.roles = roles

    def verifier(self, args, timeout, accepted, limit=MAX_RECORD_BYTES):
        code, raw, _ = bounded_command(self.roles.argv("verifier", args), ROOT,
                                       timeout=timeout, stdout_limit=limit)
        value = strict_json(raw, limit)
        if code not in accepted or type(value) is not dict:
            raise AdapterError("VERIFIER_CLI", "Verifier role could not complete its public operation")
        return value

    def challenge(self, policy_sha, timeout):
        return self.verifier(["challenge", "--policy-sha256", policy_sha], timeout, (0,))

    def prepare(self, challenge, timeout):
        result = self.guest.client({"op": "prepare", "attestation_challenge": challenge},
                                   timeout=timeout, endpoint="prepare")
        if result.get("status") != "PREPARED":
            raise AdapterError("PREPARE_UNAVAILABLE", "The target did not return its signed operation challenge")
        exact_keys(result, {"status", "action_challenge"}, "target prepare reply")
        return result["action_challenge"]

    def collect(self, challenge_id, nonce, timeout):
        require_hex(challenge_id, 32, "challenge ID")
        require_hex(nonce, 64, "collection nonce")
        name = f"wolfalibi-{challenge_id}.json"
        path = self.guest.upstream / "build/test-vm/vms" / self.guest.vm_name / "result" / name
        if os.path.lexists(path):
            raise AdapterError("EVIDENCE_EXISTS", "This challenge already has an evidence file")
        code, _, _ = self.guest.invoke("collect", canonical_json({"challenge_id": challenge_id, "nonce": nonce}), timeout)
        if code:
            raise AdapterError("EVIDENCE_COLLECTION", "The selected target's Shirudo collector failed")
        return read_bounded_file(path, MAX_EVIDENCE_BYTES)

    def assess(self, challenge_id, evidence, timeout):
        path = self.roles.public(f"handoff-{challenge_id}-evidence.json", evidence)
        response_limit = MAX_RECORD_BYTES + 2 * MAX_REPORT_BYTES
        result = self.verifier(["verify", "--challenge-id", challenge_id, "--evidence", str(path),
                                "--verifier", str(self.roles.verifier), "--include-upstream-report"],
                               timeout, (0, 1), response_limit)
        exact_keys(result, {"receipt", "upstream_report_base64"}, "verifier report reply")
        raw = result["upstream_report_base64"]
        if raw is None:
            return result["receipt"], None
        try:
            return result["receipt"], b64decode(raw, validate=True)
        except (TypeError, ValueError) as exc:
            raise AdapterError("UPSTREAM_REPORT", "Malformed upstream report encoding") from exc
