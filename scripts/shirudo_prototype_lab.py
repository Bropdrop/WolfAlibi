#!/usr/bin/env python3
"""Complete the bounded LAB prototype using genuine quotes and a scripted TTY.

The CI coordinator is a trusted administrator. Owner and verifier keys are
created and used only in their separate Unix processes. The gate executes
from a separate dm-verity image, whose root is bound by the Shirudo config.
No production deployment or actual human consent is represented by this run.
"""

from __future__ import annotations

import argparse
import base64
import copy
import os
from pathlib import Path
import secrets
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shirudo_adapter.action_gate import ACTION, verify_effect_receipt  # noqa: E402
from shirudo_adapter.bootstrap import validate_boot_report, verify_boot_policy  # noqa: E402
from shirudo_adapter.model import (  # noqa: E402
    AdapterError, MAX_EVIDENCE_BYTES, canonical_json, digest, strict_json, validate_policy,
)
from shirudo_adapter.receipt import verify_record, verify_receipt  # noqa: E402
from scripts.shirudo_real_lab import (  # noqa: E402
    LabFailure, EnvironmentFailure, RealLab, bounded_command, check_receipt_bindings,
    expect_receipt, parse_input, read_input, require, sha256,
)
from scripts.shirudo_prototype_host import OwnerTerminal, Roles, selected_run  # noqa: E402

IMAGE = "/run/wolfalibi/image"
NATIVE_MANIFEST = "/run/shirudo/config/etc/wolfalibi/gate-image.json"
WITNESS_MANIFEST = "/run/wolfalibi/config-witness/etc/wolfalibi/gate-image.json"
BOOT_REPORT = "/run/wolfalibi/image-boot.json"
STATE_PARENT = "/var/lib/wolfalibi-prototype/state"
SOCKET_PARENT = "/run/wolfalibi-prototype/socket"
SOCKET = SOCKET_PARENT + "/gate.sock"
GATE_USER = "wolfproto-gate"
CLIENT_USER = "wolfproto-client"
ENTRY = ["/usr/bin/python3", "-I", "-B", "-S", "/opt/wolfalibi/gate_entry.py"]

REQUIRED_CASES = frozenset({
    "measured-config-binding", "verity-wrong-root", "verity-corrupted-data",
    "unsigned-boot-policy", "boot-policy-root-mismatch", "private-key-separation",
    "immutable-execution", "gate-state-access-denied", "owner-declined",
    "owner-rejected-tampered-bundle", "owner-timeout", "owner-terminal-required",
    "forged-owner-grant", "authorized", "exact-retry", "lost-reply",
    "status-recovery", "owner-grant-recovery", "recovered-exact-retry",
})

LIMITATIONS = [
    "LAB_VTPM: the CI builder, administrator, hypervisor, vTPM and clocks remain trusted.",
    "The direct QEMU boot does not establish a measured UKI, Secure Boot or hardware identity.",
    "PCR14 binds the approved config containing the gate image root; trusted bootstrap and launcher observations link it to this process.",
    "The immutable interpreter image receives no Shirudo runtime authority; root and the gate UID remain trusted for writable private state.",
    "Separate UID and process custody is tested against peer accounts, not against the trusted CI administrator's sudo privileges.",
    "The approval interface is exercised by a scripted controlling terminal. Actual human approval is NOT_RUN.",
    "Freshness remains 30 seconds with 5-second admission and 2-second clock skew; continuous process identity and quote-to-effect atomicity are not proved.",
    "Only a SQLite counter increment by one is authorized. No shield deployment, general command, financial action or production readiness is qualified.",
    "The owner and target journals do not establish resistance to coordinated administrative rollback or power loss.",
    "Receipts are historical records. They do not confer current authorization or prove secure deletion of private state.",
]

RUN_JSON = r'''
import base64, hashlib, json, subprocess, sys
args=json.loads(base64.b64decode(sys.argv[1],validate=True))
assert isinstance(args,list) and 1<=len(args)<=80 and all(isinstance(x,str) and len(x)<20000 for x in args)
p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
assert len(p.stdout)<=262144 and len(p.stderr)<=65536
print(json.dumps({'exit_code':p.returncode,'document':json.loads(p.stdout),
 'stderr_bytes':len(p.stderr),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest(),
 'public_error':p.stderr[-4096:].decode('utf-8','replace') if p.returncode else ''},sort_keys=True))
'''

STORE_POLICY = r'''
import base64, hashlib, json, os, sys, tempfile
data=base64.b64decode(sys.argv[1],validate=True)
assert len(data)<=65536 and hashlib.sha256(data).hexdigest()==sys.argv[2]
assert sys.argv[3] in ('boot-policy.json','negative-manifest.json')
json.loads(data)
fd,name=tempfile.mkstemp(prefix='boot-policy-',dir='/var/lib/wolfalibi-prototype/state')
try:
 with os.fdopen(fd,'wb') as f:
  f.write(data);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o644)
 os.replace(name,'/var/lib/wolfalibi-prototype/state/'+sys.argv[3])
finally:
 if os.path.lexists(name):os.unlink(name)
print(json.dumps({'stored_sha256':hashlib.sha256(data).hexdigest()}))
'''

CLIENT_RPC = r'''
import base64, json, socket, struct, sys, time
data=base64.b64decode(sys.argv[1],validate=True)
assert 0<len(data)<=294912 and sys.argv[2] in ('read','drop')
def read_exact(s,n):
 out=bytearray()
 while len(out)<n:
  s.settimeout(max(0.001,deadline-time.monotonic()))
  chunk=s.recv(n-len(out))
  if not chunk:raise EOFError()
  out.extend(chunk)
 return bytes(out)
deadline=time.monotonic()+5
try:
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
  s.settimeout(5);s.connect('/run/wolfalibi-prototype/socket/gate.sock')
  s.sendall(struct.pack('!I',len(data))+data);s.shutdown(socket.SHUT_WR)
  if sys.argv[2]=='drop':
   result={'status':'AMBIGUOUS','code':'SCRIPTED_REPLY_NOT_READ'}
  else:
   length=struct.unpack('!I',read_exact(s,4))[0]
   assert 0<length<=262144
   result=json.loads(read_exact(s,length))
   assert s.recv(1)==b''
except (OSError,EOFError,ValueError,AssertionError):
 result={'status':'AMBIGUOUS','code':'TRANSPORT_LOST'}
print(json.dumps(result,sort_keys=True))
'''

ORACLE = r'''
import json, os, pathlib, sqlite3, stat, sys, time
root=pathlib.Path('/var/lib/wolfalibi-prototype/state/gate')
db=root/'journal.sqlite3'
c=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True);c.execute('BEGIN')
result={'counter':c.execute('SELECT value FROM counter WHERE id=1').fetchone()[0],
 'committed_operations':c.execute("SELECT COUNT(*) FROM operations WHERE status='COMMITTED'").fetchone()[0],
 'state_uid':root.stat().st_uid,'state_mode':stat.S_IMODE(root.stat().st_mode),
 'database_uid':db.stat().st_uid,'database_mode':stat.S_IMODE(db.stat().st_mode),
 'reader_uid':os.geteuid(),'observed_at_ms':time.time_ns()//1000000}
if len(sys.argv)==2:
 row=c.execute('SELECT status,request_sha256,grant_id,assessment_sha256,receipt,counter_before,counter_after FROM operations WHERE id=?',(sys.argv[1],)).fetchone()
 result['operation']=None if row is None else dict(zip(('status','request_sha256','grant_id','assessment_sha256','receipt','counter_before','counter_after'),row))
 if row is not None and row[4] is not None:result['operation']['receipt']=json.loads(row[4])
c.close();print(json.dumps(result,sort_keys=True))
'''

PROCESS_PROBE = r'''
import errno, json, os, pathlib, stat, subprocess, sys
pid=int(subprocess.check_output(['systemctl','show',sys.argv[1],'--property=MainPID','--value']))
assert pid>1
root=pathlib.Path('/run/wolfalibi/image');p=pathlib.Path('/proc')/str(pid)
status=dict(line.split(':',1) for line in (p/'status').read_text().splitlines() if ':' in line)
readonly=False;err=None
try:
 fd=os.open(root/'opt/wolfalibi/gate_entry.py',os.O_WRONLY);os.close(fd)
except OSError as e:readonly=e.errno==errno.EROFS;err=e.errno
maps=[]
for line in (p/'maps').read_text().splitlines():
 fields=line.split(None,5)
 if len(fields)==6 and fields[5].startswith('/') and int(fields[4])>0:
  entry=p/'map_files'/fields[0]
  maps.append({'path':fields[5],'device':os.stat(entry).st_dev})
result={'pid':pid,'uid':int(status['Uid'].split()[0]),'effective_capabilities':status['CapEff'].strip(),
 'command':(p/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0'),
 'image_device':root.stat().st_dev,'process_root_device':(p/'root').stat().st_dev,
 'process_root_inode':(p/'root').stat().st_ino,'image_inode':root.stat().st_ino,
 'executable_device':(p/'exe').stat().st_dev,'executable':os.readlink(p/'exe'),
 'file_mappings':maps,'root_write_open_denied_readonly':readonly,'root_write_errno':err,
 'mountinfo':(p/'mountinfo').read_text().splitlines()}
print(json.dumps(result,sort_keys=True))
'''

ACCESS_PROBE = r'''
import errno,json,os
try:
 fd=os.open('/var/lib/wolfalibi-prototype/state/gate/journal.sqlite3',os.O_WRONLY|os.O_APPEND);os.close(fd)
 result={'uid':os.geteuid(),'denied':False}
except OSError as e:result={'uid':os.geteuid(),'denied':isinstance(e,PermissionError) and e.errno==errno.EACCES,'errno':e.errno}
print(json.dumps(result,sort_keys=True))
'''

MANIFEST_PROBE = r'''
import hashlib,json,os,pathlib
root=pathlib.Path('/run/wolfalibi/image')
path=root/'etc/wolfalibi/image-files.json'
assert path.stat().st_size<=8388608
raw=path.read_bytes();obj=json.loads(raw)
canonical=json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
print(json.dumps({'canonical_sha256':hashlib.sha256(canonical).hexdigest(),
 'raw_sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),
 'same_image_device':path.stat().st_dev==root.stat().st_dev,
 'read_only':bool(os.statvfs(path).f_flag & os.ST_RDONLY)},sort_keys=True))
'''


class PrototypeLab(RealLab):
    def __init__(self, upstream, vm_name, verifier, output, *, build, authorities):
        self.build = parse_input(read_input(build / "build-result.json", 65536, "prototype build"),
                                 65536, "prototype build")
        super().__init__(upstream, vm_name, verifier, output, bundle=Path(self.build["bundle"]))
        require(vm_name == f"wolfalibi-prototype-{selected_run()}",
                "CI_TARGET", "prototype target", environment=True)
        self.roles = Roles()
        self.authorities = authorities
        self.anchors = parse_input(read_input(authorities / "anchors.json", 16384, "anchors"), 16384, "anchors")
        self.manifest = parse_input(read_input(Path(self.build["gate_image_manifest"]), 16384, "image manifest"),
                                    16384, "image manifest")
        self.units = []
        self.current_unit = None
        self.gate_uid = None
        self.client_uid = None
        self.client_gid = None
        self.identity = None
        self.last_oracle = None
        self.fresh_assessments = 0
        self.daemons_stopped = True
        self.policy = None

    def guest(self, args, stage):
        self.target_contact = True
        started = time.time_ns() // 1_000_000
        code, out, err = bounded_command([
            "make", "--silent", "--no-print-directory", "-C", "testing", "vm-ssh",
            f"VM_NAME={self.vm_name}", "VM_SSH_COMMAND=" + shlex.join(args),
        ], self.upstream, timeout=60)
        self.commands.append({"stage": stage, "started_at_ms": started,
            "completed_at_ms": time.time_ns() // 1_000_000, "exit_code": code,
            "stdout_bytes": len(out), "stdout_sha256": sha256(out),
            "stderr_bytes": len(err), "stderr_sha256": sha256(err),
            "public_error": err[-4096:].decode("utf-8", "replace") if code else ""})
        require(code == 0, "GUEST_COMMAND_EXIT", stage, environment=True)
        return out

    def guest_json(self, args, stage):
        return parse_input(self.guest(args, stage), 262144, stage)

    def unit_arguments(self, command, *, name=None, wait=True, manifest_source=WITNESS_MANIFEST):
        name = name or f"wolfproto-check-{len(self.units) + 1}.service"
        self.units.append(name)
        args = ["systemd-run", "--quiet", "--unit", name, "--property=Type=exec",
            f"--property=User={GATE_USER}", f"--property=Group={GATE_USER}",
            f"--property=SupplementaryGroups={CLIENT_USER}", "--property=UMask=0077",
            "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
            "--property=AmbientCapabilities=", "--property=PrivateDevices=yes",
            f"--property=RootDirectory={IMAGE}",
            f"--property=BindPaths={STATE_PARENT}:/state {SOCKET_PARENT}:/socket",
            f"--property=BindReadOnlyPaths={manifest_source}:/run/wolfalibi/config-manifest.json "
                f"{BOOT_REPORT}:/run/wolfalibi/image-boot.json"]
        if wait:
            args.extend(["--wait", "--pipe"])
        args.extend([*ENTRY, command, "--state", "/state/gate", "--boot-policy", "/state/boot-policy.json"])
        if command == "serve":
            args.extend(["--socket", "/socket/gate.sock", "--socket-gid", str(self.client_gid),
                         "--replace-stale-socket"])
        return args

    def gate_command(self, mode, *, manifest_source=WITNESS_MANIFEST):
        args = self.unit_arguments(mode, manifest_source=manifest_source)
        return self.guest_json(["/usr/bin/python3", "-I", "-c", RUN_JSON,
            base64.b64encode(canonical_json(args)).decode("ascii")], f"immutable gate {mode}")

    def store_policy(self, envelope, *, name="boot-policy.json"):
        data = canonical_json(envelope) + b"\n"
        result = self.guest_json(["/usr/bin/python3", "-I", "-c", STORE_POLICY,
            base64.b64encode(data).decode("ascii"), sha256(data), name], "public signed boot policy")
        require(result["stored_sha256"] == sha256(data), "POLICY_COPY", "target boot policy")

    def rpc(self, document, *, drop=False):
        return self.guest_json(["runuser", "-u", CLIENT_USER, "--", "/usr/bin/python3", "-I", "-c",
            CLIENT_RPC, base64.b64encode(canonical_json(document)).decode("ascii"),
            "drop" if drop else "read"], "unprivileged fixed-protocol client")

    def oracle(self, operation_id=None):
        args = ["/usr/bin/python3", "-I", "-c", ORACLE]
        if operation_id is not None:
            args.append(operation_id)
        result = self.guest_json(args, "independent counter journal observation")
        require(result["reader_uid"] == 0 and result["state_uid"] == self.gate_uid
                and result["database_uid"] == self.gate_uid
                and result["state_mode"] == 0o700 and result["database_mode"] == 0o600
                and type(result["counter"]) is int and result["counter"] == result["committed_operations"],
                "TARGET_STATE_BOUNDARY", "independent journal observation")
        self.last_oracle = result
        return result

    def record(self, name, value, *, counter=None):
        require(name in REQUIRED_CASES and all(c["case"] != name for c in self.cases),
                "CASE_SET", name)
        record = {"case": name, "result": "PASS", **value}
        if counter is not None:
            observation = self.oracle(value.get("operation_id"))
            require(observation["counter"] == counter, "UNEXPECTED_COUNTER", name)
            record["oracle"] = observation
        self.cases.append(record)
        self.artifacts.json(f"cases/{name}/result.json", record)

    def setup(self):
        self.policy = self.prepare()
        self.policy["policy_id"] = "prototype-immutable-gate"
        self.policy["challenge_ttl_seconds"] = 30
        self.policy = validate_policy(self.policy)
        self.policy_sha = digest(self.policy)
        require(self.policy["expected"]["config_root"] == self.build["config_root"],
                "CONFIG_BUILD_BINDING", "native baseline")
        raw_native = self.guest(["cat", NATIVE_MANIFEST], "native measured config manifest")
        raw_witness = self.guest(["cat", WITNESS_MANIFEST], "verified config witness manifest")
        require(raw_native == raw_witness
                and strict_json(raw_native, 16384) == self.manifest,
                "CONFIG_IMAGE_BINDING", "native and witness config manifests")
        boot_raw = self.guest(["cat", BOOT_REPORT], "trusted initrd image verification record")
        self.boot_report = strict_json(boot_raw, 16384)
        validate_boot_report(self.boot_report, manifest=self.manifest, config_root=self.build["config_root"])
        self.artifacts.write("measurement/native-manifest.json", raw_native)
        self.artifacts.write("measurement/witness-manifest.json", raw_witness)
        self.artifacts.write("measurement/boot-report.json", boot_raw)
        for filename in ("corrupt-read.log", "wrong-root-read.log"):
            diagnostics = self.guest(["cat", "/run/wolfalibi/" + filename], "cold verity read rejection")
            require(b"Input/output error" in diagnostics, "VERITY_EIO_REQUIRED", filename)
            self.artifacts.write("measurement/" + filename.replace(".log", ".txt"), diagnostics)
        self.artifacts.json("measurement/build-result.json", self.build)
        self.artifacts.json("anchors.json", self.anchors)
        self.artifacts.json("policy.json", self.policy)
        self.record("measured-config-binding", {"config_root": self.build["config_root"],
            "gate_image_root": self.build["gate_image_root"],
            "native_and_witness_manifest_bytes_equal": True})

        # Trusted initrd used separate cold kernel mappings and copied corrupt
        # backing data. The approved live mapping was never mutated.
        controls = {"verity-wrong-root": self.boot_report["wrong_root_control"],
                    "verity-corrupted-data": self.boot_report["corruption_control"]}
        self.artifacts.json("measurement/verity-controls.json", controls)
        for case in ("verity-wrong-root", "verity-corrupted-data"):
            result = controls[case]
            require(result["mapping_created"] is True and result["read_rejected"] is True
                    and result["read_exit_code"] != 0,
                    "VERITY_CONTROL_ACCEPTED", case)
            self.record(case, result)
        source_manifest = Path(self.build["source_manifest"])
        source_raw = read_input(source_manifest, 8 * 1024 * 1024, "image file manifest")
        self.artifacts.write("measurement/source-manifest.json", source_raw)
        source_document = strict_json(source_raw, 8 * 1024 * 1024)
        source_observed = self.guest_json(["/usr/bin/python3", "-I", "-c", MANIFEST_PROBE],
                                         "immutable image file manifest")
        require(source_observed["canonical_sha256"] == digest(source_document)
                == self.manifest["source_manifest_sha256"]
                and source_observed["raw_sha256"] == sha256(source_raw)
                and source_observed["same_image_device"] and source_observed["read_only"],
                "IMAGE_SOURCE_MANIFEST", "measured image content manifest")
        self.artifacts.json("measurement/source-manifest-observation.json", source_observed)

        trust = {"schema": "wolfalibi.shirudo.action-trust.v1", "target_id": self.vm_name,
            "owner_public_key": self.anchors["owner_public_key"],
            "verifier_public_key": self.anchors["verifier_public_key"],
            "verifier_instance_id": self.anchors["verifier_instance_id"], "policy": self.policy}
        self.artifacts.json("trust.json", trust)
        anchor_file = self.roles.public("anchors.json", self.anchors)
        manifest_file = self.roles.public("manifest.json", self.manifest)
        trust_file = self.roles.public("trust.json", trust)
        _, signed = self.roles.invoke("owner", ["sign-boot-policy", "--anchor", str(anchor_file),
            "--manifest", str(manifest_file), "--trust", str(trust_file)])
        self.boot_policy = signed["boot_policy"]
        verify_boot_policy(self.boot_policy, self.anchors, self.manifest, boot_report=self.boot_report)
        self.artifacts.json("boot-policy.json", self.boot_policy)
        policy_file = self.roles.public("policy.json", self.policy)
        _, registered = self.roles.invoke("verifier", ["register-policy", "--policy", str(policy_file)])
        require(registered["policy_sha256"] == self.policy_sha, "POLICY_DIGEST", "separate verifier")

        self.guest(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir",
                    "/nonexistent", "--shell", "/usr/sbin/nologin", CLIENT_USER], "isolated target client")
        self.guest(["useradd", "--system", "--user-group", "--groups", CLIENT_USER,
                    "--no-create-home", "--home-dir", "/nonexistent", "--shell",
                    "/usr/sbin/nologin", GATE_USER], "separate target gate account")
        self.gate_uid = int(self.guest(["id", "-u", GATE_USER], "target gate uid"))
        self.client_uid = int(self.guest(["id", "-u", CLIENT_USER], "target client uid"))
        self.client_gid = int(self.guest(["id", "-g", CLIENT_USER], "target client gid"))
        require(self.gate_uid > 0 and self.client_uid > 0 and self.gate_uid != self.client_uid,
                "TARGET_UID_SEPARATION", "gate and client")
        self.guest(["install", "-d", "-m", "0700", "-o", GATE_USER, "-g", GATE_USER,
                    STATE_PARENT], "private gate state parent")
        self.guest(["install", "-d", "-m", "0755", "-o", GATE_USER, "-g", GATE_USER,
                    SOCKET_PARENT], "nonreplaceable gate socket parent")
        broken = copy.deepcopy(self.boot_policy)
        broken["signature"] = "0" * 128
        self.store_policy(broken)
        result = self.gate_command("check")
        require(result["exit_code"] == 2 and result["document"].get("status") == "BLOCKED"
                and result["document"].get("reason") == "INVALID_SIGNATURE",
                "BOOT_POLICY_ACCEPTED", "unsigned-boot-policy")
        self.guest(["test", "!", "-e", STATE_PARENT + "/gate"], "no state after unsigned policy")
        self.record("unsigned-boot-policy", {"bootstrap_result": result, "private_gate_initialized": False})
        self.store_policy(self.boot_policy)
        wrong_manifest = copy.deepcopy(self.manifest)
        wrong_manifest["gate_image_root"] = "0" * 64
        self.store_policy(wrong_manifest, name="negative-manifest.json")
        result = self.gate_command("check", manifest_source=STATE_PARENT + "/negative-manifest.json")
        require(result["exit_code"] == 2 and result["document"].get("status") == "BLOCKED"
                and result["document"].get("reason") == "BOOTSTRAP_BINDING",
                "BOOT_ROOT_ACCEPTED", "valid signature with substituted manifest")
        self.guest(["test", "!", "-e", STATE_PARENT + "/gate"], "no state after mismatched manifest")
        self.record("boot-policy-root-mismatch", {"bootstrap_result": result,
            "owner_signature_unchanged": True, "manifest_substitution": "TRUSTED_LAB_READONLY_BIND",
            "native_config_unmodified": True, "private_gate_initialized": False})
        initialized = self.gate_command("init")
        require(initialized["exit_code"] == 0 and initialized["document"]["status"] == "INITIALIZED",
                "GATE_INIT", "immutable target gate")
        self.identity = initialized["document"]["identity"]
        require(self.identity["policy_sha256"] == self.policy_sha and self.identity["target_id"] == self.vm_name,
                "GATE_IDENTITY", "fresh initialized target")
        self.artifacts.json("target-identity.json", self.identity)
        self.artifacts.json("target-accounts.json", {"gate_uid": self.gate_uid,
            "client_uid": self.client_uid, "client_gid": self.client_gid})
        profile = {"schema": "wolfalibi.shirudo.owner-profile.v1", "target_id": self.vm_name,
            "gate_instance_id": self.identity["gate_instance_id"], "gate_public_key": self.identity["public_key"],
            "policy_generation": 1, "owner_public_key": self.anchors["owner_public_key"],
            "verifier_instance_id": self.anchors["verifier_instance_id"],
            "verifier_public_key": self.anchors["verifier_public_key"], "policy": self.policy}
        profile_file = self.roles.public("owner-profile.json", profile)
        _, pinned = self.roles.invoke("owner", ["pin-profile", "--profile", str(profile_file)])
        self.artifacts.json("owner-profile.json", profile)
        self.artifacts.json("owner-profile-pinning.json", pinned)
        self.artifacts.json("host-role-identities.json", self.roles.identity())
        self.record("private-key-separation", {"peer_uid_controls": self.roles.custody_controls(),
            "ci_coordinator": "TRUSTED_ADMINISTRATOR", "private_keys_loaded_by_coordinator": False})
        self.current_unit = "wolfproto-gate.service"
        self.daemons_stopped = False
        self.guest(self.unit_arguments("serve", name=self.current_unit, wait=False), "start immutable gate service")
        for _ in range(20):
            response = self.rpc({"op": "status", "operation_id": None})
            if response.get("status") == "STATUS":
                break
            time.sleep(0.1)
        require(response.get("status") == "STATUS", "GATE_START", "target service")
        process = self.guest_json(["/usr/bin/python3", "-I", "-c", PROCESS_PROBE, self.current_unit],
                                  "immutable interpreter process and mappings")
        require(process["uid"] == self.gate_uid and int(process["effective_capabilities"], 16) == 0
                and process["command"][:len(ENTRY)] == ENTRY
                and process["image_device"] == process["process_root_device"] == process["executable_device"]
                and process["image_inode"] == process["process_root_inode"]
                and process["file_mappings"]
                and all(m["device"] == process["image_device"] for m in process["file_mappings"])
                and process["root_write_open_denied_readonly"],
                "IMMUTABLE_EXECUTION", "interpreter and file-backed mappings")
        self.record("immutable-execution", process, counter=0)
        access = self.guest_json(["runuser", "-u", CLIENT_USER, "--", "/usr/bin/python3", "-I", "-c",
                                  ACCESS_PROBE], "client private-state denial")
        require(access["uid"] == self.client_uid and access["denied"], "CLIENT_STATE_ACCESS", "gate state")
        self.record("gate-state-access-denied", access, counter=0)

    def fresh_bundle(self, name, request_id):
        _, challenge = self.roles.invoke("verifier", ["challenge", "--policy-sha256", self.policy_sha])
        prepared = self.rpc({"op": "prepare", "attestation_challenge": challenge})
        require(prepared.get("status") == "PREPARED", "PREPARE_DENIED", name)
        action = prepared["action_challenge"]
        verify_record(action, self.identity["public_key"])
        raw = self.collect(challenge, "prototype-" + name)
        evidence_file = self.roles.public(name + "-evidence.json", raw)
        _, assessment = self.roles.invoke("verifier", ["verify", "--challenge-id",
            challenge["payload"]["challenge_id"], "--evidence", str(evidence_file), "--verifier", str(self.roles.verifier)])
        expect_receipt(assessment, outcome="EVIDENCE_ACCEPTED", reason="REQUIRED_CHECKS_PASSED")
        check_receipt_bindings(assessment, self.policy, challenge, raw)
        verification = verify_receipt(assessment, self.anchors["verifier_public_key"],
            expected_target=self.vm_name, expected_policy_sha256=self.policy_sha,
            expected_challenge_id=challenge["payload"]["challenge_id"])
        require(verification["signature_valid"] and not verification["current_authorization"],
                "ASSESSMENT_SIGNATURE", name)
        bundle = {"schema": "wolfalibi.shirudo.owner-bundle.v1", "request_id": request_id,
            "attestation_challenge": challenge, "action_challenge": action, "assessment": assessment}
        self.artifacts.write(f"materials/{name}/evidence.json", raw)
        self.artifacts.json(f"materials/{name}/bundle.json", bundle)
        self.artifacts.json(f"materials/{name}/assessment-verification.json", verification)
        self.fresh_assessments += 1
        self.positive_accepted = True
        return bundle

    def ceremony(self, name, behavior="approve"):
        intent = {"schema": "wolfalibi.shirudo.owner-intent.v1", "request_id": secrets.token_hex(16),
            "target_id": self.vm_name, "gate_instance_id": self.identity["gate_instance_id"],
            "policy_sha256": self.policy_sha, "policy_generation": 1, "action": dict(ACTION)}
        self.artifacts.json(f"materials/{name}/intent.json", intent)
        intent_file = self.roles.public(name + "-intent.json", intent)
        bundle_name = name + "-bundle.json"
        args = self.roles.argv("owner", ["approve", "--intent", str(intent_file),
            "--bundle", str(self.roles.exchange / bundle_name), "--ready-timeout", "15", "--bundle-timeout", "25"])
        with OwnerTerminal(args) as terminal:
            terminal.wait_prompt("Type READY")
            terminal.send("READY")
            ready = terminal.event()
            require(ready.get("status") == "READY", "OWNER_NOT_READY", name)
            bundle = self.fresh_bundle(name, intent["request_id"])
            submitted = copy.deepcopy(bundle)
            if behavior == "tamper":
                submitted["assessment"]["signature"] = "0" * 128
            self.roles.public(bundle_name, submitted)
            event = terminal.event()
            if behavior != "tamper":
                require(event.get("status") == "AWAITING_APPROVAL", "OWNER_DID_NOT_REVIEW", name)
                if behavior != "timeout":
                    terminal.send("NO" if behavior == "deny" else event["approval_phrase"])
                event = terminal.event(timeout=35)
            return_code = terminal.process.wait(timeout=5)
            record = {"driver": "SCRIPTED_PTY", "actual_human_approval": "NOT_RUN",
                "ready": ready, "events": terminal.records, "exit_code": return_code,
                "terminal_transcript_sha256": sha256(bytes(terminal.transcript)),
                "terminal_transcript_bytes": len(terminal.transcript)}
            self.artifacts.json(f"materials/{name}/terminal.json", record)
            self.artifacts.write(f"materials/{name}/terminal-transcript.txt", bytes(terminal.transcript))
            self.artifacts.json(f"materials/{name}/submitted-bundle.json", submitted)
            if behavior == "approve":
                require(event.get("status") in ("GRANT_ISSUED", "GRANT_RECORDED") and return_code == 0,
                        "OWNER_GRANT", name)
                request = {"operation_id": bundle["action_challenge"]["payload"]["operation_id"],
                    "grant": event["grant"], "assessment": bundle["assessment"]}
                self.artifacts.json(f"materials/{name}/request.json", request)
                return {"bundle": bundle, "request": request, "ceremony": record}
            expected = {"deny": ("DENIED", "OWNER_DECLINED", 1),
                        "tamper": ("BLOCKED", "INVALID_SIGNATURE", 2),
                        "timeout": ("DENIED", "APPROVAL_TIMEOUT", 1)}[behavior]
            require((event.get("status"), event.get("reason"), return_code) == expected
                    and (behavior != "tamper" or not any(e.get("status") == "AWAITING_APPROVAL"
                                                        for e in terminal.records)),
                    "OWNER_DENIAL", name)
            operation_id = bundle["action_challenge"]["payload"]["operation_id"]
            _, no_grant = self.roles.invoke("owner", ["grant", "--operation-id", operation_id], accepted=(2,))
            require(no_grant.get("reason") == "UNKNOWN_OPERATION", "DENIED_GRANT_PERSISTED", name)
            self.record(name, {"operation_id": operation_id, "terminal_result": event,
                "owner_journal_result": no_grant, "driver": "SCRIPTED_PTY"}, counter=0)
            return None

    def effect(self, document, material, expected):
        receipt = document["receipt"]
        request = material["request"]
        result = verify_effect_receipt(receipt, self.identity["public_key"],
            expected_target=self.vm_name, expected_gate_instance_id=self.identity["gate_instance_id"],
            expected_operation_id=request["operation_id"],
            expected_grant_id=request["grant"]["payload"]["grant_id"],
            expected_grant_sha256=digest(request["grant"]),
            expected_assessment_sha256=digest(request["assessment"]),
            expected_action_challenge=material["bundle"]["action_challenge"])
        observation = self.oracle(request["operation_id"])
        row = observation["operation"]
        require(observation["counter"] == expected and row["receipt"] == receipt
                and row["request_sha256"] == digest(request) and row["status"] == "COMMITTED",
                "EFFECT_LEDGER_BINDING", "target signed effect")
        return {"operation_id": request["operation_id"], "response": document,
                "receipt_verification": result, "oracle": observation}

    def run(self):
        try:
            self.setup()
            self.ceremony("owner-declined", "deny")
            self.ceremony("owner-rejected-tampered-bundle", "tamper")
            self.ceremony("owner-timeout", "timeout")
            # The normal CLI has no --yes mode and never reads approval from
            # stdin. Here there is no controlling terminal at all.
            intent = {"schema": "wolfalibi.shirudo.owner-intent.v1", "request_id": secrets.token_hex(16),
                "target_id": self.vm_name, "gate_instance_id": self.identity["gate_instance_id"],
                "policy_sha256": self.policy_sha, "policy_generation": 1, "action": dict(ACTION)}
            path = self.roles.public("no-terminal-intent.json", intent)
            _, result = self.roles.invoke("owner", ["approve", "--intent", str(path), "--bundle",
                str(self.roles.exchange / "no-terminal-bundle.json")], accepted=(2,))
            require(result.get("reason") == "TERMINAL_REQUIRED", "OWNER_NO_TERMINAL", "terminal requirement")
            self.record("owner-terminal-required", {"response": result}, counter=0)

            authorized = self.ceremony("authorized")
            broken = copy.deepcopy(authorized["request"])
            broken["grant"]["signature"] = "0" * 128
            denied = self.rpc({"op": "execute", "request": broken})
            require(denied.get("status") == "DENIED" and denied.get("reason") == "INVALID_SIGNATURE",
                    "FORGED_GRANT_ACCEPTED", "target owner requirement")
            self.record("forged-owner-grant", {"response": denied}, counter=0)
            result = self.rpc({"op": "execute", "request": authorized["request"]})
            require(result.get("result") == "COMMITTED",
                    "AUTHORIZED_EFFECT", "target counter")
            first = result
            self.record("authorized", self.effect(first, authorized, 1))
            repeat = self.rpc({"op": "execute", "request": authorized["request"]})
            require(repeat.get("result") == "ALREADY_COMMITTED"
                    and repeat["receipt"] == first["receipt"], "RETRY_CHANGED_EFFECT", "exact retry")
            self.record("exact-retry", self.effect(repeat, authorized, 1))

            lost = self.ceremony("lost-reply")
            response = self.rpc({"op": "execute", "request": lost["request"]}, drop=True)
            require(response == {"status": "AMBIGUOUS", "code": "SCRIPTED_REPLY_NOT_READ"},
                    "LOST_REPLY_NOT_SIMULATED", "client disconnect")
            self.record("lost-reply", {"response": response, "operation_id": lost["request"]["operation_id"],
                "counter_at_disconnect": "UNKNOWN_UNTIL_STATUS"})
            for _ in range(20):
                recovered = self.rpc({"op": "status", "operation_id": lost["request"]["operation_id"]})
                if recovered.get("status") == "STATUS" and recovered["result"]["operation"]["status"] == "COMMITTED":
                    break
                time.sleep(0.1)
            require(recovered.get("status") == "STATUS" and recovered["result"]["operation"]["status"] == "COMMITTED",
                    "STATUS_RECOVERY", "lost reply")
            recovered_effect = {"result": "COMMITTED", "receipt": recovered["result"]["operation"]["receipt"]}
            self.record("status-recovery", self.effect(recovered_effect, lost, 2))
            _, grant = self.roles.invoke("owner", ["grant", "--operation-id", lost["request"]["operation_id"]])
            require(grant["grant"] == lost["request"]["grant"], "OWNER_GRANT_RECOVERY", "separate process journal")
            self.record("owner-grant-recovery", {"response": grant}, counter=2)
            repeat = self.rpc({"op": "execute", "request": lost["request"]})
            require(repeat.get("result") == "ALREADY_COMMITTED"
                    and repeat["receipt"] == recovered_effect["receipt"],
                    "RECOVERED_RETRY", "lost reply exact retry")
            self.record("recovered-exact-retry", self.effect(repeat, lost, 2))
        finally:
            if self.current_unit is not None:
                self.guest(["systemctl", "stop", self.current_unit], "stop prototype gate")
                self.current_unit = None
            if self.units:
                raw = self.guest(["systemctl", "show", *self.units, "--property=Id",
                    "--property=ActiveState", "--property=MainPID"], "verify owned prototype units stopped")
                self.artifacts.write("cleanup/units.txt", raw)
                require(all(line == "MainPID=0" for line in raw.decode().splitlines() if line.startswith("MainPID="))
                        and raw.count(b"MainPID=0") == len(self.units),
                        "PROCESS_CLEANUP", "prototype units")
            self.daemons_stopped = True
        require({x["case"] for x in self.cases} == REQUIRED_CASES
                and len(self.cases) == len(REQUIRED_CASES) and self.fresh_assessments == 5
                and self.last_oracle is not None and self.last_oracle["counter"] == 2,
                "INCOMPLETE_QUALIFICATION", "prototype completion")
        return self.finish("PASS")

    def finish(self, result, *, code=None, stage=None):
        summary = {"schema": "wolfalibi.shirudo.prototype-lab.v1", "result": result,
            "assurance": "LAB_VTPM", "prototype_version": "0.1.0",
            "actual_human_approval": "NOT_RUN", "approval_driver": "SCRIPTED_PTY",
            "owner_interface_implemented": True, "coordinator_authority": "TRUSTED_CI_ADMINISTRATOR",
            "gate_image_binding": "NATIVE_CONFIG_PCR14_TRANSITIVE_BINDING",
            "continuous_process_identity_qualified": False, "hardware_qualification": False,
            "production_qualification": False, "action": dict(ACTION),
            "fresh_genuine_assessments": self.fresh_assessments,
            "target_identity": self.identity, "final_oracle": self.last_oracle,
            "gate_daemons_stopped": self.daemons_stopped, "cases": self.cases,
            "limitations": LIMITATIONS, "current_authorization": False}
        if code is not None:
            summary.update(failure_code=code, failure_stage=stage)
        self.artifacts.json("commands.json", self.commands)
        self.artifacts.json("summary.json", summary)
        self.artifacts.json("artifact-manifest.json", {"schema": "wolfalibi.shirudo.public-artifacts.v1",
            "files": dict(self.artifacts.files), "private_state_exported": False})
        return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--authorities", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    lab = None
    try:
        lab = PrototypeLab(args.upstream, args.vm_name, args.verifier, args.output,
                           build=args.build, authorities=args.authorities)
        result, code = lab.run(), 0
    except LabFailure as exc:
        code = exc.exit_code
        result = lab.finish(exc.result, code=exc.code, stage=exc.stage) if lab else {
            "result": exc.result, "failure_code": exc.code, "failure_stage": exc.stage}
    except (AdapterError, OSError, KeyError, TypeError, ValueError) as exc:
        code = 2
        reason = exc.code if isinstance(exc, AdapterError) else type(exc).__name__
        result = lab.finish("BLOCKED_ENVIRONMENT", code=reason, stage="prototype harness") if lab else {
            "result": "BLOCKED_ENVIRONMENT", "failure_code": reason}
    print(canonical_json(result).decode("ascii"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
