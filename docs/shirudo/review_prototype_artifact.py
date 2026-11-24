#!/usr/bin/env python3
"""Read-only historical review of an extracted evidence/prototype directory.

Usage: python -B review_prototype_artifact.py DIRECTORY

Self-contained: no adapter imports, subprocesses, network, target contact or
file writes. cryptography supplies Ed25519 verification only. This checks
recorded LAB signatures, bindings, controls and observations; it does not rerun
TPM cryptography, authenticate a human, or independently attest a live process.
The JSON/signature/report-contract primitives are copied from the earlier
standalone action-artifact reviewer; all prototype scope is checked here.
"""

from __future__ import annotations

import sys

# Also suppress import-cache writes when a caller imports Review directly.
sys.dont_write_bytecode = True

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

UPSTREAM = "fb97c1ec5908c8bdbd46760c29e57677977fce74"
ELF_SHA = "be8b79cdd7efb8e635b7965bf34fa691e5e4a378957f3829530a529097abe9d2"
ARCHIVE_SHA = "e830f2384383adccba7c423e8afe81d1fd0b3d6e27e66ce2aed49eae632e989c"
VERSION = "7e222b2b27b2408615a4f5b20cb31215e185ee5d6f0ae0bee2910f7479f58c2d"
CODE_COMMIT = "86c28db9537558b4cc76d73baea4353652462147"
CODE_TREE = "bff7a0648c042215c0cdca9039e2a58bffb4bcd2"
EXPECTED_RUN = 45318855750
ACTION = {"name": "increment_counter", "delta": 1}
ENTRY = ["/usr/bin/python3", "-I", "-B", "-S", "/opt/wolfalibi/gate_entry.py"]
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_INTEGER = 2 ** 63 - 1
MATERIALS = ("owner-declined", "owner-rejected-tampered-bundle", "owner-timeout", "authorized", "lost-reply")
CASES = ("measured-config-binding", "verity-wrong-root", "verity-corrupted-data", "unsigned-boot-policy",
         "boot-policy-root-mismatch", "private-key-separation", "immutable-execution", "gate-state-access-denied",
         "owner-declined", "owner-rejected-tampered-bundle", "owner-timeout", "owner-terminal-required",
         "forged-owner-grant", "authorized", "exact-retry", "lost-reply", "status-recovery",
         "owner-grant-recovery", "recovered-exact-retry")
LIMITATIONS = [
    "Checks historical consistency and signatures under retained public LAB keys; they are not an external identity root.",
    "Does not rerun Shirudo, TPM quote or certification cryptography, dm-verity, kernel controls, or target operations.",
    "GitHub run/job/archive association and the code commit/tree require a separate authenticated provenance check.",
    "PCR14-to-gate binding relies on recorded trusted-builder, initrd and launcher observations; no live or continuous process identity is proved.",
    "Separate-UID access probes and scripted PTY events are recorded observations, not independent custody from root or actual human approval.",
    "Builder, administrator, hypervisor, software TPM, role code, signing state, gate UID, journals and clocks remain trusted.",
    "No hardware identity, Secure Boot, measured UKI, production action, coordinated rollback or power-loss guarantee is established.",
    "The two recorded counter effects and their receipts grant no current authority. Actual human approval remains NOT_RUN.",
]

SOURCE_PINS = {'shirudo_adapter/__init__.py': {'bytes': 104,
                                 'sha256': 'c0c4b5830115f8afa8824e6f66cb055c8d1fd9439445ce84ae9f600c99299f8d'},
 'shirudo_adapter/__main__.py': {'bytes': 48,
                                 'sha256': '935a1c1166b0c1ea35a82256345000bf2c73ded718d77773bc27a71ecce28f7d'},
 'shirudo_adapter/action_gate.py': {'bytes': 46583,
                                    'sha256': '2d12715767220bbaa683bfab800ad4ed56dcd721ebe8962d00fe27c96b7097ee'},
 'shirudo_adapter/action_gate_cli.py': {'bytes': 20246,
                                        'sha256': '9eeb3f67e4817341f36ac56c424f2e7704b83e67648adedf00e441f49a612b5e'},
 'shirudo_adapter/bootstrap.py': {'bytes': 14449,
                                  'sha256': 'f9fa182358a1dfc7e52ef6b3b10c24d083c671f80b0884b9f8f7e8cb9bc05d73'},
 'shirudo_adapter/cli.py': {'bytes': 3452,
                            'sha256': 'b3ad179ccd446a7a6ea78b8051707a9e2950085c5550302a075759bf5fa30457'},
 'shirudo_adapter/model.py': {'bytes': 9431,
                              'sha256': 'd7db42841dc3e2009c93da1be8474938e9dc7f7c8d442f6b715746ebf8c79ad5'},
 'shirudo_adapter/owner.py': {'bytes': 37060,
                              'sha256': '18816ba4bbbf9d59cb57cf0670d1a587052c2a24215284318a4cfeb14ae7ea8d'},
 'shirudo_adapter/owner_cli.py': {'bytes': 11905,
                                  'sha256': '866808d136a474cd4856a47aa2c2d20953b1923e8d4f8e457e6057158f079fa9'},
 'shirudo_adapter/receipt.py': {'bytes': 7629,
                                'sha256': '969d65b0b10632cb4df937a30d9d29bd258c7d81ac4ae6ee325f4f20bca9d7ca'},
 'shirudo_adapter/runner.py': {'bytes': 23466,
                               'sha256': 'a4d521dfd22e847f898efed2e0274958303982f3bdc936542f374474a7ad1ef9'},
 'shirudo_adapter/service.py': {'bytes': 21635,
                                'sha256': '828f97a03d64d80888c126a94112797091edf6cdd9f28598bdb6c011fec19d7c'}}

BASE_CHECKS = (
    "nonce matches the request", "attestation key: restricted, fixed to this TPM",
    "attestation key: name matches its public area", "attestation key: the pinned key",
    "endorsement key: name matches its public area",
    "endorsement key: TCG default template under the endorsement policy", "endorsement key: the pinned key",
    "quote: ECDSA signature by the attestation key", "quote: signed by the key as an endorsement primary",
    "quote: carries the nonce", "quote: covers the PCRs the document lists",
    "quote: PCR digest matches the listed values", "register: ECDSA signature by the attestation key",
    "register: signed by the key as an endorsement primary", "register: carries the nonce",
    "register: certification names the listed index", "register: certified contents match the listed value",
    "quote and certification are of one TPM boot", "eventlog: this boot has an init record",
    "register: the document names index 0x01818E00 and PCRs 9 and 11",
    "register: public area is bound to PCRs 9 and 11 as recorded", "binding: PCR 9 held the expected value",
    "binding: PCR 11 held the expected value", "binding: made while the initrd ran",
    "register: init record is of the TPM's current reset count", "anchor: record digest matches the index name",
    "state: register equals the expected value", "config: config root history matches the quoted PCR",
)

EPOCH = r"eventlog: one init record for this TPM reset \(([1-9][0-9]{0,3}) this boot\)"

REPLAY = r"eventlog: ([1-9][0-9]{0,3}) record(s?) replay to the certified value"

ANCHOR_OK = "anchor: PCR 9 equals the recorded value extended by the anchor"

ANCHOR_NOTE = "anchor: PCR 9 carries further measurements after the anchor; replay the logs to confirm it"

NOTES = {ANCHOR_NOTE, "config records a selection; operation completion depends on trusted runtime guards",
         "a credential was activated but none is expected (--expect-credential)"}

ATTESTATION_KEYS = {"schema", "instance_id", "challenge_id", "nonce", "policy_sha256", "target_id", "issued_at_ms", "expires_at_ms"}

ACTION_KEYS = {"schema", "gate_instance_id", "operation_id", "operation_nonce", "target_id", "policy_sha256",
               "policy_generation", "attestation_challenge_sha256", "attestation_challenge_id", "attestation_nonce",
               "action", "issued_at_ms", "expires_at_ms"}

ASSESSMENT_KEYS = {"schema", "receipt_id", "instance_id", "challenge_id", "nonce", "target_id", "policy_sha256",
                   "enrollment_record_sha256", "evidence_sha256", "assurance", "outcome", "reason_code",
                   "issued_at_ms", "expires_at_ms", "started_at_ms", "completed_at_ms", "upstream", "scope",
                   "authorization", "limitations"}

GRANT_KEYS = {"schema", "scope", "grant_id", "gate_instance_id", "target_id", "operation_id", "operation_nonce",
              "policy_sha256", "policy_generation", "action", "action_challenge_sha256", "attestation_challenge_sha256",
              "attestation_receipt_sha256", "issued_at_ms", "expires_at_ms"}

EFFECT_KEYS = {"schema", "scope", "authorization", "receipt_id", "gate_instance_id", "target_id", "operation_id",
               "operation_nonce", "policy_sha256", "policy_generation", "grant_id", "grant_sha256",
               "attestation_receipt_sha256", "attestation_challenge_sha256", "action", "counter_before",
               "counter_after", "committed_at_ms"}


EXPECTED_SCOPE_LIMITATIONS = ['LAB_VTPM: the CI builder, administrator, hypervisor, vTPM and clocks remain trusted.',
 'The direct QEMU boot does not establish a measured UKI, Secure Boot or hardware identity.',
 'PCR14 binds the approved config containing the gate image root; trusted bootstrap and launcher '
 'observations link it to this process.',
 'The immutable interpreter image receives no Shirudo runtime authority; root and the gate UID remain '
 'trusted for writable private state.',
 'Separate UID and process custody is tested against peer accounts, not against the trusted CI '
 "administrator's sudo privileges.",
 'The approval interface is exercised by a scripted controlling terminal. Actual human approval is NOT_RUN.',
 'Freshness remains 30 seconds with 5-second admission and 2-second clock skew; continuous process identity '
 'and quote-to-effect atomicity are not proved.',
 'Only a SQLite counter increment by one is authorized. No shield deployment, general command, financial '
 'action or production readiness is qualified.',
 'The owner and target journals do not establish resistance to coordinated administrative rollback or power '
 'loss.',
 'Receipts are historical records. They do not confer current authorization or prove secure deletion of '
 'private state.']

class ReviewError(Exception):
    pass


def need(condition, label):
    if not condition:
        raise ReviewError(label)


def exact(value, keys, label):
    need(type(value) is dict and set(value) == set(keys), label + ":schema")


def integer(value, low=0, high=MAX_INTEGER, label="integer"):
    need(type(value) is int and low <= value <= high, label)
    return value


def hexadecimal(value, length=64, label="hex"):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is not None, label)
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(canonical(value))


def same(first, second):
    """JSON equality that does not collapse true/false into 1/0."""
    return canonical(first) == canonical(second)


def strict(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_FILE, "JSON:byte-limit")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "JSON:duplicate-member")
            result[key] = value
        return result
    def number(text):
        need(len(text.lstrip("-")) <= 19, "JSON:number-limit")
        value = int(text)
        need(-(2 ** 63) <= value <= MAX_INTEGER, "JSON:number-limit")
        return value
    def forbidden(_text):
        raise ReviewError("JSON:noninteger-number")
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_int=number,
                       parse_float=forbidden, parse_constant=forbidden)
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        need(count <= 200_000 and depth <= 50, "JSON:complexity-limit")
        if type(item) is dict:
            stack.extend((v, depth + 1) for v in item.values())
            stack.extend((k, depth + 1) for k in item)
        elif type(item) is list:
            stack.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            need(not any(0xD800 <= ord(c) <= 0xDFFF for c in item), "JSON:surrogate")
    return value


def signed(record, public_key, label):
    exact(record, {"schema", "payload", "signature"}, label)
    need(record["schema"] == "wolfalibi.signed-record.v1" and type(record["payload"]) is dict, label + ":record")
    hexadecimal(public_key, 64, label + ":key")
    hexadecimal(record["signature"], 128, label + ":signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
            bytes.fromhex(record["signature"]), canonical(record["payload"]))
    except (InvalidSignature, ValueError) as exc:
        raise ReviewError(label + ":signature") from exc
    return record["payload"]


def invalid_signature(record, public_key, label):
    try:
        signed(record, public_key, label)
    except ReviewError as exc:
        need(str(exc) == label + ":signature", label + ":must-be-signature-failure")
    else:
        raise ReviewError(label + ":unexpected-valid-signature")


def fixed_action(value, label):
    exact(value, {"name", "delta"}, label)
    need(value["name"] == ACTION["name"], label + ":name")
    integer(value["delta"], 1, 1, label + ":delta")


def interval(value, maximum, label):
    integer(value["issued_at_ms"], label=label + ":issued")
    integer(value["expires_at_ms"], label=label + ":expires")
    need(0 < value["expires_at_ms"] - value["issued_at_ms"] <= maximum, label + ":interval")


class Review:
    def __init__(self, directory):
        self.root = Path(directory).absolute()
        self.raw, self.materials, self.effects = {}, {}, {}
        self.directories, self.signature_records = set(), set()
        self.reports, self.signatures = 0, 0


    def json(self, name):
        need(name in self.raw, "FILE:missing:" + name)
        return strict(self.raw[name])


    def record(self, value, key, label):
        payload = signed(value, key, label)
        self.signatures += 1
        self.signature_records.add((key, digest(value)))
        return payload


    def load(self):
        need(stat.S_ISDIR(self.root.lstat().st_mode), "DIRECTORY:not-regular")
        total = 0
        for directory, subdirs, files in os.walk(self.root, followlinks=False):
            for name in subdirs:
                child = Path(directory) / name
                need(stat.S_ISDIR(child.lstat().st_mode), "DIRECTORY:symlink")
                self.directories.add(child.relative_to(self.root).as_posix())
                need(len(self.directories) <= 512, "DIRECTORY:resource-limit")
            for name in files:
                path = Path(directory) / name
                relative = path.relative_to(self.root).as_posix()
                need(re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.[A-Za-z0-9]+", relative) is not None,
                     "FILE:unsafe-name")
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    info = os.fstat(fd)
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAX_FILE,
                         "FILE:type-or-size:" + relative)
                    chunks, size = [], 0
                    while True:
                        chunk = os.read(fd, min(65_536, MAX_FILE + 1 - size))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        size += len(chunk)
                        need(size <= MAX_FILE, "FILE:size:" + relative)
                    raw = b"".join(chunks)
                    need(len(raw) == info.st_size, "FILE:changed:" + relative)
                finally:
                    os.close(fd)
                self.raw[relative] = raw
                total += len(raw)
                need(len(self.raw) <= 512 and total <= MAX_TOTAL, "DIRECTORY:resource-limit")
        manifest = self.json("artifact-manifest.json")
        exact(manifest, {"schema", "files", "private_state_exported"}, "MANIFEST")
        need(manifest["schema"] == "wolfalibi.shirudo.public-artifacts.v1"
             and manifest["private_state_exported"] is False, "MANIFEST:scope")
        need(type(manifest["files"]) is dict and set(manifest["files"]) == set(self.raw) - {"artifact-manifest.json"},
             "MANIFEST:exact-file-set")
        for name, item in manifest["files"].items():
            exact(item, {"sha256", "bytes"}, "MANIFEST:" + name)
            hexadecimal(item["sha256"], label="MANIFEST:digest")
            integer(item["bytes"], 1, MAX_FILE, "MANIFEST:bytes")
            need(item == {"sha256": sha(self.raw[name]), "bytes": len(self.raw[name])}, "FILE:hash:" + name)
        self.file_count, self.byte_count = len(self.raw), total


    def trust(self):
        trust = self.json("trust.json")
        exact(trust, {"schema", "target_id", "owner_public_key", "verifier_public_key", "verifier_instance_id", "policy"}, "TRUST")
        need(trust["schema"] == "wolfalibi.shirudo.action-trust.v1", "TRUST:schema-value")
        need(type(trust["target_id"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", trust["target_id"]) is not None, "TRUST:target")
        for name in ("owner_public_key", "verifier_public_key"):
            hexadecimal(trust[name], label="TRUST:" + name)
        need(trust["owner_public_key"] != trust["verifier_public_key"], "TRUST:separate-authority-keys")
        hexadecimal(trust["verifier_instance_id"], 32, "TRUST:instance")
        policy = self.json("policy.json")
        need(same(policy, trust["policy"]), "TRUST:policy-copy")
        exact(policy, {"schema", "policy_id", "target_id", "assurance", "enrollment", "expected", "verifier", "challenge_ttl_seconds"}, "POLICY")
        need(policy["schema"] == "wolfalibi.shirudo.policy.v1" and policy["policy_id"] == "prototype-immutable-gate"
             and policy["target_id"] == trust["target_id"] and policy["assurance"] == "LAB_VTPM", "POLICY:scope")
        integer(policy["challenge_ttl_seconds"], 30, 30, "POLICY:ttl")
        enrollment = policy["enrollment"]
        exact(enrollment, {"method", "record_sha256", "ak_name", "ek_name"}, "POLICY:enrollment")
        need(enrollment["method"] == "trusted_builder", "POLICY:enrollment-method")
        for name in ("ak_name", "ek_name"):
            hexadecimal(enrollment[name], 68, "POLICY:" + name)
            need(enrollment[name].startswith("000b"), "POLICY:tpm-name-algorithm")
        need(enrollment["record_sha256"] == sha(self.raw["inputs/enrollment.json"]), "POLICY:builder-record-hash")
        builder = self.json("inputs/enrollment.json")
        exact(builder, {"source", "nodes"}, "BUILDER")
        need(builder["source"] == "test-vm" and type(builder["nodes"]) is list and len(builder["nodes"]) == 1, "BUILDER:selection")
        need(builder["nodes"][0] == {"node_id": trust["target_id"], "ak_name": enrollment["ak_name"], "ek_name": enrollment["ek_name"]}, "BUILDER:target-keys")
        expected = policy["expected"]
        exact(expected, {"chain", "config_root", "binding_pcrs", "quote_pcrs", "config_pcr"}, "POLICY:expected")
        integer(expected["config_pcr"], 14, 14, "POLICY:config-pcr")
        need(expected["quote_pcrs"] == {}, "POLICY:quoted-pcr-contract")
        exact(expected["binding_pcrs"], {"9", "11"}, "POLICY:binding-pcrs")
        for value in (expected["chain"], expected["config_root"], *expected["binding_pcrs"].values()):
            hexadecimal(value, label="POLICY:measurement")
        need(policy["verifier"] == {"source_commit": UPSTREAM, "sha256": ELF_SHA, "version_id": VERSION, "timeout_seconds": 30}, "POLICY:reviewed-verifier")
        self.trusted, self.policy = trust, policy
        self.policy_sha, self.target = digest(policy), trust["target_id"]
        self.owner_key, self.verifier_key = trust["owner_public_key"], trust["verifier_public_key"]
        identity = self.json("target-identity.json")
        exact(identity, {"schema", "gate_instance_id", "target_id", "public_key", "policy_sha256", "policy_generation"}, "TARGET-IDENTITY")
        need(identity["schema"] == "wolfalibi.shirudo.action-identity.v1" and identity["target_id"] == self.target
             and identity["policy_sha256"] == self.policy_sha, "TARGET-IDENTITY:binding")
        integer(identity["policy_generation"], 1, 1, "TARGET-IDENTITY:generation")
        self.gate_id = hexadecimal(identity["gate_instance_id"], 32, "TARGET-IDENTITY:instance")
        self.gate_key = hexadecimal(identity["public_key"], label="TARGET-IDENTITY:key")
        need(self.gate_key not in {self.owner_key, self.verifier_key}, "TARGET-IDENTITY:distinct-key")
        self.identity = identity
        baseline = self.json("baseline-manifest.json")
        for key, value in {"schema": "wolfalibi.shirudo.lab-baseline.v1", "source_commit": UPSTREAM,
                "verifier_sha256": ELF_SHA, "verifier_archive_sha256": ARCHIVE_SHA, "verifier_version_id": VERSION,
                "builder_record_sha256": enrollment["record_sha256"], "config_prefix": "config-boot-keys",
                "config_pcr": 14, "config_root": expected["config_root"], "expected_chain": expected["chain"],
                "binding_pcrs": expected["binding_pcrs"], "assurance": "LAB_VTPM"}.items():
            need(baseline.get(key) == value, "BASELINE:" + key)
        need(baseline["baseline_before_all_challenges"] is True and baseline["expectations_from_submitted_evidence"] is False
             and baseline["pcr11_is_zero"] is (expected["binding_pcrs"]["11"] == "0" * 64), "BASELINE:trust-origin")
        self.baseline_time = integer(baseline["baseline_recorded_at_ms"], label="BASELINE:time")
        need(self.raw["inputs/config-root.txt"].decode("ascii").strip() == expected["config_root"], "BASELINE:host-root")
        need(self.raw["inputs/verifier-version.txt"] in (VERSION.encode(), (VERSION + "\n").encode()), "BASELINE:runtime-version")
        need(self.raw["inputs/target-build.txt"].decode("ascii").strip() == baseline["target_build_id"], "BASELINE:target-build")
        hexadecimal(baseline["target_build_id"], label="BASELINE:target-build-format")
        need(self.json("inputs/prediction.json")["register_at_boot"] == expected["chain"], "BASELINE:host-prediction")
        status = self.json("inputs/baseline-status.json")
        need(type(status["schema"]) is int and status["schema"] == 1 and status["lsm_attached"] is True
             and status["keyring_mode"] == "bpf" and status["version_id"] == baseline["target_build_id"], "BASELINE:runtime-status")
        tpm, config = status["tpm"], status["config"]
        need(tpm["bound_in"] == "initrd" and tpm["register_bound"] is True and tpm["reachable"] is True
             and tpm["chain"] == expected["chain"] and tpm["pcr_before"] == expected["binding_pcrs"]["9"]
             and tpm["phase_before"] == expected["binding_pcrs"]["11"], "BASELINE:trusted-pcr-observation")
        need(config["root_hash"] == expected["config_root"] and config["activation_pending"] is False
             and config["error"] is None, "BASELINE:config-observation")
        template = {}
        for line in self.raw["inputs/runtime-template.txt"].decode().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                need(key.strip() not in template, "BASELINE:duplicate-template-key")
                template[key.strip()] = value.strip()
        need(template.get("config.image") == "/var/lib/shirudo/images/@config_image@" and template.get("config.pcr") == "14"
             and "config.nvpcr" not in template, "BASELINE:host-template")


    def attestation(self, record, label):
        payload = self.record(record, self.verifier_key, label)
        exact(payload, ATTESTATION_KEYS, label)
        need(payload["schema"] == "wolfalibi.shirudo.challenge.v1" and payload["instance_id"] == self.trusted["verifier_instance_id"]
             and payload["target_id"] == self.target and payload["policy_sha256"] == self.policy_sha, label + ":scope")
        hexadecimal(payload["challenge_id"], 32, label + ":id")
        hexadecimal(payload["nonce"], label=label + ":nonce")
        interval(payload, 30_000, label)
        need(payload["expires_at_ms"] - payload["issued_at_ms"] == 30_000 and payload["issued_at_ms"] >= self.baseline_time,
             label + ":time")
        return payload


    def report(self, upstream, label):
        exact(upstream, {"source_commit", "expected_binary_sha256", "expected_version_id", "observed_binary_sha256",
                         "observed_version_id", "execution_profile", "exit_code", "report", "report_sha256", "required_checks"}, label)
        need(upstream["source_commit"] == UPSTREAM and upstream["expected_binary_sha256"] == ELF_SHA
             and upstream["observed_binary_sha256"] == ELF_SHA and upstream["expected_version_id"] == VERSION
             and upstream["observed_version_id"] == VERSION and upstream["execution_profile"] == "UPSTREAM_CLI", label + ":pins-and-profile")
        integer(upstream["exit_code"], 0, 0, label + ":exit")
        report = upstream["report"]
        exact(report, {"schema", "verdict", "checks"}, label + ":report")
        integer(report["schema"], 1, 1, label + ":report-schema")
        need(report["verdict"] == "ok" and digest(report) == upstream["report_sha256"] and len(canonical(report)) <= 65_536,
             label + ":report-digest-verdict")
        required = list(BASE_CHECKS)
        contract = required + ["regex:" + EPOCH, "regex:" + REPLAY,
                               "one-of:" + ANCHOR_OK + "|note:" + ANCHOR_NOTE]
        need(upstream["required_checks"] == contract, label + ":complete-independent-contract")
        checks = report["checks"]
        need(type(checks) is list and 1 <= len(checks) <= 4096, label + ":check-count")
        seen, dynamics, anchor = set(), set(), 0
        for check in checks:
            exact(check, {"result", "text"}, label + ":check")
            text = check["text"]
            need(type(text) is str and 1 <= len(text) <= 8192 and not any(ord(c) < 32 for c in text), label + ":check-text")
            if check["result"] == "note":
                need(text in NOTES or re.fullmatch(r"event after boot: [^\r\n]+ [^\r\n]+", text) is not None, label + ":known-note")
                anchor += int(text == ANCHOR_NOTE)
                continue
            need(check["result"] == "ok" and text not in seen, label + ":passing-unique-assertion")
            seen.add(text)
            epoch, replay = re.fullmatch(EPOCH, text), re.fullmatch(REPLAY, text)
            if epoch:
                need(1 <= int(epoch[1]) <= 4096 and "epoch" not in dynamics, label + ":epoch")
                dynamics.add("epoch")
            elif replay:
                need(1 <= int(replay[1]) <= 4096 and (replay[2] == "s") == (int(replay[1]) != 1)
                     and "replay" not in dynamics, label + ":replay")
                dynamics.add("replay")
            else:
                need(text in required or text == ANCHOR_OK, label + ":known-assertion")
            anchor += int(text == ANCHOR_OK)
        need(set(required) <= seen and dynamics == {"epoch", "replay"} and anchor == 1, label + ":all-required-checks")
        self.reports += 1


    def effect(self, record, material_name):
        material = self.materials[material_name]
        action, att, grant, assessment = (material[k]["payload"] for k in ("action", "attestation", "grant", "assessment"))
        payload = self.record(record, self.gate_key, material_name + ":effect")
        exact(payload, EFFECT_KEYS, material_name + ":effect")
        expected = {"schema": "wolfalibi.shirudo.effect-receipt.v1", "scope": "LAB_COUNTER_EFFECT_ONLY",
            "authorization": "CONSUMED_FOR_RECORDED_EFFECT", "grant_id": grant["grant_id"],
            "grant_sha256": digest(material["grant"]), "attestation_receipt_sha256": digest(material["assessment"])}
        expected.update({k: action[k] for k in ("gate_instance_id", "target_id", "operation_id", "operation_nonce",
                          "policy_sha256", "policy_generation", "attestation_challenge_sha256", "action")})
        need(all(payload[k] == v for k, v in expected.items()), material_name + ":effect-authority-bindings")
        hexadecimal(payload["receipt_id"], 32, material_name + ":effect-id")
        fixed_action(payload["action"], material_name + ":effect-action")
        integer(payload["policy_generation"], 1, 1, material_name + ":effect-generation")
        before = integer(payload["counter_before"], 0, 1)
        after = integer(payload["counter_after"], 1, 2)
        need(after == before + 1, material_name + ":single-effect")
        order = {"authorized": 1, "lost-reply": 2}
        need(material_name in order and after == order[material_name], material_name + ":counter-chain")
        when = integer(payload["committed_at_ms"])
        need(action["issued_at_ms"] <= when < min(action["expires_at_ms"], grant["expires_at_ms"])
             and when - att["issued_at_ms"] <= 30_000
             and max(att["issued_at_ms"], assessment["started_at_ms"], assessment["completed_at_ms"], grant["issued_at_ms"]) <= when + 2000,
             material_name + ":effect-freshness")
        if material_name in self.effects:
            need(same(record, self.effects[material_name]), material_name + ":historical-receipt-identical")
        else:
            self.effects[material_name] = record
        return {"signature_valid": True, "historical_outcome": "COMMITTED", "current_authorization": False,
                "scope": "LAB_COUNTER_EFFECT_ONLY", "receipt_id": payload["receipt_id"],
                "operation_id": payload["operation_id"], "counter_before": before, "counter_after": after}

    def layout(self):
        files = {"artifact-manifest.json", "baseline-manifest.json", "trust.json", "policy.json",
                 "target-identity.json", "target-accounts.json", "owner-profile.json", "owner-profile-pinning.json",
                 "host-role-identities.json", "anchors.json", "boot-policy.json", "summary.json", "commands.json",
                 "cleanup/units.txt"}
        files.update("inputs/" + name for name in ("enrollment.json", "target-build.txt", "runtime-template.txt",
                     "config-root.txt", "primary.der", "boot.der", "verifier-version.txt", "prediction.json", "baseline-status.json"))
        files.update("measurement/" + name for name in ("native-manifest.json", "witness-manifest.json", "boot-report.json",
                     "corrupt-read.txt", "wrong-root-read.txt", "build-result.json", "verity-controls.json",
                     "source-manifest.json", "source-manifest-observation.json", "launch-bindings.json"))
        files.update(f"cases/{name}/result.json" for name in CASES)
        for name in MATERIALS:
            files.update(f"materials/{name}/{item}" for item in ("intent.json", "bundle.json", "evidence.json",
                         "assessment-verification.json", "terminal.json", "terminal-transcript.txt", "submitted-bundle.json"))
        files.update(f"materials/{name}/request.json" for name in ("authorized", "lost-reply"))
        need(set(self.raw) == files, "LAYOUT:exact-public-exports")
        expected_directories = {parent.as_posix() for name in files for parent in Path(name).parents
                                if parent != Path(".")}
        need(self.directories == expected_directories, "LAYOUT:exact-directories")

    def measurement(self):
        need(re.fullmatch(r"wolfalibi-prototype-" + str(EXPECTED_RUN) + r"-[1-9][0-9]{0,5}", self.target) is not None,
             "TARGET:reviewed-run-name")
        anchors = self.json("anchors.json")
        expected_anchors = {"schema": "wolfalibi.shirudo.bootstrap-anchors.v1",
            **{k: self.trusted[k] for k in ("target_id", "owner_public_key", "verifier_public_key", "verifier_instance_id")},
            "verifier": {k: self.policy["verifier"][k] for k in ("source_commit", "sha256", "version_id")},
            "assurance": "LAB_VTPM", "action": ACTION, "max_challenge_ttl_seconds": 30, "config_pcr": 14}
        need(same(anchors, expected_anchors), "ANCHORS:immutable-authorities-and-scope")
        native = self.raw["measurement/native-manifest.json"]
        need(native == self.raw["measurement/witness-manifest.json"], "IMAGE:native-witness-identical-bytes")
        manifest = strict(native)
        exact(manifest, {"schema", "gate_image_root", "anchors_sha256", "source_manifest_sha256", "entrypoint", "mount_point", "authority"}, "IMAGE")
        need(manifest["schema"] == "wolfalibi.shirudo.gate-image.v1" and manifest["anchors_sha256"] == digest(anchors)
             and manifest["entrypoint"] == ENTRY and manifest["mount_point"] == "/run/wolfalibi/image"
             and manifest["authority"] == "NO_SHIRUDO_RUNTIME_AUTHORITY", "IMAGE:execution-contract")
        gate_root = hexadecimal(manifest["gate_image_root"], label="IMAGE:root")
        config_root = self.policy["expected"]["config_root"]
        build = self.json("measurement/build-result.json")
        need(build["schema"] == "wolfalibi.shirudo.prototype-image-build.v1"
             and build["gate_image_root"] == gate_root and build["config_root"] == config_root
             and build["anchors_sha256"] == digest(anchors) and build["entrypoint"] == ENTRY
             and build["mount_point"] == manifest["mount_point"] and build["upstream_tracked_changes"] is False
             and build["kernel_runtime_controls"] == "REQUIRED_AT_BOOT", "BUILD:image-contract")
        hexadecimal(build["runtime_root"], label="BUILD:native-runtime-root")
        need(len({gate_root, config_root, build["runtime_root"]}) == 3, "BUILD:separate-runtime-config-gate-images")
        boot = self.json("measurement/boot-report.json")
        exact(boot, {"schema", "scope", "gate_image_root", "config_root", "anchors_sha256", "mount_point",
                    "mapper_name", "read_only", "full_read", "data_bytes", "image_device", "dm_table",
                    "config_witness", "corruption_control", "wrong_root_control"}, "BOOT")
        need(boot["schema"] == "wolfalibi.shirudo.image-boot.v1" and boot["scope"] == "LAB_TRUSTED_INITRD"
             and boot["gate_image_root"] == gate_root and boot["config_root"] == config_root
             and boot["anchors_sha256"] == digest(anchors) and boot["mount_point"] == manifest["mount_point"]
             and boot["mapper_name"] == "wolfalibi-gate" and boot["read_only"] is True and boot["full_read"] is True,
             "BOOT:approved-mapping")
        self.image_device = integer(boot["image_device"], 1, label="BOOT:device")
        self.verity_table(boot, gate_root, "BOOT:gate")
        witness = boot["config_witness"]
        exact(witness, {"root_hash", "mount_point", "mapper_name", "read_only", "full_read", "data_bytes", "dm_table"}, "BOOT:witness")
        need(witness["root_hash"] == config_root and witness["mount_point"] == "/run/wolfalibi/config-witness"
             and witness["mapper_name"] == "wolfalibi-config-witness" and witness["read_only"] is True
             and witness["full_read"] is True, "BOOT:config-witness")
        self.verity_table(witness, config_root, "BOOT:witness")
        controls = self.json("measurement/verity-controls.json")
        need(same(controls, {"verity-wrong-root": boot["wrong_root_control"],
                             "verity-corrupted-data": boot["corruption_control"]}), "BOOT:control-copies")
        for field, filename in (("corruption_control", "corrupt-read.txt"), ("wrong_root_control", "wrong-root-read.txt")):
            control = boot[field]
            exact(control, {"mapping_created", "read_rejected", "read_exit_code", "block"}, "BOOT:" + field)
            need(control["mapping_created"] is True and control["read_rejected"] is True, "BOOT:cold-map-rejection")
            integer(control["read_exit_code"], 1, 1, "BOOT:negative-read-status")
            integer(control["block"], 0, boot["data_bytes"] // 4096 - 1, "BOOT:negative-read-offset")
            need(b"Input/output error" in self.raw["measurement/" + filename], "BOOT:kernel-EIO-observation")
        integer(boot["wrong_root_control"]["block"], 0, 0, "BOOT:wrong-root-first-block")
        boot_policy = self.record(self.json("boot-policy.json"), self.owner_key, "BOOT:owner-signature")
        need(same(boot_policy, {"schema": "wolfalibi.shirudo.boot-policy.v1", "scope": "LAB_IMMUTABLE_GATE_BOOTSTRAP",
             "anchors_sha256": digest(anchors), "gate_image_root": gate_root, "config_root": config_root,
             "trust": self.trusted}), "BOOT:owner-approved-full-trust")
        self.anchors, self.image_manifest, self.boot = anchors, manifest, boot
        self.image_source()
        self.launch_bindings()

    def launch_bindings(self):
        bindings = self.json("measurement/launch-bindings.json")
        exact(bindings, {"schema", "launcher", "boot_report_copy", "mounts"}, "LAUNCH")
        need(bindings["schema"] == "wolfalibi.shirudo.prototype-bindings.v1", "LAUNCH:schema-value")
        launcher = bindings["launcher"]
        exact(launcher, {"kind", "path", "resolved_path", "uid", "mode", "bytes", "sha256", "version"}, "LAUNCH:executable")
        need(launcher["kind"] == "GNU_CHROOT" and launcher["path"] in
             ("/usr/sbin/gnuchroot", "/usr/sbin/chroot", "/usr/bin/chroot"), "LAUNCH:fixed-executable-selection")
        resolved = launcher["resolved_path"]
        need(type(resolved) is str and 1 < len(resolved) <= 4096 and resolved.startswith("/")
             and os.path.normpath(resolved) == resolved and not any(ord(c) < 32 for c in resolved),
             "LAUNCH:resolved-executable-path")
        integer(launcher["uid"], 0, 0, "LAUNCH:root-owned-executable")
        mode = integer(launcher["mode"], 0, 0o7777, "LAUNCH:executable-mode")
        need(mode & 0o111 and not mode & 0o6022, "LAUNCH:executable-permissions")
        integer(launcher["bytes"], 1, 16 * 1024 * 1024, "LAUNCH:executable-size")
        hexadecimal(launcher["sha256"], label="LAUNCH:executable-hash")
        need(type(launcher["version"]) is str and re.fullmatch(
             r"(?:gnu)?chroot \(GNU coreutils\) [0-9]+(?:\.[0-9]+)+", launcher["version"]) is not None,
             "LAUNCH:GNU-chroot-version")
        copied_report = "/var/lib/wolfalibi-prototype/bootstrap/image-boot.json"
        need(same(bindings["boot_report_copy"], {"source": "/run/wolfalibi/image-boot.json",
             "copy": copied_report, "sha256": sha(self.raw["measurement/boot-report.json"]),
             "uid": 0, "mode": 0o444}), "LAUNCH:root-owned-report-copy")
        expected = (
            ("state", "/var/lib/wolfalibi-prototype/state", "/state", False),
            ("socket", "/var/lib/wolfalibi-prototype/socket", "/socket", False),
            ("config-manifest", "/run/wolfalibi/config-witness/etc/wolfalibi/gate-image.json",
             "/run/wolfalibi/config-manifest.json", True),
            ("boot-report", copied_report, "/run/wolfalibi/image-boot.json", True),
        )
        mounts = bindings["mounts"]
        need(type(mounts) is list and len(mounts) == len(expected), "LAUNCH:exact-bind-count")
        self.bound_mounts = {}
        for mount, (name, source, destination, readonly) in zip(mounts, expected):
            exact(mount, {"name", "source", "destination", "read_only", "source_device", "destination_device",
                          "source_inode", "destination_inode"}, "LAUNCH:bind")
            need(mount["name"] == name and mount["source"] == source
                 and mount["destination"] == self.image_manifest["mount_point"] + destination
                 and mount["read_only"] is readonly, "LAUNCH:fixed-bind-contract")
            for field in ("device", "inode"):
                value = integer(mount["source_" + field], 1, label="LAUNCH:source-" + field)
                integer(mount["destination_" + field], value, value, "LAUNCH:same-bind-" + field)
            self.bound_mounts[destination] = mount

    @staticmethod
    def verity_table(record, root, label):
        size = integer(record["data_bytes"], 4096, 2 ** 34, label + ":size")
        need(size % 4096 == 0 and type(record["dm_table"]) is str, label + ":geometry")
        table = record["dm_table"].split()
        need(len(table) == 13 and table[:4] == ["0", str(size // 512), "verity", "1"]
             and table[6:11] == ["4096", "4096", str(size // 4096), "1", "sha256"]
             and table[11] == root, label + ":root-and-strict-options")
        for device in table[4:6]:
            need(re.fullmatch(r"[0-9]+:[0-9]+", device) is not None, label + ":backing-device")
        hexadecimal(table[12], label=label + ":salt")

    def image_source(self):
        raw = self.raw["measurement/source-manifest.json"]
        source = strict(raw)
        exact(source, {"schema", "upstream_commit", "adapter_commit", "python_version", "dependencies", "files", "self_exclusion"}, "SOURCE")
        need(source["schema"] == "wolfalibi.shirudo.image-source.v1" and source["upstream_commit"] == UPSTREAM
             and source["adapter_commit"] == CODE_COMMIT and source["self_exclusion"] == "/etc/wolfalibi/image-files.json"
             and digest(source) == self.image_manifest["source_manifest_sha256"], "SOURCE:reviewed-build-and-measured-digest")
        observed = self.json("measurement/source-manifest-observation.json")
        need(same(observed, {"canonical_sha256": digest(source), "raw_sha256": sha(raw), "bytes": len(raw),
                             "same_image_device": True, "read_only": True}), "SOURCE:observed-immutable-manifest")
        version = source["python_version"]
        need(type(version) is str and re.fullmatch(r"3\.(?:1[1-9]|[2-9][0-9])\.[0-9]+", version) is not None, "SOURCE:python-version")
        exact(source["dependencies"], {"cryptography", "cffi", "pycparser"}, "SOURCE:dependencies")
        need(source["dependencies"]["cryptography"] == "50.0.0", "SOURCE:cryptography-pin")
        for value in source["dependencies"].values():
            need(type(value) is str and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value) is not None, "SOURCE:dependency-version")
        files = source["files"]
        need(type(files) is dict and 100 <= len(files) <= 10000, "SOURCE:file-count")
        for name, entry in files.items():
            need(type(name) is str and name.startswith("/") and ".." not in Path(name).parts
                 and re.fullmatch(r"/[A-Za-z0-9_./+\-]+", name) is not None, "SOURCE:absolute-file-name")
            exact(entry, {"sha256", "bytes", "mode"}, "SOURCE:file")
            hexadecimal(entry["sha256"], label="SOURCE:file-hash")
            integer(entry["bytes"], 0, 256 * 1024 * 1024, "SOURCE:file-size")
            need(entry["mode"] in ("0644", "0755"), "SOURCE:immutable-file-mode")
        selected = {name.removeprefix("/opt/wolfalibi/"): entry for name, entry in files.items()
                    if name.startswith("/opt/wolfalibi/shirudo_adapter/")}
        need(set(selected) == set(SOURCE_PINS), "SOURCE:exact-reviewed-adapter-modules")
        for name, pin in SOURCE_PINS.items():
            need(same(selected[name], {**pin, "mode": "0644"}), "SOURCE:reviewed-commit:" + name)
        anchor_raw = canonical(self.anchors) + b"\n"
        need(same(files["/etc/wolfalibi/anchors.json"], {"sha256": sha(anchor_raw), "bytes": len(anchor_raw), "mode": "0644"}),
             "SOURCE:immutable-anchor-file")
        major_minor = ".".join(version.split(".")[:2])
        launcher = ("import sys\n"
            f"sys.path[:] = ['/opt/wolfalibi', '/usr/lib/python{major_minor}', "
            f"'/usr/lib/python{major_minor}/lib-dynload', '/usr/lib/python{major_minor}/site-packages']\n"
            "from shirudo_adapter.bootstrap import main\nraise SystemExit(main())\n").encode()
        need(same(files["/opt/wolfalibi/gate_entry.py"], {"sha256": sha(launcher), "bytes": len(launcher), "mode": "0644"}),
             "SOURCE:fixed-immutable-import-paths")
        need(files["/usr/bin/python3"]["mode"] == "0755" and files["/usr/bin/python3"]["bytes"] > 4096,
             "SOURCE:interpreter")
        need(any("/cryptography/" in name and name.endswith(".so") and entry["mode"] == "0755"
                 for name, entry in files.items()), "SOURCE:cryptography-native-extension")
        self.source_file_count = len(files)

    def owner_profile(self):
        profile = self.json("owner-profile.json")
        expected = {"schema": "wolfalibi.shirudo.owner-profile.v1", "target_id": self.target,
            "gate_instance_id": self.gate_id, "gate_public_key": self.gate_key, "policy_generation": 1,
            "owner_public_key": self.owner_key, "verifier_instance_id": self.trusted["verifier_instance_id"],
            "verifier_public_key": self.verifier_key, "policy": self.policy}
        need(same(profile, expected), "OWNER:independent-profile-pins")
        need(same(self.json("owner-profile-pinning.json"), {"status": "PROFILE_PINNED", "profile_sha256": digest(profile)}),
             "OWNER:profile-pinning")
        self.profile, self.owner_ids = profile, set()
        roles = self.json("host-role-identities.json")
        exact(roles, {"owner", "verifier", "client"}, "ROLES")
        for name, identity in roles.items():
            exact(identity, {"user", "uid", "gid"}, "ROLES:" + name)
            need(identity["user"] == "wolfproto-" + name, "ROLES:user-name")
            for key in ("uid", "gid"):
                integer(identity[key], 1, 2 ** 31 - 1, "ROLES:" + key)
        need(len({identity["uid"] for identity in roles.values()}) == 3, "ROLES:distinct-uids")
        accounts = self.json("target-accounts.json")
        exact(accounts, {"gate_uid", "gate_gid", "client_uid", "client_gid"}, "TARGET:accounts")
        for value in accounts.values():
            integer(value, 1, 2 ** 31 - 1, "TARGET:uid-gid")
        need(accounts["gate_uid"] != accounts["client_uid"], "TARGET:separate-accounts")
        self.roles, self.accounts = roles, accounts

    def material(self, name):
        prefix = "materials/" + name + "/"
        bundle = self.json(prefix + "bundle.json")
        exact(bundle, {"schema", "request_id", "attestation_challenge", "action_challenge", "assessment"}, name + ":bundle")
        need(bundle["schema"] == "wolfalibi.shirudo.owner-bundle.v1", name + ":bundle-schema")
        request_id = hexadecimal(bundle["request_id"], 32, name + ":request-id")
        intent = self.json(prefix + "intent.json")
        need(same(intent, {"schema": "wolfalibi.shirudo.owner-intent.v1", "request_id": request_id,
             "target_id": self.target, "gate_instance_id": self.gate_id, "policy_sha256": self.policy_sha,
             "policy_generation": 1, "action": ACTION}), name + ":intent-pins")
        att_record, action_record, assessment_record = (bundle[k] for k in ("attestation_challenge", "action_challenge", "assessment"))
        att = self.attestation(att_record, name + ":challenge")
        action = self.record(action_record, self.gate_key, name + ":action")
        exact(action, ACTION_KEYS, name + ":action")
        expected = {"schema": "wolfalibi.shirudo.action-challenge.v1", "gate_instance_id": self.gate_id,
            "target_id": self.target, "policy_sha256": self.policy_sha, "policy_generation": 1,
            "attestation_challenge_sha256": digest(att_record), "attestation_challenge_id": att["challenge_id"],
            "attestation_nonce": att["nonce"], "action": ACTION}
        need(all(same(action[k], v) for k, v in expected.items()), name + ":action-bindings")
        hexadecimal(action["operation_id"], 32, name + ":operation")
        hexadecimal(action["operation_nonce"], label=name + ":operation-nonce")
        interval(action, 30_000, name + ":action")
        need(-2000 <= action["issued_at_ms"] - att["issued_at_ms"] <= 5000 and action["expires_at_ms"] ==
             min(action["issued_at_ms"] + 30_000, att["issued_at_ms"] + 30_000, att["expires_at_ms"]), name + ":gate-freshness")
        assessment = self.record(assessment_record, self.verifier_key, name + ":assessment")
        exact(assessment, ASSESSMENT_KEYS, name + ":assessment")
        expected = {"schema": "wolfalibi.shirudo.receipt.v1", "assurance": "LAB_VTPM", "outcome": "EVIDENCE_ACCEPTED",
            "reason_code": "REQUIRED_CHECKS_PASSED", "scope": "HISTORICAL_EVIDENCE_ONLY", "authorization": "NONE",
            "enrollment_record_sha256": self.policy["enrollment"]["record_sha256"]}
        expected.update({k: att[k] for k in ("instance_id", "challenge_id", "nonce", "target_id", "policy_sha256", "issued_at_ms", "expires_at_ms")})
        need(all(same(assessment[k], v) for k, v in expected.items()), name + ":assessment-bindings")
        hexadecimal(assessment["receipt_id"], 32, name + ":assessment-id")
        started, completed = integer(assessment["started_at_ms"]), integer(assessment["completed_at_ms"])
        need(att["issued_at_ms"] <= started <= completed < att["expires_at_ms"]
             and started >= action["issued_at_ms"] - 2000, name + ":assessment-time")
        limits = assessment["limitations"]
        need(type(limits) is list and 1 <= len(limits) <= 16 and all(type(v) is str and 1 <= len(v) <= 1024
             and not any(ord(c) < 32 for c in v) for v in limits), name + ":assessment-limitations")
        evidence_raw = self.raw[prefix + "evidence.json"]
        need(len(evidence_raw) <= 1_048_576 and sha(evidence_raw) == assessment["evidence_sha256"], name + ":evidence-digest")
        evidence = strict(evidence_raw)
        need(type(evidence["schema"]) is int and evidence["schema"] == 1 and evidence["kind"] == "shirudo-attestation"
             and evidence["pcr_bank"] == "sha256" and evidence["nonce"] == att["nonce"]
             and evidence["ak"]["name"] == self.policy["enrollment"]["ak_name"]
             and evidence["ek"]["name"] == self.policy["enrollment"]["ek_name"]
             and evidence["register"]["value"] == self.policy["expected"]["chain"], name + ":evidence-bindings")
        self.report(assessment["upstream"], name + ":upstream")
        need(same(self.json(prefix + "assessment-verification.json"), {"signature_valid": True, "historical_outcome": "EVIDENCE_ACCEPTED",
             "current_authorization": False, "current_target_state": "NOT_ESTABLISHED", "assurance": "LAB_VTPM",
             "receipt_id": assessment["receipt_id"], "scope": "HISTORICAL_EVIDENCE_ONLY"}), name + ":assessment-review-copy")
        self.materials[name] = {"attestation": att_record, "action": action_record, "assessment": assessment_record,
                                "bundle": bundle, "intent": intent}
        self.ceremony(name)

    def ceremony(self, name):
        material = self.materials[name]
        bundle, intent = material["bundle"], material["intent"]
        att, action, assessment = (material[k]["payload"] for k in ("attestation", "action", "assessment"))
        prefix = "materials/" + name + "/"
        terminal = self.json(prefix + "terminal.json")
        exact(terminal, {"driver", "actual_human_approval", "ready", "events", "exit_code", "terminal_transcript_sha256", "terminal_transcript_bytes"}, name + ":terminal")
        transcript = self.raw[prefix + "terminal-transcript.txt"]
        need(terminal["driver"] == "SCRIPTED_PTY" and terminal["actual_human_approval"] == "NOT_RUN"
             and terminal["terminal_transcript_sha256"] == sha(transcript)
             and type(terminal["terminal_transcript_bytes"]) is int and terminal["terminal_transcript_bytes"] == len(transcript)
             and b"Type READY" in transcript, name + ":scripted-terminal-record")
        ready, events = terminal["ready"], terminal["events"]
        exact(ready, {"status", "owner_instance_id", "request_id", "intent_sha256", "profile_sha256", "ready_at_ms"}, name + ":ready")
        need(ready["status"] == "READY" and ready["request_id"] == intent["request_id"]
             and ready["intent_sha256"] == digest(intent) and ready["profile_sha256"] == digest(self.profile), name + ":reviewed-intent")
        self.owner_ids.add(hexadecimal(ready["owner_instance_id"], 32, name + ":owner-instance"))
        ready_time = integer(ready["ready_at_ms"], self.baseline_time, label=name + ":ready-time")
        need(att["issued_at_ms"] >= ready_time - 2000 and type(events) is list and same(events[0], ready), name + ":fresh-after-readiness")
        submitted = self.json(prefix + "submitted-bundle.json")
        if name == "owner-rejected-tampered-bundle":
            changed = copy.deepcopy(bundle)
            changed["assessment"]["signature"] = "0" * 128
            need(same(submitted, changed) and len(events) == 2, name + ":exact-tamper-control")
            invalid_signature(submitted["assessment"], self.verifier_key, name + ":submitted-assessment")
            expected = ("BLOCKED", "INVALID_SIGNATURE", 2)
        else:
            need(same(submitted, bundle) and len(events) == 3, name + ":unmodified-submission")
            awaiting = events[1]
            exact(awaiting, {"status", "operation_id", "target_id", "action", "policy_sha256", "policy_generation",
                            "expires_at_ms", "remaining_ms", "assessment_outcome", "assurance", "bundle_sha256", "intent_sha256", "approval_phrase"}, name + ":awaiting")
            phrase = "APPROVE " + action["operation_id"][-12:]
            expected = {"status": "AWAITING_APPROVAL", "operation_id": action["operation_id"], "target_id": self.target,
                "action": ACTION, "policy_sha256": self.policy_sha, "policy_generation": 1, "expires_at_ms": action["expires_at_ms"],
                "assessment_outcome": "EVIDENCE_ACCEPTED", "assurance": "LAB_VTPM", "bundle_sha256": digest(bundle),
                "intent_sha256": digest(intent), "approval_phrase": phrase}
            need(all(same(awaiting[k], v) for k, v in expected.items()) and phrase.encode() in transcript, name + ":concrete-review")
            remaining = integer(awaiting["remaining_ms"], 2000, 30_000, name + ":remaining")
            reviewed = action["expires_at_ms"] - remaining
            need(ready_time <= reviewed <= ready_time + 30_000 and action["issued_at_ms"] <= reviewed
                 and max(att["issued_at_ms"], assessment["started_at_ms"], assessment["completed_at_ms"]) <= reviewed + 2000
                 and reviewed - att["issued_at_ms"] <= 30_000, name + ":review-freshness")
            material["reviewed_at_ms"] = reviewed
            expected = ("DENIED", "OWNER_DECLINED", 1) if name == "owner-declined" else ("DENIED", "APPROVAL_TIMEOUT", 1)
        final = events[-1]
        if name not in ("authorized", "lost-reply"):
            exact(final, {"status", "reason", "message"}, name + ":denial")
            need((final["status"], final["reason"], terminal["exit_code"]) == expected
                 and type(terminal["exit_code"]) is int, name + ":exact-denial")
        else:
            exact(final, {"status", "operation_id", "grant", "effect"}, name + ":issued")
            need(final["status"] == "GRANT_ISSUED" and final["operation_id"] == action["operation_id"]
                 and final["effect"] == "NOT_ESTABLISHED", name + ":grant-event")
            integer(terminal["exit_code"], 0, 0, name + ":terminal-success")
            grant_record = final["grant"]
            grant = self.record(grant_record, self.owner_key, name + ":owner-grant")
            exact(grant, GRANT_KEYS, name + ":grant")
            expected = {k: action[k] for k in ("gate_instance_id", "target_id", "operation_id", "operation_nonce", "policy_sha256",
                        "policy_generation", "action", "attestation_challenge_sha256")}
            expected.update(schema="wolfalibi.shirudo.action-grant.v1", scope="LAB_OWNER_GRANT",
                action_challenge_sha256=digest(material["action"]), attestation_receipt_sha256=digest(material["assessment"]))
            need(all(same(grant[k], v) for k, v in expected.items()), name + ":grant-bindings")
            hexadecimal(grant["grant_id"], 32, name + ":grant-id")
            interval(grant, 30_000, name + ":grant")
            need(grant["expires_at_ms"] == action["expires_at_ms"]
                 and material["reviewed_at_ms"] <= grant["issued_at_ms"] <= ready_time + 30_000
                 and grant["expires_at_ms"] - grant["issued_at_ms"] >= 2000
                 and grant["issued_at_ms"] >= max(action["issued_at_ms"], assessment["completed_at_ms"]) - 2000,
                 name + ":grant-freshness-and-no-extension")
            request = self.json(prefix + "request.json")
            need(same(request, {"operation_id": action["operation_id"], "grant": grant_record, "assessment": material["assessment"]}),
                 name + ":exact-request")
            material.update(grant=grant_record, request=request)
        material["terminal"] = terminal

    def oracle(self, value, *, expected, material_name=None):
        keys = {"counter", "committed_operations", "observed_at_ms", "reader_uid", "state_uid", "state_mode", "database_uid", "database_mode"}
        exact(value, keys | ({"operation"} if material_name is not None else set()), "ORACLE")
        integer(value["counter"], expected, expected, "ORACLE:counter")
        integer(value["committed_operations"], expected, expected, "ORACLE:committed-count")
        integer(value["observed_at_ms"], self.baseline_time, label="ORACLE:time")
        integer(value["reader_uid"], 0, 0, "ORACLE:independent-root-reader")
        for key in ("state_uid", "database_uid"):
            integer(value[key], self.accounts["gate_uid"], self.accounts["gate_uid"], "ORACLE:gate-ownership")
        integer(value["state_mode"], 0o700, 0o700, "ORACLE:private-directory")
        integer(value["database_mode"], 0o600, 0o600, "ORACLE:private-journal")
        if material_name is not None:
            row = value["operation"]
            exact(row, {"status", "request_sha256", "grant_id", "assessment_sha256", "receipt", "counter_before", "counter_after"}, "ORACLE:operation")
            if material_name not in ("authorized", "lost-reply"):
                need(row["status"] == "PREPARED" and all(row[k] is None for k in set(row) - {"status"}), "ORACLE:no-denied-effect")
            else:
                material = self.materials[material_name]
                checked = self.effect(row["receipt"], material_name)
                need(row["status"] == "COMMITTED" and row["request_sha256"] == digest(material["request"])
                     and row["grant_id"] == material["grant"]["payload"]["grant_id"]
                     and row["assessment_sha256"] == digest(material["assessment"])
                     and same(row["counter_before"], checked["counter_before"])
                     and same(row["counter_after"], checked["counter_after"])
                     and row["counter_after"] <= value["counter"]
                     and row["receipt"]["payload"]["committed_at_ms"] <= value["observed_at_ms"], "ORACLE:authority-effect-ledger-binding")

    def cases(self):
        self.case_records = {name: self.json(f"cases/{name}/result.json") for name in CASES}
        for name, case in self.case_records.items():
            need(case["case"] == name and case["result"] == "PASS", "CASE:required-pass:" + name)
        binding = self.case_records["measured-config-binding"]
        need(same(binding, {"case": "measured-config-binding", "result": "PASS", "config_root": self.boot["config_root"],
             "gate_image_root": self.boot["gate_image_root"], "native_and_witness_manifest_bytes_equal": True}), "CASE:config-binding")
        for name, control in (("verity-wrong-root", "wrong_root_control"), ("verity-corrupted-data", "corruption_control")):
            need(same(self.case_records[name], {"case": name, "result": "PASS", **self.boot[control]}), "CASE:verity-control")
        for name, reason in (("unsigned-boot-policy", "INVALID_SIGNATURE"), ("boot-policy-root-mismatch", "BOOTSTRAP_BINDING")):
            case = self.case_records[name]
            expected_keys = {"case", "result", "bootstrap_result", "private_gate_initialized"}
            if name == "boot-policy-root-mismatch":
                expected_keys |= {"owner_signature_unchanged", "manifest_substitution", "native_config_unmodified"}
                need(case["owner_signature_unchanged"] is True and case["native_config_unmodified"] is True
                     and case["manifest_substitution"] == "TRUSTED_LAB_READONLY_BIND", "CASE:valid-signature-wrong-manifest")
            exact(case, expected_keys, "CASE:" + name)
            response = case["bootstrap_result"]
            exact(response, {"exit_code", "document", "stderr_bytes", "stderr_sha256", "public_error"}, "CASE:bootstrap-response")
            integer(response["exit_code"], 2, 2, "CASE:bootstrap-exit")
            integer(response["stderr_bytes"], 0, 65536, "CASE:bootstrap-stderr-size")
            hexadecimal(response["stderr_sha256"], label="CASE:bootstrap-stderr-hash")
            need(type(response["public_error"]) is str and len(response["public_error"]) <= 4096, "CASE:bootstrap-diagnostic")
            self.denial(response["document"], "BLOCKED", reason, "CASE:" + name)
            need(case["private_gate_initialized"] is False, "CASE:fail-before-state-initialization")
        self.custody()
        self.execution()
        access = self.case_records["gate-state-access-denied"]
        exact(access, {"case", "result", "uid", "denied", "errno", "oracle"}, "CASE:state-denial")
        need(access["denied"] is True, "CASE:client-denied")
        integer(access["uid"], self.accounts["client_uid"], self.accounts["client_uid"], "CASE:client-uid")
        integer(access["errno"], 13, 13, "CASE:filesystem-EACCES")
        self.oracle(access["oracle"], expected=0)
        for name, reason in (("owner-declined", "OWNER_DECLINED"), ("owner-rejected-tampered-bundle", "INVALID_SIGNATURE"), ("owner-timeout", "APPROVAL_TIMEOUT")):
            case, material = self.case_records[name], self.materials[name]
            exact(case, {"case", "result", "operation_id", "terminal_result", "owner_journal_result", "driver", "oracle"}, "CASE:" + name)
            need(case["operation_id"] == material["action"]["payload"]["operation_id"]
                 and case["driver"] == "SCRIPTED_PTY" and same(case["terminal_result"], material["terminal"]["events"][-1]), "CASE:owner-denial-copy")
            self.denial(case["terminal_result"], "BLOCKED" if name == "owner-rejected-tampered-bundle" else "DENIED", reason, "CASE:" + name)
            self.denial(case["owner_journal_result"], "BLOCKED", "UNKNOWN_OPERATION", "CASE:no-persisted-grant")
            self.oracle(case["oracle"], expected=0, material_name=name)
        for name, status, reason in (("owner-terminal-required", "BLOCKED", "TERMINAL_REQUIRED"), ("forged-owner-grant", "DENIED", "INVALID_SIGNATURE")):
            case = self.case_records[name]
            exact(case, {"case", "result", "response", "oracle"}, "CASE:" + name)
            self.denial(case["response"], status, reason, "CASE:" + name)
            self.oracle(case["oracle"], expected=0)
        for name, material_name, result, count in (("authorized", "authorized", "COMMITTED", 1), ("exact-retry", "authorized", "ALREADY_COMMITTED", 1),
                ("status-recovery", "lost-reply", "COMMITTED", 2), ("recovered-exact-retry", "lost-reply", "ALREADY_COMMITTED", 2)):
            case = self.case_records[name]
            exact(case, {"case", "result", "operation_id", "response", "receipt_verification", "oracle"}, "CASE:" + name)
            response = case["response"]
            exact(response, {"result", "receipt"}, "CASE:effect-response")
            need(response["result"] == result and case["operation_id"] == self.materials[material_name]["action"]["payload"]["operation_id"], "CASE:effect-result")
            checked = self.effect(response["receipt"], material_name)
            need(same(checked, case["receipt_verification"]) and same(response["receipt"], case["oracle"]["operation"]["receipt"]), "CASE:same-ledger-receipt")
            self.oracle(case["oracle"], expected=count, material_name=material_name)
        lost = self.case_records["lost-reply"]
        need(same(lost, {"case": "lost-reply", "result": "PASS", "response": {"status": "AMBIGUOUS", "code": "SCRIPTED_REPLY_NOT_READ"},
             "operation_id": self.materials["lost-reply"]["action"]["payload"]["operation_id"], "counter_at_disconnect": "UNKNOWN_UNTIL_STATUS"}), "CASE:lost-reply-remains-ambiguous")
        recovery = self.case_records["owner-grant-recovery"]
        exact(recovery, {"case", "result", "response", "oracle"}, "CASE:owner-grant-recovery")
        need(same(recovery["response"], {"status": "GRANT_RECORDED", "operation_id": self.materials["lost-reply"]["request"]["operation_id"],
            "grant": self.materials["lost-reply"]["grant"], "scope": "RECORDED_GRANT_ONLY", "current_authorization": "NOT_ESTABLISHED", "effect": "NOT_ESTABLISHED"}), "CASE:identical-recovered-grant")
        self.oracle(recovery["oracle"], expected=2)

    @staticmethod
    def denial(value, status, reason, label):
        exact(value, {"status", "reason", "message"}, label)
        need(value["status"] == status and value["reason"] == reason and type(value["message"]) is str
             and 1 <= len(value["message"]) <= 4096, label + ":exact-reason")

    def custody(self):
        case = self.case_records["private-key-separation"]
        exact(case, {"case", "result", "peer_uid_controls", "ci_coordinator", "private_keys_loaded_by_coordinator"}, "CUSTODY")
        need(case["ci_coordinator"] == "TRUSTED_ADMINISTRATOR" and case["private_keys_loaded_by_coordinator"] is False, "CUSTODY:bounded-claim")
        controls = case["peer_uid_controls"]
        exact(controls, {"client", "owner", "verifier"}, "CUSTODY:readers")
        for role, destinations in (("client", {"owner", "verifier"}), ("owner", {"verifier"}), ("verifier", {"owner"})):
            record = controls[role]
            exact(record, {"uid", "probes"}, "CUSTODY:reader")
            integer(record["uid"], self.roles[role]["uid"], self.roles[role]["uid"], "CUSTODY:observed-uid")
            need(type(record["probes"]) is list and len(record["probes"]) == len(destinations)
                 and {p["path_role"] for p in record["probes"]} == destinations, "CUSTODY:exact-peer-paths")
            for probe in record["probes"]:
                exact(probe, {"path_role", "denied", "errno"}, "CUSTODY:probe")
                need(probe["denied"] is True, "CUSTODY:denied")
                integer(probe["errno"], 13, 13, "CUSTODY:filesystem-EACCES")

    def execution(self):
        case = self.case_records["immutable-execution"]
        exact(case, {"case", "result", "pid", "uid", "uids", "gids", "supplementary_groups", "effective_capabilities",
                    "permitted_capabilities", "ambient_capabilities", "command", "image_device", "process_root_device",
                    "process_root_inode", "image_inode", "executable_device", "executable", "file_mappings", "root_write_open_denied_readonly",
                    "root_write_errno", "mountinfo", "oracle"}, "PROCESS")
        integer(case["pid"], 2, 2 ** 31 - 1, "PROCESS:pid")
        integer(case["uid"], self.accounts["gate_uid"], self.accounts["gate_uid"], "PROCESS:gate-uid")
        need(same(case["uids"], [self.accounts["gate_uid"]] * 4)
             and same(case["gids"], [self.accounts["gate_gid"]] * 4)
             and same(case["supplementary_groups"], [self.accounts["client_gid"]]), "PROCESS:dropped-credentials")
        for field in ("effective_capabilities", "permitted_capabilities", "ambient_capabilities"):
            need(type(case[field]) is str and re.fullmatch(r"0+", case[field]) is not None, "PROCESS:no-capabilities")
        for field in ("image_device", "process_root_device", "executable_device"):
            integer(case[field], self.image_device, self.image_device, "PROCESS:verity-device")
        integer(case["image_inode"], 1, label="PROCESS:root-inode")
        integer(case["process_root_inode"], case["image_inode"], case["image_inode"], "PROCESS:same-root-inode")
        expected_command = ENTRY + ["serve", "--state", "/state/gate", "--boot-policy", "/state/boot-policy.json",
            "--socket", "/socket/gate.sock", "--socket-gid", str(self.accounts["client_gid"]), "--replace-stale-socket"]
        need(case["command"] == expected_command and case["executable"].endswith("/usr/bin/python3"), "PROCESS:fixed-entrypoint")
        need(case["root_write_open_denied_readonly"] is True, "PROCESS:root-write-denied")
        integer(case["root_write_errno"], 30, 30, "PROCESS:EROFS")
        mappings = case["file_mappings"]
        need(type(mappings) is list and 1 <= len(mappings) <= 4096, "PROCESS:file-mappings")
        for mapping in mappings:
            exact(mapping, {"path", "device"}, "PROCESS:mapping")
            need(type(mapping["path"]) is str and mapping["path"].startswith("/"), "PROCESS:mapped-path")
            integer(mapping["device"], self.image_device, self.image_device, "PROCESS:all-mapped-code-on-image")
        mountinfo = case["mountinfo"]
        need(type(mountinfo) is list and 1 <= len(mountinfo) <= 4096, "PROCESS:mount-records")
        mounts = {}
        for line in mountinfo:
            need(type(line) is str and len(line) <= 8192, "PROCESS:mount-record")
            parts = line.split()
            need(len(parts) >= 10 and "-" in parts[6:], "PROCESS:mount-grammar")
            if parts[4] in ("/", "/state", "/socket", "/run/wolfalibi/config-manifest.json", "/run/wolfalibi/image-boot.json"):
                need(parts[4] not in mounts, "PROCESS:unambiguous-required-mount")
            mounts[parts[4]] = parts
        need("/" in mounts and "ro" in mounts["/"][5].split(","), "PROCESS:readonly-root-mount")
        need(mounts["/"][2] == f"{os.major(self.image_device)}:{os.minor(self.image_device)}",
             "PROCESS:root-mount-device-binding")
        for path in ("/state", "/socket"):
            need(path in mounts and "rw" in mounts[path][5].split(","), "PROCESS:bounded-writable-binds")
        for path in ("/run/wolfalibi/config-manifest.json", "/run/wolfalibi/image-boot.json"):
            need(path in mounts and "ro" in mounts[path][5].split(","), "PROCESS:readonly-bootstrap-binds")
        for path, binding in self.bound_mounts.items():
            device = binding["destination_device"]
            need(mounts[path][2] == f"{os.major(device)}:{os.minor(device)}", "PROCESS:launch-bind-device")
        self.oracle(case["oracle"], expected=0)

    def completion(self):
        summary = self.json("summary.json")
        exact(summary, {"schema", "result", "assurance", "prototype_version", "actual_human_approval", "approval_driver",
            "owner_interface_implemented", "coordinator_authority", "gate_image_binding", "continuous_process_identity_qualified",
            "hardware_qualification", "production_qualification", "action", "fresh_genuine_assessments", "target_identity",
            "final_oracle", "gate_daemons_stopped", "cases", "limitations", "current_authorization"}, "SUMMARY")
        expected = {"schema": "wolfalibi.shirudo.prototype-lab.v1", "result": "PASS", "assurance": "LAB_VTPM", "prototype_version": "0.1.0",
            "actual_human_approval": "NOT_RUN", "approval_driver": "SCRIPTED_PTY", "owner_interface_implemented": True,
            "coordinator_authority": "TRUSTED_CI_ADMINISTRATOR", "gate_image_binding": "NATIVE_CONFIG_PCR14_TRANSITIVE_BINDING",
            "continuous_process_identity_qualified": False, "hardware_qualification": False, "production_qualification": False,
            "action": ACTION, "fresh_genuine_assessments": 5, "target_identity": self.identity, "gate_daemons_stopped": True,
            "current_authorization": False}
        need(all(same(summary[k], v) for k, v in expected.items()), "SUMMARY:bounded-prototype-verdict")
        need(same(summary["cases"], [self.case_records[name] for name in CASES]), "SUMMARY:ordered-case-copies")
        need(same(summary["limitations"], EXPECTED_SCOPE_LIMITATIONS), "SUMMARY:limitations")
        need(same(summary["final_oracle"], self.case_records["recovered-exact-retry"]["oracle"]), "SUMMARY:final-ledger-copy")
        self.oracle(summary["final_oracle"], expected=2, material_name="lost-reply")
        for key in ("challenge_id", "nonce"):
            need(len({m["attestation"]["payload"][key] for m in self.materials.values()}) == 5, "MATERIAL:distinct-fresh-" + key)
        need(len({m["action"]["payload"]["operation_id"] for m in self.materials.values()}) == 5
             and len(self.owner_ids) == 1 and set(self.effects) == {"authorized", "lost-reply"}, "MATERIAL:unique-operations-owner-effects")
        need(len({m["action"]["payload"]["operation_nonce"] for m in self.materials.values()}) == 5
             and len({m["intent"]["request_id"] for m in self.materials.values()}) == 5,
             "MATERIAL:unique-operation-nonces-and-reviewed-requests")
        need(len({self.materials[name]["grant"]["payload"]["grant_id"] for name in self.effects}) == 2
             and len({record["payload"]["receipt_id"] for record in self.effects.values()}) == 2,
             "EFFECT:distinct-grants-and-receipts")
        commands = self.json("commands.json")
        need(type(commands) is list and 20 <= len(commands) <= 512, "COMMANDS:bounded-records")
        for command in commands:
            keys = {"stage", "started_at_ms", "completed_at_ms", "exit_code", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256"}
            need(type(command) is dict and set(command) in (keys, keys | {"public_error"}), "COMMANDS:schema")
            need(type(command["stage"]) is str and 1 <= len(command["stage"]) <= 256, "COMMANDS:stage")
            start = integer(command["started_at_ms"])
            integer(command["completed_at_ms"], start, start + 120_000, "COMMANDS:bounded-time")
            integer(command["exit_code"], 0, 0, "COMMANDS:success")
            for stream in ("stdout", "stderr"):
                integer(command[stream + "_bytes"], 0, 262144, "COMMANDS:bounded-output")
                hexadecimal(command[stream + "_sha256"], label="COMMANDS:output-hash")
            need(command.get("public_error", "") == "", "COMMANDS:no-hidden-error")
        units = self.raw["cleanup/units.txt"].decode("ascii")
        blocks = [b for b in units.strip().split("\n\n") if b]
        expected_units = {"wolfproto-check-1.service", "wolfproto-check-2.service", "wolfproto-check-3.service", "wolfproto-gate.service"}
        seen = set()
        for block in blocks:
            pairs = [line.split("=", 1) for line in block.splitlines()]
            need(all(len(pair) == 2 for pair in pairs), "CLEANUP:unit-fields")
            values = dict(pairs)
            exact(values, {"Id", "ActiveState", "MainPID"}, "CLEANUP:unit")
            need(len(pairs) == 3 and values["Id"] not in seen and values["ActiveState"] in ("inactive", "failed")
                 and values["MainPID"] == "0", "CLEANUP:stopped-unit")
            seen.add(values["Id"])
        need(seen == expected_units, "CLEANUP:exact-owned-units")

    def run(self):
        self.load()
        self.layout()
        self.trust()
        self.measurement()
        self.owner_profile()
        for name in MATERIALS:
            self.material(name)
        self.cases()
        self.completion()
        return {"schema": "wolfalibi.shirudo.prototype-artifact-review.v1", "result": "PASS",
            "scope": "HISTORICAL_LAB_ARTIFACT_CONSISTENCY", "executed_code_commit": CODE_COMMIT,
            "executed_code_tree": CODE_TREE, "expected_run_id": EXPECTED_RUN, "file_count": self.file_count,
            "total_bytes": self.byte_count, "image_manifest_files": self.source_file_count,
            "required_cases": len(CASES), "genuine_recorded_assessments": self.reports,
            "ed25519_signatures_verified": len(self.signature_records), "ed25519_signature_checks": self.signatures,
            "recorded_owner_grants": 2,
            "recorded_counter_effects": 2, "final_counter": 2, "actual_human_approval": "NOT_RUN",
            "current_authorization": False, "external_provenance": "REQUIRES_SEPARATE_AUTHENTICATED_CHECK",
            "limitations": LIMITATIONS}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        report = Review(args.directory).run()
    except (ReviewError, OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"schema": "wolfalibi.shirudo.prototype-artifact-review.v1", "result": "FAIL",
                          "reason": str(exc)[:1024], "current_authorization": False}, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


