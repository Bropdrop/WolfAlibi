#!/usr/bin/env python3
"""Read-only consistency review of an extracted evidence/action directory.

Usage: python review_action_artifact.py DIRECTORY

This standalone reviewer imports no WolfAlibi adapter code and performs no
network, target, subprocess, installation, or state-mutating operation. It
requires cryptography for Ed25519 verification. Retained laboratory keys are
not an external identity root. TPM crypto and GitHub metadata are not rerun.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

UPSTREAM = "fb97c1ec5908c8bdbd46760c29e57677977fce74"
ELF_SHA = "be8b79cdd7efb8e635b7965bf34fa691e5e4a378957f3829530a529097abe9d2"
ARCHIVE_SHA = "e830f2384383adccba7c423e8afe81d1fd0b3d6e27e66ce2aed49eae632e989c"
VERSION = "7e222b2b27b2408615a4f5b20cb31215e185ee5d6f0ae0bee2910f7479f58c2d"
CODE_COMMIT = "521a3c887e86a9d4db0c4b416433146d7161fef9"
CODE_TREE = "1d4356d5b0da3c7dfef13b0c3f9c246a778ba64b"
EXPECTED_RUN = 45298950620
ACTION = {"name": "increment_counter", "delta": 1}
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_INTEGER = 2 ** 63 - 1
EMPTY_SHA = hashlib.sha256(b"").hexdigest()
RECOVERY = "DAEMON_RESTART_AND_SQLITE_CRASH_RECOVERY; NO_EXECUTION_REQUEST"
SOURCE_PINS = {
    "shirudo_adapter/__init__.py": (104, "c0c4b5830115f8afa8824e6f66cb055c8d1fd9439445ce84ae9f600c99299f8d"),
    "shirudo_adapter/__main__.py": (48, "935a1c1166b0c1ea35a82256345000bf2c73ded718d77773bc27a71ecce28f7d"),
    "shirudo_adapter/action_gate.py": (46583, "2d12715767220bbaa683bfab800ad4ed56dcd721ebe8962d00fe27c96b7097ee"),
    "shirudo_adapter/action_gate_cli.py": (20246, "9eeb3f67e4817341f36ac56c424f2e7704b83e67648adedf00e441f49a612b5e"),
    "shirudo_adapter/cli.py": (3452, "b3ad179ccd446a7a6ea78b8051707a9e2950085c5550302a075759bf5fa30457"),
    "shirudo_adapter/model.py": (9431, "d7db42841dc3e2009c93da1be8474938e9dc7f7c8d442f6b715746ebf8c79ad5"),
    "shirudo_adapter/receipt.py": (7629, "969d65b0b10632cb4df937a30d9d29bd258c7d81ac4ae6ee325f4f20bca9d7ca"),
    "shirudo_adapter/runner.py": (23466, "a4d521dfd22e847f898efed2e0274958303982f3bdc936542f374474a7ad1ef9"),
    "shirudo_adapter/service.py": (21635, "828f97a03d64d80888c126a94112797091edf6cdd9f28598bdb6c011fec19d7c"),
}
MATERIALS = ("operation-expiry", "authorized", "missing-authority", "signatures",
             "bounded-action", "different-assessment", "grant-revocation", "grant-expiry",
             "concurrent", "before-commit", "after-commit", "policy-revocation")
# name, material, expected response/denial, protected counter delta
CASES = (
    ("authorized", "authorized", "COMMITTED", 1),
    ("exact-retry", "authorized", "ALREADY_COMMITTED", 0),
    ("attestation-reuse", "authorized", "ATTESTATION_REUSED", 0),
    ("completed-operation-conflict", "authorized", "OPERATION_CONFLICT", 0),
    ("assessment-alone", "missing-authority", "INVALID_SCHEMA", 0),
    ("grant-alone", "missing-authority", "INVALID_SCHEMA", 0),
    ("forged-owner", "signatures", "INVALID_SIGNATURE", 0),
    ("forged-verifier", "signatures", "INVALID_SIGNATURE", 0),
    ("widened-action", "bounded-action", "INVALID_SCHEMA", 0),
    ("wrong-target", "bounded-action", "GRANT_MISMATCH", 0),
    ("wrong-policy", "bounded-action", "GRANT_MISMATCH", 0),
    ("different-valid-assessment", "different-assessment", "RECEIPT_SCOPE_MISMATCH", 0),
    ("grant-revoked", "grant-revocation", "GRANT_REVOKED", 0),
    ("grant-expired", "grant-expiry", "GRANT_EXPIRED", 0),
    ("operation-expired", "operation-expiry", "OPERATION_EXPIRED", 0),
    ("concurrent", "concurrent", "CONCURRENT", 1),
    ("direct-database-access", None, "DIRECT_DENIED", 0),
    ("client-admin-denied", "authorized", "UNKNOWN_OPERATION", 0),
    ("before-commit-interruption", "before-commit", "AMBIGUOUS", 0),
    ("before-commit-retry", "before-commit", "COMMITTED", 1),
    ("after-commit-lost-reply", "after-commit", "AMBIGUOUS", 1),
    ("lost-reply-status-recovery", "after-commit", "STATUS", 0),
    ("lost-reply-exact-retry", "after-commit", "ALREADY_COMMITTED", 0),
    ("policy-revoked", "policy-revocation", "POLICY_REVOKED", 0),
    ("prepare-after-revocation", "policy-revocation", "POLICY_REVOKED", 0),
    ("historical-retry-after-revocation", "authorized", "ALREADY_COMMITTED", 0),
)
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
LIMITATIONS = [
    "Checks consistency and Ed25519 signatures under public LAB keys retained in this artifact; those keys are not an external identity root.",
    "Does not independently execute Shirudo or verify the underlying TPM quote/certification cryptography.",
    "Source content is pinned to the reviewed code commit; GitHub run, job, artifact and archive association require a separate authenticated provenance check.",
    "Builder, hypervisor, software TPM, verifier signer, owner signer, target root, databases, clocks and recorded observations remain trusted.",
    "No hardware identity, independent owner custody, human approval, measured gate image, continuous state or coordinated rollback resistance is established.",
    "Effect receipts authenticate past laboratory counter records; they provide no current authorization or general target command authority.",
    "Process-exit observations do not establish power-loss durability or complete agent confinement.",
]


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
        self.reports, self.signatures = 0, 0

    def json(self, name):
        need(name in self.raw, "FILE:missing:" + name)
        return strict(self.raw[name])

    def record(self, value, key, label):
        payload = signed(value, key, label)
        self.signatures += 1
        return payload

    def load(self):
        need(stat.S_ISDIR(self.root.lstat().st_mode), "DIRECTORY:not-regular")
        total = 0
        for directory, subdirs, files in os.walk(self.root, followlinks=False):
            for name in subdirs:
                need(stat.S_ISDIR((Path(directory) / name).lstat().st_mode), "DIRECTORY:symlink")
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

    def layout(self):
        fixed = {"artifact-manifest.json", "baseline-manifest.json", "trust.json", "policy.json",
                 "target-identity.json", "client-identity.json", "initial-oracle.json", "summary.json", "commands.json",
                 "source/target-code.zip", "source/manifest.json", "source/target-installation.json",
                 "cleanup/daemon-status.json", "faults/exit-70.json", "faults/exit-71.json"}
        fixed.update("inputs/" + name for name in ("enrollment.json", "target-build.txt", "runtime-template.txt",
                     "config-root.txt", "primary.der", "boot.der", "verifier-version.txt", "prediction.json", "baseline-status.json"))
        for name in MATERIALS:
            fixed.update(f"materials/{name}/{file}" for file in ("attestation-challenge.json", "action-challenge.json",
                         "evidence.json", "assessment.json", "assessment-verification.json", "grant.json", "request.json"))
        for name, _material, _result, _delta in CASES:
            fixed.add(f"cases/{name}/result.json")
            if name not in {"direct-database-access", "lost-reply-status-recovery"}:
                fixed.add(f"cases/{name}/request.json")
            if name not in {"concurrent", "direct-database-access", "lost-reply-status-recovery"}:
                fixed.add(f"cases/{name}/response.json")
        fixed.update(f"cases/{name}/expiry-observation.json" for name in ("grant-expired", "operation-expired"))
        fixed.update(f"cases/{name}/admin-result.json" for name in ("grant-revoked", "policy-revoked"))
        need(set(self.raw) == fixed, "LAYOUT:exact-public-exports")

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
        need(policy["schema"] == "wolfalibi.shirudo.policy.v1" and policy["policy_id"] == "lab-counter-policy"
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

    def source(self):
        raw = self.raw["source/target-code.zip"]
        need(len(raw) <= 65_536, "SOURCE:zip-limit")
        observed = {}
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            need(len(names) == len(set(names)) and set(names) == set(SOURCE_PINS) | {"trust.json"}, "SOURCE:exact-zip-members")
            need(sum(item.file_size for item in infos) <= 1_048_576, "SOURCE:expanded-limit")
            for item in infos:
                need(not item.is_dir() and item.file_size <= 262_144 and ((item.external_attr >> 16) & 0o170000) == 0o100000,
                     "SOURCE:regular-member")
                body = archive.read(item)
                observed[item.filename] = {"sha256": sha(body), "bytes": len(body)}
                if item.filename == "trust.json":
                    need(body == canonical(self.trusted) + b"\n", "SOURCE:trust-copy")
                else:
                    size, digest_pin = SOURCE_PINS[item.filename]
                    need(len(body) == size and sha(body) == digest_pin, "SOURCE:reviewed-commit:" + item.filename)
        need(same(self.json("source/manifest.json"), observed), "SOURCE:manifest")
        installed = self.json("source/target-installation.json")
        exact(installed, {"uid", "files", "python_version", "cryptography_version"}, "SOURCE:installation")
        integer(installed["uid"], 0, 0, "SOURCE:installer-uid")
        need(same(installed["files"], observed) and installed["cryptography_version"] == "50.0.0", "SOURCE:installed-content-and-dependency")
        need(type(installed["python_version"]) is str and re.fullmatch(r"3\.(?:1[1-9]|[2-9][0-9])\.[0-9]+", installed["python_version"]) is not None,
             "SOURCE:supported-python")

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

    def material(self, name):
        prefix = "materials/" + name + "/"
        att_record, action_record = self.json(prefix + "attestation-challenge.json"), self.json(prefix + "action-challenge.json")
        assessment_record, grant_record = self.json(prefix + "assessment.json"), self.json(prefix + "grant.json")
        att = self.attestation(att_record, name + ":challenge")
        action = self.record(action_record, self.gate_key, name + ":action")
        exact(action, ACTION_KEYS, name + ":action")
        expected = {"schema": "wolfalibi.shirudo.action-challenge.v1", "gate_instance_id": self.gate_id,
                    "target_id": self.target, "policy_sha256": self.policy_sha, "policy_generation": 1,
                    "attestation_challenge_sha256": digest(att_record), "attestation_challenge_id": att["challenge_id"],
                    "attestation_nonce": att["nonce"]}
        need(all(action[k] == v for k, v in expected.items()), name + ":action-binding")
        integer(action["policy_generation"], 1, 1, name + ":generation")
        hexadecimal(action["operation_id"], 32, name + ":operation")
        hexadecimal(action["operation_nonce"], label=name + ":operation-nonce")
        fixed_action(action["action"], name + ":action-effect")
        interval(action, 30_000, name + ":action")
        need(-2000 <= action["issued_at_ms"] - att["issued_at_ms"] <= 5000 and action["expires_at_ms"] ==
             min(action["issued_at_ms"] + 30_000, att["issued_at_ms"] + 30_000, att["expires_at_ms"]), name + ":admission-freshness")
        assessment = self.record(assessment_record, self.verifier_key, name + ":assessment")
        exact(assessment, ASSESSMENT_KEYS, name + ":assessment")
        for key in ("instance_id", "challenge_id", "nonce", "target_id", "policy_sha256", "issued_at_ms", "expires_at_ms"):
            need(assessment[key] == att[key], name + ":assessment-challenge:" + key)
        need(assessment["schema"] == "wolfalibi.shirudo.receipt.v1" and assessment["assurance"] == "LAB_VTPM"
             and assessment["outcome"] == "EVIDENCE_ACCEPTED" and assessment["reason_code"] == "REQUIRED_CHECKS_PASSED"
             and assessment["scope"] == "HISTORICAL_EVIDENCE_ONLY" and assessment["authorization"] == "NONE"
             and assessment["enrollment_record_sha256"] == self.policy["enrollment"]["record_sha256"], name + ":assessment-scope")
        hexadecimal(assessment["receipt_id"], 32, name + ":assessment-id")
        started, completed = integer(assessment["started_at_ms"]), integer(assessment["completed_at_ms"])
        need(att["issued_at_ms"] <= started <= completed < att["expires_at_ms"]
             and started >= action["issued_at_ms"] - 2000, name + ":assessment-time")
        limits = assessment["limitations"]
        need(type(limits) is list and 1 <= len(limits) <= 16 and all(type(v) is str and 1 <= len(v) <= 1024 for v in limits), name + ":assessment-limitations")
        raw_evidence = self.raw[prefix + "evidence.json"]
        need(len(raw_evidence) <= 1_048_576 and assessment["evidence_sha256"] == sha(raw_evidence), name + ":evidence-hash")
        evidence = strict(raw_evidence)
        need(type(evidence) is dict and type(evidence["schema"]) is int and evidence["schema"] == 1
             and evidence["kind"] == "shirudo-attestation" and evidence["pcr_bank"] == "sha256"
             and evidence["nonce"] == att["nonce"] and evidence["ak"]["name"] == self.policy["enrollment"]["ak_name"]
             and evidence["ek"]["name"] == self.policy["enrollment"]["ek_name"]
             and evidence["register"]["value"] == self.policy["expected"]["chain"], name + ":evidence-bindings")
        self.report(assessment["upstream"], name + ":upstream")
        need(same(self.json(prefix + "assessment-verification.json"), {"signature_valid": True, "historical_outcome": "EVIDENCE_ACCEPTED",
             "current_authorization": False, "current_target_state": "NOT_ESTABLISHED", "assurance": "LAB_VTPM",
             "receipt_id": assessment["receipt_id"], "scope": "HISTORICAL_EVIDENCE_ONLY"}), name + ":assessment-verification-copy")
        grant = self.record(grant_record, self.owner_key, name + ":grant")
        exact(grant, GRANT_KEYS, name + ":grant")
        for key in ("gate_instance_id", "target_id", "operation_id", "operation_nonce", "policy_sha256", "policy_generation", "action", "attestation_challenge_sha256"):
            need(grant[key] == action[key], name + ":grant-binding:" + key)
        need(grant["schema"] == "wolfalibi.shirudo.action-grant.v1" and grant["scope"] == "LAB_OWNER_GRANT"
             and grant["action_challenge_sha256"] == digest(action_record)
             and grant["attestation_receipt_sha256"] == digest(assessment_record), name + ":grant-authority")
        integer(grant["policy_generation"], 1, 1, name + ":grant-generation")
        hexadecimal(grant["grant_id"], 32, name + ":grant-id")
        fixed_action(grant["action"], name + ":grant-action")
        interval(grant, 30_000, name + ":grant")
        need(grant["expires_at_ms"] <= action["expires_at_ms"] and
             grant["issued_at_ms"] >= max(action["issued_at_ms"], completed) - 2000, name + ":grant-time")
        request = self.json(prefix + "request.json")
        need(same(request, {"operation_id": action["operation_id"], "grant": grant_record, "assessment": assessment_record}), name + ":request")
        self.materials[name] = {"attestation": att_record, "action": action_record,
                                "assessment": assessment_record, "grant": grant_record, "request": request}

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
        before = integer(payload["counter_before"], 0, 3)
        after = integer(payload["counter_after"], 1, 4)
        need(after == before + 1, material_name + ":single-effect")
        order = {"authorized": 1, "concurrent": 2, "before-commit": 3, "after-commit": 4}
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

    def oracle(self, value, material_name=None):
        keys = {"counter", "committed_operations", "observed_at_ms", "reader_uid", "state_uid",
                "state_mode", "database_uid", "database_mode"}
        exact(value, keys | ({"operation"} if material_name is not None else set()), "ORACLE")
        integer(value["counter"], 0, 4, "ORACLE:counter")
        integer(value["committed_operations"], 0, 4, "ORACLE:committed-count")
        integer(value["observed_at_ms"], label="ORACLE:time")
        need(value["counter"] == value["committed_operations"], "ORACLE:counter-ledger")
        for name in ("reader_uid", "state_uid", "database_uid"):
            integer(value[name], 0, 0, "ORACLE:" + name)
        integer(value["state_mode"], 0o700, 0o700, "ORACLE:directory-mode")
        integer(value["database_mode"], 0o600, 0o600, "ORACLE:database-mode")
        if material_name is not None:
            row = value["operation"]
            exact(row, {"status", "request_sha256", "grant_id", "assessment_sha256", "receipt", "counter_before", "counter_after"}, "ORACLE:operation")
            if row["status"] == "PREPARED":
                need(all(row[k] is None for k in set(row) - {"status"}), "ORACLE:uncommitted-effect-empty")
            else:
                need(row["status"] == "COMMITTED", "ORACLE:status")
                checked = self.effect(row["receipt"], material_name)
                material = self.materials[material_name]
                integer(row["counter_before"], 0, 3, "ORACLE:counter-before")
                integer(row["counter_after"], 1, 4, "ORACLE:counter-after")
                need(row["request_sha256"] == digest(material["request"])
                     and row["grant_id"] == material["grant"]["payload"]["grant_id"]
                     and row["assessment_sha256"] == digest(material["assessment"])
                     and row["counter_before"] == checked["counter_before"]
                     and row["counter_after"] == checked["counter_after"]
                     and row["counter_after"] <= value["counter"]
                     and row["receipt"]["payload"]["committed_at_ms"] <= value["observed_at_ms"],
                     "ORACLE:retained-authority-binding")
        return value

    def wrapper(self, wrapper, label):
        exact(wrapper, {"client_exit_code", "document", "stderr_bytes", "stderr_sha256"}, label)
        integer(wrapper["client_exit_code"], 0, 2, label + ":client-exit")
        need(wrapper["client_exit_code"] in (0, 2) and type(wrapper["document"]) is dict, label + ":transport-shape")
        integer(wrapper["stderr_bytes"], 0, 0, label + ":stderr-bytes")
        need(wrapper["stderr_sha256"] == EMPTY_SHA, label + ":stderr-hash")
        need((wrapper["client_exit_code"] == 2) == (wrapper["document"].get("status") == "AMBIGUOUS"), label + ":transport-outcome")
        return wrapper["document"]

    def request_case(self, name, material_name):
        document = self.json(f"cases/{name}/request.json")
        material = self.materials[material_name]
        if name == "client-admin-denied":
            need(same(document, {"op": "revoke-policy"}), name + ":requested-admin-control")
            return
        if name == "attestation-reuse":
            need(same(document, {"op": "prepare", "attestation_challenge": material["attestation"]}), name + ":same-challenge")
            return
        if name == "prepare-after-revocation":
            exact(document, {"op", "attestation_challenge"}, name)
            need(document["op"] == "prepare", name + ":operation")
            challenge = self.attestation(document["attestation_challenge"], name)
            need(challenge["challenge_id"] not in {m["attestation"]["payload"]["challenge_id"] for m in self.materials.values()},
                 name + ":fresh-challenge")
            return
        exact(document, {"op", "request"}, name)
        need(document["op"] == "execute", name + ":operation")
        requested = document["request"]
        original = material["request"]
        if name in {"assessment-alone", "grant-alone"}:
            expected = dict(original)
            del expected["grant" if name == "assessment-alone" else "assessment"]
            need(same(requested, expected), name + ":missing-authority-control")
            return
        exact(requested, {"operation_id", "grant", "assessment"}, name + ":request")
        need(requested["operation_id"] == original["operation_id"], name + ":retained-operation")
        changed = {"completed-operation-conflict", "forged-owner", "forged-verifier", "widened-action",
                   "wrong-target", "wrong-policy", "different-valid-assessment"}
        if name not in changed:
            need(same(requested, original), name + ":exact-request")
            return
        grant_expected = copy.deepcopy(original["grant"]["payload"])
        if name == "forged-verifier":
            need(same(requested["assessment"]["payload"], original["assessment"]["payload"]), name + ":same-assessment-payload")
            invalid_signature(requested["assessment"], self.verifier_key, name + ":assessment")
            grant_expected["attestation_receipt_sha256"] = digest(requested["assessment"])
        elif name == "different-valid-assessment":
            need(same(requested["assessment"], self.materials["authorized"]["assessment"]), name + ":other-valid-assessment")
            grant_expected["attestation_receipt_sha256"] = digest(requested["assessment"])
        else:
            need(same(requested["assessment"], original["assessment"]), name + ":assessment-unchanged")
        if name == "forged-owner":
            need(same(requested["grant"]["payload"], grant_expected), name + ":same-grant-payload")
            invalid_signature(requested["grant"], self.owner_key, name + ":owner")
            return
        grant = self.record(requested["grant"], self.owner_key, name + ":owner")
        if name == "completed-operation-conflict":
            hexadecimal(grant["grant_id"], 32, name + ":new-grant")
            need(grant["grant_id"] != grant_expected["grant_id"], name + ":changed-grant")
            grant_expected["grant_id"] = grant["grant_id"]
        elif name == "widened-action":
            grant_expected["action"]["delta"] = 2
        elif name == "wrong-target":
            grant_expected["target_id"] = "other-lab-target"
        elif name == "wrong-policy":
            grant_expected["policy_sha256"] = "0" * 64
        need(same(grant, grant_expected), name + ":exact-hostile-mutation")

    def status_response(self, document, material_name, after):
        exact(document, {"status", "result"}, "RECOVERY:response")
        need(document["status"] == "STATUS", "RECOVERY:status")
        value = document["result"]
        exact(value, {"schema", "gate_instance_id", "target_id", "policy_sha256", "policy_generation",
                      "policy_active", "counter", "committed_operations", "operation"}, "RECOVERY:body")
        need(value["schema"] == "wolfalibi.shirudo.action-status.v1" and value["gate_instance_id"] == self.gate_id
             and value["target_id"] == self.target and value["policy_sha256"] == self.policy_sha
             and value["policy_active"] is True, "RECOVERY:identity-policy")
        integer(value["policy_generation"], 1, 1, "RECOVERY:generation")
        integer(value["counter"], 4, 4, "RECOVERY:counter")
        integer(value["committed_operations"], 4, 4, "RECOVERY:committed-count")
        row = value["operation"]
        exact(row, {"operation_id", "status", "action_challenge", "request_sha256", "grant_id", "receipt"}, "RECOVERY:operation")
        material = self.materials[material_name]
        need(row["operation_id"] == material["request"]["operation_id"] and row["status"] == "COMMITTED"
             and row["action_challenge"] == material["action"] and row["request_sha256"] == digest(material["request"])
             and row["grant_id"] == material["grant"]["payload"]["grant_id"]
             and row["receipt"] == after["operation"]["receipt"], "RECOVERY:retained-operation")
        return self.effect(row["receipt"], material_name)

    def cases(self):
        summary = self.json("summary.json")
        expected_summary = {"schema": "wolfalibi.shirudo.action-lab.v1", "result": "PASS", "assurance": "LAB_VTPM",
            "owner_authority": "LAB_OWNER_GRANT", "source_commit": UPSTREAM, "verifier_sha256": ELF_SHA,
            "verifier_archive_sha256": ARCHIVE_SHA, "target_state_changes": "LAB_SETUP_AND_COUNTER",
            "protected_effect": "SQLITE_COUNTER_INCREMENT_BY_ONE", "target_identity": self.identity, "action": ACTION}
        for name, value in expected_summary.items():
            need(summary.get(name) == value, "SUMMARY:" + name)
        for name in ("positive_evidence_accepted", "target_contact", "private_adapter_state_removed", "gate_daemons_stopped"):
            need(summary.get(name) is True, "SUMMARY:" + name)
        for name in ("current_authorization", "hardware_qualification", "gate_measured_into_boot_image", "human_approval_implemented"):
            need(summary.get(name) is False, "SUMMARY:" + name)
        integer(summary["fresh_genuine_assessments"], 12, 12, "SUMMARY:assessment-count")
        need(type(summary["limitations"]) is list and len(summary["limitations"]) >= 8, "SUMMARY:limitations")
        results = summary["cases"]
        need(type(results) is list and [r["case"] for r in results] == [c[0] for c in CASES], "SUMMARY:exact-ordered-controls")
        initial = self.oracle(self.json("initial-oracle.json"))
        need(initial["counter"] == 0, "ORACLE:initial-zero")
        counter, timestamp = 0, initial["observed_at_ms"]
        self.case_results = {}
        for specification, result in zip(CASES, results):
            name, material_name, expected_response, delta = specification
            need(same(result, self.json(f"cases/{name}/result.json")), name + ":summary-case-copy")
            need(result["result"] == "PASS", name + ":recorded-pass")
            integer(result["expected_counter_delta"], delta, delta, name + ":expected-delta")
            integer(result["observed_counter_delta"], delta, delta, name + ":observed-delta")
            before = self.oracle(result["before"], material_name)
            after = self.oracle(result["after"], material_name)
            need(before["counter"] == counter and after["counter"] == counter + delta
                 and after["committed_operations"] - before["committed_operations"] == delta
                 and timestamp <= before["observed_at_ms"] <= after["observed_at_ms"], name + ":ordered-counter-observations")
            counter, timestamp = after["counter"], after["observed_at_ms"]
            if material_name is not None:
                need(result["material"] == material_name, name + ":material")
            common = {"case", "result", "expected_counter_delta", "observed_counter_delta", "before", "after"}
            if expected_response == "DIRECT_DENIED":
                exact(result, common | {"observation"}, name + ":case")
                observation = result["observation"]
                exact(observation, {"uid", "write_access", "errno", "permission_denied"}, name + ":observation")
                integer(observation["uid"], self.client_uid, self.client_uid, name + ":uid")
                integer(observation["errno"], 13, 13, name + ":EACCES")
                need(observation["write_access"] is False and observation["permission_denied"] is True, name + ":write-denied")
            elif expected_response == "STATUS":
                exact(result, common | {"material", "response", "receipt_verification"}, name + ":case")
                document = self.wrapper(result["response"], name)
                checked = self.status_response(document, material_name, after)
                need(same(result["receipt_verification"], checked), name + ":verification-copy")
            elif expected_response == "CONCURRENT":
                exact(result, common | {"material", "responses", "receipt_verification"}, name + ":case")
                self.request_case(name, material_name)
                wrappers = result["responses"]
                need(type(wrappers) is list and len(wrappers) == 2, name + ":two-responses")
                documents = [self.wrapper(w, name) for w in wrappers]
                for document in documents:
                    exact(document, {"result", "receipt"}, name + ":response")
                need(sorted(d["result"] for d in documents) == ["ALREADY_COMMITTED", "COMMITTED"]
                     and documents[0]["receipt"] == documents[1]["receipt"] == after["operation"]["receipt"], name + ":one-effect")
                checked = self.effect(documents[0]["receipt"], material_name)
                need(same(result["receipt_verification"], checked) and checked["counter_before"] == before["counter"]
                     and checked["counter_after"] == after["counter"], name + ":receipt-counter-binding")
            else:
                self.request_case(name, material_name)
                wrapper = self.json(f"cases/{name}/response.json")
                document = self.wrapper(wrapper, name)
                need(same(result["response"], document) and type(result["client_exit_code"]) is int
                     and result["client_exit_code"] == wrapper["client_exit_code"], name + ":response-copy")
                fields = common | {"material", "client_exit_code", "response"}
                if expected_response in {"COMMITTED", "ALREADY_COMMITTED"}:
                    fields.add("receipt_verification")
                    exact(document, {"result", "receipt"}, name + ":response")
                    need(wrapper["client_exit_code"] == 0 and document["result"] == expected_response
                         and document["receipt"] == after["operation"]["receipt"], name + ":effect-response")
                    checked = self.effect(document["receipt"], material_name)
                    need(same(result["receipt_verification"], checked), name + ":effect-verification-copy")
                    if delta:
                        need(checked["counter_before"] == before["counter"] and checked["counter_after"] == after["counter"],
                             name + ":effect-observed-delta")
                else:
                    exact(document, {"status", "reason", "message"}, name + ":response")
                    need(type(document["message"]) is str and len(document["message"]) <= 512, name + ":message")
                    if expected_response == "AMBIGUOUS":
                        need(wrapper["client_exit_code"] == 2 and document["status"] == "AMBIGUOUS"
                             and document["reason"] == "TRANSPORT_LOST", name + ":lost-transport")
                        if name == "before-commit-interruption":
                            fields.add("recovery_before_oracle")
                            need(result["recovery_before_oracle"] == RECOVERY and after["operation"]["status"] == "PREPARED"
                                 and after["operation"]["receipt"] is None, name + ":rollback-before-readonly-oracle")
                        else:
                            need(after["operation"]["status"] == "COMMITTED", name + ":durable-effect-despite-lost-reply")
                    else:
                        need(wrapper["client_exit_code"] == 0 and document["status"] == "DENIED"
                             and document["reason"] == expected_response, name + ":exact-denial")
                exact(result, fields, name + ":case")
            self.case_results[name] = result
        need(counter == 4 and same(summary["final_oracle"], results[-1]["after"]), "SUMMARY:final-ledger")
        need(set(self.effects) == {"authorized", "concurrent", "before-commit", "after-commit"}, "EFFECT:four-unique-operations")
        for key in ("receipt_id", "operation_id", "grant_id"):
            need(len({v["payload"][key] for v in self.effects.values()}) == 4, "EFFECT:unique-" + key)
        need([self.effects[name]["payload"]["counter_after"] for name in ("authorized", "concurrent", "before-commit", "after-commit")] == [1, 2, 3, 4],
             "EFFECT:complete-counter-chain")
        self.summary = summary

    def auxiliaries(self):
        for case_name, material_name, authority in (("grant-expired", "grant-expiry", "grant"),
                                                   ("operation-expired", "operation-expiry", "action")):
            observed = self.oracle(self.json(f"cases/{case_name}/expiry-observation.json"))
            need(observed["observed_at_ms"] >= self.materials[material_name][authority]["payload"]["expires_at_ms"]
                 and observed["observed_at_ms"] <= self.case_results[case_name]["before"]["observed_at_ms"], case_name + ":actual-clock-expiry")
        grant_revoke = self.json("cases/grant-revoked/admin-result.json")
        need(grant_revoke == {"status": "REVOKED", "grant_id": self.materials["grant-revocation"]["grant"]["payload"]["grant_id"]},
             "REVOCATION:grant")
        need(self.json("cases/policy-revoked/admin-result.json") == {"status": "REVOKED", "scope": "POLICY"}, "REVOCATION:policy")
        for code, number in ((70, 2), (71, 4)):
            fault = self.json(f"faults/exit-{code}.json")
            need(fault == {"unit": f"wolfalibi-action-gate-{number}.service", "ActiveState": "failed",
                          "ExecMainCode": "1", "ExecMainStatus": str(code)}, "FAULT:observed-exit-" + str(code))
        cleanup = self.json("cleanup/daemon-status.json")
        need(type(cleanup) is dict and set(cleanup) == {f"wolfalibi-action-gate-{i}.service" for i in range(1, 6)},
             "CLEANUP:all-five-owned-daemons")
        for unit, values in cleanup.items():
            exact(values, {"LoadState", "ActiveState", "MainPID", "query_exit_code"}, "CLEANUP:" + unit)
            need(values["MainPID"] == "0" and values["ActiveState"] in ("inactive", "failed"), "CLEANUP:no-running-daemon")
            integer(values["query_exit_code"], 0, 1, "CLEANUP:query-exit")
            need(values["query_exit_code"] == 0 or (values["LoadState"] == "not-found" and values["ActiveState"] == "inactive"),
                 "CLEANUP:successful-observation")
        commands = self.json("commands.json")
        need(type(commands) is list and 1 <= len(commands) <= 2000, "COMMANDS:bounded-list")
        stages = []
        for command in commands:
            exact(command, {"stage", "started_at_ms", "completed_at_ms", "exit_code", "stdout_bytes", "stdout_sha256",
                             "stderr_bytes", "stderr_sha256"}, "COMMANDS:record")
            need(type(command["stage"]) is str and 1 <= len(command["stage"]) <= 256, "COMMANDS:stage")
            stages.append(command["stage"])
            start = integer(command["started_at_ms"])
            end = integer(command["completed_at_ms"])
            need(start <= end, "COMMANDS:time")
            integer(command["exit_code"], 0, 0, "COMMANDS:exit")
            integer(command["stdout_bytes"], 0, 262_144, "COMMANDS:stdout-limit")
            integer(command["stderr_bytes"], 0, 65_536, "COMMANDS:stderr-limit")
            hexadecimal(command["stdout_sha256"], label="COMMANDS:stdout-hash")
            hexadecimal(command["stderr_sha256"], label="COMMANDS:stderr-hash")
        for stage, count in {"install selected public gate source": 1, "initialize private target state": 1,
                "start owned gate daemon": 5, "stop owned gate daemon": 5, "owned daemon process exit": 2,
                "unprivileged direct database access": 1, "verify all owned daemons stopped": 1}.items():
            need(stages.count(stage) == count, "COMMANDS:phase-count:" + stage)
        for name in MATERIALS:
            need(stages.count("collect action-" + name) == 1, "COMMANDS:fresh-collection:" + name)

    def run(self):
        self.load()
        self.layout()
        self.trust()
        self.source()
        client = self.json("client-identity.json")
        exact(client, {"user", "uid", "gid"}, "CLIENT")
        need(client["user"] == "wolfalibi-action-client", "CLIENT:name")
        self.client_uid = integer(client["uid"], 1, 2 ** 31 - 1, "CLIENT:nonroot-uid")
        integer(client["gid"], 1, 2 ** 31 - 1, "CLIENT:nonroot-gid")
        for name in MATERIALS:
            self.material(name)
        for record, field in (("attestation", "challenge_id"), ("attestation", "nonce"),
                              ("action", "operation_id"), ("action", "operation_nonce"),
                              ("grant", "grant_id"), ("assessment", "receipt_id")):
            need(len({m[record]["payload"][field] for m in self.materials.values()}) == 12, "MATERIALS:unique-" + field)
        self.cases()
        self.auxiliaries()
        return {
            "schema": "wolfalibi.shirudo.action-artifact-review.v1", "result": "PASS",
            "scope": "PUBLIC_ARTIFACT_CONSISTENCY_UNDER_RETAINED_LAB_KEYS",
            "files_verified": self.file_count, "bytes_verified": self.byte_count,
            "artifact_manifest_sha256": sha(self.raw["artifact-manifest.json"]),
            "summary_sha256": sha(self.raw["summary.json"]),
            "trust_sha256": digest(self.trusted), "policy_sha256": self.policy_sha,
            "target_id": self.target, "gate_instance_id": self.gate_id,
            "material_sets_verified": 12, "accepted_recorded_upstream_reports_verified": self.reports,
            "case_results_verified": 26, "unique_effects_verified": 4,
            "counter_chain": [0, 1, 2, 3, 4], "signature_verifications": self.signatures,
            "source_content_matches_commit": CODE_COMMIT,
            "expected_ci_context": {"repository": "Bropdrop/WolfAlibi", "run_id": EXPECTED_RUN,
                                    "commit": CODE_COMMIT, "tree": CODE_TREE,
                                    "run_association_independently_verified": False},
            "independent_tpm_verification": False, "current_authorization": False,
            "hardware_qualification": False, "human_approval_implemented": False,
            "limitations": LIMITATIONS,
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="extracted evidence/action directory")
    args = parser.parse_args(argv)
    try:
        result, code = Review(args.directory).run(), 0
    except ReviewError as exc:
        result, code = {"schema": "wolfalibi.shirudo.action-artifact-review.v1", "result": "FAIL",
                        "failed_check": str(exc), "current_authorization": False, "limitations": LIMITATIONS}, 1
    except Exception as exc:
        result, code = {"schema": "wolfalibi.shirudo.action-artifact-review.v1", "result": "FAIL",
                        "failed_check": "UNREADABLE_OR_MALFORMED_INPUT", "error_type": type(exc).__name__,
                        "current_authorization": False, "limitations": LIMITATIONS}, 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
