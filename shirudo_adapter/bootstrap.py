"""Authenticate one owner-approved policy for an immutable LAB gate image.

The image contains authority anchors, not a policy that hashes the image
containing itself. Its root is retained in Shirudo's signed configuration.
The owner signs the complete policy after that configuration root is known.
This provisioning signature does not authorize any counter operation.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

from .action_gate import (ACTION, MAX_TRUST_BYTES, Gate, _validate_trust)
from .model import (AdapterError, UPSTREAM_COMMIT, bounded_int, canonical_json,
                    digest, exact_keys, fail, identifier, read_bounded_file,
                    require_hex, strict_json)
from .receipt import verify_record

MAX_ANCHOR_BYTES = 16_384
MAX_MANIFEST_BYTES = 16_384
MAX_BOOT_POLICY_BYTES = MAX_TRUST_BYTES + 16_384
ANCHORS_PATH = Path("/etc/wolfalibi/anchors.json")
CONFIG_MANIFEST_PATH = Path("/run/wolfalibi/config-manifest.json")
BOOT_REPORT_PATH = Path("/run/wolfalibi/image-boot.json")
ENTRYPOINT = ["/usr/bin/python3", "-I", "-B", "-S", "/opt/wolfalibi/gate_entry.py"]
MOUNT_POINT = "/run/wolfalibi/image"


def _freeze(value, limit):
    return strict_json(canonical_json(value), limit)


def validate_anchors(value):
    anchors = _freeze(value, MAX_ANCHOR_BYTES)
    exact_keys(anchors, {"schema", "target_id", "owner_public_key", "verifier_public_key",
                         "verifier_instance_id", "verifier", "assurance", "action",
                         "max_challenge_ttl_seconds", "config_pcr"}, "bootstrap anchors")
    if anchors["schema"] != "wolfalibi.shirudo.bootstrap-anchors.v1":
        fail("BOOTSTRAP_SCHEMA", "Unsupported immutable bootstrap anchors")
    identifier(anchors["target_id"], "bootstrap target")
    for field in ("owner_public_key", "verifier_public_key"):
        require_hex(anchors[field], 64, field)
    require_hex(anchors["verifier_instance_id"], 32, "verifier instance")
    if anchors["owner_public_key"] == anchors["verifier_public_key"]:
        fail("BOOTSTRAP_AUTHORITY", "Owner and verifier keys must differ")
    verifier = anchors["verifier"]
    exact_keys(verifier, {"source_commit", "sha256", "version_id"}, "bootstrap verifier")
    if verifier["source_commit"] != UPSTREAM_COMMIT:
        fail("BOOTSTRAP_PIN", "Unsupported Shirudo source revision")
    for field in ("sha256", "version_id"):
        require_hex(verifier[field], 64, field)
    if (anchors["assurance"] != "LAB_VTPM" or anchors["action"] != ACTION
            or type(anchors["action"]) is not dict
            or type(anchors["action"].get("delta")) is not int):
        fail("BOOTSTRAP_SCOPE", "Only the laboratory counter and LAB_VTPM are supported")
    bounded_int(anchors["max_challenge_ttl_seconds"], 30, 30, "bootstrap challenge limit")
    bounded_int(anchors["config_pcr"], 14, 14, "bootstrap config PCR")
    return anchors


def validate_image_manifest(value):
    manifest = _freeze(value, MAX_MANIFEST_BYTES)
    exact_keys(manifest, {"schema", "gate_image_root", "anchors_sha256",
                          "source_manifest_sha256", "entrypoint", "mount_point", "authority"},
               "gate image manifest")
    if (manifest["schema"] != "wolfalibi.shirudo.gate-image.v1"
            or manifest["entrypoint"] != ENTRYPOINT
            or manifest["mount_point"] != MOUNT_POINT
            or manifest["authority"] != "NO_SHIRUDO_RUNTIME_AUTHORITY"):
        fail("BOOTSTRAP_IMAGE", "Unsupported image execution contract")
    for field in ("gate_image_root", "anchors_sha256", "source_manifest_sha256"):
        require_hex(manifest[field], 64, field)
    return manifest


def prepare_boot_policy(anchors, trust, manifest, owner_public_key):
    """Validate public provisioning inputs and return an unsigned payload."""
    anchors = validate_anchors(anchors)
    manifest = validate_image_manifest(manifest)
    trust = _validate_trust(trust)
    require_hex(owner_public_key, 64, "boot-policy owner")
    if (owner_public_key != anchors["owner_public_key"]
            or manifest["anchors_sha256"] != digest(anchors)):
        fail("BOOTSTRAP_AUTHORITY", "Image anchors do not match the provisioning authority")
    for field in ("target_id", "owner_public_key", "verifier_public_key", "verifier_instance_id"):
        if trust[field] != anchors[field]:
            fail("BOOTSTRAP_PIN", "Trust configuration differs from immutable authority anchors")
    policy = trust["policy"]
    if (policy["assurance"] != anchors["assurance"]
            or policy["enrollment"]["method"] != "trusted_builder"
            or policy["challenge_ttl_seconds"] > anchors["max_challenge_ttl_seconds"]
            or policy["expected"].get("config_pcr") != anchors["config_pcr"]
            or "config_nvpcr" in policy["expected"]):
        fail("BOOTSTRAP_SCOPE", "Policy exceeds the immutable laboratory scope")
    if any(policy["verifier"][field] != value for field, value in anchors["verifier"].items()):
        fail("BOOTSTRAP_PIN", "Policy changes the immutable verifier pins")
    return {"schema": "wolfalibi.shirudo.boot-policy.v1",
            "scope": "LAB_IMMUTABLE_GATE_BOOTSTRAP", "anchors_sha256": digest(anchors),
            "gate_image_root": manifest["gate_image_root"],
            "config_root": policy["expected"]["config_root"], "trust": trust}


def validate_boot_report(value, *, manifest, config_root):
    report = _freeze(value, MAX_MANIFEST_BYTES)
    exact_keys(report, {"schema", "scope", "gate_image_root", "config_root", "anchors_sha256",
                        "mount_point", "mapper_name", "read_only", "full_read", "data_bytes", "image_device",
                        "dm_table", "config_witness", "corruption_control", "wrong_root_control"}, "initrd image report")
    if (report["schema"] != "wolfalibi.shirudo.image-boot.v1"
            or report["scope"] != "LAB_TRUSTED_INITRD"
            or report["read_only"] is not True or report["full_read"] is not True
            or report["mapper_name"] != "wolfalibi-gate"
            or report["mount_point"] != MOUNT_POINT
            or report["config_root"] != config_root):
        fail("BOOTSTRAP_MAPPING", "Initrd did not report the approved read-only mapping")
    for field in ("gate_image_root", "anchors_sha256"):
        if report[field] != manifest[field]:
            fail("BOOTSTRAP_MAPPING", "Initrd mapping does not match the measured configuration")
    size = bounded_int(report["data_bytes"], 4096, 2 ** 34, "image data size")
    bounded_int(report["image_device"], 1, 2 ** 63 - 1, "image device")
    if size % 4096 or type(report["dm_table"]) is not str:
        fail("BOOTSTRAP_MAPPING", "Invalid mapped image geometry")
    table = report["dm_table"].split()
    if (len(table) != 13 or table[0] != "0" or table[1] != str(size // 512)
            or table[2:4] != ["verity", "1"] or table[6:8] != ["4096", "4096"]
            or table[8] != str(size // 4096) or table[9:11] != ["1", "sha256"]
            or table[11] != manifest["gate_image_root"]):
        fail("BOOTSTRAP_MAPPING", "Device-mapper table differs from the approved verity root")
    require_hex(table[12], 64, "verity salt")
    for device in table[4:6]:
        parts = device.split(":")
        if len(parts) != 2 or any(not part.isascii() or not part.isdigit() for part in parts):
            fail("BOOTSTRAP_MAPPING", "Invalid device-mapper device identity")
    for field in ("corruption_control", "wrong_root_control"):
        control = report[field]
        exact_keys(control, {"mapping_created", "read_rejected", "read_exit_code", "block"}, field)
        if control["mapping_created"] is not True or control["read_rejected"] is not True:
            fail("BOOTSTRAP_CONTROL", "Required kernel dm-verity control did not reject")
        bounded_int(control["read_exit_code"], 1, 1, "negative read exit code")
        bounded_int(control["block"], 0, size // 4096 - 1, "negative read block")
    witness = report["config_witness"]
    exact_keys(witness, {"root_hash", "mount_point", "mapper_name", "read_only", "full_read",
                         "data_bytes", "dm_table"}, "configuration witness")
    if (witness["root_hash"] != config_root
            or witness["mount_point"] != "/run/wolfalibi/config-witness"
            or witness["mapper_name"] != "wolfalibi-config-witness"
            or witness["read_only"] is not True or witness["full_read"] is not True):
        fail("BOOTSTRAP_MAPPING", "Configuration witness does not match the signed policy root")
    witness_size = bounded_int(witness["data_bytes"], 4096, 2 ** 34, "witness size")
    if witness_size % 4096 or type(witness["dm_table"]) is not str:
        fail("BOOTSTRAP_MAPPING", "Invalid configuration witness geometry")
    witness_table = witness["dm_table"].split()
    if (len(witness_table) != 13 or witness_table[0] != "0"
            or witness_table[1] != str(witness_size // 512)
            or witness_table[2:4] != ["verity", "1"]
            or witness_table[6:8] != ["4096", "4096"]
            or witness_table[8] != str(witness_size // 4096)
            or witness_table[9:11] != ["1", "sha256"] or witness_table[11] != config_root):
        fail("BOOTSTRAP_MAPPING", "Configuration witness uses a different verity root")
    require_hex(witness_table[12], 64, "witness salt")
    for device in witness_table[4:6]:
        parts = device.split(":")
        if len(parts) != 2 or any(not part.isascii() or not part.isdigit() for part in parts):
            fail("BOOTSTRAP_MAPPING", "Invalid configuration witness device identity")
    return report


def verify_boot_policy(envelope, anchors, manifest, *, boot_report=None):
    anchors = validate_anchors(anchors)
    manifest = validate_image_manifest(manifest)
    record = _freeze(envelope, MAX_BOOT_POLICY_BYTES)
    payload = verify_record(record, anchors["owner_public_key"])
    exact_keys(payload, {"schema", "scope", "anchors_sha256", "gate_image_root", "config_root", "trust"},
               "boot policy")
    expected = prepare_boot_policy(anchors, payload["trust"], manifest, anchors["owner_public_key"])
    if payload != expected:
        fail("BOOTSTRAP_BINDING", "Signed boot policy differs from image, configuration, or authority pins")
    if boot_report is not None:
        validate_boot_report(boot_report, manifest=manifest, config_root=payload["config_root"])
    return payload["trust"]


def _read(path, limit):
    return strict_json(read_bounded_file(path, limit), limit)


def _immutable_runtime(expected_device):
    """Fail closed if the fixed interpreter, entrypoint, or anchors are writable."""
    if not (sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site):
        fail("BOOTSTRAP_RUNTIME", "Isolated Python, disabled site imports, and disabled bytecode are required")
    image_device = os.stat("/").st_dev
    if image_device != expected_device:
        fail("BOOTSTRAP_RUNTIME", "Process root is not the initrd-verified gate device")
    for path in (Path("/usr/bin/python3"), Path("/opt/wolfalibi/gate_entry.py"),
                 ANCHORS_PATH, Path(__file__)):
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_dev != image_device
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022
                or not os.statvfs(path).f_flag & os.ST_RDONLY):
            fail("BOOTSTRAP_RUNTIME", "Gate code and anchors must execute from the read-only image")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=("check", "init", "serve", "status"))
    parser.add_argument("--state", default="/state/gate")
    parser.add_argument("--boot-policy", default="/state/boot-policy.json")
    parser.add_argument("--socket", default="/socket/gate.sock")
    parser.add_argument("--socket-gid", type=int)
    parser.add_argument("--replace-stale-socket", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.state != "/state/gate" or args.boot_policy != "/state/boot-policy.json" or args.socket != "/socket/gate.sock":
            fail("BOOTSTRAP_PATH", "Prototype state, policy, and socket locations are fixed")
        if args.socket_gid is not None:
            bounded_int(args.socket_gid, 0, 2 ** 31 - 1, "socket group")
        boot_report = _read(BOOT_REPORT_PATH, MAX_MANIFEST_BYTES)
        trust = verify_boot_policy(_read(args.boot_policy, MAX_BOOT_POLICY_BYTES),
                    _read(ANCHORS_PATH, MAX_ANCHOR_BYTES),
                    _read(CONFIG_MANIFEST_PATH, MAX_MANIFEST_BYTES),
                    boot_report=boot_report)
        _immutable_runtime(boot_report["image_device"])
        if args.command == "check":
            result = {"status": "BOOT_POLICY_VERIFIED", "scope": "LAB_IMMUTABLE_GATE_BOOTSTRAP",
                      "target_id": trust["target_id"], "policy_sha256": digest(trust["policy"]),
                      "current_action_authorization": False}
        elif args.command == "init":
            gate = Gate.initialize(args.state, trust)
            result = {"status": "INITIALIZED", "identity": gate.public_identity()}
        else:
            gate = Gate(args.state)
            if canonical_json(trust) != canonical_json(_read(Path(args.state) / "trust.json", MAX_TRUST_BYTES)):
                fail("BOOTSTRAP_STATE", "Persisted gate trust differs from owner-approved image policy")
            if args.command == "serve":
                from .action_gate_cli import serve
                serve(gate, Path(args.socket), socket_gid=args.socket_gid,
                      replace_stale=args.replace_stale_socket)
                return 0
            result = {"status": "STATUS", "result": gate.status()}
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        return 0
    except AdapterError as exc:
        sys.stdout.buffer.write(canonical_json({"status": "BLOCKED", "reason": exc.code,
                                               "message": exc.message}) + b"\n")
        return 2
    except OSError:
        sys.stdout.buffer.write(canonical_json({"status": "BLOCKED", "reason": "BOOTSTRAP_IO",
                                               "message": "Required immutable image input is unavailable"}) + b"\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
