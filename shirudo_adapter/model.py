"""Strict local policy and bounded JSON contracts.

Enrollment and expected values are operator inputs. Parsing evidence never
enrolls a target, approves a configuration, or chooses an executable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

UPSTREAM_COMMIT = "fb97c1ec5908c8bdbd46760c29e57677977fce74"
MAX_POLICY_BYTES = 65_536
MAX_EVIDENCE_BYTES = 1_048_576
MAX_RECORD_BYTES = 262_144
MAX_JSON_DEPTH = 40
MAX_JSON_NODES = 50_000


class AdapterError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def fail(code: str, message: str) -> None:
    raise AdapterError(code, message)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError) as exc:
        raise AdapterError("INVALID_JSON", "Value cannot be encoded canonically") from exc


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def strict_json(data: bytes, max_bytes: int = MAX_RECORD_BYTES) -> Any:
    if not isinstance(data, bytes) or not data or len(data) > max_bytes:
        fail("JSON_SIZE", "JSON input is empty or exceeds its byte limit")

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                fail("DUPLICATE_JSON_KEY", "Duplicate JSON member")
            out[key] = value
        return out

    def integer(value):
        if len(value.lstrip("-")) > 19:
            fail("INVALID_JSON_NUMBER", "JSON integer exceeds the supported bound")
        n = int(value)
        if not -(2 ** 63) <= n < 2 ** 63:
            fail("INVALID_JSON_NUMBER", "JSON integer exceeds the supported bound")
        return n

    def no_number(_):
        fail("INVALID_JSON_NUMBER", "Floating point and non-finite values are unsupported")

    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=no_number, parse_constant=no_number)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AdapterError("INVALID_JSON", "Input is not one strict UTF-8 JSON document") from exc
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            fail("JSON_COMPLEXITY", "JSON structure exceeds its complexity limit")
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
            stack.extend((k, depth + 1) for k in item)
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                fail("INVALID_JSON", "Unpaired Unicode surrogate")
    return value


def exact_keys(value: Any, keys: set[str], name: str) -> None:
    if type(value) is not dict or set(value) != keys:
        fail("INVALID_SCHEMA", f"{name} has missing or unexpected fields")


def require_hex(value: Any, size: int, name: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{" + str(size) + r"}", value) is None:
        fail("INVALID_SCHEMA", f"{name} must be canonical lowercase hexadecimal")
    return value


def bounded_int(value: Any, lo: int, hi: int, name: str) -> int:
    if type(value) is not int or not lo <= value <= hi:
        fail("INVALID_SCHEMA", f"{name} is outside its supported range")
    return value


def identifier(value: Any, name: str) -> str:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is None:
        fail("INVALID_SCHEMA", f"{name} must be a bounded identifier")
    return value


def validate_policy(policy: Any) -> dict:
    exact_keys(policy, {"schema", "policy_id", "target_id", "assurance", "enrollment",
                        "expected", "verifier", "challenge_ttl_seconds"}, "policy")
    if policy["schema"] != "wolfalibi.shirudo.policy.v1":
        fail("UNSUPPORTED_POLICY", "Unsupported policy schema")
    identifier(policy["policy_id"], "policy_id")
    identifier(policy["target_id"], "target_id")
    assurance = policy["assurance"]
    methods = {"SYNTHETIC": "synthetic_fixture", "LAB_VTPM": "trusted_builder",
               "HARDWARE_TPM": "manufacturer_chain"}
    if type(assurance) is not str or assurance not in methods:
        fail("INVALID_SCHEMA", "Unsupported assurance class")
    enrollment = policy["enrollment"]
    exact_keys(enrollment, {"method", "record_sha256", "ak_name", "ek_name"}, "enrollment")
    if enrollment["method"] != methods[assurance]:
        fail("ENROLLMENT_MISMATCH", "Enrollment method does not match the assurance class")
    require_hex(enrollment["record_sha256"], 64, "enrollment record")
    for key in ("ak_name", "ek_name"):
        require_hex(enrollment[key], 68, key)
        if not enrollment[key].startswith("000b"):
            fail("INVALID_SCHEMA", "Only SHA-256 TPM names are supported")
    expected = policy["expected"]
    base = {"chain", "config_root", "binding_pcrs", "quote_pcrs"}
    if type(expected) is not dict or set(expected) not in (base | {"config_pcr"}, base | {"config_nvpcr"}):
        fail("INVALID_SCHEMA", "Expected state needs exactly one configuration measurement selector")
    for key in ("chain", "config_root"):
        require_hex(expected[key], 64, key)
    exact_keys(expected["binding_pcrs"], {"9", "11"}, "binding_pcrs")
    for value in expected["binding_pcrs"].values():
        require_hex(value, 64, "binding PCR")
    if type(expected["quote_pcrs"]) is not dict:
        fail("INVALID_SCHEMA", "quote_pcrs must be an object")
    for key, value in expected["quote_pcrs"].items():
        if key not in {str(i) for i in range(24)}:
            fail("INVALID_SCHEMA", "Invalid quote PCR index")
        require_hex(value, 64, "quote PCR")
    if "config_pcr" in expected:
        bounded_int(expected["config_pcr"], 0, 15, "config PCR")
        if expected["config_pcr"] in (9, 11):
            fail("INVALID_SCHEMA", "Configuration PCR cannot be a binding PCR")
    else:
        require_hex(expected["config_nvpcr"], 68, "config NvPCR")
        if not expected["config_nvpcr"].startswith("000b"):
            fail("INVALID_SCHEMA", "Only SHA-256 NvPCR names are supported")
    verifier = policy["verifier"]
    exact_keys(verifier, {"source_commit", "sha256", "version_id", "timeout_seconds"}, "verifier")
    if verifier["source_commit"] != UPSTREAM_COMMIT:
        fail("UNSUPPORTED_UPSTREAM", "This adapter supports only its reviewed upstream revision")
    require_hex(verifier["sha256"], 64, "verifier digest")
    require_hex(verifier["version_id"], 64, "verifier build ID")
    bounded_int(verifier["timeout_seconds"], 1, 30, "verifier deadline")
    bounded_int(policy["challenge_ttl_seconds"], 1, 300, "challenge lifetime")
    if len(canonical_json(policy)) > MAX_POLICY_BYTES:
        fail("JSON_SIZE", "Policy exceeds its byte limit")
    return policy


def check_evidence(data: bytes, policy: dict, nonce: str) -> dict:
    value = strict_json(data, MAX_EVIDENCE_BYTES)
    if type(value) is not dict or type(value.get("schema")) is not int or value["schema"] != 1:
        fail("INVALID_EVIDENCE", "Unsupported attestation schema")
    if value.get("kind") != "shirudo-attestation" or value.get("pcr_bank") != "sha256":
        fail("INVALID_EVIDENCE", "Unsupported attestation kind or PCR bank")
    if value.get("nonce") != nonce:
        fail("NONCE_MISMATCH", "Evidence does not match the issued challenge")
    for field, pin in (("ak", "ak_name"), ("ek", "ek_name")):
        if type(value.get(field)) is not dict or value[field].get("name") != policy["enrollment"][pin]:
            fail("TARGET_MISMATCH", "Evidence does not match the enrolled target keys")
    if type(value.get("register")) is not dict or value["register"].get("value") != policy["expected"]["chain"]:
        fail("STATE_MISMATCH", "Evidence does not match the approved measurement chain")
    # These comparisons are only preflight. All cryptographic checks remain
    # the responsibility of the pinned upstream verifier.
    return value


def read_bounded_file(path: str | Path, limit: int) -> bytes:
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                fail("FILE_SIZE", "Input must be a bounded regular file")
            pieces = []
            size = 0
            while True:
                chunk = os.read(fd, min(65_536, limit + 1 - size))
                if not chunk:
                    return b"".join(pieces)
                pieces.append(chunk)
                size += len(chunk)
                if size > limit:
                    fail("FILE_SIZE", "Input exceeds its byte limit")
        finally:
            os.close(fd)
    except OSError as exc:
        raise AdapterError("FILE_UNREADABLE", "Cannot read the requested input safely") from exc
