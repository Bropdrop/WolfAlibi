"""Synthetic fixtures for the Shirudo adapter's local boundary tests.

Nothing in this module is a genuine Shirudo attestation, a TPM enrollment,
or a target authorization.  The executable fixture deliberately exits 77.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


UPSTREAM_COMMIT = "fb97c1ec5908c8bdbd46760c29e57677977fce74"
FIXTURE_VERSION_ID = "ab" * 32

# Independently transcribed pinned-upstream success assertions.  This is a
# simulated report, not proof that any of these assertions were actually run.
STATIC_ASSERTIONS = (
    "nonce matches the request",
    "attestation key: restricted, fixed to this TPM",
    "attestation key: name matches its public area",
    "attestation key: the pinned key",
    "endorsement key: name matches its public area",
    "endorsement key: TCG default template under the endorsement policy",
    "endorsement key: the pinned key",
    "quote: ECDSA signature by the attestation key",
    "quote: signed by the key as an endorsement primary",
    "quote: carries the nonce",
    "quote: covers the PCRs the document lists",
    "quote: PCR digest matches the listed values",
    "register: ECDSA signature by the attestation key",
    "register: signed by the key as an endorsement primary",
    "register: carries the nonce",
    "register: certification names the listed index",
    "register: certified contents match the listed value",
    "quote and certification are of one TPM boot",
    "eventlog: this boot has an init record",
    "register: the document names index 0x01818E00 and PCRs 9 and 11",
    "register: public area is bound to PCRs 9 and 11 as recorded",
    "binding: PCR 9 held the expected value",
    "binding: PCR 11 held the expected value",
    "binding: made while the initrd ran",
    "register: init record is of the TPM's current reset count",
    "anchor: record digest matches the index name",
    "state: register equals the expected value",
    "config: config root history matches the quoted PCR",
)
ANCHOR_OK = "anchor: PCR 9 equals the recorded value extended by the anchor"
ANCHOR_NOTE = (
    "anchor: PCR 9 carries further measurements after the anchor; "
    "replay the logs to confirm it"
)
CONTRACT_MARKERS = (
    r"regex:eventlog: one init record for this TPM reset \(([1-9][0-9]{0,3}) this boot\)",
    r"regex:eventlog: ([1-9][0-9]{0,3}) record(s?) replay to the certified value",
    "one-of:" + ANCHOR_OK + "|note:" + ANCHOR_NOTE,
)


def write_nonexecuted_fixture(path: Path) -> Path:
    """Create identifiable bytes; service tests mock the verifier boundary."""
    path.write_bytes(b"#!/bin/sh\n# SYNTHETIC TEST FIXTURE ONLY\nexit 77\n")
    path.chmod(0o500)
    return path


def policy_for(verifier: Path) -> dict:
    return {
        "schema": "wolfalibi.shirudo.policy.v1",
        "policy_id": "synthetic-boundary-tests",
        "target_id": "synthetic-target-001",
        "assurance": "SYNTHETIC",
        "enrollment": {
            "method": "synthetic_fixture",
            "record_sha256": "cc" * 32,
            "ak_name": "000b" + "a1" * 32,
            "ek_name": "000b" + "e1" * 32,
        },
        "expected": {
            "chain": "11" * 32,
            "config_root": "22" * 32,
            "binding_pcrs": {"9": "33" * 32, "11": "44" * 32},
            "quote_pcrs": {},
            "config_pcr": 12,
        },
        "verifier": {
            "source_commit": UPSTREAM_COMMIT,
            "sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
            "version_id": FIXTURE_VERSION_ID,
            "timeout_seconds": 2,
        },
        "challenge_ttl_seconds": 30,
    }


def evidence_object(policy: dict, challenge: dict) -> dict:
    """Minimal structural fixture; mocked verifier does no TPM verification."""
    payload = challenge["payload"]
    return {
        "schema": 1,
        "kind": "shirudo-attestation",
        "pcr_bank": "sha256",
        "nonce": payload["nonce"],
        "ak": {"name": policy["enrollment"]["ak_name"]},
        "ek": {"name": policy["enrollment"]["ek_name"]},
        "register": {"value": policy["expected"]["chain"]},
    }


def encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def evidence_bytes(policy: dict, challenge: dict) -> bytes:
    return encode(evidence_object(policy, challenge))


def fixture_verifier_result(policy: dict, *, accepted: bool = True) -> dict:
    assertions = list(STATIC_ASSERTIONS)
    assertions.extend(f"PCR {pcr} matches the expected value" for pcr in sorted(policy["expected"]["quote_pcrs"], key=int))
    checks = [
        {"result": "ok", "text": text}
        for text in assertions + [
            "eventlog: one init record for this TPM reset (1 this boot)",
            "eventlog: 1 record replay to the certified value",
            ANCHOR_OK,
        ]
    ] if accepted else [{"result": "fail", "text": "nonce matches the request"}]
    return {
        "accepted": accepted,
        "report": {
            "schema": 1,
            "verdict": "ok" if accepted else "fail",
            "checks": checks,
        },
        "exit_code": 0 if accepted else 1,
        "binary_sha256": policy["verifier"]["sha256"],
        "version_id": policy["verifier"]["version_id"],
        "required_checks": assertions + list(CONTRACT_MARKERS),
        "execution_profile": "SYNTHETIC",
    }


def changed(value: dict, path: tuple[str, ...], replacement: object) -> dict:
    clone = copy.deepcopy(value)
    item = clone
    for key in path[:-1]:
        item = item[key]
    item[path[-1]] = replacement
    return clone


def different(text: str) -> str:
    """Change a nonempty text value without depending on random collisions."""
    return ("1" if text[0] != "1" else "2") + text[1:]
