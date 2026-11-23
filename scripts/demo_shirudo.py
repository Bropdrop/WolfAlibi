#!/usr/bin/env python3
"""Local SYNTHETIC CLI round trip; no TPM, target, network, or deployment.

The executable generated here deliberately simulates a successful verifier
report. Its output qualifies CLI and receipt plumbing only. It does not
establish compatibility with a real Shirudo binary or any hardware trust.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "fb97c1ec5908c8bdbd46760c29e57677977fce74"
BUILD_ID = hashlib.sha256(b"wolfalibi-shirudo synthetic demo build v1").hexdigest()

# Protocol text is intentionally independent of runner._BASE_CHECKS. A change
# to that private constant cannot silently update this simulated report.
SUCCESS_CHECKS = (
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
    "config: config root history matches the quoted PCR",
    "eventlog: this boot has an init record",
    "register: the document names index 0x01818E00 and PCRs 9 and 11",
    "register: public area is bound to PCRs 9 and 11 as recorded",
    "binding: PCR 9 held the expected value",
    "binding: PCR 11 held the expected value",
    "binding: made while the initrd ran",
    "eventlog: one init record for this TPM reset (1 this boot)",
    "register: init record is of the TPM's current reset count",
    "eventlog: 1 record replay to the certified value",
    "anchor: record digest matches the index name",
    "anchor: PCR 9 equals the recorded value extended by the anchor",
    "state: register equals the expected value",
)


class DemoFailure(Exception):
    """A bounded diagnostic that never includes child output or key material."""


def require(condition: bool, stage: str) -> None:
    if not condition:
        raise DemoFailure(stage)


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def cli(*args: str, expected_exit: int = 0) -> dict:
    command = [sys.executable, "-m", "shirudo_adapter", *map(str, args)]
    result = subprocess.run(
        command, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True,
        timeout=40, check=False,
        env={"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
             "TZ": "UTC", "PYTHONNOUSERSITE": "1"},
    )
    require(result.returncode == expected_exit, f"{args[0]}: unexpected exit")
    require(len(result.stdout) <= 262_144, f"{args[0]}: oversized output")
    require(not result.stderr, f"{args[0]}: unexpected stderr")
    try:
        value = json.loads(result.stdout)
    except (ValueError, UnicodeError) as exc:
        raise DemoFailure(f"{args[0]}: invalid JSON output") from exc
    require(type(value) is dict, f"{args[0]}: non-object output")
    return value


def make_fixture(directory: Path) -> tuple[Path, dict]:
    # Script execution is permitted by the runner only for SYNTHETIC policies.
    # This fixture checks its input bindings but performs no cryptography.
    report = {"schema": 1, "verdict": "ok", "checks": [
        {"result": "ok", "text": label} for label in SUCCESS_CHECKS
    ]}
    executable = directory / "synthetic-verifier"
    require("\n" not in sys.executable and " " not in sys.executable,
            "unsupported interpreter path for synthetic shebang")
    source = f'''#!{sys.executable}
# SYNTHETIC DEMONSTRATION: not Shirudo and not TPM verification.
import json, sys
if sys.argv[1:] == ["version", "--version-id"]:
    print({BUILD_ID!r})
    raise SystemExit(0)
if sys.argv[1:3] != ["attest", "verify"]:
    raise SystemExit(2)
options = {{}}
for item in sys.argv[3:]:
    if "=" in item:
        name, value = item.split("=", 1)
        options.setdefault(name, []).append(value)
    elif item not in {{"--require-initrd", "--json"}}:
        raise SystemExit(2)
def one(name):
    values = options.get(name, [])
    if len(values) != 1:
        raise SystemExit(2)
    return values[0]
with open(one("--evidence"), "rb") as stream:
    evidence = json.load(stream)
if not (evidence.get("nonce") == one("--nonce")
        and evidence.get("ak", {{}}).get("name") == one("--ak-name")
        and evidence.get("ek", {{}}).get("name") == one("--ek-name")
        and evidence.get("register", {{}}).get("value") == one("--expect-chain")):
    print(json.dumps({{"schema": 1, "verdict": "fail", "checks": [
        {{"result": "fail", "text": "nonce matches the request"}}
    ]}}))
    raise SystemExit(1)
print({encoded(report).decode('ascii')!r})
'''
    executable.write_bytes(source.encode("utf-8"))
    executable.chmod(0o500)
    policy = {
        "schema": "wolfalibi.shirudo.policy.v1",
        "policy_id": "synthetic-cli-demo",
        "target_id": "synthetic-local-fixture",
        "assurance": "SYNTHETIC",
        "enrollment": {
            "method": "synthetic_fixture",
            "record_sha256": sha("synthetic enrollment only"),
            "ak_name": "000b" + sha("synthetic AK only"),
            "ek_name": "000b" + sha("synthetic EK only"),
        },
        "expected": {
            "chain": sha("synthetic measurement chain only"),
            "config_root": sha("synthetic configuration root only"),
            "binding_pcrs": {"9": sha("synthetic PCR9"), "11": sha("synthetic PCR11")},
            "quote_pcrs": {}, "config_pcr": 12,
        },
        "verifier": {
            "source_commit": SOURCE_COMMIT,
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "version_id": BUILD_ID, "timeout_seconds": 10,
        },
        "challenge_ttl_seconds": 120,
    }
    return executable, policy


def demo() -> dict:
    require(sys.platform == "linux" and hasattr(os, "memfd_create"),
            "Linux sealed-memfd support required")
    with tempfile.TemporaryDirectory(prefix="wolfalibi-shirudo-demo-") as scratch:
        directory = Path(scratch)
        directory.chmod(0o700)
        state = directory / "state"
        executable, policy = make_fixture(directory)
        policy_file = directory / "policy.json"
        policy_file.write_bytes(encoded(policy))

        initialized = cli("init", "--state", state)
        require(initialized.get("status") == "INITIALIZED", "initialization status")
        public_key = initialized["public_key"]  # Never printed.
        registered = cli("register-policy", "--state", state, "--policy", policy_file)
        policy_digest = registered["policy_sha256"]
        challenge = cli("challenge", "--state", state, "--policy-sha256", policy_digest)
        requested = challenge["payload"]
        challenge_id = requested["challenge_id"]
        require(requested["target_id"] == policy["target_id"], "challenge target")
        require(requested["policy_sha256"] == policy_digest, "challenge policy")

        evidence_file = directory / "evidence.json"
        evidence_file.write_bytes(encoded({
            "schema": 1, "kind": "shirudo-attestation", "pcr_bank": "sha256",
            "nonce": requested["nonce"],
            "ak": {"name": policy["enrollment"]["ak_name"]},
            "ek": {"name": policy["enrollment"]["ek_name"]},
            "register": {"value": policy["expected"]["chain"]},
        }))
        assessment = cli("verify", "--state", state, "--challenge-id", challenge_id,
                         "--evidence", evidence_file, "--verifier", executable)
        payload = assessment["payload"]
        require(payload["outcome"] == "SIMULATED_POLICY_ONLY", "synthetic outcome")
        require(payload["assurance"] == "SYNTHETIC", "synthetic assurance")
        require(payload["upstream"]["execution_profile"] == "SYNTHETIC", "synthetic execution profile")
        require(payload["authorization"] == "NONE", "no authorization")

        recovered = cli("receipt", "--state", state, "--challenge-id", challenge_id)
        require(recovered == assessment, "durable receipt retrieval")
        receipt_file = directory / "receipt.json"
        receipt_file.write_bytes(encoded(recovered))
        expected = ["--public-key", public_key, "--expected-target", policy["target_id"],
                    "--expected-policy-sha256", policy_digest,
                    "--expected-challenge-id", challenge_id]
        verification = cli("verify-receipt", "--receipt", receipt_file, *expected)
        require(verification.get("signature_valid") is True, "receipt signature")
        require(verification.get("historical_outcome") == "SIMULATED_POLICY_ONLY",
                "receipt historical outcome")
        require(verification.get("current_authorization") is False, "historical-only verification")

        replay = cli("verify", "--state", state, "--challenge-id", challenge_id,
                     "--evidence", evidence_file, "--verifier", executable, expected_exit=2)
        require(replay.get("code") == "CHALLENGE_SPENT", "replay denial")

        tampered = copy.deepcopy(recovered)
        signature = tampered["signature"]
        tampered["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
        tampered_file = directory / "tampered-receipt.json"
        tampered_file.write_bytes(encoded(tampered))
        rejected = cli("verify-receipt", "--receipt", tampered_file, *expected, expected_exit=2)
        require(rejected.get("code") == "INVALID_SIGNATURE", "tampered signature denial")

        revoked = cli("revoke-policy", "--state", state, "--policy-sha256", policy_digest)
        require(revoked.get("status") == "REVOKED", "local policy revocation")
        refused = cli("challenge", "--state", state, "--policy-sha256", policy_digest, expected_exit=2)
        require(refused.get("code") == "POLICY_REVOKED", "revoked policy challenge denial")
        after_revocation = cli("verify-receipt", "--receipt", receipt_file, *expected)
        require(after_revocation == verification, "historical receipt after revocation")

    require(not Path(scratch).exists(), "temporary state cleanup")
    return {
        "schema": "wolfalibi.shirudo.demo.v1", "result": "PASS",
        "assurance": "SYNTHETIC", "assessment_outcome": "SIMULATED_POLICY_ONLY",
        "receipt_signature_valid": True, "retrieved_receipt_matches": True,
        "replay_denied": True, "tampered_signature_denied": True,
        "revocation_blocks_new_challenge": True, "historical_receipt_survives_revocation": True,
        "current_authorization": False, "real_upstream_verification": False,
        "target_contact": False, "deployment": False, "temporary_state_removed": True,
    }


def main() -> int:
    try:
        result = demo()
    except (DemoFailure, OSError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        result = {"schema": "wolfalibi.shirudo.demo.v1", "result": "BLOCKED",
                  "assurance": "SYNTHETIC", "real_upstream_verification": False,
                  "reason": str(exc) if isinstance(exc, DemoFailure) else type(exc).__name__}
        print(encoded(result).decode("ascii"))
        return 1
    print(encoded(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
