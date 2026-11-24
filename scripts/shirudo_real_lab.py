#!/usr/bin/env python3
"""Qualify fresh LAB_VTPM evidence from an already booted upstream test VM.

The caller prepares the pinned upstream checkout, private builder state and
LOCAL_STACK=0 VM. This script collects evidence; it never installs, deploys,
loads or unloads a shield. Its one trusted baseline is frozen before issuing
any adapter challenge. Public results are explicitly selected; the adapter's
private key and journal live in a separate, temporary directory.

This is a trusted-builder lab experiment. A direct QEMU kernel boot does not
establish a measured UKI, Secure Boot, hardware identity or authorization.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shirudo_adapter.model import (  # noqa: E402
    AdapterError, MAX_EVIDENCE_BYTES, UPSTREAM_COMMIT, canonical_json,
    read_bounded_file, strict_json, validate_policy,
)
from shirudo_adapter.receipt import verify_receipt  # noqa: E402
from shirudo_adapter.service import Service  # noqa: E402
from shirudo_adapter.runner import (  # noqa: E402
    _bounded_run, _executable_snapshot,
)


# Reviewed official shirudo-tar artifact, workflow run 45269604356. There is
# deliberately no CLI override: a different build needs an explicit review.
VERIFIER_SHA256 = "be8b79cdd7efb8e635b7965bf34fa691e5e4a378957f3829530a529097abe9d2"
ARCHIVE_SHA256 = "e830f2384383adccba7c423e8afe81d1fd0b3d6e27e66ce2aed49eae632e989c"
MAX_COMMAND_OUTPUT = 262_144
MAX_COMMAND_STDERR = 65_536
VM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TPM_NAME = re.compile(r"000b[0-9a-f]{64}")
LIMITATIONS = [
    "LAB_VTPM: the builder, hypervisor, vTPM state and operator are trusted.",
    "The direct kernel/initrd boot does not establish measured UKI or Secure Boot.",
    "Builder records supply AK/EK association; credential activation is not performed.",
    "The adapter records an enrollment digest; it does not validate the original enrollment.",
    "The target build ID is retained as metadata, not a cryptographically enforced build pin.",
    "Evidence and receipts describe a historical observation, never current authorization.",
]


class LabFailure(Exception):
    result = "FAIL_ASSERTION"
    exit_code = 1

    def __init__(self, code: str, stage: str):
        self.code, self.stage = code, stage
        super().__init__(f"{code}: {stage}")


class EnvironmentFailure(LabFailure):
    result = "BLOCKED_ENVIRONMENT"
    exit_code = 2


def require(condition: bool, code: str, stage: str, *, environment=False) -> None:
    if not condition:
        raise (EnvironmentFailure if environment else LabFailure)(code, stage)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_input(path: Path, limit: int, stage: str) -> bytes:
    try:
        return read_bounded_file(path, limit)
    except AdapterError as exc:
        raise EnvironmentFailure(exc.code, stage) from exc


def parse_input(data: bytes, limit: int, stage: str) -> dict:
    try:
        value = strict_json(data, limit)
    except AdapterError as exc:
        raise EnvironmentFailure(exc.code, stage) from exc
    require(type(value) is dict, "INPUT_SCHEMA", stage, environment=True)
    return value


def hex_value(value: object, stage: str, *, tpm_name=False) -> str:
    pattern = TPM_NAME if tpm_name else HEX64
    require(type(value) is str and pattern.fullmatch(value) is not None,
            "INPUT_HEX", stage, environment=True)
    return value


def altered_hex(value: str) -> str:
    """Change the last nibble, preserving TPM name and signature headers."""
    require(bool(value) and re.fullmatch(r"[0-9a-f]+", value) is not None,
            "MUTATION_SCHEMA", "hexadecimal control")
    return value[:-1] + ("1" if value[-1] == "0" else "0")


def bounded_command(argv: list[str], cwd: Path, *, timeout=60.0,
                    stdout_limit=MAX_COMMAND_OUTPUT) -> tuple[int, bytes, bytes]:
    """Bound time, memory and descendants without using a shell or a sandbox."""
    require(0 < timeout <= 60, "COMMAND_DEADLINE", "subprocess", environment=True)
    env = os.environ.copy()
    # Neither ambient make options nor shell startup code may add operations.
    for key in ("MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "BASH_ENV", "ENV",
                "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"):
        env.pop(key, None)
    env.update({"LC_ALL": "C", "LANG": "C", "NO_COLOR": "1",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0"})
    try:
        process = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, close_fds=True, start_new_session=True,
        )
    except OSError as exc:
        raise EnvironmentFailure("COMMAND_START", "subprocess") from exc
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": MAX_COMMAND_STDERR}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise EnvironmentFailure("COMMAND_TIMEOUT", "subprocess")
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), 16_384)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    dest = buffers[key.data]
                    if len(dest) + len(data) > limits[key.data]:
                        raise EnvironmentFailure("COMMAND_OUTPUT_LIMIT", "subprocess")
                    dest.extend(data)
            return process.wait(timeout=max(0.001, deadline - time.monotonic())), \
                bytes(buffers["stdout"]), bytes(buffers["stderr"])
    except subprocess.TimeoutExpired as exc:
        raise EnvironmentFailure("COMMAND_TIMEOUT", "subprocess") from exc
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        process.stdout.close()
        process.stderr.close()


class PublicArtifacts:
    """Write explicit public files into a new directory; never copy trees."""

    def __init__(self, path: Path):
        self.path = path.absolute()
        self.files: dict[str, dict] = {}
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.path.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise EnvironmentFailure("OUTPUT_EXISTS", "public output directory") from exc
        except OSError as exc:
            raise EnvironmentFailure("OUTPUT_UNAVAILABLE", "public output directory") from exc

    def write(self, name: str, data: bytes) -> Path:
        require(re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.[A-Za-z0-9]+", name)
                is not None, "ARTIFACT_NAME", "public artifact")
        require(name not in self.files, "ARTIFACT_EXISTS", name)
        destination = self.path / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        self.files[name] = {"sha256": sha256(data), "bytes": len(data)}
        return destination

    def json(self, name: str, value: object) -> Path:
        return self.write(name, canonical_json(value) + b"\n")


def enrollment_names(raw: bytes, vm_name: str) -> tuple[str, str]:
    enrollment = parse_input(raw, 16_384, "preboot builder enrollment")
    require(set(enrollment) == {"source", "nodes"} and enrollment["source"] == "test-vm"
            and type(enrollment["nodes"]) is list and len(enrollment["nodes"]) == 1,
            "ENROLLMENT_SCHEMA", "preboot builder enrollment", environment=True)
    node = enrollment["nodes"][0]
    require(type(node) is dict and set(node) == {"ak_name", "ek_name", "node_id"}
            and node["node_id"] == vm_name,
            "ENROLLMENT_TARGET", "preboot builder enrollment", environment=True)
    return (hex_value(node["ak_name"], "builder AK", tpm_name=True),
            hex_value(node["ek_name"], "builder EK", tpm_name=True))


def runtime_selection(template: bytes) -> tuple[str, int]:
    """Interpret only the pinned host template, never a target-supplied path."""
    try:
        text = template.decode("utf-8")
    except UnicodeError as exc:
        raise EnvironmentFailure("CONFIG_TEMPLATE", "host runtime template") from exc
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("=", 1)
        require(len(parts) == 2 and parts[0].strip() not in values,
                "CONFIG_TEMPLATE", "host runtime template", environment=True)
        values[parts[0].strip()] = parts[1].strip()
    require(values.get("config.image") == "/var/lib/shirudo/images/@config_image@"
            and values.get("config.pcr") == "14"
            and "config.nvpcr" not in values,
            "CONFIG_TEMPLATE", "host runtime template", environment=True)
    return "config-boot-keys", 14


def make_policy(vm_name: str, enrollment: bytes, root: str, config_pcr: int,
                prediction: dict, baseline: dict, target_version: str,
                verifier_version: str) -> dict:
    ak_name, ek_name = enrollment_names(enrollment, vm_name)
    chain = hex_value(prediction.get("register_at_boot"), "independent chain prediction")
    require(type(baseline.get("tpm")) is dict and type(baseline.get("config")) is dict,
            "BASELINE_SCHEMA", "trusted baseline", environment=True)
    tpm, config = baseline["tpm"], baseline["config"]
    require(baseline.get("schema") == 1 and baseline.get("lsm_attached") is True
            and baseline.get("keyring_mode") == "bpf" and tpm.get("bound_in") == "initrd"
            and tpm.get("register_bound") is True and tpm.get("reachable") is True,
            "BASELINE_INITIALIZATION", "trusted baseline", environment=True)
    require(baseline.get("version_id") == target_version,
            "BASELINE_BUILD", "target builder metadata", environment=True)
    # Target observations corroborate host expectations; they never select the
    # approved root, certificate set or expected chain.
    require(config.get("root_hash") == root and config.get("activation_pending") is False
            and config.get("error") is None and tpm.get("chain") == chain,
            "BASELINE_EXPECTATIONS", "host-built state and trusted baseline", environment=True)
    policy = {
        "schema": "wolfalibi.shirudo.policy.v1", "policy_id": "fresh-lab-baseline",
        "target_id": vm_name, "assurance": "LAB_VTPM",
        "enrollment": {"method": "trusted_builder", "record_sha256": sha256(enrollment),
                       "ak_name": ak_name, "ek_name": ek_name},
        "expected": {"chain": chain, "config_root": hex_value(root, "host config root"),
                     "config_pcr": config_pcr, "quote_pcrs": {},
                     "binding_pcrs": {
                         "9": hex_value(tpm.get("pcr_before"), "trusted binding PCR9"),
                         "11": hex_value(tpm.get("phase_before"), "trusted binding PCR11")}},
        "verifier": {"source_commit": UPSTREAM_COMMIT, "sha256": VERIFIER_SHA256,
                     "version_id": hex_value(verifier_version, "operator verifier build"),
                     "timeout_seconds": 30},
        "challenge_ttl_seconds": 300,
    }
    return validate_policy(policy)


def signature_control(evidence: bytes) -> bytes:
    value = parse_input(evidence, MAX_EVIDENCE_BYTES, "fresh signature-control evidence")
    quote = value.get("quote")
    require(type(quote) is dict and type(quote.get("signature")) is str
            and re.fullmatch(r"[0-9a-f]{16,1024}", quote["signature"]) is not None
            and len(quote["signature"]) % 2 == 0,
            "SIGNATURE_CONTROL_SCHEMA", "fresh signature-control evidence")
    quote["signature"] = altered_hex(quote["signature"])
    return canonical_json(value) + b"\n"


def expect_receipt(receipt: dict, *, outcome: str, reason: str,
                   crypto_failure: str | None = None) -> None:
    payload = receipt["payload"]
    if payload["outcome"] == "BLOCKED":
        raise EnvironmentFailure(payload["reason_code"], "adapter assessment")
    require(payload["outcome"] == outcome and payload["reason_code"] == reason,
            "UNEXPECTED_ASSESSMENT", "adapter assessment")
    require(payload["assurance"] == "LAB_VTPM" and payload["authorization"] == "NONE"
            and payload["scope"] == "HISTORICAL_EVIDENCE_ONLY",
            "ASSESSMENT_SCOPE", "adapter receipt")
    upstream = payload["upstream"]
    if outcome == "EVIDENCE_ACCEPTED" or crypto_failure is not None:
        require(upstream["execution_profile"] == "UPSTREAM_CLI",
                "REAL_VERIFIER_REQUIRED", "adapter receipt")
        require(upstream["observed_binary_sha256"] == VERIFIER_SHA256,
                "REAL_VERIFIER_DIGEST", "adapter receipt")
    if crypto_failure is not None:
        require(upstream["exit_code"] == 1 and upstream["report"]["verdict"] == "fail"
                and any(check == {"result": "fail", "text": crypto_failure}
                        for check in upstream["report"]["checks"]),
                "EXPECTED_CRYPTO_FAILURE", "upstream negative control")


def check_receipt_bindings(receipt: dict, policy: dict, challenge: dict, evidence: bytes) -> None:
    """Use retained originals for bindings a standalone receipt cannot recover."""
    payload, requested = receipt["payload"], challenge["payload"]
    for key in ("instance_id", "challenge_id", "nonce", "target_id", "policy_sha256",
                "issued_at_ms", "expires_at_ms"):
        require(payload[key] == requested[key], "RECEIPT_CHALLENGE_BINDING", key)
    require(payload["enrollment_record_sha256"] == policy["enrollment"]["record_sha256"],
            "RECEIPT_ENROLLMENT_BINDING", "retained policy")
    require(payload["evidence_sha256"] in (None, sha256(evidence)),
            "RECEIPT_EVIDENCE_BINDING", "retained evidence")
    if payload["outcome"] == "EVIDENCE_ACCEPTED":
        require(payload["evidence_sha256"] == sha256(evidence),
                "RECEIPT_EVIDENCE_BINDING", "accepted evidence")
    upstream = payload["upstream"]
    require(upstream["source_commit"] == policy["verifier"]["source_commit"]
            and upstream["expected_binary_sha256"] == policy["verifier"]["sha256"]
            and upstream["expected_version_id"] == policy["verifier"]["version_id"],
            "RECEIPT_VERIFIER_BINDING", "retained policy")


class RealLab:
    def __init__(self, upstream: Path, vm_name: str, verifier: Path, output: Path,
                 *, bundle: Path | None = None):
        require(VM_NAME.fullmatch(vm_name) is not None, "VM_NAME", "arguments", environment=True)
        require(sys.platform == "linux" and hasattr(os, "memfd_create"),
                "LINUX_REQUIRED", "arguments", environment=True)
        self.upstream = upstream.absolute()
        self.vm_name = vm_name
        self.verifier = verifier.absolute()
        self.bundle = (bundle.absolute() if bundle is not None else
                       self.upstream / "build/test-vm/host-bundle-bpf-next-verity")
        self.vm_dir = self.upstream / "build/test-vm/vms" / vm_name
        self.artifacts = PublicArtifacts(output)
        self.commands: list[dict] = []
        self.cases: list[dict] = []
        self.target_contact = False
        self.positive_accepted = False
        self.state_removed = True

    def command(self, args: list[str], stage: str, *, timeout=60.0) -> bytes:
        started = time.time_ns() // 1_000_000
        try:
            code, stdout, stderr = bounded_command(args, self.upstream, timeout=timeout)
        except EnvironmentFailure as exc:
            raise EnvironmentFailure(exc.code, stage) from exc
        # Child stderr is not copied into public artifacts. Diagnostics retain
        # its size/digest, avoiding an accidental disclosure from child output.
        self.commands.append({"stage": stage, "started_at_ms": started,
                              "completed_at_ms": time.time_ns() // 1_000_000,
                              "exit_code": code, "stdout_bytes": len(stdout),
                              "stdout_sha256": sha256(stdout), "stderr_bytes": len(stderr),
                              "stderr_sha256": sha256(stderr)})
        require(code == 0, "COMMAND_EXIT", stage, environment=True)
        return stdout

    def target(self, args: list[str], stage: str) -> bytes:
        self.target_contact = True
        return self.command([
            "make", "--silent", "--no-print-directory", "-C", "testing", "vm-ssh",
            f"VM_NAME={self.vm_name}", "VM_SSH_COMMAND=" + shlex.join(args),
        ], stage)

    def prepare(self) -> dict:
        head = self.command(["git", "--no-replace-objects", "rev-parse", "HEAD"],
                            "source revision", timeout=10).strip()
        require(head == UPSTREAM_COMMIT.encode("ascii"), "SOURCE_REVISION",
                "upstream checkout", environment=True)
        dirty = self.command(["git", "--no-replace-objects", "status", "--porcelain", "--untracked-files=no"],
                             "source cleanliness", timeout=10)
        require(not dirty.strip(), "SOURCE_DIRTY", "upstream checkout", environment=True)
        bundle = self.bundle
        enrollment = read_input(self.vm_dir / "enroll.json", 16_384, "builder enrollment")
        enrollment_names(enrollment, self.vm_name)
        target_version_raw = read_input(self.vm_dir / "shirudo-build", 128, "builder target version")
        target_version = hex_value(target_version_raw.decode("ascii").strip(), "builder target version")
        template = read_input(self.upstream / "testing/vm/files/runtime.conf.in", 16_384,
                              "host runtime template")
        prefix, pcr = runtime_selection(template)
        root_raw = read_input(bundle / f"verity/{prefix}.roothash", 256, "host configuration root")
        root = hex_value(root_raw.decode("ascii").strip(), "host configuration root")
        primary = read_input(bundle / "fixtures/cert.der", 65_536, "host primary certificate")
        boot = read_input(bundle / "fixtures/own.der", 65_536, "host boot certificate")
        require(primary == read_input(bundle / "verity/primary.der", 65_536, "image primary certificate")
                and boot == read_input(bundle / "verity/boot.der", 65_536, "image boot certificate"),
                "CERTIFICATE_INPUTS", "host bundle consistency", environment=True)
        self.artifacts.write("inputs/enrollment.json", enrollment)
        self.artifacts.write("inputs/target-build.txt", target_version_raw)
        self.artifacts.write("inputs/runtime-template.txt", template)
        self.artifacts.write("inputs/config-root.txt", root_raw)
        primary_copy = self.artifacts.write("inputs/primary.der", primary)
        boot_copy = self.artifacts.write("inputs/boot.der", boot)

        # Reuse the adapter's reviewed sealed-snapshot/bounded invocation for
        # startup and prediction. These private helpers are intentionally tied
        # to this repository revision, not a separate supported public API.
        try:
            with ExitStack() as stack:
                fd, actual = _executable_snapshot(stack, str(self.verifier), VERIFIER_SHA256, False)
                code, version_raw, _ = _bounded_run(
                    fd, ["version", "--version-id"], (fd,), time.monotonic() + 30)
                require(code == 0, "VERIFIER_STARTUP", "operator verifier", environment=True)
                version = hex_value(version_raw.decode("ascii").strip(), "operator verifier version")
                code, prediction_raw, _ = _bounded_run(
                    fd, ["attest", "predict", f"--cert={primary_copy}",
                         f"--cert={boot_copy}", "--json"],
                    (fd,), time.monotonic() + 30)
                require(code == 0, "PREDICTION_EXIT", "independent chain prediction", environment=True)
        except AdapterError as exc:
            raise EnvironmentFailure(exc.code, "operator verifier") from exc
        self.artifacts.write("inputs/verifier-version.txt", version_raw)
        self.artifacts.write("inputs/prediction.json", prediction_raw)
        prediction = parse_input(prediction_raw, 16_384, "independent chain prediction")
        baseline_raw = self.target(["shirudo-runtime", "status", "--json"], "trusted baseline")
        baseline = parse_input(baseline_raw, MAX_COMMAND_OUTPUT, "trusted baseline")
        self.artifacts.write("inputs/baseline-status.json", baseline_raw)
        policy = make_policy(self.vm_name, enrollment, root, pcr, prediction, baseline,
                             target_version, version)
        self.artifacts.json("baseline-manifest.json", {
            "schema": "wolfalibi.shirudo.lab-baseline.v1", "source_commit": UPSTREAM_COMMIT,
            "verifier_sha256": actual, "verifier_archive_sha256": ARCHIVE_SHA256,
            "verifier_version_id": version, "target_build_id": target_version,
            "builder_record_sha256": sha256(enrollment), "config_prefix": prefix,
            "config_pcr": pcr, "config_root": root, "expected_chain": policy["expected"]["chain"],
            "binding_pcrs": policy["expected"]["binding_pcrs"],
            "baseline_recorded_at_ms": time.time_ns() // 1_000_000,
            "baseline_before_all_challenges": True, "expectations_from_submitted_evidence": False,
            "pcr11_is_zero": policy["expected"]["binding_pcrs"]["11"] == "0" * 64,
            "assurance": "LAB_VTPM", "limitations": LIMITATIONS,
        })
        return policy

    def collect(self, challenge: dict, case: str) -> bytes:
        nonce = hex_value(challenge["payload"]["nonce"], "issued challenge nonce")
        identifier = challenge["payload"]["challenge_id"]
        require(re.fullmatch(r"[0-9a-f]{32}", identifier) is not None,
                "CHALLENGE_ID", case)
        filename = f"wolfalibi-{identifier}.json"
        path = self.vm_dir / "result" / filename
        require(not os.path.lexists(path), "EVIDENCE_EXISTS", case, environment=True)
        self.target(["shirudo-runtime", "attest", f"--nonce={nonce}",
                     f"--output=/mnt/shirudo-out/{filename}"], f"collect {case}")
        raw = read_input(path, MAX_EVIDENCE_BYTES, f"collected evidence {case}")
        obj = parse_input(raw, MAX_EVIDENCE_BYTES, f"collected evidence {case}")
        require(obj.get("nonce") == nonce, "COLLECTION_NONCE", case)
        return raw

    def assess_case(self, service: Service, policy: dict, name: str, *,
                    outcome="REJECTED", reason="UPSTREAM_REJECTED",
                    crypto_failure=None, stale: bytes | None = None,
                    tamper=False, expire=False, revoke=False) -> tuple[dict, bytes, dict]:
        policy = copy.deepcopy(policy)
        policy["policy_id"] = "fresh-lab-" + name
        if expire:
            policy["challenge_ttl_seconds"] = 1
        policy_sha = service.register_policy(policy)
        self.artifacts.json(f"cases/{name}/policy.json", policy)
        challenge = service.issue_challenge(policy_sha)
        self.artifacts.json(f"cases/{name}/challenge.json", challenge)
        evidence = stale if stale is not None else self.collect(challenge, name)
        if tamper:
            self.artifacts.write(f"cases/{name}/original-evidence.json", evidence)
            evidence = signature_control(evidence)
        evidence_path = self.artifacts.write(f"cases/{name}/evidence.json", evidence)
        if expire:
            # Real wall-clock expiry; never change Service._clock or its journal.
            remaining = challenge["payload"]["expires_at_ms"] / 1000 - time.time()
            if remaining >= 0:
                time.sleep(min(remaining + 0.02, 1.1))
        if revoke:
            service.revoke_policy(policy_sha)
        receipt = service.assess_file(challenge["payload"]["challenge_id"], evidence_path,
                                      str(self.verifier))
        self.artifacts.json(f"cases/{name}/receipt.json", receipt)
        verification = verify_receipt(
            receipt, service.public_key_hex(), expected_target=policy["target_id"],
            expected_policy_sha256=policy_sha,
            expected_challenge_id=challenge["payload"]["challenge_id"],
        )
        self.artifacts.json(f"cases/{name}/receipt-verification.json", verification)
        require(verification["signature_valid"] is True
                and verification["current_authorization"] is False,
                "RECEIPT_VERIFICATION", name)
        check_receipt_bindings(receipt, policy, challenge, evidence)
        require(service.get_receipt(challenge["payload"]["challenge_id"]) == receipt,
                "DURABLE_RECEIPT", name)
        result = {"case": name, "outcome": receipt["payload"]["outcome"],
                  "reason_code": receipt["payload"]["reason_code"],
                  "execution_profile": receipt["payload"]["upstream"]["execution_profile"],
                  "fresh_collection": stale is None, "evidence_mutated": tamper,
                  "receipt_signature_valid": True, "result": "PENDING_ASSERTION"}
        self.cases.append(result)
        expect_receipt(receipt, outcome=outcome, reason=reason, crypto_failure=crypto_failure)
        result["result"] = "PASS"
        self.artifacts.json(f"cases/{name}/result.json", result)
        return challenge, evidence, receipt

    def run_cases(self, service: Service, baseline: dict) -> None:
        self.artifacts.json("public-key.json", {"instance_id": service.instance_id,
                                               "public_key": service.public_key_hex()})
        challenge, evidence, receipt = self.assess_case(
            service, baseline, "positive", outcome="EVIDENCE_ACCEPTED",
            reason="REQUIRED_CHECKS_PASSED")
        self.positive_accepted = True
        replay_path = self.artifacts.path / "cases/positive/evidence.json"
        try:
            service.assess_file(challenge["payload"]["challenge_id"], replay_path, str(self.verifier))
        except AdapterError as exc:
            require(exc.code == "CHALLENGE_SPENT", "REPLAY_CODE", "same challenge replay")
        else:
            raise LabFailure("REPLAY_ACCEPTED", "same challenge replay")
        require(service.get_receipt(challenge["payload"]["challenge_id"]) == receipt,
                "REPLAY_CHANGED_RECEIPT", "same challenge replay")
        replay = {"case": "same-challenge-replay", "result": "PASS", "code": "CHALLENGE_SPENT",
                  "fresh_collection": False, "original_receipt_unchanged": True}
        self.cases.append(replay)
        self.artifacts.json("cases/same-challenge-replay/result.json", replay)
        self.assess_case(service, baseline, "new-nonce-stale-evidence", stale=evidence,
                         reason="NONCE_MISMATCH")
        self.assess_case(service, baseline, "tampered-signature", tamper=True,
                         crypto_failure="quote: ECDSA signature by the attestation key")
        for name, path, reason, crypto in (
            ("wrong-identity", ("enrollment", "ak_name"), "TARGET_MISMATCH", None),
            ("wrong-chain", ("expected", "chain"), "STATE_MISMATCH", None),
            ("wrong-config", ("expected", "config_root"), "UPSTREAM_REJECTED",
             "config: config root was not approved by the operator"),
            ("wrong-binding", ("expected", "binding_pcrs", "9"), "UPSTREAM_REJECTED",
             "binding: PCR 9 held the expected value"),
        ):
            variant = copy.deepcopy(baseline)
            selected = variant
            for key in path[:-1]:
                selected = selected[key]
            selected[path[-1]] = altered_hex(selected[path[-1]])
            self.assess_case(service, variant, name, reason=reason, crypto_failure=crypto)
        self.assess_case(service, baseline, "expired-challenge", expire=True,
                         reason="CHALLENGE_EXPIRED")
        revoked_challenge, _, _ = self.assess_case(
            service, baseline, "revoked-policy", revoke=True, reason="POLICY_REVOKED")
        try:
            service.issue_challenge(revoked_challenge["payload"]["policy_sha256"])
        except AdapterError as exc:
            require(exc.code == "POLICY_REVOKED", "REVOCATION_CODE", "new challenge after revocation")
        else:
            raise LabFailure("REVOCATION_BYPASS", "new challenge after revocation")

    def run(self) -> dict:
        baseline = self.prepare()
        private_path = None
        try:
            with tempfile.TemporaryDirectory(prefix="wolfalibi-real-lab-private-") as private:
                private_path = Path(private)
                private_path.chmod(0o700)
                self.state_removed = False
                service = Service.initialize(private_path / "state")
                self.run_cases(service, baseline)
        finally:
            # TemporaryDirectory also removes signing.key and journal when a
            # failed assertion interrupts the run; no private tree is exported.
            if private_path is not None:
                self.state_removed = not private_path.exists()
        require(self.state_removed, "PRIVATE_STATE_CLEANUP", "local verifier state")
        return self.finish("PASS")

    def finish(self, result: str, *, code=None, stage=None) -> dict:
        summary = {
            "schema": "wolfalibi.shirudo.real-lab.v1", "result": result,
            "assurance": "LAB_VTPM", "source_commit": UPSTREAM_COMMIT,
            "verifier_sha256": VERIFIER_SHA256, "positive_evidence_accepted": self.positive_accepted,
            "current_authorization": False, "hardware_qualification": False,
            "measured_uki_qualification": False, "target_contact": self.target_contact,
            "target_state_changes": "EVIDENCE_COLLECTION_ONLY",
            "private_adapter_state_removed": self.state_removed,
            "cases": self.cases, "limitations": LIMITATIONS,
        }
        if code is not None:
            summary.update({"failure_code": code, "failure_stage": stage})
        self.artifacts.json("commands.json", self.commands)
        self.artifacts.json("summary.json", summary)
        self.artifacts.json("artifact-manifest.json", {
            "schema": "wolfalibi.shirudo.public-artifacts.v1", "files": dict(self.artifacts.files),
            "private_state_exported": False,
        })
        return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bundle", type=Path,
                        help="Independently built bundle used for this VM; defaults to the upstream bundle")
    args = parser.parse_args(argv)
    lab = None
    try:
        lab = RealLab(args.upstream, args.vm_name, args.verifier, args.output, bundle=args.bundle)
        result, code = lab.run(), 0
    except LabFailure as exc:
        code = exc.exit_code
        result = lab.finish(exc.result, code=exc.code, stage=exc.stage) if lab else {
            "schema": "wolfalibi.shirudo.real-lab.v1", "result": exc.result,
            "failure_code": exc.code, "failure_stage": exc.stage, "current_authorization": False}
    except (AdapterError, OSError, UnicodeError) as exc:
        code = 2
        failure = exc.code if isinstance(exc, AdapterError) else type(exc).__name__
        result = lab.finish("BLOCKED_ENVIRONMENT", code=failure, stage="harness") if lab else {
            "schema": "wolfalibi.shirudo.real-lab.v1", "result": "BLOCKED_ENVIRONMENT",
            "failure_code": failure, "current_authorization": False}
    print(canonical_json(result).decode("ascii"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
