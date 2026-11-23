#!/usr/bin/env python3
"""Gate A: genuine upstream executable, explicitly historical test vectors.

This command never creates a Service, enrollment, challenge, or signed receipt.
The runner's SYNTHETIC policy class marks copied corpus expectations as test
inputs; the executable is separately required to match the official ELF pin.
An old corpus nonce is not evidence that a target is fresh or currently safe.
"""

from __future__ import annotations

import argparse
import copy
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shirudo_adapter.model import (  # noqa: E402
    AdapterError, MAX_EVIDENCE_BYTES, UPSTREAM_COMMIT, canonical_json,
    read_bounded_file, strict_json, validate_policy,
)
from shirudo_adapter import runner  # noqa: E402


SCOPE = "HISTORICAL_FIXTURE_COMPATIBILITY"
OFFICIAL_ELF_SHA256 = "be8b79cdd7efb8e635b7965bf34fa691e5e4a378957f3829530a529097abe9d2"
OFFICIAL_ARTIFACT_SHA256 = "e830f2384383adccba7c423e8afe81d1fd0b3d6e27e66ce2aed49eae632e989c"
OFFICIAL_RUN = 45269604356
OFFICIAL_ARTIFACT = 14865910776
TIMEOUT_SECONDS = 20
STREAM_LIMIT = 65_536
FIXTURES = {
    "known-negative": {
        "path": "testing/fuzz/corpus/attest/evidence",
        "bytes": 5653,
        "git_blob_sha": "d422ceb1b94e0e52aed771971355b9d405b9bdfe",
        "sha256": "e2e3951c0caa108b345a99746e0fc6d31b30927c956e9df0c0ed297fdbacb71d",
    },
    "candidate-config-history": {
        "path": "testing/fuzz/corpus/attest/evidence-config-history",
        "bytes": 15108,
        "git_blob_sha": "637faccb13186fed4d581fe70f2c74a57ef6411a",
        "sha256": "99b3105d3ee72334fdc63c17313f5ba931cead43248c35ebe191d53a643ce343",
    },
}


@dataclass(frozen=True)
class Capture:
    exit_code: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    error: str | None = None


def capture(argv: list[str], *, pass_fds: tuple[int, ...] = (),
            timeout: float = TIMEOUT_SECONDS, stdout_limit: int = STREAM_LIMIT) -> Capture:
    """Capture bounded bytes, including the actual stderr of startup failures."""
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": STREAM_LIMIT}
    deadline = time.monotonic() + timeout
    error = None
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, close_fds=True, pass_fds=pass_fds, start_new_session=True,
            cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                          "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                          "GIT_TERMINAL_PROMPT": "0"},
        )
    except OSError:
        return Capture(None, error="EXECUTION_UNAVAILABLE")
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    error = "TIMEOUT"
                    break
                for event, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(event.fileobj.fileno(), 16_384)
                    if not chunk:
                        selector.unregister(event.fileobj)
                        continue
                    target = buffers[event.data]
                    available = limits[event.data] - len(target)
                    target.extend(chunk[:available])
                    if len(chunk) > available:
                        error = "OUTPUT_LIMIT"
                        break
                if error:
                    break
            if not error and time.monotonic() >= deadline:
                error = "TIMEOUT"
    finally:
        # This also kills a descendant holding a pipe after the parent exits.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            error = error or "CLEANUP_TIMEOUT"
        process.stdout.close()
        process.stderr.close()
    return Capture(process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]), error)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_bytes(output: Path, name: str, data: bytes) -> dict:
    if len(data) > 2 * MAX_EVIDENCE_BYTES or Path(name).name != name:
        raise AdapterError("OUTPUT_BOUND", "Invalid or oversized harness artifact")
    fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        runner._write_all(fd, data)
    finally:
        os.close(fd)
    return {"file": name, "bytes": len(data), "sha256": sha256(data)}


def save_json(output: Path, name: str, value: object) -> dict:
    return save_bytes(output, name, canonical_json(value) + b"\n")


def record_capture(output: Path, name: str, result: Capture) -> dict:
    return {
        "exit_code": result.exit_code, "error": result.error,
        "stdout": save_bytes(output, name + ".stdout", result.stdout),
        "stderr": save_bytes(output, name + ".stderr", result.stderr),
    }


def load_fixtures(upstream: Path, output: Path) -> tuple[dict, dict[str, bytes]]:
    git = shutil.which("git")
    if git is None:
        raise AdapterError("SOURCE_UNAVAILABLE", "git is required to inspect the pinned source")
    command = [git, "--no-replace-objects", "-C", str(upstream)]
    head = capture([*command, "rev-parse", "--verify", "HEAD"], timeout=10, stdout_limit=1024)
    head_record = record_capture(output, "source-head", head)
    if head.error or head.exit_code != 0 or head.stdout != (UPSTREAM_COMMIT + "\n").encode():
        raise AdapterError("SOURCE_COMMIT", "Upstream checkout HEAD must equal the reviewed commit")
    source = {"commit": UPSTREAM_COMMIT, "head_check": head_record, "fixtures": {}}
    fixtures = {}
    for name, pin in FIXTURES.items():
        result = capture([*command, "cat-file", "blob", f"{UPSTREAM_COMMIT}:{pin['path']}"],
                         timeout=10, stdout_limit=MAX_EVIDENCE_BYTES)
        if result.error or result.exit_code != 0:
            raise AdapterError("SOURCE_FIXTURE", "Cannot read the pinned fixture from git objects")
        raw = result.stdout
        blob_id = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if len(raw) != pin["bytes"] or sha256(raw) != pin["sha256"] or blob_id != pin["git_blob_sha"]:
            raise AdapterError("SOURCE_FIXTURE", "Historical corpus bytes do not match their reviewed pins")
        fixtures[name] = raw
        source["fixtures"][name] = {
            **pin, "url": f"https://github.com/shirudo-dev/shirudo/blob/{UPSTREAM_COMMIT}/{pin['path']}",
            "artifact": save_bytes(output, name + ".original.json", raw),
        }
    return source, fixtures


def fixture_policy(raw: bytes, name: str, version_id: str) -> tuple[dict, str]:
    """Freeze expectations ONCE from hash-pinned corpus, before any mutation.

    This is test-vector construction, not learning a deployment policy from
    untrusted evidence. The known-negative corpus lacks configuration evidence;
    its explicit zero-root expectation requires the strict verifier to reject.
    """
    document = strict_json(raw, MAX_EVIDENCE_BYTES)
    init = next(row for row in document["eventlog"] if row["type"] == "init")
    config = document.get("config")
    expected = {
        "chain": document["register"]["value"],
        "config_root": config["events"][-1]["root_hash"] if config else "0" * 64,
        "config_pcr": config["pcr"] if config else 14,
        "binding_pcrs": {"9": init["pcr_before"], "11": init["phase_before"]},
        "quote_pcrs": {str(row["index"]): row["value"] for row in document["pcrs"]},
    }
    policy = validate_policy({
        "schema": "wolfalibi.shirudo.policy.v1", "policy_id": "historical-" + name,
        "target_id": "corpus-" + name, "assurance": "SYNTHETIC",
        "enrollment": {"method": "synthetic_fixture", "record_sha256": sha256(raw),
                       "ak_name": document["ak"]["name"], "ek_name": document["ek"]["name"]},
        "expected": expected,
        "verifier": {"source_commit": UPSTREAM_COMMIT, "sha256": OFFICIAL_ELF_SHA256,
                     "version_id": version_id, "timeout_seconds": TIMEOUT_SECONDS},
        # Required by the policy schema; no challenge is created or TTL tested.
        "challenge_ttl_seconds": 1,
    })
    return policy, document["nonce"]


def upstream_arguments(policy: dict, nonce: str, evidence_path: str) -> list[str]:
    """Independent CLI argument construction; do not call runner._arguments."""
    pins, expected = policy["enrollment"], policy["expected"]
    args = ["attest", "verify", "--json", "--require-initrd", f"--evidence={evidence_path}",
            f"--nonce={nonce}", f"--ak-name={pins['ak_name']}", f"--ek-name={pins['ek_name']}",
            f"--expect-chain={expected['chain']}", f"--expect-config-root={expected['config_root']}",
            f"--expect-config-pcr={expected['config_pcr']}"]
    for pcr in (9, 11):
        args.append(f"--expect-bind-pcr={pcr}={expected['binding_pcrs'][str(pcr)]}")
    for pcr in sorted(expected["quote_pcrs"], key=int):
        args.append(f"--expect-pcr={pcr}={expected['quote_pcrs'][pcr]}")
    return args


def raw_report(result: Capture) -> dict | None:
    """Check raw CLI framing/exit semantics independently of runner._report."""
    if result.error or result.exit_code not in (0, 1):
        return None
    try:
        report = strict_json(result.stdout, STREAM_LIMIT)
    except AdapterError:
        return None
    if type(report) is not dict or set(report) != {"schema", "verdict", "checks"}:
        return None
    if type(report["schema"]) is not int or report["schema"] != 1:
        return None
    if report["verdict"] != ("ok" if result.exit_code == 0 else "fail"):
        return None
    checks = report["checks"]
    if type(checks) is not list or not 1 <= len(checks) <= 4096:
        return None
    for check in checks:
        if (type(check) is not dict or set(check) != {"result", "text"} or
                type(check["result"]) is not str or check["result"] not in {"ok", "fail", "note"} or
                type(check["text"]) is not str or not check["text"]):
            return None
    has_failure = any(check["result"] == "fail" for check in checks)
    if has_failure != (result.exit_code == 1):
        return None
    return report


def flipped(value: str) -> str:
    return value[:-2] + f"{int(value[-2:], 16) ^ 1:02x}"


def negative_controls(raw: bytes, nonce: str) -> list[dict]:
    base = strict_json(raw, MAX_EVIDENCE_BYTES)
    controls = []
    edits = (
        ("quote-signature-bitflip", ("quote", "signature"),
         "quote: ECDSA signature by the attestation key"),
        ("register-value-bitflip", ("register", "value"),
         "register: certified contents match the listed value"),
    )
    for name, (group, field), assertion in edits:
        altered = copy.deepcopy(base)
        altered[group][field] = flipped(altered[group][field])
        controls.append({"name": name, "evidence": canonical_json(altered), "nonce": nonce,
                         "failure_assertion": assertion, "expected": "reject"})
    altered = copy.deepcopy(base)
    altered["config"]["events"][-1]["root_hash"] = flipped(altered["config"]["events"][-1]["root_hash"])
    controls.append({"name": "config-history-bitflip", "evidence": canonical_json(altered), "nonce": nonce,
                     "failure_assertion": "config: config history does not match the quoted PCR", "expected": "reject"})
    altered = copy.deepcopy(base)
    row = next(row for row in altered["pcrs"] if row["index"] == 7)
    row["value"] = flipped(row["value"])
    controls.append({"name": "quoted-pcr-bitflip", "evidence": canonical_json(altered), "nonce": nonce,
                     "failure_assertion": "quote: PCR digest matches the listed values", "expected": "reject"})
    controls.append({"name": "wrong-expected-nonce", "evidence": raw, "nonce": flipped(nonce),
                     "failure_assertion": "nonce matches the request", "expected": "reject"})
    controls.append({"name": "truncated-json", "evidence": raw[:len(raw) // 2], "nonce": nonce,
                     "failure_assertion": None, "expected": "parse_reject"})
    return controls


def run_case(output: Path, executable_fd: int, executable: str, policy: dict, case: dict) -> dict:
    name, evidence, nonce = case["name"], case["evidence"], case["nonce"]
    result = {"name": name, "expected": case["expected"], "nonce": nonce,
              "evidence": save_bytes(output, name + ".evidence.json", evidence),
              "required_failure_assertion": case.get("failure_assertion"),
              "scope": SCOPE, "fresh_target_claim": False}
    with ExitStack() as stack:
        fd = runner._new_memfd(stack, "historical-fixture")
        runner._write_all(fd, evidence)
        runner._seal(fd)
        args = upstream_arguments(policy, nonce, f"/proc/self/fd/{fd}")
        raw = capture([f"/proc/self/fd/{executable_fd}", *args], pass_fds=(executable_fd, fd))
    result["raw_upstream"] = {"argv": args, **record_capture(output, name + ".raw", raw)}
    report = raw_report(raw)
    result["raw_upstream"]["report"] = report
    adapter_result = None
    adapter_error = None
    try:
        # A detached policy copy prevents any caller or test double mutating
        # the frozen baseline expectations for subsequent controls.
        adapter_result = runner.run_verifier(executable, evidence, copy.deepcopy(policy), nonce)
    except AdapterError as exc:
        adapter_error = {"code": exc.code, "message": exc.message}
    result["adapter"] = {"result": adapter_result, "error": adapter_error}
    if case["expected"] == "parse_reject":
        matched = (not raw.error and raw.exit_code == 2 and raw.stdout == b"" and
                   adapter_error is not None and adapter_error["code"] in {"INVALID_JSON", "JSON_SIZE"})
        result.update(interface_compatible=matched, expected_outcome_observed=matched,
                      status="PARSE_REJECTED" if matched else "INTERFACE_MISMATCH")
    else:
        matched = (report is not None and adapter_result is not None and adapter_error is None and
                   type(adapter_result.get("accepted")) is bool and
                   adapter_result.get("exit_code") == raw.exit_code and
                   adapter_result["accepted"] == (raw.exit_code == 0) and
                   adapter_result.get("report") == report)
        assertion = case.get("failure_assertion")
        assertion_failed = bool(report and (assertion is None or any(
            check == {"result": "fail", "text": assertion} for check in report["checks"])))
        expected = matched and (raw.exit_code == 0 if case["expected"] == "candidate_accept" else
                                raw.exit_code == 1 and assertion_failed)
        status = "ACCEPTED" if matched and raw.exit_code == 0 else "REJECTED" if matched else "INTERFACE_MISMATCH"
        result.update(interface_compatible=matched, expected_outcome_observed=expected, status=status,
                      required_failure_observed=assertion_failed if assertion else None)
    save_json(output, name + ".case.json", result)
    return result


def run_gate(upstream: Path, executable: str, output: Path) -> tuple[dict, int]:
    output = Path(os.path.abspath(output))
    if output.is_symlink():
        raise AdapterError("OUTPUT_PATH", "Output directory must not be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise AdapterError("OUTPUT_PATH", "Use an empty output directory to avoid stale qualification artifacts")
    summary = {
        "schema": "wolfalibi.shirudo.gate-a.v1", "scope": SCOPE,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "binary_ready": False, "version_id": None, "result": "PREFLIGHT_BLOCKED",
        "candidate_validity": "NOT_RUN", "interface_compatible": False,
        "known_negative_rejected": False, "negative_controls_passed": False,
        "negative_controls_validated_against_passing_baseline": False,
        "fresh_target_claim": False, "enrollment_performed": False,
        "receipt_created": False, "hardware_tpm_claim": False,
        "policy_basis": "Hash-pinned historical corpus; SYNTHETIC test-vector policy, genuine separately pinned ELF",
        "known_negative_policy_note": "This old corpus has no configuration block; zero-root/PCR14 is an explicit rejection sentinel, not an approved target configuration",
        "environment": {"memlock_soft_hard": list(resource.getrlimit(resource.RLIMIT_MEMLOCK))},
        "source": {"expected_commit": UPSTREAM_COMMIT}, "cases": [],
        "official_build_reference": {
            "run": OFFICIAL_RUN, "artifact": OFFICIAL_ARTIFACT,
            "archive_sha256": OFFICIAL_ARTIFACT_SHA256,
            "elf_sha256": OFFICIAL_ELF_SHA256,
            "url": f"https://github.com/shirudo-dev/shirudo/actions/runs/{OFFICIAL_RUN}/artifacts/{OFFICIAL_ARTIFACT}",
            "qualification": "CI source association; not an independently reproduced build",
        },
    }
    exit_code = 2
    try:
        summary["source"], fixtures = load_fixtures(Path(upstream).resolve(), output)
        if not os.path.isabs(executable):
            raise AdapterError("EXECUTABLE_PATH", "--verifier must be an absolute path")
        binary = read_bounded_file(executable, runner.MAX_EXECUTABLE_BYTES)
        summary["binary"] = {"sha256": sha256(binary), "bytes": len(binary), "elf": binary.startswith(b"\x7fELF")}
        if not binary.startswith(b"\x7fELF") or sha256(binary) != OFFICIAL_ELF_SHA256:
            raise AdapterError("EXECUTABLE_PIN", "Verifier must be the reviewed official static ELF")
        del binary
        with ExitStack() as stack:
            executable_fd, _ = runner._executable_snapshot(stack, executable, OFFICIAL_ELF_SHA256, False)
            startup = capture([f"/proc/self/fd/{executable_fd}", "version", "--version-id"],
                              pass_fds=(executable_fd,), timeout=10, stdout_limit=1024)
            summary["startup"] = {"argv": ["version", "--version-id"], **record_capture(output, "startup", startup)}
            version_ok = (not startup.error and startup.exit_code == 0 and
                          re.fullmatch(rb"[0-9a-f]{64}\n", startup.stdout) is not None)
            if not version_ok:
                summary["result"] = "STARTUP_BLOCKED"
                exit_code = 1
            else:
                version = startup.stdout.decode("ascii").strip()
                summary.update(binary_ready=True, version_id=version)
                policies = {}
                for name, raw in fixtures.items():
                    policy, nonce = fixture_policy(raw, name, version)
                    policies[name] = (policy, nonce)
                    save_json(output, name + ".historical-policy.json", policy)
                for name, expected in (("known-negative", "reject"), ("candidate-config-history", "candidate_accept")):
                    policy, nonce = policies[name]
                    summary["cases"].append(run_case(output, executable_fd, executable, policy,
                        {"name": name, "evidence": fixtures[name], "nonce": nonce, "expected": expected}))
                policy, nonce = policies["candidate-config-history"]
                for case in negative_controls(fixtures["candidate-config-history"], nonce):
                    summary["cases"].append(run_case(output, executable_fd, executable, policy, case))
                known, candidate, *controls = summary["cases"]
                compatible = all(case["interface_compatible"] for case in summary["cases"])
                candidate_raw = candidate["raw_upstream"]
                raw_validity = ("ACCEPTED" if candidate_raw["report"] is not None and candidate_raw["exit_code"] == 0 else
                                "REJECTED" if candidate_raw["report"] is not None and candidate_raw["exit_code"] == 1 else "INDETERMINATE")
                valid = raw_validity == "ACCEPTED"
                summary.update(
                    interface_compatible=compatible,
                    known_negative_rejected=known["expected_outcome_observed"],
                    candidate_validity=raw_validity,
                    candidate_adapter_accepted=candidate["status"] == "ACCEPTED",
                    negative_controls_passed=all(case["expected_outcome_observed"] for case in controls),
                    negative_controls_validated_against_passing_baseline=valid and all(case["expected_outcome_observed"] for case in controls),
                )
                if not compatible:
                    summary["result"] = "INTERFACE_MISMATCH"
                elif not known["expected_outcome_observed"]:
                    summary["result"] = "NEGATIVE_CONTROL_FAILURE"
                elif not valid:
                    summary["result"] = "CANDIDATE_NOT_QUALIFIED"
                elif not summary["negative_controls_passed"]:
                    summary["result"] = "NEGATIVE_CONTROL_FAILURE"
                else:
                    summary["result"] = "QUALIFIED"
                exit_code = 0 if summary["result"] == "QUALIFIED" else 1
    except AdapterError as exc:
        summary["error"] = {"code": exc.code, "message": exc.message}
        summary["result"] = "HARNESS_BLOCKED" if summary["binary_ready"] else "PREFLIGHT_BLOCKED"
    except (OSError, KeyError, TypeError, ValueError, StopIteration) as exc:
        summary["error"] = {"code": "HARNESS_ERROR", "type": type(exc).__name__,
                            "message": "Unable to complete the bounded historical-fixture harness"}
        summary["result"] = "HARNESS_BLOCKED" if summary["binary_ready"] else "PREFLIGHT_BLOCKED"
    summary["exit_code"] = exit_code
    save_json(output, "gate-a-report.json", summary)
    return summary, exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True, help="Checkout of the pinned upstream commit")
    parser.add_argument("--verifier", required=True, help="Absolute path to the exact official static ELF")
    parser.add_argument("--output", type=Path, required=True, help="Empty directory for bounded diagnostic artifacts")
    args = parser.parse_args(argv)
    try:
        report, code = run_gate(args.upstream, args.verifier, args.output)
        print(canonical_json({key: report[key] for key in
                              ("scope", "result", "binary_ready", "version_id", "candidate_validity", "exit_code")}).decode())
        return code
    except (AdapterError, OSError) as exc:
        print(canonical_json({"scope": SCOPE, "result": "OUTPUT_BLOCKED", "binary_ready": False,
                              "code": getattr(exc, "code", "OUTPUT_IO")}).decode(), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
