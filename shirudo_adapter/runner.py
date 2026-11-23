"""Bounded, offline execution of one reviewed Shirudo verifier build.

The pinned upstream schema has human check text, not stable check IDs.  The
allowlist below is therefore part of the compatibility contract for
UPSTREAM_COMMIT, and must be reviewed when that source pin changes.

Sealed memfds remove executable/evidence path races.  They do not sandbox the
verifier, attest its ELF interpreter/shared libraries, or enroll a TPM.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from contextlib import ExitStack

from .model import (
    AdapterError, MAX_EVIDENCE_BYTES, MAX_POLICY_BYTES, UPSTREAM_COMMIT,
    canonical_json, strict_json, validate_policy,
)


MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_CHECKS = 4096
# Linux UAPI constants (linux/fcntl.h). Some Python distributions expose
# memfd_create but omit these fcntl names; the kernel still supports them.
_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
_F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
_REQUIRED_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008

_BASE_CHECKS = (
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
)
_NVPCR_CHECKS = (
    "config NvPCR: ECDSA signature by the attestation key",
    "config NvPCR: signed by the key as an endorsement primary",
    "config NvPCR: carries the nonce",
    "config NvPCR: certified name and contents",
    "config NvPCR: same TPM boot as quote",
    "config NvPCR: the operator-pinned index",
)
# Upstream checks inits_epoch == 1 but prints its separate total `inits`.
# A later TPM reset may therefore legitimately print an ok total above one.
_EPOCH = re.compile(r"eventlog: one init record for this TPM reset \(([1-9][0-9]{0,3}) this boot\)")
_REPLAY = re.compile(r"eventlog: ([1-9][0-9]{0,3}) record(s?) replay to the certified value")
_ANCHOR_OK = "anchor: PCR 9 equals the recorded value extended by the anchor"
_ANCHOR_NOTE = (
    "anchor: PCR 9 carries further measurements after the anchor; "
    "replay the logs to confirm it"
)
_KNOWN_NOTES = {
    _ANCHOR_NOTE,
    "config records a selection; operation completion depends on trusted runtime guards",
    "a credential was activated but none is expected (--expect-credential)",
}
_KNOWN_FAILURES = {
    "attestation key: public area is not a P-256 ECDSA key",
    "config NvPCR: certification missing",
    "register: cannot compute the signed write policy",
    "register: cannot compute the index name",
    "anchor: PCR 9 is not in the quote",
    "config: the events are one boot event followed by updates in sequence",
    "config: configuration evidence is missing",
    "config: config PCR is unquoted or unexpected",
    "config: config NvPCR is not certified",
    "config: config history does not start at the NvPCR's initial value",
    "config: config history belongs to another TPM boot",
    "config: expected config root needs an expected PCR",
    "config: config history does not match the certified NvPCR",
    "config: config history does not match the quoted PCR",
    "config: config root was not approved by the operator",
}
for _signed in ("quote", "register", "config NvPCR"):
    for _reason in ("attestation structure unparseable", "signature structure unparseable"):
        _KNOWN_FAILURES.add(f"{_signed}: {_reason}")


def _error(code: str, message: str) -> AdapterError:
    return AdapterError(code, message)


def _hex(value: object, length: int, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{%d}" % length, value) is None:
        raise _error("VERIFIER_POLICY", f"{label} must be {length} lowercase hexadecimal characters")
    return value


def _arguments(policy: dict, nonce: str, evidence_path: str) -> tuple[list[str], list[str]]:
    """Construct only this adapter's reviewed options; never forward user flags."""
    try:
        if policy["schema"] != "wolfalibi.shirudo.policy.v1":
            raise _error("VERIFIER_POLICY", "Unsupported policy schema")
        assurance = policy["assurance"]
        if assurance not in {"SYNTHETIC", "LAB_VTPM", "HARDWARE_TPM"}:
            raise _error("VERIFIER_POLICY", "Unsupported assurance level")
        enrolled = policy["enrollment"]
        if (enrolled["method"] == "synthetic_fixture") != (assurance == "SYNTHETIC"):
            raise _error("VERIFIER_POLICY", "Synthetic enrollment and assurance must agree")
        expected = policy["expected"]
        if ("config_pcr" in expected) == ("config_nvpcr" in expected):
            raise _error("VERIFIER_POLICY", "Exactly one configuration PCR or NvPCR pin is required")
        if not isinstance(nonce, str) or re.fullmatch(r"(?:[0-9a-f]{2}){1,64}", nonce) is None:
            raise _error("VERIFIER_POLICY", "Nonce must contain 1 to 64 bytes in lowercase hexadecimal")
        bindings = expected["binding_pcrs"]
        if not isinstance(bindings, dict) or set(bindings) != {"9", "11"}:
            raise _error("VERIFIER_POLICY", "Binding PCRs 9 and 11 must both be pinned")
        args = [
            "attest", "verify", f"--evidence={evidence_path}", f"--nonce={nonce}",
            "--ak-name=" + _hex(enrolled["ak_name"], 68, "AK name"),
            "--ek-name=" + _hex(enrolled["ek_name"], 68, "EK name"),
            "--expect-chain=" + _hex(expected["chain"], 64, "Expected chain"),
            "--expect-bind-pcr=9=" + _hex(bindings["9"], 64, "Binding PCR 9"),
            "--expect-bind-pcr=11=" + _hex(bindings["11"], 64, "Binding PCR 11"),
            "--expect-config-root=" + _hex(expected["config_root"], 64, "Configuration root"),
        ]
        required = list(_BASE_CHECKS)
        if "config_pcr" in expected:
            pcr = expected["config_pcr"]
            if type(pcr) is not int or not 0 <= pcr <= 15 or pcr in {9, 11}:
                raise _error("VERIFIER_POLICY", "Configuration PCR must be 0..15 excluding 9 and 11")
            args.append(f"--expect-config-pcr={pcr}")
            required.append("config: config root history matches the quoted PCR")
        else:
            args.append("--expect-config-nvpcr=" + _hex(expected["config_nvpcr"], 68, "Configuration NvPCR"))
            required.extend(_NVPCR_CHECKS)
            required.append("config: config root history matches the certified NvPCR")
        quoted = expected["quote_pcrs"]
        if not isinstance(quoted, dict):
            raise _error("VERIFIER_POLICY", "Quoted PCR expectations must be an object")
        for key in quoted:
            if not isinstance(key, str) or re.fullmatch(r"(?:[0-9]|1[0-9]|2[0-3])", key) is None:
                raise _error("VERIFIER_POLICY", "Quoted PCR indices must be decimal strings from 0 to 23")
        for key in sorted(quoted, key=int):
            args.append(f"--expect-pcr={key}=" + _hex(quoted[key], 64, f"Quoted PCR {key}"))
            required.append(f"PCR {key} matches the expected value")
        args.extend(("--require-initrd", "--json"))
        return args, required
    except (KeyError, TypeError) as exc:
        raise _error("VERIFIER_POLICY", "Policy is missing a required verifier input") from exc


def _new_memfd(stack: ExitStack, name: str) -> int:
    if sys.platform != "linux" or not hasattr(os, "memfd_create"):
        raise _error("EXECUTION_UNSUPPORTED", "Sealed verifier execution requires Linux memfd support")
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    stack.callback(os.close, fd)
    return fd


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise _error("EXECUTION_IO", "Unable to create the sealed snapshot")
        view = view[written:]


def _seal(fd: int, executable: bool = False) -> None:
    os.fchmod(fd, 0o500 if executable else 0o400)
    fcntl.fcntl(fd, _F_ADD_SEALS, _REQUIRED_SEALS)
    if fcntl.fcntl(fd, _F_GET_SEALS) & _REQUIRED_SEALS != _REQUIRED_SEALS:
        raise _error("EXECUTION_UNSUPPORTED", "The kernel did not seal the snapshot")
    os.lseek(fd, 0, os.SEEK_SET)


def _executable_snapshot(stack: ExitStack, path: str, expected_sha: str, synthetic: bool) -> tuple[int, str]:
    if not isinstance(path, str) or not os.path.isabs(path) or "\x00" in path:
        raise _error("EXECUTABLE_PATH", "Verifier must be an absolute path to a regular file")
    source = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(source)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_EXECUTABLE_BYTES:
            raise _error("EXECUTABLE_TYPE", "Verifier must be a nonempty regular file within the size bound")
        snapshot = _new_memfd(stack, "wolfalibi-verifier")
        digest = hashlib.sha256()
        count, magic = 0, b""
        while True:
            chunk = os.read(source, 64 * 1024)
            if not chunk:
                break
            if not magic:
                magic = chunk[:4]
            count += len(chunk)
            if count > MAX_EXECUTABLE_BYTES:
                raise _error("EXECUTABLE_LIMIT", "Verifier exceeded the executable size bound")
            digest.update(chunk)
            _write_all(snapshot, chunk)
        if count != info.st_size:
            raise _error("EXECUTABLE_CHANGED", "Verifier changed size while it was being snapshotted")
    finally:
        os.close(source)
    actual = digest.hexdigest()
    if actual != expected_sha:
        raise _error("EXECUTABLE_DIGEST", "Verifier executable does not match the operator's SHA-256 pin")
    if magic != b"\x7fELF" and not (synthetic and magic.startswith(b"#!")):
        raise _error("EXECUTABLE_TYPE", "Real verification requires ELF; scripts are allowed only for SYNTHETIC fixtures")
    _seal(snapshot, executable=True)
    return snapshot, actual


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        # SIGKILL was sent.  An uninterruptible kernel wait cannot be repaired
        # by spinning in this verifier wrapper.
        pass


def _bounded_run(executable_fd: int, args: list[str], pass_fds: tuple[int, ...], deadline: float,
                 stdout_limit: int = MAX_REPORT_BYTES) -> tuple[int, bytes, bytes]:
    if time.monotonic() >= deadline:
        raise _error("VERIFIER_TIMEOUT", "Verifier execution exceeded the policy deadline")
    process = subprocess.Popen(
        [f"/proc/self/fd/{executable_fd}", *args],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        shell=False, close_fds=True, pass_fds=pass_fds, start_new_session=True,
        cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
    )
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": MAX_STDERR_BYTES}
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _error("VERIFIER_TIMEOUT", "Verifier execution exceeded the policy deadline")
                for event, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(event.fileobj.fileno(), 16 * 1024)
                    if not chunk:
                        selector.unregister(event.fileobj)
                        continue
                    stream = output[event.data]
                    if len(stream) + len(chunk) > limits[event.data]:
                        raise _error("VERIFIER_OUTPUT_LIMIT", "Verifier output exceeded the bounded capture limit")
                    stream.extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _error("VERIFIER_TIMEOUT", "Verifier execution exceeded the policy deadline")
            return process.wait(timeout=remaining), bytes(output["stdout"]), bytes(output["stderr"])
    finally:
        # Also remove descendants that retained pipes, or outlived the direct
        # verifier process.  This is process cleanup, not a security sandbox.
        _kill_group(process)
        process.stdout.close()
        process.stderr.close()


def _dynamic_check(text: str) -> str | None:
    match = _EPOCH.fullmatch(text)
    if match and 1 <= int(match[1]) <= 4096:
        return "epoch"
    match = _REPLAY.fullmatch(text)
    if match and 1 <= int(match[1]) <= 4096 and (match[2] == "s") == (int(match[1]) != 1):
        return "replay"
    return None


def _report(stdout: bytes, code: int, required: list[str]) -> tuple[bool, dict, list[str]]:
    if code not in {0, 1}:
        raise _error("VERIFIER_EXIT", "Verifier did not produce a verification result (expected exit 0 or 1)")
    report = strict_json(stdout, max_bytes=MAX_REPORT_BYTES)
    if not isinstance(report, dict) or set(report) != {"schema", "verdict", "checks"}:
        raise _error("VERIFIER_REPORT", "Verifier report has an unsupported object shape")
    if type(report["schema"]) is not int or report["schema"] != 1:
        raise _error("VERIFIER_REPORT", "Verifier report schema must be integer 1")
    if report["verdict"] not in ("ok", "fail") or (code == 0) != (report["verdict"] == "ok"):
        raise _error("VERIFIER_REPORT", "Verifier exit code and verdict disagree")
    checks = report["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS:
        raise _error("VERIFIER_REPORT", "Verifier report must contain a bounded nonempty check list")
    allowed_ok = set(required) | {_ANCHOR_OK}
    seen, dynamic, has_failure, anchor = set(), {}, False, False
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"result", "text"}:
            raise _error("VERIFIER_REPORT", "Verifier check has an unsupported shape")
        result, text = check["result"], check["text"]
        if not isinstance(result, str) or result not in {"ok", "fail", "note"}:
            raise _error("VERIFIER_REPORT", "Verifier check has an unknown result")
        if not isinstance(text, str) or not text or len(text) > 8192 or any(ord(c) < 32 for c in text):
            raise _error("VERIFIER_REPORT", "Verifier check has invalid text")
        kind = _dynamic_check(text)
        if result == "note":
            if text not in _KNOWN_NOTES and re.fullmatch(r"event after boot: [^\r\n]+ [^\r\n]+", text) is None:
                raise _error("VERIFIER_REPORT", "Verifier emitted an unknown note for the pinned source contract")
            if text == _ANCHOR_NOTE:
                if anchor:
                    raise _error("VERIFIER_REPORT", "Verifier emitted duplicate anchor assertions")
                anchor = True
            continue
        if text in seen or (kind and kind in dynamic):
            raise _error("VERIFIER_REPORT", "Verifier emitted duplicate assertions")
        seen.add(text)
        if kind:
            dynamic[kind] = (result, text)
        known_failure = text in _KNOWN_FAILURES or re.fullmatch(
            r"eventlog: event [0-9]+ \([^\r\n]+\) digest does not derive from its fields", text
        ) is not None
        if text not in allowed_ok and not kind and not (result == "fail" and known_failure):
            raise _error("VERIFIER_REPORT", "Verifier emitted an unknown assertion for the pinned source contract")
        if result == "fail":
            has_failure = True
        if text == _ANCHOR_OK:
            if anchor:
                raise _error("VERIFIER_REPORT", "Verifier emitted duplicate anchor assertions")
            anchor = True
    accepted = code == 0
    if accepted == has_failure:
        raise _error("VERIFIER_REPORT", "Verifier checks and overall verdict disagree")
    if accepted and (not set(required).issubset(seen) or set(dynamic) != {"epoch", "replay"} or not anchor):
        raise _error("VERIFIER_ASSERTIONS", "Successful report omitted a required pinned assertion")
    # Early upstream rejections legitimately lack the later checks.  The
    # requirements remain recorded, but only an ok report must satisfy all.
    contract = required + [
        "regex:" + _EPOCH.pattern,
        "regex:" + _REPLAY.pattern,
        "one-of:" + _ANCHOR_OK + "|note:" + _ANCHOR_NOTE,
    ]
    return accepted, report, contract


def validate_recorded_report(report: dict, code: int, contract: list[str]) -> bool:
    """Recheck a receipt's assertion contract without rerunning TPM verification.

    A signed receipt still needs a well-formed, complete recorded contract.
    The policy digest and signer remain externally trusted inputs; this does
    not reconstruct the policy's expected values or authenticate a TPM.
    """
    if type(code) is not int or code not in (0, 1):
        raise _error("INVALID_RECEIPT", "Recorded verifier exit must be integer 0 or 1")
    if (type(contract) is not list or not 1 <= len(contract) <= 64 or
            any(type(item) is not str for item in contract)):
        raise _error("INVALID_RECEIPT", "Invalid recorded assertion contract")
    pcr = "config: config root history matches the quoted PCR"
    nvpcr = "config: config root history matches the certified NvPCR"
    if (pcr in contract) == (nvpcr in contract):
        raise _error("INVALID_RECEIPT", "Recorded contract needs one configuration branch")
    required = list(_BASE_CHECKS)
    required.extend([pcr] if pcr in contract else [*_NVPCR_CHECKS, nvpcr])
    quoted = []
    for item in contract:
        match = re.fullmatch(r"PCR ([0-9]|1[0-9]|2[0-3]) matches the expected value", item)
        if match:
            quoted.append(int(match[1]))
    required.extend(f"PCR {index} matches the expected value" for index in sorted(set(quoted)))
    accepted, _, expected = _report(canonical_json(report), code, required)
    if contract != expected:
        raise _error("INVALID_RECEIPT", "Recorded assertion contract is incomplete or unsupported")
    return accepted


def run_verifier(executable: str, evidence: bytes, policy: dict, nonce: str) -> dict:
    """Verify immutable evidence using an operator-pinned executable snapshot.

    Exit-1 verification failures return ``accepted=False``.  Inability to run
    or establish the pinned interface raises AdapterError and must never be
    upgraded to acceptance.  No target commands or enrollment are performed.
    """
    try:
        # Freeze caller-controlled policy structures before subprocess work.
        policy = validate_policy(strict_json(canonical_json(policy), max_bytes=MAX_POLICY_BYTES))
        verifier = policy["verifier"]
        if verifier["source_commit"] != UPSTREAM_COMMIT:
            raise _error("VERIFIER_SOURCE", "Verifier source commit is not supported by this adapter")
        sha = _hex(verifier["sha256"], 64, "Verifier SHA-256")
        version = _hex(verifier["version_id"], 64, "Verifier version ID")
        timeout = verifier["timeout_seconds"]
        if type(timeout) is not int or not 1 <= timeout <= 30:
            raise _error("VERIFIER_POLICY", "Verifier timeout must be an integer from 1 to 30 seconds")
        if not isinstance(evidence, bytes) or not 0 < len(evidence) <= MAX_EVIDENCE_BYTES:
            raise _error("EVIDENCE_LIMIT", "Evidence must be nonempty bytes within the size bound")
        # This only validates framing.  The caller validates the complete raw
        # evidence contract, and the pinned upstream verifier checks the proof.
        framing = strict_json(evidence, max_bytes=MAX_EVIDENCE_BYTES)
        if not isinstance(framing, dict) or type(framing.get("schema")) is not int or framing["schema"] != 1 or framing.get("kind") != "shirudo-attestation":
            raise _error("EVIDENCE_SCHEMA", "Unsupported raw Shirudo evidence schema or kind")
        synthetic = policy["assurance"] == "SYNTHETIC"
        with ExitStack() as stack:
            executable_fd, actual_sha = _executable_snapshot(stack, executable, sha, synthetic)
            evidence_fd = _new_memfd(stack, "wolfalibi-evidence")
            _write_all(evidence_fd, evidence)
            _seal(evidence_fd)
            args, required = _arguments(policy, nonce, f"/proc/self/fd/{evidence_fd}")
            deadline = time.monotonic() + timeout
            code, out, _ = _bounded_run(executable_fd, ["version", "--version-id"],
                                      (executable_fd,), deadline, stdout_limit=1024)
            if code != 0 or out not in {version.encode("ascii"), version.encode("ascii") + b"\n"}:
                raise _error("VERIFIER_VERSION", "Verifier version ID does not match the operator pin")
            code, out, _ = _bounded_run(executable_fd, args, (executable_fd, evidence_fd), deadline)
            accepted, report, contract = _report(out, code, required)
            return {
                "accepted": accepted, "report": report, "exit_code": code,
                "binary_sha256": actual_sha, "version_id": version,
                "required_checks": contract,
                "execution_profile": "SYNTHETIC" if synthetic else "UPSTREAM_CLI",
            }
    except AdapterError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise _error("VERIFIER_POLICY", "Invalid or incomplete verifier input") from exc
    except (OSError, AttributeError, subprocess.SubprocessError) as exc:
        if isinstance(exc, OSError) and exc.errno == errno.ELOOP:
            raise _error("EXECUTABLE_PATH", "Verifier symlinks are not allowed") from exc
        raise _error("EXECUTION_UNAVAILABLE", "Unable to execute the pinned verifier with sealed snapshots") from exc
