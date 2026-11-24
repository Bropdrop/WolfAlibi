"""Terminal-only owner approval; public JSON events, no automatic action grants.

The READY prompt starts one fresh collection attempt. The final APPROVE prompt
names the concrete verified operation. Input is read from the controlling
terminal, never stdin. Scripted PTY qualification is not human approval.
"""

from __future__ import annotations

import argparse
import os
import select
import stat
import sys
import termios
import time
from pathlib import Path

from .model import AdapterError, canonical_json, read_bounded_file, strict_json
from .owner import (MAX_BUNDLE_BYTES, MAX_INTENT_BYTES, MAX_PROFILE_BYTES,
                    MIN_REMAINING_MS, Owner)


class ApprovalDenied(Exception):
    def __init__(self, reason, message):
        self.reason, self.message = reason, message
        super().__init__(message)


def _seconds(value):
    try:
        seconds = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be an integer number of seconds") from exc
    if not 1 <= seconds <= 900:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 900 seconds")
    return seconds


def _collection_seconds(value):
    seconds = _seconds(value)
    if seconds > 30:
        raise argparse.ArgumentTypeError("fresh bundle timeout cannot exceed 30 seconds")
    return seconds


def _emit(value):
    sys.stdout.buffer.write(canonical_json(value) + b"\n")
    sys.stdout.buffer.flush()


def _read(path, limit):
    return strict_json(read_bounded_file(path, limit), limit)


class Terminal:
    """One bounded canonical line per displayed prompt; discard old typeahead."""

    def __init__(self):
        self.fd = None
        self.saved = None

    def __enter__(self):
        try:
            self.fd = os.open("/dev/tty", os.O_RDWR | os.O_CLOEXEC | os.O_NOCTTY)
            if not os.isatty(self.fd) or os.tcgetpgrp(self.fd) != os.getpgrp():
                raise OSError("No foreground controlling terminal")
            self.saved = termios.tcgetattr(self.fd)
            settings = termios.tcgetattr(self.fd)
            settings[3] |= termios.ICANON | termios.ECHO
            termios.tcsetattr(self.fd, termios.TCSANOW, settings)
            return self
        except (OSError, termios.error) as exc:
            self.__exit__(None, None, None)
            raise AdapterError("TERMINAL_REQUIRED", "Owner approval requires its foreground controlling terminal") from exc

    def __exit__(self, *_):
        if self.fd is not None:
            if self.saved is not None:
                try:
                    termios.tcsetattr(self.fd, termios.TCSANOW, self.saved)
                except (OSError, termios.error):
                    pass
            os.close(self.fd)
            self.fd = None

    def write(self, text):
        data = text.encode("ascii", "strict")
        while data:
            count = os.write(self.fd, data)
            if count <= 0:
                raise ApprovalDenied("TERMINAL_LOST", "The owner terminal closed")
            data = data[count:]

    def line(self, prompt, timeout, *, on_prompt=None):
        if timeout <= 0:
            raise ApprovalDenied("APPROVAL_TIMEOUT", "The approval deadline expired")
        # READY and APPROVE must each follow their own displayed prompt.
        # Prequeued confirmation cannot authorize an unseen fresh operation.
        termios.tcflush(self.fd, termios.TCIFLUSH)
        self.write(prompt)
        if on_prompt is not None:
            on_prompt()
        deadline = time.monotonic() + timeout
        raw = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], remaining)[0]:
                raise ApprovalDenied("APPROVAL_TIMEOUT", "No confirmation arrived before the deadline")
            chunk = os.read(self.fd, 129 - len(raw))
            if not chunk:
                raise ApprovalDenied("APPROVAL_EOF", "No approval was supplied")
            raw.extend(chunk)
            if len(raw) > 128:
                raise ApprovalDenied("APPROVAL_INVALID", "Approval input exceeds its fixed line limit")
            if raw.endswith(b"\n"):
                try:
                    line = bytes(raw[:-1]).decode("ascii", "strict")
                except UnicodeDecodeError as exc:
                    raise ApprovalDenied("APPROVAL_INVALID", "Approval must be the exact displayed ASCII phrase") from exc
                if any(ord(c) < 32 or ord(c) > 126 for c in line):
                    raise ApprovalDenied("APPROVAL_INVALID", "Approval contains unsupported control characters")
                return line


def _new_bundle_path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise AdapterError("BUNDLE_PATH", "The fresh bundle needs an absolute path without parent traversal")
    try:
        path.lstat()
    except FileNotFoundError:
        return path
    except OSError as exc:
        raise AdapterError("BUNDLE_PATH", "Cannot inspect the fresh bundle path") from exc
    raise AdapterError("BUNDLE_EXISTS", "The fresh bundle path must not already exist before READY")


def _wait_bundle(path, timeout):
    deadline = time.monotonic() + min(timeout, 30)
    while True:
        try:
            info = path.lstat()
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise ApprovalDenied("BUNDLE_TIMEOUT", "No fresh public bundle arrived for this attempt")
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            continue
        except OSError as exc:
            raise AdapterError("BUNDLE_PATH", "Cannot inspect the public bundle") from exc
        if not stat.S_ISREG(info.st_mode):
            raise AdapterError("BUNDLE_PATH", "The fresh bundle must be a regular file without symlinks")
        return _read(path, MAX_BUNDLE_BYTES)


def approve(owner, intent, bundle_path, *, ready_timeout=300, bundle_timeout=25):
    # Parse and freeze intent/profile before either terminal prompt. Never
    # reread either submitted file after the owner sees this review.
    review = owner.review(intent)
    intent = review["intent"]
    path = _new_bundle_path(bundle_path)
    with Terminal() as terminal:
        terminal.write("\nWolfAlibi laboratory owner approval\n"
            "Action: increment the protected counter by exactly 1.\n"
            f"Target: {intent['target_id']}\nGate instance: {intent['gate_instance_id']}\n"
            f"Policy generation: {intent['policy_generation']}\nPolicy SHA-256: {intent['policy_sha256']}\n"
            f"Owner public key: {review['owner_public_key']}\n"
            f"Verifier public key: {review['verifier_public_key']}\n"
            f"Target public key: {review['gate_public_key']}\n"
            "Assurance: LAB_VTPM. This review grants no authority.\n"
            "READY starts one fresh evidence attempt; another confirmation is required to sign.\n")
        if terminal.line("Type READY to collect fresh evidence, or anything else to deny: ", ready_timeout) != "READY":
            raise ApprovalDenied("OWNER_DECLINED", "The owner declined to start a fresh attempt")
        # Reject a stale/prepositioned file even if it appeared while the
        # stable review was open. The coordinator writes only after READY.
        _new_bundle_path(path)
        ready = owner.begin_attempt(intent)
        attempt_deadline = time.monotonic() + 30
        _emit(ready)
        bundle = _wait_bundle(path, bundle_timeout)
        reviewed = owner.review_bundle(intent, bundle, ready_at_ms=ready["ready_at_ms"])
        summary = reviewed.summary()
        terminal.write("\nFresh accepted upstream evidence verified against the pinned profile.\n"
            f"Target: {summary['target_id']}\nAction: increment_counter, delta 1\n"
            f"Operation: {summary['operation_id']}\nPolicy SHA-256: {summary['policy_sha256']}\n"
            f"Bundle SHA-256: {summary['bundle_sha256']}\n"
            f"Remaining operation lifetime: {summary['remaining_ms']} milliseconds.\n"
            "Signing creates a one-use grant for this operation; it does not establish an effect.\n")
        prompt = f"Type {summary['approval_phrase']} to sign this one grant, or anything else to deny: "
        timeout = min((summary["remaining_ms"] - MIN_REMAINING_MS) / 1000,
                      attempt_deadline - time.monotonic())
        # Emit only after flushing old typeahead and displaying the concrete
        # prompt. The public event is never a substitute for terminal input.
        answer = terminal.line(prompt, timeout,
            on_prompt=lambda: _emit({"status": "AWAITING_APPROVAL", **summary}))
        if answer != summary["approval_phrase"]:
            raise ApprovalDenied("OWNER_DECLINED", "The owner did not confirm the concrete operation")
        return owner._issue_grant(reviewed, approval_phrase=answer)


def parser():
    root = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("init", "identity", "pin-profile", "review", "approve", "grant", "sign-boot-policy"):
        sub = commands.add_parser(name, allow_abbrev=False)
        sub.add_argument("--state", required=True)
        if name == "pin-profile":
            sub.add_argument("--profile", required=True)
        if name in ("review", "approve"):
            sub.add_argument("--intent", required=True)
        if name == "approve":
            sub.add_argument("--bundle", required=True)
            sub.add_argument("--ready-timeout", type=_seconds, default=300)
            sub.add_argument("--bundle-timeout", type=_collection_seconds, default=25)
        if name == "grant":
            sub.add_argument("--operation-id", required=True)
        if name == "sign-boot-policy":
            sub.add_argument("--anchor", required=True)
            sub.add_argument("--manifest", required=True)
            sub.add_argument("--trust", required=True)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        owner = Owner.initialize(args.state) if args.command == "init" else Owner(args.state)
        if args.command in ("init", "identity"):
            result = {"status": "INITIALIZED" if args.command == "init" else "IDENTITY",
                      "identity": owner.public_identity()}
        elif args.command == "pin-profile":
            result = owner.pin_profile(_read(args.profile, MAX_PROFILE_BYTES))
        elif args.command == "review":
            result = owner.review(_read(args.intent, MAX_INTENT_BYTES))
        elif args.command == "approve":
            result = approve(owner, _read(args.intent, MAX_INTENT_BYTES), args.bundle,
                             ready_timeout=args.ready_timeout, bundle_timeout=args.bundle_timeout)
        elif args.command == "grant":
            result = owner.grant(args.operation_id)
        else:
            from .action_gate import MAX_TRUST_BYTES
            result = owner.sign_boot_policy(_read(args.anchor, 16_384),
                _read(args.trust, MAX_TRUST_BYTES), _read(args.manifest, 16_384))
        _emit(result)
        return 0
    except ApprovalDenied as exc:
        _emit({"status": "DENIED", "reason": exc.reason, "message": exc.message})
        return 1
    except AdapterError as exc:
        _emit({"status": "BLOCKED", "reason": exc.code, "message": exc.message})
        return 2
    except (OSError, termios.error):
        _emit({"status": "BLOCKED", "reason": "OWNER_IO", "message": "Owner input or output became unavailable"})
        return 2
    except KeyboardInterrupt:
        _emit({"status": "DENIED", "reason": "OWNER_CANCELLED", "message": "Owner approval was cancelled"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
