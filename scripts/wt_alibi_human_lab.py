#!/usr/bin/env python3
"""Stage or qualify the human handoff and operate the disposable counter lab."""

from __future__ import annotations

import argparse
import copy
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.shirudo_prototype_host import USERS, command
from scripts.shirudo_prototype_lab import PrototypeLab
from scripts.shirudo_real_lab import (
    LabFailure, bounded_command, require,
)
from scripts.wt_alibi_human_handoff import (
    HandoffError, PIN_SCHEMA, absolute_path, coordinate, strict_read,
)
from scripts.wt_alibi_human_transport import LabGuest, LabCollection
from scripts.wt_alibi_human_verify import AUDIT_PINS_SCHEMA
from shirudo_adapter.action_gate import ACTION, MAX_ACTION_REQUEST_BYTES
from shirudo_adapter.model import (
    AdapterError, MAX_RECORD_BYTES, canonical_json, digest, exact_keys, require_hex, strict_json,
)
from shirudo_adapter.owner import MAX_PROFILE_BYTES
from shirudo_adapter.receipt import verify_receipt

def make_intent(profile):
    return {"schema": "wolfalibi.shirudo.owner-intent.v1", "request_id": secrets.token_hex(16),
            "target_id": profile["target_id"], "gate_instance_id": profile["gate_instance_id"],
            "policy_sha256": digest(profile["policy"]), "policy_generation": profile["policy_generation"],
            "action": dict(ACTION)}


def make_pins(intent, profile, owner_identity, owner_uid):
    return {"schema": PIN_SCHEMA, "owner_instance_id": owner_identity["owner_instance_id"],
            "owner_uid": owner_uid, "profile_sha256": digest(profile), "intent_sha256": digest(intent),
            "request_id": intent["request_id"]}


class HandoffLab(PrototypeLab):
    """Genuine VM recipe with explicitly scripted terminal input for tests."""

    retain_scripted_transcript = False

    def __init__(self, upstream, vm_name, verifier, output, *, build, authorities):
        super().__init__(upstream, vm_name, verifier, output, build=build, authorities=authorities)
        self.lab_guest = LabGuest(upstream, vm_name)
        self.collection = LabCollection(self.lab_guest, self.roles)
        self.materials = {}
        self.audit_count = 0
        self.approved_profile = None
        self.approved_owner = None

    def setup(self):
        super().setup()
        self.approved_profile = strict_read(self.roles.exchange / "owner-profile.json", MAX_PROFILE_BYTES)
        self.approved_owner = strict_read(self.authorities / "owner-identity.json", 4096)
        require(self.approved_owner.get("public_key") == self.approved_profile["owner_public_key"],
                "OWNER_PIN", "provisioned owner identity")
        self.approved_owner_uid = self.roles.identity()["owner"]["uid"]

    def pins(self, intent):
        return make_pins(intent, self.approved_profile, self.approved_owner, self.approved_owner_uid)

    def stage_human(self):
        self.setup()
        intent = make_intent(self.approved_profile)
        pins = self.pins(intent)
        before = self.lab_guest.observe()
        self.roles.public("human-intent.json", intent)
        self.roles.public("human-pins.json", pins)
        self.roles.public("human-before.json", before)
        events = self.roles.exchange / "owner-events"
        command(["sudo", "-n", "install", "-d", "-m", "2750", "-o", USERS["owner"],
                 "-g", str(os.getegid()), str(events)])
        self.artifacts.json("human-before.json", before)
        return {"status": "STAGED", "request_id": intent["request_id"],
                "pins_sha256": digest(pins), "before_sha256": digest(before),
                "actual_human_approval": "NOT_RUN", "target_effect": "NOT_RUN"}

    def ceremony(self, name, behavior="approve"):
        before = self.lab_guest.observe()
        result = super().ceremony(name, behavior)
        if result is not None:
            operation = result["request"]["operation_id"]
            self.materials[operation] = (name, before, 0)
        else:
            after = self.lab_guest.observe()
            require(before["ledger"] == after["ledger"] and before["counter"] == after["counter"],
                    "ORACLE_DELTA", name)
            self.artifacts.json(f"materials/{name}/oracle-before.json", before)
            self.artifacts.json(f"materials/{name}/oracle-after.json", after)
        return result

    def owner_bundle(self, name, intent, ready, bundle_name, behavior):
        pins = self.pins(intent)
        prefix = f"materials/{name}"
        self.artifacts.json(f"{prefix}/pins.json", pins)
        watched = self.roles.exchange / bundle_name
        prepared = watched if behavior != "tamper" else watched.with_suffix(".control.json")
        result = coordinate(pins, intent, self.approved_profile, ready, prepared, self.collection,
                            lambda filename, data: self.artifacts.write(f"{prefix}/{filename}", data))
        require(result["status"] == "BUNDLE_PUBLISHED", "HANDOFF_PUBLICATION", name)
        bundle = strict_read(prepared)
        submitted = copy.deepcopy(bundle)
        if behavior == "tamper":
            submitted["assessment"]["signature"] = "0" * 128
            self.roles.public(bundle_name, submitted)
        verification = verify_receipt(
            bundle["assessment"], self.approved_profile["verifier_public_key"],
            expected_target=intent["target_id"], expected_policy_sha256=intent["policy_sha256"],
            expected_challenge_id=bundle["attestation_challenge"]["payload"]["challenge_id"])
        self.artifacts.json(f"{prefix}/assessment-verification.json", verification)
        self.fresh_assessments += 1
        self.positive_accepted = True
        return bundle, submitted

    def rpc(self, document, *, drop=False):
        response = super().rpc(document, drop=drop)
        if not drop or response != {"status": "AMBIGUOUS", "code": "SCRIPTED_REPLY_NOT_READ"}:
            return response
        operation = document["request"]["operation_id"]
        deadline = time.monotonic() + 4
        while True:
            observed = self.lab_guest.observe()
            if any(row["operation_id"] == operation for row in observed["ledger"]):
                break
            require(time.monotonic() < deadline, "COMMIT_UNOBSERVED", "lost reply before gate restart")
            time.sleep(0.05)
        unit = self.current_unit
        require(unit == "wolfproto-gate.service", "GATE_UNIT", "owned gate restart")
        self.guest(["systemctl", "kill", "--signal=SIGKILL", unit], "interrupt committed gate process")
        deadline = time.monotonic() + 4
        while True:
            status = self.guest(["systemctl", "show", unit, "--property=MainPID",
                                 "--property=ExecMainStatus"], "observe gate process exit")
            if {b"MainPID=0", b"ExecMainStatus=9"}.issubset(status.splitlines()):
                break
            require(time.monotonic() < deadline, "GATE_EXIT", "SIGKILL did not terminate owned gate")
            time.sleep(0.05)
        self.current_unit = "wolfproto-gate-recovered.service"
        self.guest(self.unit_arguments("serve", name=self.current_unit, wait=False), "restart owned gate")
        self.artifacts.json("measurement/lost-reply-gate-restart.json", {
            "operation_id": operation, "signal": "SIGKILL", "previous_main_pid": 0,
            "committed_before_restart": observed, "actual_human_approval": "NOT_RUN",
        })
        return response

    def effect(self, document, material, expected):
        result = super().effect(document, material, expected)
        operation = result["operation_id"]
        name, before, sequence = self.materials[operation]
        self.materials[operation] = (name, before, sequence + 1)
        prefix = f"materials/{name}"
        after = self.lab_guest.observe()
        owner_review = next(event for event in material["ceremony"]["events"]
                            if event["status"] == "AWAITING_APPROVAL")
        owner_ready = material["ceremony"]["ready"]
        review_pins = {"schema": AUDIT_PINS_SCHEMA, "request_id": owner_ready["request_id"],
                       "operation_id": owner_review["operation_id"],
                       "bundle_sha256": owner_review["bundle_sha256"],
                       "ready_sha256": digest(owner_ready),
                       "before_sha256": digest(before), "after_sha256": digest(after)}
        case = f"{prefix}/audit-{sequence + 1}"
        paths = {"pins": self.artifacts.path / f"{prefix}/pins.json",
                 "intent": self.artifacts.path / f"{prefix}/intent.json",
                 "profile": self.artifacts.path / "owner-profile.json",
                 "ready": self.artifacts.path / f"{prefix}/ready.json",
                 "bundle": self.artifacts.path / f"{prefix}/bundle.json",
                 "evidence": self.artifacts.path / f"{prefix}/evidence.json",
                 "request": self.artifacts.path / f"{prefix}/request.json",
                 "audit-pins": self.artifacts.json(f"{case}/pins.json", review_pins),
                 "before": self.artifacts.json(f"{case}/before.json", before),
                 "after": self.artifacts.json(f"{case}/after.json", after),
                 "receipt": self.artifacts.json(f"{case}/receipt.json", document["receipt"])}
        argv = [sys.executable, "-I", "-B", str(ROOT / "scripts/wt_alibi_human_verify.py")]
        for label, path in paths.items():
            argv.extend(("--" + label, str(path)))
        # The trusted harness retains these independently of the material
        # under review. The verifier's CLI has no state or execution arguments.
        argv.extend(("--pins-sha256", digest(self.pins(strict_read(paths["intent"]))),
                     "--audit-pins-sha256", digest(review_pins)))
        code, raw, _ = bounded_command(argv, ROOT, timeout=8)
        review = strict_json(raw, MAX_RECORD_BYTES)
        self.artifacts.json(f"{case}/result.json", review)
        require(code == 0 and review.get("status") == "HISTORICAL_EFFECT_VERIFIED"
                and review["operation_id"] == operation and review["counter_after"] == expected,
                "INDEPENDENT_EFFECT_REVIEW", name)
        self.audit_count += 1
        return {**result, "independent_review": review}

    def finish(self, result, *, code=None, stage=None):
        if result == "PASS":
            require(self.audit_count == 4, "INDEPENDENT_REVIEW_COUNT", "completed effect and retry cases")
        self.artifacts.json("handoff-review.json", {
            "result": result, "independent_effect_reviews": self.audit_count,
            "approval_driver": "SCRIPTED_PTY", "actual_human_approval": "NOT_RUN",
        })
        return super().finish(result, code=code, stage=stage)


def run_lab(args):
    lab = HandoffLab(args.upstream, args.vm_name, args.verifier, args.output,
                     build=args.build, authorities=args.authorities)
    if args.command == "stage":
        try:
            return lab.stage_human(), 0
        except BaseException:
            if lab.current_unit is not None:
                lab.guest(["systemctl", "stop", lab.current_unit], "stop incomplete manual stage")
            raise
    try:
        return lab.run(), 0
    except (AdapterError, LabFailure, OSError) as exc:
        reason = exc.code if isinstance(exc, (AdapterError, LabFailure)) else "LOCAL_IO"
        summary = lab.finish("BLOCKED" if not isinstance(exc, LabFailure) else exc.result,
                             code=reason, stage=getattr(exc, "stage", "handoff"))
        return summary, getattr(exc, "exit_code", 2)


def operate(args):
    if args.command in {"stage", "test"}:
        return run_lab(args)
    guest = LabGuest(args.upstream, args.vm_name)
    if args.command == "observe":
        return guest.observe(), 0
    operation_id = require_hex(args.operation_id, 32, "original operation ID")
    if args.command == "status":
        document = {"op": "status", "operation_id": operation_id}
    else:
        request = strict_read(absolute_path(args.request), MAX_ACTION_REQUEST_BYTES)
        exact_keys(request, {"operation_id", "grant", "assessment"}, "frozen execution request")
        require_hex(args.request_sha256, 64, "original request digest")
        if request["operation_id"] != operation_id or digest(request) != args.request_sha256:
            raise HandoffError("REQUEST_CHANGED", "Execution must use the frozen exact request and operation ID")
        document = {"op": "execute", "request": request}
    response = guest.client(document)
    return response, 2 if response.get("status") == "AMBIGUOUS" else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("stage", "test", "observe", "submit", "status"):
        sub = subparsers.add_parser(name, allow_abbrev=False)
        sub.add_argument("--upstream", required=True, type=Path)
        sub.add_argument("--vm-name", required=True)
        if name in ("stage", "test"):
            for field in ("verifier", "build", "authorities"):
                sub.add_argument("--" + field, required=True, type=Path)
            sub.add_argument("--output", required=True, type=Path)
        if name in ("submit", "status"):
            sub.add_argument("--operation-id", required=True)
        if name == "submit":
            sub.add_argument("--request", required=True, type=Path)
            sub.add_argument("--request-sha256", required=True)
    try:
        result, code = operate(parser.parse_args(argv))
    except (AdapterError, LabFailure, OSError) as exc:
        code = getattr(exc, "exit_code", 2)
        result = {"status": "BLOCKED", "reason": getattr(exc, "code", "LOCAL_IO"),
                  "actual_human_approval": "NOT_RUN"}
    print(canonical_json(result).decode("ascii"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
