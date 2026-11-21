"""Record and reconcile one fictional finance intent over local Linux transport."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory

from alibi import Signer, canon
from examples.quorvane_education_demo import (
    FixtureError, LocalFixture, _ROOT, _denial, fixture as managed_fixture, write_new,
)
from wolfalibi import finance_records, finance_transport
from wolfalibi.finance_records import ACCOUNT, CURRENCY, OPERATION, PENDING, TENANT


class FinanceFixture(LocalFixture):
    """Reuse the measured process setup with a finance run-scoped target."""

    caller_source = _ROOT / "wolfalibi" / "finance_fixture_caller.py"
    records = finance_records
    transport = finance_transport
    target_module = "wolfalibi.finance_target"
    target_class = "FinanceTarget"
    action = "initiate"
    grant_id = "fictional-payment-grant"
    scope_fields = {
        "tenant": TENANT, "account": ACCOUNT, "currency": CURRENCY, "operation": OPERATION,
        "payee": "fictional-supplier", "amount_minor": 4500, "policy_epoch": 1,
    }

    def target_scope(self):
        return self.records.run_scope(self.scope)

    def verify(self, packet, receipt):
        return self.records.verify_receipt(
            receipt, target_pub=bytes.fromhex(self.expectations["target_pub"]), scope=self.scope, packet=packet,
        )


def fixture(root, *, challenge=None):
    return managed_fixture(root, challenge=challenge, fixture_type=FinanceFixture)


def _retained_dispatch(resource):
    packet_path = resource.control / "dispatch.json"
    write_new(packet_path, canon(resource.invoke("sign")["packet"]) + b"\n")
    return packet_path


def demo(root, *, expectations_out=None, challenge=None):
    with fixture(root, challenge=challenge) as resource:
        if expectations_out is not None:
            write_new(expectations_out, canon(resource.expectations) + b"\n")
        packet_path = _retained_dispatch(resource)
        retained = json.loads(packet_path.read_bytes())
        auth_reason = "AUTHORIZATION_OR_QUALIFICATION_UNVERIFIED"
        malformed = "INVALID_TARGET_REQUEST"
        observed = {
            "wrong_peer": _denial(resource.direct(retained), "PEER_IDENTITY_MISMATCH"),
            "unsigned": _denial(resource.invoke("unsigned")["result"], malformed),
            "fake_settlement": _denial(resource.invoke("fake-settlement")["result"], malformed),
            "missing_owner_grant": _denial(resource.invoke("no-owner")["result"], auth_reason),
            "wrong_owner": _denial(
                resource.invoke(grant=resource.make_grant(signer=Signer()))["result"], auth_reason,
            ),
        }
        checkpoint = resource.retained_anchor()
        observed["lost_reply"] = resource.invoke("lost-reply", packet=retained)["result"]
        if observed["lost_reply"] != {"outcome": "UNKNOWN", "response_read": False}:
            raise FixtureError("the finance fixture did not complete its send-and-close control")
        resource.wait_for_checkpoint_change(checkpoint)
        observed["checkpoint_advanced_before_restart"] = resource.retained_anchor() != checkpoint
        resource.restart_target()
        retained = json.loads(packet_path.read_bytes())
        reconciliation = resource.invoke("reconcile", packet=retained)["result"]
        if set(reconciliation) != {"outcome", "receipt"} or reconciliation["outcome"] != "RECONCILED":
            raise FixtureError("the retained finance dispatch did not reconcile")
        receipt = reconciliation["receipt"]
        observed["restart_reconciliation"] = reconciliation["outcome"]
        observed["receipt_outcome"] = resource.verify(retained, receipt)["outcome"]
        if resource.invoke("reconcile", packet=retained)["result"] != reconciliation:
            raise FixtureError("the original finance receipt changed during reconciliation")
        observed["second_reconciliation"] = "SAME_RECEIPT"
        resource.stop_target()
        observed["intent_count"] = resource.offline_status()["intent_count"]
        expected = {
            "wrong_peer": {"outcome": "DENIED", "reason": "PEER_IDENTITY_MISMATCH"},
            "unsigned": {"outcome": "DENIED", "reason": malformed},
            "fake_settlement": {"outcome": "DENIED", "reason": malformed},
            "missing_owner_grant": {"outcome": "DENIED", "reason": auth_reason},
            "wrong_owner": {"outcome": "DENIED", "reason": auth_reason},
            "lost_reply": {"outcome": "UNKNOWN", "response_read": False},
            "checkpoint_advanced_before_restart": True,
            "restart_reconciliation": "RECONCILED", "receipt_outcome": PENDING,
            "second_reconciliation": "SAME_RECEIPT", "intent_count": 1,
        }
        if observed != expected:
            raise FixtureError("finance fixture controls did not match")
        return {
            "schema": "QUORVANE_FINANCE_DEMO_V1", "outcome": "PASS",
            "assurance": "SIMULATED_POLICY_ONLY", "cross_uid_custody": "UNSUPPORTED",
            "certification": "NOT_ISSUED", "confinement": "BLOCKED", "production": "BLOCKED",
            "caller_preflight": resource.caller_preflight, "expected": expected, "observed": observed,
            "evidence": {"packet": retained, "receipt": receipt},
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations-out", type=Path,
                        help="create-only file for separately retained pre-dispatch public pins")
    parser.add_argument("--challenge", help="optional controller-pinned 32-byte lowercase hex challenge")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or not hasattr(socket, "SCM_CREDENTIALS") or not hasattr(os, "pidfd_open"):
        result = {"outcome": "UNSUPPORTED", "reason": "LINUX_PEER_AND_PIDFD_REQUIRED"}
    else:
        try:
            with TemporaryDirectory(prefix="wolfalibi-finance-") as root:
                result = demo(root, expectations_out=args.expectations_out, challenge=args.challenge)
        except (KeyError, ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
            result = {
                "outcome": "BLOCKED", "reason": "LOCAL_FINANCE_FIXTURE_UNAVAILABLE",
                "diagnostic": str(error) if isinstance(error, FixtureError) else type(error).__name__,
            }
    print(canon(result).decode("ascii"))
    return 0 if result["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
