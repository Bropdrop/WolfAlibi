"""Offline demonstration and historical receipt check for Quorvane Gate V1."""

import argparse
import json
import os
from pathlib import Path
import stat
import time
from unittest.mock import patch

from alibi import H, Signer, canon
from .quorvane import ResourceGate
from .quorvane_live import LiveCaller, LiveCallerError
from .quorvane_records import (
    check_grant, check_qualification, check_settlement, grant, issue_qualification, settlement, verify_receipt,
)
from .solitary_cli import _read, _write_new
from .stage3_evidence import _hex


_EDUCATION = {"tutoring": "ALLOWED", "student_records": "DENIED", "process_substitution": "BLOCKED"}
_FINANCE = {
    "balance": "ALLOWED", "payment_with_read_authority": "DENIED", "lost_response": "UNKNOWN",
    "reconciliation": "INITIATED", "duplicate_payment": "DENIED", "settlement": "SETTLED",
}
_PAYMENT = {"payment_id": "synthetic-library-001", "payee": "synthetic-library", "amount_cents": 1200}
_EFFECT_PINS = {"run", "request_sha256", "request_id", "operation", "owner_pub", "identity_sha256", "witness_head"}


def _request(run, operation, request_id, parameters):
    return {
        **{key: run[key] for key in ("run_id", "tenant", "challenge", "policy_epoch")},
        "operation": operation, "request_id": request_id, "parameters": parameters,
    }


def _approve(signer, run, request):
    return grant(signer, run=run, request=request, grant_id=request["request_id"],
                 not_before=int(time.time()), expires_at=run["expires_at"])


def _qualification(gate, caller, qualifier, witness, prior, retained):
    identity = caller.identity()
    record = issue_qualification(qualifier, witness, run=caller.run, identity=identity, previous_head=prior)
    head = H(canon(record))
    retained[caller.run["run_id"]] = head
    if gate.qualify(caller, record)["outcome"] != "QUALIFIED":
        raise ValueError("live fixture did not qualify")
    return record, {"identity_sha256": H(canon(identity)).hex(), "witness_head": head.hex()}


def _expect_effect(run, request, identity, owner):
    return {
        "run": run, "request_sha256": H(canon(request)).hex(), "request_id": request["request_id"],
        "operation": request["operation"], "owner_pub": owner.pub.hex(), **identity,
    }


def _demo(state):
    target, qualifier, witness, owner, payment_owner, settler = (Signer() for _ in range(6))
    prior = H(b"wolfalibi/quorvane/demo-witness-genesis/" + witness.pub)
    retained = {}
    with ResourceGate(
        state / "resource.sqlite", signer=target, qualifier_pub=qualifier.pub, witness_pub=witness.pub,
        owner_pub=owner.pub, payment_owner_pub=payment_owner.pub, settler_pub=settler.pub,
        observe_witness_head=retained.get,
    ) as gate:
        edu = gate.issue_run("education", "school-a", previous_head=prior)
        fin = gate.issue_run("finance", "bank-a", previous_head=prior)
        tutoring = _request(edu, "tutor", "lesson-1", {"topic": "fractions"})
        records = _request(edu, "student_record", "student-1", {"student_id": "synthetic-student"})
        balance = _request(fin, "balance", "balance-1", {})
        payment = _request(fin, "initiate_payment", "payment-1", _PAYMENT)
        with LiveCaller(edu) as student, LiveCaller(fin) as finance:
            edu_proof, edu_identity = _qualification(gate, student, qualifier, witness, prior, retained)
            fin_proof, fin_identity = _qualification(gate, finance, qualifier, witness, prior, retained)
            approvals = {
                "tutoring": _approve(owner, edu, tutoring), "balance": _approve(owner, fin, balance),
                "initiation": _approve(payment_owner, fin, payment),
            }
            expected = {
                "target_pub": target.pub.hex(), "settler_pub": settler.pub.hex(),
                "qualifier_pub": qualifier.pub.hex(), "witness_pub": witness.pub.hex(), "previous_head": prior.hex(),
                "tutoring": _expect_effect(edu, tutoring, edu_identity, owner),
                "balance": _expect_effect(fin, balance, fin_identity, owner),
                "initiation": _expect_effect(fin, payment, fin_identity, payment_owner),
                "payment": _PAYMENT,
            }
            _write_new(state / "expected.json", expected)
            _write_new(state / "live-qualifications.json", {
                "qualifier_pub": qualifier.pub.hex(), "witness_pub": witness.pub.hex(),
                "previous_head": prior.hex(), "education": edu_proof, "finance": fin_proof,
            })
            tutor_grant = approvals["tutoring"]
            with LiveCaller(edu) as substitute:
                refused = gate.perform(substitute, tutoring, grant=tutor_grant)
            taught = gate.perform(student, tutoring, grant=tutor_grant)
            blocked_records = gate.perform(student, records, grant=None)
            inspected = gate.perform(finance, balance, grant=approvals["balance"])
            refused_payment = gate.perform(finance, payment, grant=_approve(owner, fin, payment))
            exchange = finance.exchange

            def lost_reply(message):
                if message.get("type") == "quorvane-resource-result":
                    raise LiveCallerError("synthetic loss of committed payment reply")
                return exchange(message)

            with patch.object(finance, "exchange", side_effect=lost_reply):
                unconfirmed = gate.perform(finance, payment, grant=approvals["initiation"])
            recovered = gate.reconcile(fin["tenant"], _PAYMENT["payment_id"])
            duplicate = _request(fin, "initiate_payment", "payment-duplicate", _PAYMENT)
            repeated = gate.perform(finance, duplicate, grant=_approve(payment_owner, fin, duplicate))
        if recovered["outcome"] != "INITIATED":
            raise ValueError("target did not retain an initiation receipt")
        authority = settlement(settler, tenant=fin["tenant"], payment_id=_PAYMENT["payment_id"],
                               initiation_sha256=H(canon(recovered["receipt"])).hex())
        settled = gate.settle(authority)
        education = {
            "tutoring": taught["outcome"], "student_records": blocked_records["outcome"],
            "process_substitution": refused["outcome"],
        }
        finance_outcomes = {
            "balance": inspected["outcome"], "payment_with_read_authority": refused_payment["outcome"],
            "lost_response": unconfirmed["outcome"], "reconciliation": recovered["outcome"],
            "duplicate_payment": repeated["outcome"], "settlement": settled["outcome"],
        }
        passed = education == _EDUCATION and finance_outcomes == _FINANCE
        result = {
            "outcome": "PASS" if passed else "BLOCKED", "confinement": "BLOCKED",
            "assurance": "RESOURCE_SIDE_EFFECT_GATE", "education": education, "finance": finance_outcomes,
            "report": str(state / "report.json"), "expected": str(state / "expected.json"),
        }
        _write_new(state / "report.json", {
            **result, "network_upload": False, "settlement_authority": authority,
            "owner_grants": approvals, "requests": {"tutoring": tutoring, "balance": balance, "initiation": payment},
            "qualifications": {"education": edu_proof, "finance": fin_proof},
            "effects": {
                "tutoring": taught.get("receipt"), "balance": inspected.get("receipt"),
                "initiation": recovered.get("receipt"), "settlement": settled.get("receipt"),
            },
        })
        return result


def _verify(report, expected):
    if type(expected) is not dict or expected.keys() != {
            "target_pub", "settler_pub", "qualifier_pub", "witness_pub", "previous_head",
            "tutoring", "balance", "initiation", "payment"}:
        raise ValueError("complete independent receipt references required")
    target = _hex(expected["target_pub"], 32, "target key")
    settler = _hex(expected["settler_pub"], 32, "settlement authority key")
    qualifier = _hex(expected["qualifier_pub"], 32, "qualifier key")
    witness = _hex(expected["witness_pub"], 32, "witness key")
    prior = _hex(expected["previous_head"], 32, "previous witness head")
    if len({target, settler, qualifier, witness}) != 4:
        raise ValueError("distinct target, qualifier, witness and settlement keys required")
    effects = report["effects"]
    for label, outcome in (("tutoring", "ALLOWED"), ("balance", "ALLOWED"), ("initiation", "INITIATED")):
        payload = verify_receipt(effects[label], target)
        wanted = expected[label]
        if (type(wanted) is not dict or wanted.keys() != _EFFECT_PINS
                or payload["outcome"] != outcome or any(canon(payload[name]) != canon(value) for name, value in wanted.items())
                or type(payload["checked_at"]) is not int or not 0 <= payload["checked_at"] < payload["run"]["expires_at"]):
            raise ValueError("accepted effect differs from expected run")
        request, approval = report["requests"][label], report["owner_grants"][label]
        owner = _hex(wanted["owner_pub"], 32, "owner key")
        authorized = check_grant(approval, owner_pub=owner, run=wanted["run"], request=request,
                                 now=payload["checked_at"])
        if (H(canon(request)).hex() != wanted["request_sha256"]
                or H(canon(approval)).hex() != payload["grant_sha256"]
                or authorized["grant_id"] != payload["grant_id"]):
            raise ValueError("owner grant does not bind the expected accepted request")
        qualification = report["qualifications"][wanted["run"]["profile"]]
        identity = qualification["qualification"]["payload"]["identity"]
        head = check_qualification(qualification, qualifier_pub=qualifier, witness_pub=witness,
                                   run=wanted["run"], identity=identity, previous_head=prior)
        if H(canon(identity)).hex() != wanted["identity_sha256"] or head != wanted["witness_head"]:
            raise ValueError("qualification or witness head differs from the expected effect")
    initiated = verify_receipt(effects["initiation"], target)
    settled = verify_receipt(effects["settlement"], target)
    authority = check_settlement(report["settlement_authority"], settler_pub=settler)
    digest = H(canon(effects["initiation"])).hex()
    tenant = expected["initiation"]["run"]["tenant"]
    payment = expected["payment"]
    if (initiated["details"] != {**payment, "settlement_status": "PENDING"}
            or settled["outcome"] != "SETTLED" or settled["operation"] != "settle_payment"
            or settled["tenant"] != tenant or settled["settler_pub"] != settler.hex()
            or settled["settlement_authority_sha256"] != H(canon(report["settlement_authority"])).hex()
            or settled["checked_at"] < initiated["checked_at"]
            or settled["details"] != {**payment, "initiation_sha256": digest, "settlement_status": "SETTLED"}
            or authority["tenant"] != tenant or authority["payment_id"] != payment["payment_id"]
            or authority["initiation_sha256"] != digest):
        raise ValueError("settlement does not bind the expected initiation and authority")
    return {"outcome": "VERIFIED", "verification_scope": "HISTORICAL_EFFECT_AND_SETTLEMENT",
            "confinement": "BLOCKED", "assurance": "RESOURCE_SIDE_EFFECT_GATE"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--state-dir", required=True)
    demo.add_argument("--consent", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("--report", required=True)
    verify.add_argument("--expect", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            result = _verify(_read(args.report, 262144), _read(args.expect, 65536))
        elif not args.consent:
            result = {"outcome": "BLOCKED", "reason": "explicit local fixture consent required"}
        else:
            state = Path(args.state_dir).absolute()
            entry = state.lstat()
            if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid()
                    or entry.st_mode & 0o077 or any(state.iterdir())):
                raise ValueError("use a new private state directory")
            result = _demo(state)
    except (LiveCallerError, OSError, ValueError, TypeError, KeyError, RuntimeError):
        result = {"outcome": "BLOCKED", "reason": "local state, live caller or evidence unavailable",
                  "confinement": "BLOCKED"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in {"PASS", "VERIFIED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
