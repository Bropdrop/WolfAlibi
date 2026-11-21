"""Offline controls over one genuinely run synthetic Clearance report."""

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest

from alibi import DurableWitness, H, Signer
from wolfalibi.clearance import ClearanceGateway
from wolfalibi.clearance_records import grant, identity_pins, sign_decision, sign_request
from wolfalibi.clearance_report import REPORT_TYPE, verify_report
from wolfalibi.solitary import run_solitary, solitary_contract
from wolfalibi.solitary_cli import _read, _write_new
from wolfalibi.stage3_worker import UnsupportedWorker


class ClearanceReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = int(time.time())
        try:
            profile = solitary_contract("preflight", bytes(32), cls.now + 120)["profile"]
        except UnsupportedWorker as exc:
            raise unittest.SkipTest(f"UNSUPPORTED static Solitary prerequisite: {exc}") from exc
        temporary = TemporaryDirectory(prefix="wolfalibi-clearance-report-")
        cls.addClassCleanup(temporary.cleanup)
        state = Path(temporary.name)
        db = state / "gateway"
        db.mkdir(mode=0o700)
        cls.gateway, cls.owner, cls.agent, broker, supervisor = (Signer() for _ in range(5))
        cls.secret = b"synthetic private service credential for report control"
        cls.fixture = b"synthetic response whose bytes stay out of the report"

        def upstream(credential):
            if credential != cls.secret:
                raise PermissionError("invalid synthetic credential")
            return cls.fixture

        with DurableWitness(state / "witness.json", Signer()) as witness:
            initial = witness.state_digest
            pins = dict(owner_pub=cls.owner.pub, broker_pub=broker.pub, witness_pub=witness.signer.pub,
                        supervisor_pub=supervisor.pub)
            with ClearanceGateway(
                db, signer=cls.gateway, **pins, expected_witness_state_digest=initial,
                observe_witness_head=lambda: witness.state_digest,
                observe_identity=lambda _: identity_pins(profile),
                upstream=upstream, upstream_credential=cls.secret, clock=lambda: cls.now,
            ) as gateway:
                prepared = gateway.prepare("offline-synthetic-report", agent_pub=cls.agent.pub)
                if prepared["outcome"] != "ISSUED":
                    raise AssertionError(prepared)
                contract = prepared["contract"]
                cls.expected = {
                    **{key: value.hex() for key, value in pins.items()},
                    "gateway_pub": cls.gateway.pub.hex(), "agent_pub": cls.agent.pub.hex(),
                    "contract": contract, "expected_witness_state_digest": initial.hex(),
                }
                cls.expected_path = state / "expected.json"
                _write_new(cls.expected_path, cls.expected)
                trial = run_solitary(
                    state, contract=contract, signer=broker, witness=witness, supervisor=supervisor,
                    expected_witness_state_digest=initial,
                )
                if trial["outcome"] != "COMPLETED":
                    raise AssertionError(trial)
                envelope = trial["envelope"]
                approved = grant(cls.owner, scope=prepared["scope"], not_before=cls.now,
                                 expires_at=cls.now + 90, grant_id="synthetic-owner-grant")
                admitted = gateway.admit(challenge=contract["challenge"], envelope=envelope, grant=approved)
                if admitted["outcome"] != "ADMITTED":
                    raise AssertionError(admitted)
                cls.token = admitted["capability"]
                request = sign_request(cls.agent, capability=cls.token, request_id="synthetic-request")
                operation = gateway.perform(capability=cls.token, request=request)
                if operation["outcome"] != "ALLOWED":
                    raise AssertionError(operation)
                cls.report = {
                    "type": REPORT_TYPE, "outcome": operation["outcome"],
                    "prepare": prepared["decision"], "qualification": envelope, "grant": approved,
                    "admission": admitted["decision"], "request": request, "operation": operation["decision"],
                }
        cls.report_path = state / "report.json"
        _write_new(cls.report_path, cls.report)

    def test_export_verifies_after_gateway_closure_and_omits_secrets(self):
        actual = verify_report(_read(self.report_path, 512_000), _read(self.expected_path, 64_000))
        self.assertEqual(actual["outcome"], "VERIFIED", actual)
        self.assertIs(actual["historical"], True)
        self.assertEqual(actual["effect"], "OBSERVED")
        self.assertEqual(actual["effect_source"], "GATEWAY_SIGNATURE")
        self.assertEqual(actual["response_sha256"], H(self.fixture).hex())
        self.assertEqual(actual["broker_assurance"], "BROKER_ONLY")
        self.assertEqual(actual["confinement"], "BLOCKED")
        self.assertEqual(actual["production"], "BLOCKED")
        exported = self.report_path.read_bytes() + self.expected_path.read_bytes()
        for value in (self.secret, self.fixture, self.token.encode()):
            self.assertNotIn(value, exported)
            self.assertNotIn(value.hex().encode(), exported)

    def test_key_and_witness_anchor_substitution_are_rejected(self):
        replacement = Signer().pub.hex()
        for key in ("agent_pub", "gateway_pub", "owner_pub", "broker_pub", "witness_pub",
                    "supervisor_pub", "expected_witness_state_digest"):
            with self.subTest(key=key):
                result = verify_report(self.report, dict(self.expected, **{key: replacement}))
                self.assertEqual(result["outcome"], "REJECTED", result)

    def test_missing_witness_and_operation_cannot_verify(self):
        expected = dict(self.expected)
        del expected["expected_witness_state_digest"]
        self.assertEqual(verify_report(self.report, expected)["outcome"], "BLOCKED")
        report = dict(self.report)
        del report["operation"]
        self.assertEqual(verify_report(report, self.expected)["outcome"], "BLOCKED")

        missing_witness = deepcopy(self.report)
        del missing_witness["qualification"]["evidence"]["witness_state_chain"]
        self.assertEqual(verify_report(missing_witness, self.expected)["outcome"], "REJECTED")

    def test_signed_operation_at_capability_expiry_is_rejected(self):
        deadline = self.report["admission"]["payload"]["expires_at"]
        self.assertLess(deadline, self.report["grant"]["payload"]["expires_at"])
        self.assertLess(deadline, self.expected["contract"]["expires_at"])
        changed = dict(self.report["operation"]["payload"], checked_at=deadline)
        report = dict(self.report, operation=sign_decision(self.gateway, changed))
        self.assertEqual(verify_report(report, self.expected)["outcome"], "REJECTED")

    def test_signed_alternative_grant_or_scope_is_rejected(self):
        owner = self.report["grant"]["payload"]
        for scope, grant_id in (
            (owner["scope"], "another-synthetic-grant"),
            (dict(owner["scope"], worker_sha256="ab" * 32), owner["grant_id"]),
        ):
            with self.subTest(scope_changed=(scope != owner["scope"])):
                replacement = grant(self.owner, scope=scope, grant_id=grant_id,
                                    not_before=owner["not_before"], expires_at=owner["expires_at"])
                result = verify_report(dict(self.report, grant=replacement), self.expected)
                self.assertEqual(result["outcome"], "REJECTED", result)


if __name__ == "__main__":
    unittest.main()
