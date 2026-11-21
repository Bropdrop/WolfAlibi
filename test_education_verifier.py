"""Check the historical admission verifier against independently retained expectations."""

import copy
import unittest
from unittest.mock import patch

from alibi import Signer
from wolfalibi.education_records import digest, dispatch, owner_grant, qualify, receipt
from wolfalibi.education_verify import verify_admission


class HistoricalAdmissionTests(unittest.TestCase):
    def setUp(self):
        owner, supervisor, witness, target, caller = (Signer() for _ in range(5))
        scope = dict(tenant="fictional-school", student="fictional-aster", purpose="approved-support",
                     operation="edu.student_record.read", target_pub=target.pub.hex(),
                     policy_version="edu-gate-002.v1", run_id="offline-verifier-run",
                     challenge="31" * 32, caller_pub=caller.pub.hex(), request_id="read-one")
        peer = dict(pid=35, uid=1000, gid=1000, start_ticks=702,
                    boot_id="e71b9418-275a-4617-9364-e12b208ddd43", exe_sha256="51" * 32,
                    argv_sha256="52" * 32, source_sha256="53" * 32)
        qualification = qualify(supervisor, witness, scope, peer, 1000, 1020)
        grant = owner_grant(owner, scope, "school-grant", 1000, 1060)
        packet = dispatch(caller, scope, grant, qualification)
        response = {"student_ref": "fictional-aster", "support_level": "scheduled-check-in"}
        self.expected = dict(scope=scope, target_pub=target.pub.hex(), owner_pub=owner.pub.hex(),
                             supervisor_pub=supervisor.pub.hex(), witness_pub=witness.pub.hex(),
                             witness_head=digest(qualification), peer=peer, response_sha256=digest(response))
        self.evidence = dict(packet=packet, receipt=receipt(target, scope, packet, response, 1019),
                             response=response)
        self.owner, self.supervisor, self.witness = owner, supervisor, witness
        self.target, self.caller = target, caller

    def test_valid_historical_admission_requires_external_pins(self):
        verdict = verify_admission(self.expected, self.evidence)
        self.assertEqual(verdict["verified"], "HISTORICAL_SYNTHETIC_ADMISSION")
        self.assertEqual(verdict["authorized_at"], 1019)
        self.assertEqual(verdict["cross_uid_custody"], "UNSUPPORTED")
        self.assertEqual(verdict["certification"], "NOT_ISSUED")

    def test_changing_any_external_expectation_invalidates_the_bundle(self):
        for field in ("target_pub", "owner_pub", "supervisor_pub", "witness_pub",
                      "witness_head", "response_sha256", "scope", "peer"):
            changed = copy.deepcopy(self.expected)
            if field == "scope":
                changed["scope"]["run_id"] = "other-run"
            elif field == "peer":
                changed["peer"]["pid"] += 1
            else:
                changed[field] = "00" * 32
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_admission(changed, self.evidence)

    def test_signed_qualification_binds_expected_source_and_arguments(self):
        for field in ("source_sha256", "argv_sha256"):
            changed = copy.deepcopy(self.expected)
            changed["peer"][field] = "00" * 32
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "measured peer"):
                verify_admission(changed, self.evidence)

    def test_authentic_target_receipt_cannot_replace_independent_owner_check(self):
        scope = self.expected["scope"]
        counterfeit = owner_grant(Signer(), scope, "school-grant", 1000, 1060)
        packet = dispatch(self.caller, scope, counterfeit, self.evidence["packet"]["qualification"])
        response = self.evidence["response"]
        improperly_issued = receipt(self.target, scope, packet, response, 1019)
        with self.assertRaises(ValueError):
            verify_admission(self.expected, dict(response=response, packet=packet, receipt=improperly_issued))

    def test_authentic_signatures_cannot_extend_the_fixed_fixture_to_another_tenant(self):
        tenant = "fictional-other-school"
        scope = dict(self.expected["scope"], tenant=tenant)
        grant = owner_grant(self.owner, scope, "school-grant", 1000, 1060)
        qualification = qualify(self.supervisor, self.witness, scope, self.expected["peer"], 1000, 1020)
        packet = dispatch(self.caller, scope, grant, qualification)
        response = self.evidence["response"]
        expectations = dict(self.expected, scope=scope, witness_head=digest(qualification))
        with patch("wolfalibi.education_records._SYNTHETIC_TENANT", tenant, create=True):
            signed = receipt(self.target, scope, packet, response, 1019)
            evidence = dict(packet=packet, response=response, receipt=signed)
            self.assertEqual(verify_admission(expectations, evidence)["outcome"], "VERIFIED")
        with self.assertRaisesRegex(ValueError, "fixed synthetic Education fixture"):
            verify_admission(expectations, evidence)
