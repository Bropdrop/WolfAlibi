"""Offline verification of an actual fixed Linux run under independently supplied public references."""

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from alibi import Signer
from wolfalibi import byoa002_package as public
from wolfalibi.solitary_preflight import preflight


class PackageInputTests(unittest.TestCase):
    def test_missing_evidence_keeps_settlement_and_authority_unestablished(self):
        checked = public.verify_package(None, None)
        self.assertEqual(checked["outcome"], "BLOCKED")
        self.assertEqual(checked["settlement"], "UNESTABLISHED")
        self.assertEqual(checked["current_authority"], "NOT_ISSUED")
        self.assertEqual(checked["production"], "BLOCKED")

    def test_packaging_detaches_records_and_does_not_issue_a_decision(self):
        fields = {name: {"item": name} for name in ("challenge", "grant", "request", "report", "receipt", "ack")}
        package = public.make_package(**fields)
        fields["challenge"]["item"] = "changed"
        self.assertEqual(package["challenge"], {"item": "challenge"})
        self.assertEqual(set(package), set(fields) | {"schema"})
        self.assertNotIn("outcome", package)


class PortablePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scripts.byoa002_demo import run_fixture

        if preflight()["outcome"] != "READY":
            raise unittest.SkipTest("the physical positive control needs the measured Linux profile")
        cls.revision = {"commit": "32" * 20, "tree": "41" * 20}
        with TemporaryDirectory(prefix="bi2-") as directory:
            output = Path(directory, "public")
            operator = Path(directory, "op")
            run_fixture(output, cls.revision, operator_state=operator)
            cls.package = json.loads((output / "package.json").read_bytes())
            cls.expected = json.loads((output / "expectations.json").read_bytes())
            cls.operator = Signer((operator / "operator.seed").read_bytes())
        # All issuing processes, private storage and services except this disposable
        # test's operator signer are gone before the verification checks start.

    def test_original_verifies_offline_twice_without_dispatch(self):
        with patch("socket.socket", side_effect=AssertionError("network during verification")), \
             patch("subprocess.Popen", side_effect=AssertionError("launch during verification")), \
             patch("sqlite3.connect", side_effect=AssertionError("database during verification")):
            first = public.verify_package(self.package, self.expected)
            second = public.verify_package(self.package, self.expected)
        self.assertEqual((first.get("outcome"), first.get("claim")),
                         ("VERIFIED", "HISTORICAL_MEASURED_TRIAL_AND_RETAINED_TARGET_RECORD"), first.get("reason"))
        self.assertEqual(first, second)
        self.assertEqual(first["observation"]["assurance"], "OBSERVATIONAL_ONLY")
        self.assertEqual(first["target"]["claim"], "HISTORICAL_RETAINED_RELEASE_COMMITMENT")
        self.assertEqual(first["target"]["recipient_delivery"], "NOT_ESTABLISHED")
        self.assertEqual(first["current_authority"], "NOT_ISSUED")
        self.assertEqual(first["settlement"], "UNESTABLISHED")
        self.assertEqual(first["independent_custody"], "UNSUPPORTED")
        self.assertEqual(first["cross_uid_custody"], "UNSUPPORTED")
        self.assertEqual(first["history"]["head"], self.expected["head"])

    def test_package_has_no_source_of_trust_for_itself(self):
        self.assertEqual(public.verify_package(self.package, None)["outcome"], "BLOCKED")
        self.assertNotEqual(public.verify_package(self.package, self.package)["outcome"], "VERIFIED")
        typo = dict(self.package, expected=self.expected)
        self.assertEqual(public.verify_package(typo, self.expected)["outcome"], "REJECTED")

    def test_all_external_role_pins_must_match(self):
        for key in ("operator_pub", "target_pub", "owner_pub", "verifier_pub"):
            with self.subTest(key=key):
                changed = deepcopy(self.expected)
                self.assertIn(key, changed["enrollment"])
                changed["enrollment"][key] = Signer().pub.hex()
                self.assertNotEqual(public.verify_package(self.package, changed)["outcome"], "VERIFIED")

    def test_each_signed_component_is_mandatory(self):
        for key in ("report", "receipt", "ack", "challenge", "grant", "request"):
            with self.subTest(key=key):
                incomplete = {k: v for k, v in self.package.items() if k != key}
                self.assertEqual(public.verify_package(incomplete, self.expected)["outcome"], "BLOCKED")

    def test_added_unsigned_claim_in_any_component_is_refused(self):
        for key in ("report", "receipt", "ack", "challenge", "grant", "request"):
            with self.subTest(key=key):
                changed = deepcopy(self.package)
                changed[key]["present_authority"] = "APPROVED"
                self.assertNotEqual(public.verify_package(changed, self.expected)["outcome"], "VERIFIED")

    def test_signed_event_must_match_externally_retained_history(self):
        for key in ("previous", "head"):
            with self.subTest(key=key):
                wrong = deepcopy(self.expected)
                wrong[key]["digest"] = "bd" * 32
                decision = public.verify_package(self.package, wrong)
                self.assertEqual(decision["outcome"], "REJECTED", decision)
                self.assertIn("supplied prior or final head", decision["reason"])

    def test_external_generation_is_an_exact_integer(self):
        for invalid in (True, 0.0, -1, "0"):
            with self.subTest(value=invalid):
                wrong = deepcopy(self.expected)
                wrong["previous"]["generation"] = invalid
                self.assertEqual(public.verify_package(self.package, wrong)["outcome"], "REJECTED")

    def test_source_revision_is_bound_to_the_enrolled_challenge(self):
        for name in ("commit", "tree"):
            with self.subTest(name=name):
                wrong = deepcopy(self.expected)
                wrong["enrollment"]["revision"][name] = "54" * 20
                self.assertNotEqual(public.verify_package(self.package, wrong)["outcome"], "VERIFIED")

    def test_replacing_measured_trial_fails_even_with_authentic_002_records(self):
        changed = deepcopy(self.package)
        changed["report"]["signature"] = "45" * 64
        self.assertEqual(public.verify_package(changed, self.expected)["outcome"], "REJECTED")

    def test_operator_observations_remain_attributed_statements(self):
        observations = {"tested_revision": self.revision, "synthetic_observation": "reviewer entered value"}
        signed = public.sign_observations(self.package, self.expected, observations, self.operator)
        decision = public.verify_observations(signed, self.package, self.expected, observations)
        self.assertEqual((decision["outcome"], decision["classification"]), ("VERIFIED", "OPERATOR_REPORTED"))
        self.assertEqual(decision["current_authority"], "NOT_ISSUED")
        self.assertEqual(public.verify_observations(signed, self.package, self.expected,
                         dict(observations, synthetic_observation="later value"))["outcome"], "REJECTED")
        with self.assertRaisesRegex(ValueError, "operator key"):
            public.sign_observations(self.package, self.expected, observations, Signer())

    def test_unsigned_observations_cannot_be_inserted_into_the_verified_package(self):
        combined = dict(self.package, reported_qualification="PASS")
        self.assertEqual(public.verify_package(combined, self.expected)["outcome"], "REJECTED")
        with self.assertRaisesRegex(ValueError, "revision"):
            public.sign_observations(self.package, self.expected, {"tested_revision": {}}, self.operator)

    def test_observation_signature_cannot_be_detached_from_its_operator_or_package(self):
        observations = {"tested_revision": self.revision}
        signed = public.sign_observations(self.package, self.expected, observations, self.operator)
        bad = dict(signed, signature="08" * 64)
        self.assertEqual(public.verify_observations(bad, self.package, self.expected, observations)["outcome"],
                         "REJECTED")
        wrong = dict(self.expected, schema="unknown")
        self.assertNotEqual(public.verify_observations(signed, self.package, wrong, observations)["outcome"],
                            "VERIFIED")
