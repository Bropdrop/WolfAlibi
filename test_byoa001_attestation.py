"""Historical report verification against separate, pre-launch public references."""

from copy import deepcopy
from pathlib import Path
import tempfile
import time
import unittest

from alibi import DurableWitness, Signer, canon
from wolfalibi import byoa_attestation as attestation
from wolfalibi.byoa_bundle import load_bundle
from wolfalibi.byoa_cell import cell_contract, run_cell
from wolfalibi.byoa_effect_gate import (
    ReadGate, enroll_read_authorities, initialize_read_target, issue_read_grant,
)
from wolfalibi.solitary_preflight import preflight


class HistoricalTrialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ready = preflight()
        if ready["outcome"] != "READY":
            raise unittest.SkipTest(f"BYOA Linux cell {ready['outcome']}: {ready['reason']}")
        cls.supervisor, broker, witness_key, owner, target = (Signer() for _ in range(5))
        root = Path(__file__).resolve().parent
        bundle = load_bundle(root / "examples/qualification001/agent.json")
        reference = int(time.time())
        with tempfile.TemporaryDirectory(prefix="byoa-check-") as work:
            run = Path(work) / "trial"
            run.mkdir(mode=0o700)
            target_dir = Path(work) / "target"
            target_dir.mkdir(mode=0o700)
            initialize_read_target(target_dir, target)
            with DurableWitness(Path(work) / "witness.json", witness_key) as witness:
                contract = cell_contract(bundle, "offline-review-001", bytes(range(32)), reference + 120)
                cls.pins = attestation.make_expectations(
                    contract, broker_pub=broker.pub, witness_pub=witness_key.pub,
                    supervisor_pub=cls.supervisor.pub, owner_pub=owner.pub, target_pub=target.pub,
                    expected_witness_state_digest=witness.state_digest, now=reference)
                enroll_read_authorities(target_dir, owner_pub=cls.pins["owner_pub"], broker_pub=cls.pins["broker_pub"],
                                        supervisor_pub=cls.pins["supervisor_pub"], witness_pub=cls.pins["witness_pub"],
                                        target_signer=target)
                grant = issue_read_grant(cls.pins, owner)
                with ReadGate(target_dir, cls.pins, grant, target, witness_state=witness.state_anchor) as gate:
                    trial = run_cell(run, bundle=bundle, contract=contract, signer=broker,
                                     witness=witness, supervisor=cls.supervisor,
                                     expected_witness_state_digest=witness.state_digest, read_gate=gate, consent=True)
                    if trial["outcome"] != "COMPLETED":
                        raise AssertionError(trial)
                    cls.signed = attestation.sign_trial(
                        cls.pins, trial["envelope"], trial["observation"], cls.supervisor,
                        grant=grant, admission=gate.decision)

    def _resign(self, record):
        record["signature"] = self.supervisor.sign(attestation._DOMAIN, canon(record["payload"])).hex()
        return record

    def test_repeatable_historical_claim_has_separate_axes_and_no_current_authority(self):
        first = attestation.verify_trial(self.signed, self.pins)
        self.assertEqual(first, attestation.verify_trial(self.signed, self.pins))
        self.assertEqual(first["outcome"], "VERIFIED", first)
        self.assertEqual(first["observation"]["assurance"], "OBSERVATIONAL_ONLY")
        self.assertTrue(all(first["execution"]["closure"].values()))
        self.assertEqual(first["authorization"]["read"]["outcome"], "VERIFIED_HISTORICAL_READ_ADMISSION")
        self.assertEqual(first["authorization"]["present_authority"], "NOT_ISSUED")
        self.assertEqual(first["effect"]["broker_read"]["actor"], "TRUSTED_CELL_BOOTSTRAP")
        self.assertEqual(first["effect"]["financial"]["settlement"], "UNESTABLISHED")
        self.assertEqual(first["assurance"]["cross_uid_custody"], "UNSUPPORTED")

    def test_issuer_substitution_and_role_reuse(self):
        for name in ("broker_pub", "witness_pub", "supervisor_pub", "owner_pub", "target_pub"):
            with self.subTest(role=name):
                wrong = dict(self.pins, **{name: Signer().pub.hex()})
                self.assertEqual(attestation.verify_trial(self.signed, wrong)["outcome"], "REJECTED")
        reused = dict(self.pins, target_pub=self.pins["owner_pub"])
        self.assertEqual(attestation.verify_trial(self.signed, reused)["outcome"], "BLOCKED")

    def test_changed_manifest_run_challenge_or_witness_head_fails(self):
        changes = (
            (("contract", "run_id"), "other-authorized-run"),
            (("contract", "challenge"), "ac" * 32),
            (("contract", "profile", "byoa", "manifest_sha256"), "ff" * 32),
            (("expected_witness_state_digest",), "ac" * 32),
        )
        for path, value in changes:
            with self.subTest(path=path):
                pins = deepcopy(self.pins)
                dest = pins
                for field in path[:-1]:
                    dest = dest[field]
                dest[path[-1]] = value
                self.assertEqual(attestation.verify_trial(self.signed, pins)["outcome"], "REJECTED")

    def test_outer_signature_cannot_repudiate_the_measured_native_profile_or_witness_head(self):
        # Even if the trial supervisor endorses an outer envelope for a different
        # public reference, the inner broker and witness transcript must agree.
        for changes in ("head", "runtime"):
            record = deepcopy(self.signed)
            pins = deepcopy(self.pins)
            if changes == "head":
                pins["expected_witness_state_digest"] = "ca" * 32
            else:
                pins["contract"]["profile"]["python_sha256"] = "ca" * 32
            record["payload"]["expectations_sha256"] = attestation.H(canon(pins)).hex()
            with self.subTest(changes=changes):
                self.assertEqual(attestation.verify_trial(self._resign(record), pins)["outcome"], "REJECTED")

    def test_unapproved_callback_fields_are_refused_even_if_signed(self):
        record = deepcopy(self.signed)
        record["payload"]["observation"]["summary"]["coverage"] = "ALL_PROCESS_ACTIVITY"
        self.assertEqual(attestation.verify_trial(self._resign(record), self.pins)["outcome"], "REJECTED")

    def test_unsigned_replacement_of_aggregate_fails(self):
        record = deepcopy(self.signed)
        record["payload"]["observation"]["summary"]["run_id"] = "ab" * 16
        rejected = attestation.verify_trial(record, self.pins)
        self.assertEqual(rejected["reason"], "invalid trial supervisor signature")

    def test_incomplete_record_or_claim_inflation_is_refused_even_with_supervisor_endorsement(self):
        for removed in ("execution", "observation", "authorization", "effect"):
            with self.subTest(removed=removed):
                record = deepcopy(self.signed)
                del record["payload"][removed]
                self.assertEqual(attestation.verify_trial(self._resign(record), self.pins)["outcome"], "BLOCKED")
        for axis, field, value in (("assurance", "confinement", "QUALIFIED"),
                                   ("effect", "financial", {"settlement": "SETTLED"}),
                                   ("authorization", "financial", {"outcome": "APPROVED"})):
            with self.subTest(axis=axis):
                record = deepcopy(self.signed)
                record["payload"][axis][field] = value
                self.assertEqual(attestation.verify_trial(self._resign(record), self.pins)["outcome"], "REJECTED")

    def test_missing_inner_supervisor_or_target_cannot_be_replaced_by_outer_signature(self):
        for component in ("target_admission", "owner_grant", "supervisor_record"):
            record = deepcopy(self.signed)
            if component == "supervisor_record":
                record["payload"]["execution"][component] = None
            else:
                record["payload"]["authorization"][component] = None
            with self.subTest(component=component):
                self.assertEqual(attestation.verify_trial(self._resign(record), self.pins)["outcome"], "BLOCKED")

    def test_wrong_target_signature_and_incomplete_closure_do_not_verify(self):
        for place in ("target", "closure"):
            record = deepcopy(self.signed)
            if place == "target":
                record["payload"]["authorization"]["target_admission"]["admission"]["signature"] = "00" * 64
            else:
                record["payload"]["execution"]["supervisor_record"]["payload"]["closure"]["broker_drained"] = False
            with self.subTest(place=place):
                self.assertEqual(attestation.verify_trial(self._resign(record), self.pins)["outcome"], "REJECTED")

    def test_report_cannot_supply_its_own_expectations_or_extra_authority(self):
        self.assertEqual(attestation.verify_trial(self.signed, None)["outcome"], "BLOCKED")
        record = dict(self.signed, expectations=self.pins)
        self.assertEqual(attestation.verify_trial(record, self.pins)["outcome"], "REJECTED")
        record = deepcopy(self.signed)
        record["payload"]["authority_to_repeat"] = True
        self.assertEqual(attestation.verify_trial(self._resign(record), self.pins)["outcome"], "REJECTED")
