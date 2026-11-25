"""Hostile handoff and effect-review tests with fabricated signed evidence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from base64 import b64decode
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from scripts import wt_alibi_human_handoff as handoff
from scripts import wt_alibi_human_lab as lab
from scripts import wt_alibi_human_oracle as oracle
from scripts import wt_alibi_human_transport as transport
from scripts import wt_alibi_human_verify as review
from scripts.shirudo_prototype_host import OwnerTerminal
from scripts.shirudo_real_lab import PublicArtifacts
from shirudo_adapter import action_gate_cli, cli
from shirudo_adapter.model import AdapterError, UPSTREAM_COMMIT, canonical_json, digest, strict_json
from shirudo_adapter.receipt import sign_record
from shirudo_adapter.service import Service

try:
    from .support import evidence_bytes, fixture_verifier_result
    from .test_owner import OwnerFixture
except ImportError:
    from support import evidence_bytes, fixture_verifier_result
    from test_owner import OwnerFixture


class HostileFiles(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="wa-handoff-files-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "record.json"

    def denied(self, reason, operation, *args, **kwargs):
        with self.assertRaises(AdapterError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, reason)

    def test_duplicate_json_key(self):
        self.path.write_bytes(b'{"a":1,"a":2}')
        self.denied("DUPLICATE_JSON_KEY", handoff.strict_read, self.path)

    def test_nonfinite_json(self):
        self.path.write_bytes(b'{"a":NaN}')
        self.denied("INVALID_JSON_NUMBER", handoff.strict_read, self.path)

    def test_relative_path(self):
        self.denied("PATH", handoff.strict_read, Path("relative.json"))

    def test_traversal(self):
        self.denied("PATH", handoff.strict_read, self.root / ".." / "record.json")

    def test_input_symlink(self):
        self.path.symlink_to(self.root / "missing")
        self.denied("DIRECTORY_IO", handoff.strict_read, self.path)

    def test_parent_symlink(self):
        link = self.root / "parent-link"
        link.symlink_to(self.root)
        self.denied("DIRECTORY_IO", handoff.atomic_new, link / "output", b"complete")

    def test_hardlink_is_not_a_public_snapshot(self):
        self.path.write_bytes(b"{}")
        os.link(self.path, self.root / "alternate")
        self.denied("FILE_TYPE_SIZE", handoff.strict_read, self.path)

    def test_fifo_is_rejected_without_a_writer(self):
        os.mkfifo(self.path)
        self.denied("FILE_TYPE_SIZE", handoff.strict_read, self.path)

    def test_publication_never_replaces_existing_file(self):
        handoff.atomic_new(self.path, b"original")
        self.denied("OUTPUT_EXISTS", handoff.atomic_new, self.path, b"changed")
        self.assertEqual(self.path.read_bytes(), b"original")

    def test_publication_never_follows_destination_symlink(self):
        victim = self.root / "victim"
        victim.write_bytes(b"safe")
        self.path.symlink_to(victim)
        self.denied("OUTPUT_EXISTS", handoff.atomic_new, self.path, b"changed")
        self.assertEqual(victim.read_bytes(), b"safe")

    def test_shared_writable_output_ancestor(self):
        child = self.root / "protected"
        child.mkdir()
        self.root.chmod(0o777)
        try:
            self.denied("DIRECTORY_CUSTODY", handoff.atomic_new, child / "output", b"changed")
            self.assertFalse((child / "output").exists())
        finally:
            self.root.chmod(0o700)

    def test_concurrent_publication_is_single_and_complete(self):
        def publish(data):
            try:
                handoff.atomic_new(self.path, data)
                return data
            except AdapterError as exc:
                self.assertEqual(exc.code, "OUTPUT_EXISTS")
                return None

        with ThreadPoolExecutor(max_workers=4) as pool:
            values = list(pool.map(publish, (bytes([i]) * 10_000 for i in range(4))))
        winners = [data for data in values if data is not None]
        self.assertEqual(winners, [self.path.read_bytes()])
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_stdout_in_unrelated_account_is_not_ready(self):
        self.path.write_bytes(b'{"status":"READY"}\n')
        self.denied("READY_CUSTODY", handoff.wait_ready, self.path, os.geteuid() + 1, timeout=1)

    def test_coordinator_cannot_claim_its_own_stdout_is_the_owner(self):
        if os.geteuid() == 0:
            self.denied("INVALID_SCHEMA", handoff.wait_ready, self.path, 0, timeout=1)
        else:
            self.denied("READY_CUSTODY", handoff.wait_ready, self.path, os.geteuid(), timeout=1)

    def test_vault_owner_and_next_event_control(self):
        # Stub just the coordinator identity. The file and directory checks
        # use real descriptors, modes and file ownership.
        owner = os.geteuid() or 1
        self.path.write_bytes(b'{"status":"READY"}\n{"status":"DENIED"}\n')
        with patch.object(handoff.os, "geteuid", return_value=owner + 1):
            expected = "READY_CLOSED" if owner == self.root.stat().st_uid else "READY_CUSTODY"
            self.denied(expected, handoff.wait_ready, self.path, owner, timeout=1)


class FixtureTransport:
    """Deliberately fabricated signed lab-shaped evidence and no upstream binary."""

    def __init__(self, fixture):
        self.f = fixture
        self.calls = []
        self.issued = None

    def challenge(self, policy_sha, timeout):
        self.calls.append("challenge")
        if policy_sha != digest(self.f.profile["policy"]) or timeout <= 0:
            raise AssertionError("Incorrect challenge request")
        self.issued = self.f.f.challenge()
        return self.issued

    def prepare(self, challenge, timeout):
        self.calls.append("prepare")
        return self.f.gate.prepare(challenge)

    def collect(self, challenge_id, nonce, timeout):
        self.calls.append("collect")
        if (challenge_id, nonce) != (self.issued["payload"]["challenge_id"], self.issued["payload"]["nonce"]):
            raise AssertionError("Collector received a different challenge")
        return evidence_bytes(self.f.profile["policy"], self.issued)

    def assess(self, challenge_id, raw, timeout):
        self.calls.append("assess")
        if challenge_id != self.issued["payload"]["challenge_id"]:
            raise AssertionError("Verifier received a different challenge")
        payload = self.f.f.assessment(self.issued)["payload"]
        payload["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
        return self.signed_assessment(payload)

    def signed_assessment(self, payload):
        stdout = (json.dumps(payload["upstream"]["report"], indent=2) + "\n").encode("ascii")
        return sign_record(self.f.f.verifier_key, payload), stdout


class HandoffCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="wa-handoff-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.f = OwnerFixture(self.root / "fixture")
        self.intent = self.f.intent()
        self.profile = self.f.profile
        self.identity = self.f.owner.public_identity()
        self.pins = lab.make_pins(self.intent, self.profile, self.identity, 12345)
        self.ready = self.f.owner.begin_attempt(self.intent)
        self.output = self.root / "fresh-bundle.json"
        self.transport = FixtureTransport(self.f)
        self.records = {}

    def denied(self, reason, operation, *args, **kwargs):
        with self.assertRaises(AdapterError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, reason)

    def coordinate(self):
        return handoff.coordinate(self.pins, self.intent, self.profile, self.ready, self.output,
                                  self.transport, self.records.__setitem__, clock=lambda: self.f.now)

    def refused(self, reason, calls):
        self.denied(reason, self.coordinate)
        self.assertEqual(self.transport.calls, calls)
        self.assertFalse(self.output.exists())


class CoordinatorTests(HandoffCase):
    def test_verified_publication_binds_raw_evidence_and_does_not_commit(self):
        result = self.coordinate()
        self.assertEqual(self.transport.calls, ["challenge", "prepare", "collect", "assess"])
        self.assertEqual(result["actual_human_approval"], "NOT_RUN")
        bundle = handoff.strict_read(self.output)
        self.assertEqual(result["bundle_sha256"], digest(bundle))
        self.assertEqual(bundle["assessment"]["payload"]["evidence_sha256"],
                         hashlib.sha256(self.records["evidence.json"]).hexdigest())
        self.assertTrue(self.records["upstream-report.json"].startswith(b"{\n"))
        self.assertEqual(oracle.observe(self.f.gate.path / "journal.sqlite3")["ledger"], [])

    def test_wrong_ready_request_never_issues_challenge(self):
        self.ready["request_id"] = "d" * 32
        self.refused("READY_BINDING", [])

    def test_wrong_owner_instance_never_issues_challenge(self):
        self.ready["owner_instance_id"] = "c" * 32
        self.refused("READY_BINDING", [])

    def test_forged_ready_digest_never_issues_challenge(self):
        self.ready["profile_sha256"] = "0" * 64
        self.refused("READY_BINDING", [])

    def test_unknown_ready_field_never_issues_challenge(self):
        self.ready["command"] = "unexpected"
        self.refused("INVALID_SCHEMA", [])

    def test_ready_is_stale(self):
        self.f.now += 30_000
        self.refused("APPROVAL_EXPIRED", [])

    def test_remaining_owner_file_wait_has_expired(self):
        self.f.now += 25_000
        self.refused("APPROVAL_EXPIRED", [])

    def test_profile_cannot_widen_freshness_even_when_digest_matching(self):
        self.profile["policy"]["challenge_ttl_seconds"] = 31
        self.intent["policy_sha256"] = digest(self.profile["policy"])
        self.pins = lab.make_pins(self.intent, self.profile, self.identity, 12345)
        self.ready.update(profile_sha256=self.pins["profile_sha256"], intent_sha256=self.pins["intent_sha256"])
        self.refused("FRESHNESS_POLICY", [])

    def test_changed_profile_cannot_choose_own_trust(self):
        self.profile["gate_public_key"] = "b" * 64
        self.refused("PINS_MISMATCH", [])

    def test_preexisting_bundle_never_starts_an_attempt(self):
        self.output.write_bytes(b"prepositioned")
        self.denied("OUTPUT_EXISTS", self.coordinate)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.output.read_bytes(), b"prepositioned")

    def test_invalid_verifier_signature_stops_before_prepare(self):
        original = self.transport.challenge

        def corrupt(*args):
            document = original(*args)
            document["signature"] = "00" * 64
            return document

        with patch.object(self.transport, "challenge", side_effect=corrupt):
            self.refused("INVALID_SIGNATURE", ["challenge"])

    def test_signed_challenge_cannot_predate_ready_beyond_skew(self):
        original = self.transport.challenge

        def old(*args):
            original(*args)
            return self.f.f.challenge(issued_at_ms=self.ready["ready_at_ms"] - 2001)

        with patch.object(self.transport, "challenge", side_effect=old):
            self.refused("CHALLENGE_TIME", ["challenge"])

    def test_late_admission_is_denied_before_sending_prepare(self):
        original = self.transport.challenge

        def delayed(*args):
            document = original(*args)
            self.f.now += 5001
            return document

        with patch.object(self.transport, "challenge", side_effect=delayed):
            self.refused("ATTESTATION_STALE", ["challenge"])

    def test_bad_target_signature_stops_before_evidence_collection(self):
        original = self.transport.prepare

        def corrupt(*args):
            document = original(*args)
            document["signature"] = "00" * 64
            return document

        with patch.object(self.transport, "prepare", side_effect=corrupt):
            self.refused("INVALID_SIGNATURE", ["challenge", "prepare"])

    def test_valid_target_signature_cannot_substitute_policy_generation(self):
        original = self.transport.prepare

        def foreign(*args):
            payload = original(*args)["payload"]
            payload["policy_generation"] += 1
            return sign_record(self.f.gate._key, payload)

        with patch.object(self.transport, "prepare", side_effect=foreign):
            self.refused("ACTION_MISMATCH", ["challenge", "prepare"])

    def test_wrong_evidence_nonce_stops_before_assessment(self):
        original = self.transport.collect

        def stale(*args):
            document = strict_json(original(*args))
            document["nonce"] = "d" * 64
            return canonical_json(document)

        with patch.object(self.transport, "collect", side_effect=stale):
            self.refused("NONCE_MISMATCH", ["challenge", "prepare", "collect"])

    def test_assessment_signed_for_different_evidence_is_rejected(self):
        original = self.transport.assess

        def swapped(*args):
            payload = original(*args)[0]["payload"]
            payload["evidence_sha256"] = "d" * 64
            return self.transport.signed_assessment(payload)

        with patch.object(self.transport, "assess", side_effect=swapped):
            self.refused("EVIDENCE_DIGEST", ["challenge", "prepare", "collect", "assess"])

    def test_consistent_signed_report_omitting_pinned_pcr_is_rejected(self):
        original = self.transport.assess

        def omitted_pcr(*args):
            payload = original(*args)[0]["payload"]
            upstream = payload["upstream"]
            expected = "PCR 15 matches the expected value"
            upstream["required_checks"].remove(expected)
            upstream["report"]["checks"] = [check for check in upstream["report"]["checks"]
                                             if check["text"] != expected]
            upstream["report_sha256"] = digest(upstream["report"])
            return self.transport.signed_assessment(payload)

        with patch.object(self.transport, "assess", side_effect=omitted_pcr):
            self.refused("ASSESSMENT_MISMATCH", ["challenge", "prepare", "collect", "assess"])

    def test_signed_rejection_retains_the_expected_upstream_failure(self):
        original = self.transport.assess
        failure = "quote: ECDSA signature by the attestation key"

        def rejected(*args):
            payload = original(*args)[0]["payload"]
            payload.update(outcome="REJECTED", reason_code="UPSTREAM_REJECTED")
            upstream = payload["upstream"]
            upstream["exit_code"] = 1
            upstream["report"] = {"schema": 1, "verdict": "fail",
                                  "checks": [{"result": "fail", "text": failure}]}
            upstream["report_sha256"] = digest(upstream["report"])
            return self.transport.signed_assessment(payload)

        with patch.object(self.transport, "assess", side_effect=rejected):
            self.refused("UPSTREAM_REJECTED", ["challenge", "prepare", "collect", "assess"])
        retained = strict_json(self.records["upstream-report.json"])
        self.assertEqual(retained["checks"], [{"result": "fail", "text": failure}])

    def test_upstream_stdout_must_match_the_signed_report(self):
        original = self.transport.assess

        def mismatched(*args):
            assessment, _ = original(*args)
            return assessment, b'{}\n'

        with patch.object(self.transport, "assess", side_effect=mismatched):
            self.refused("UPSTREAM_REPORT", ["challenge", "prepare", "collect", "assess"])

    def test_lost_prepare_reply_does_not_allocate_a_second_operation(self):
        original = self.transport.prepare

        def interrupted(*args):
            action = original(*args)
            self.prepared_id = action["payload"]["operation_id"]
            raise AdapterError("AMBIGUOUS", "Prepared reply lost")

        with patch.object(self.transport, "prepare", side_effect=interrupted):
            self.refused("AMBIGUOUS", ["challenge", "prepare"])
        self.denied("OUTPUT_EXISTS", self.coordinate)
        self.assertEqual(self.transport.calls, ["challenge", "prepare"])
        self.assertEqual(self.f.gate.status(self.prepared_id)["operation"]["status"], "PREPARED")
        self.assertEqual(oracle.observe(self.f.gate.path / "journal.sqlite3")["counter"], 0)

    def test_last_two_seconds_do_not_publish(self):
        original = self.transport.assess

        def expires(*args):
            value = original(*args)
            self.f.now += 28_001
            return value

        with patch.object(self.transport, "assess", side_effect=expires):
            self.refused("APPROVAL_EXPIRED", ["challenge", "prepare", "collect", "assess"])

    def test_slow_file_sync_rechecks_freshness_before_visibility(self):
        original = os.fsync
        syncs = []

        def delayed(fd):
            original(fd)
            syncs.append(fd)
            if len(syncs) == 3:  # Start file and directory were already synced.
                self.f.now += handoff.OWNER_BUNDLE_WAIT_MS

        with patch.object(handoff.os, "fsync", side_effect=delayed):
            self.refused("APPROVAL_EXPIRED", ["challenge", "prepare", "collect", "assess"])
        self.assertFalse(list(self.root.glob(".wolfalibi-*")))

    def test_fixed_guest_prepare_keeps_public_request_bytes_off_argv(self):
        responses = [(0, UPSTREAM_COMMIT.encode() + b"\n", b""), (0, b"", b""),
                     (0, b'{"status":"PREPARED"}', b"")]
        document = {"op": "prepare", "attestation_challenge": {"data": "$(untrusted)"}}
        with patch.object(transport, "selected_run", return_value="123-1"), \
                patch.object(transport, "bounded_command", side_effect=responses) as command:
            guest = transport.LabGuest(self.root, "wolfalibi-prototype-123-1")
            guest.client(document, endpoint="prepare")
        argv = command.call_args.args[0]
        self.assertIn("VM_SSH_COMMAND=" + transport.GUEST_COMMANDS["prepare"], argv)
        self.assertNotIn("$(untrusted)", " ".join(argv))
        self.assertEqual(command.call_args.kwargs["input_data"], canonical_json(document))

    def test_original_report_bytes_are_returned_by_verifier_cli(self):
        service = Service.initialize(self.root / "test-verifier")
        policy = copy.deepcopy(self.profile["policy"])
        policy["assurance"] = "SYNTHETIC"
        policy["enrollment"]["method"] = "synthetic_fixture"
        challenge = service.issue_challenge(service.register_policy(policy))
        evidence = self.root / "synthetic-evidence.json"
        evidence.write_bytes(evidence_bytes(policy, challenge))
        result = fixture_verifier_result(policy)
        report = (json.dumps(result["report"], indent=4) + "\n").encode("ascii")

        def fixture_run(*_args, report_sink):
            report_sink(report)
            return result

        output = io.BytesIO()
        argv = ["verify", "--state", str(service.path), "--include-upstream-report",
                "--challenge-id", challenge["payload"]["challenge_id"], "--evidence", str(evidence),
                "--verifier", str(self.root / "synthetic")]
        with patch("shirudo_adapter.service.run_verifier", side_effect=fixture_run), \
                patch("shirudo_adapter.cli.sys.stdout", SimpleNamespace(buffer=output)):
            self.assertEqual(cli.main(argv), 0)
        wrapped = strict_json(output.getvalue())
        self.assertEqual(b64decode(wrapped["upstream_report_base64"], validate=True), report)
        self.assertEqual(wrapped["receipt"]["payload"]["outcome"], "SIMULATED_POLICY_ONLY")


class EffectAuditTests(HandoffCase):
    def setUp(self):
        super().setUp()
        self.before = oracle.observe(self.f.gate.path / "journal.sqlite3")
        self.coordinate()
        self.bundle = handoff.strict_read(self.output)
        self.f.now = max(self.f.now, self.before["observed_at_ms"])
        # Fabricated unit-test authority under a temporary fixture key.
        reviewed = self.f.owner.review_bundle(self.intent, self.bundle, ready_at_ms=self.ready["ready_at_ms"])
        result = self.f.approve(reviewed)
        self.request = {"operation_id": result["operation_id"],
                        "grant": result["grant"], "assessment": self.bundle["assessment"]}
        self.receipt = self.f.gate.execute(self.request)["receipt"]
        self.after = oracle.observe(self.f.gate.path / "journal.sqlite3")
        self.audit = {"schema": review.AUDIT_PINS_SCHEMA, "request_id": self.intent["request_id"],
                      "bundle_sha256": digest(self.bundle), "operation_id": result["operation_id"],
                      "ready_sha256": digest(self.ready),
                      "before_sha256": digest(self.before), "after_sha256": digest(self.after)}
        self.raw = self.records["evidence.json"]

    def check(self):
        return review.verify_effect(self.pins, self.audit, self.intent, self.profile, self.ready,
                                    self.bundle, self.raw, self.request, self.receipt, self.before, self.after)

    def test_public_records_verify_the_independent_sqlite_counter(self):
        original = self.f.gate.path / "journal.sqlite3"
        before = original.read_bytes()
        result = self.check()
        self.assertEqual((result["status"], result["counter_before"], result["counter_after"]),
                         ("HISTORICAL_EFFECT_VERIFIED", 0, 1))
        self.assertEqual(result["authorization"], "NONE")
        self.assertEqual(before, original.read_bytes())

    def test_receipt_tampering_reaches_the_target_signature_check(self):
        self.receipt["signature"] = "0" * 128
        self.denied("INVALID_SIGNATURE", self.check)

    def test_grant_tampering_reaches_the_owner_signature_check(self):
        self.request["grant"]["signature"] = "0" * 128
        self.denied("INVALID_SIGNATURE", self.check)

    def test_signed_grant_cannot_widen_the_owner_review(self):
        payload = self.request["grant"]["payload"]
        payload["operation_nonce"] = "f" * 64
        self.request["grant"] = sign_record(self.f.owner._key, payload)
        self.denied("GRANT_MISMATCH", self.check)

    def test_altered_raw_evidence_digest_is_checked(self):
        self.raw += b"\n"
        self.denied("EVIDENCE_DIGEST", self.check)

    def test_wholly_relabelled_request_cannot_replace_independent_binding(self):
        self.bundle["request_id"] = "d" * 32
        self.denied("AUDIT_BUNDLE", self.check)

    def test_changed_ready_time_cannot_replace_the_observed_owner_event(self):
        self.ready["ready_at_ms"] -= 1
        self.denied("AUDIT_READY", self.check)

    def test_different_operation_id_never_substitutes_for_the_exact_request(self):
        self.request["operation_id"] = "d" * 32
        self.denied("AUDIT_OPERATION", self.check)

    def test_forged_observation_digest_is_checked_before_ledger(self):
        self.after["counter"] = 0
        self.denied("ORACLE_DIGEST", self.check)

    def test_rehashed_ledger_with_a_missing_increment_is_detected(self):
        self.after["ledger"].clear()
        self.audit["after_sha256"] = digest(self.after)
        self.denied("ORACLE_COUNTER", self.check)

    def test_rehashed_ledger_with_wrong_exact_request_is_detected(self):
        self.after["ledger"][0]["request_sha256"] = "d" * 64
        self.audit["after_sha256"] = digest(self.after)
        self.denied("ORACLE_BINDING", self.check)

    def test_another_valid_signed_effect_is_an_unreported_increment(self):
        # Produce a second, distinct committed effect under ephemeral test
        # identities. Both receipt signatures remain valid.
        intent = self.f.intent()
        self.f.now = handoff.now_ms()
        _, ready, bundle = self.f.material(intent)
        issued = self.f.approve(self.f.owner.review_bundle(intent, bundle, ready_at_ms=ready["ready_at_ms"]))
        self.f.gate.execute({"operation_id": issued["operation_id"], "grant": issued["grant"],
                             "assessment": bundle["assessment"]})
        self.after = oracle.observe(self.f.gate.path / "journal.sqlite3")
        self.audit["after_sha256"] = digest(self.after)
        self.denied("ORACLE_DELTA", self.check)

    def test_boolean_counter_cannot_equate_to_one(self):
        self.after["counter"] = True
        self.audit["after_sha256"] = digest(self.after)
        self.denied("INVALID_SCHEMA", self.check)

    def test_separate_verify_cli_requires_independent_pins(self):
        records = {"pins": self.pins, "audit-pins": self.audit, "intent": self.intent,
                   "profile": self.profile, "ready": self.ready, "bundle": self.bundle,
                   "evidence": self.raw, "request": self.request, "receipt": self.receipt,
                   "before": self.before, "after": self.after}
        argv = [sys.executable, "-I", "-B", str(lab.ROOT / "scripts/wt_alibi_human_verify.py")]
        for name, value in records.items():
            path = self.root / f"{name}.json"
            path.write_bytes(value if isinstance(value, bytes) else canonical_json(value))
            argv.extend(("--" + name, str(path)))
        argv.extend(("--pins-sha256", digest(self.pins), "--audit-pins-sha256", digest(self.audit)))
        result = subprocess.run(argv, capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(strict_json(result.stdout)["request_id"], self.intent["request_id"])
        result = subprocess.run([*argv[:-1], "0" * 64], capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(strict_json(result.stdout)["reason"], "PINS_DIGEST")

    def test_oracle_rejects_counter_without_a_committed_row(self):
        path = self.f.gate.path / "journal.sqlite3"
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE counter SET value=2")
        with self.assertRaisesRegex(ValueError, "Counter disagrees"):
            oracle.observe(path)


class ScriptedPtyRecoveryTests(HandoffCase):
    """An actual owner subprocess and gate socket with fabricated TPM evidence."""

    def setUp(self):
        super().setUp()
        self.sock = self.root / "gate.sock"
        self.journal = self.f.gate.path / "journal.sqlite3"

    def freeze_execution(self):
        before = oracle.observe(self.journal)
        intent_path = self.root / "intent.json"
        intent_path.write_bytes(canonical_json(self.intent))
        argv = [sys.executable, "-B", "-m", "shirudo_adapter.owner_cli", "approve",
                "--state", str(self.f.state), "--intent", str(intent_path),
                "--bundle", str(self.output), "--ready-timeout", "5", "--bundle-timeout", "5"]
        with OwnerTerminal(argv) as terminal:
            terminal.wait_prompt("Type READY", timeout=5)
            terminal.send("READY")
            self.ready = terminal.event(timeout=5)
            self.f.now = handoff.now_ms()
            self.coordinate()
            owner_review = terminal.event(timeout=5)
            self.assertEqual(owner_review["status"], "AWAITING_APPROVAL")
            terminal.send(owner_review["approval_phrase"])
            issued = terminal.event(timeout=5)
            self.assertEqual(issued["status"], "GRANT_ISSUED")
            self.assertEqual(terminal.process.wait(timeout=5), 0)
            self.events = [event["status"] for event in terminal.records]
        self.bundle = handoff.strict_read(self.output)
        self.request = {"operation_id": issued["operation_id"], "grant": issued["grant"],
                        "assessment": self.bundle["assessment"]}
        self.before = before
        self.owner_review = owner_review
        self.assertEqual(digest(self.bundle), owner_review["bundle_sha256"])

    def start(self, *options):
        argv = [sys.executable, "-B", "-m", "shirudo_adapter.action_gate_cli", "serve",
                "--state", str(self.f.gate.path), "--socket", str(self.sock),
                "--replace-stale-socket", *options]
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(self.stop_process, process)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(4), "Gate failed to start")
            self.assertEqual(strict_json(process.stdout.readline(4096))["status"], "READY")
        return process

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        process.stdout.close()

    def submit(self):
        return action_gate_cli.request(self.sock, {"op": "execute", "request": self.request}, timeout=4)

    def status(self):
        response, code = action_gate_cli.request(self.sock, {"op": "status",
            "operation_id": self.request["operation_id"]}, timeout=4)
        self.assertEqual(code, 0)
        self.assertEqual(response["status"], "STATUS")
        row = response["result"]["operation"]
        self.assertEqual(row["operation_id"], self.request["operation_id"])
        return row

    def audited(self, receipt):
        after = oracle.observe(self.journal)
        audit = {"schema": review.AUDIT_PINS_SCHEMA, "request_id": self.intent["request_id"],
                 "operation_id": self.owner_review["operation_id"],
                 "bundle_sha256": self.owner_review["bundle_sha256"],
                 "ready_sha256": digest(self.ready),
                 "before_sha256": digest(self.before), "after_sha256": digest(after)}
        result = review.verify_effect(self.pins, audit, self.intent, self.profile, self.ready, self.bundle,
                     self.records["evidence.json"], self.request, receipt, self.before, after)
        self.assertEqual((result["counter_before"], result["counter_after"]), (0, 1))
        return result, audit, after

    def test_exit_before_commit_recovers_only_the_frozen_operation(self):
        self.freeze_execution()
        first = self.start("--exit-before-commit-once")
        response, code = self.submit()
        self.assertEqual((code, response["status"], response["reason"]), (2, "AMBIGUOUS", "TRANSPORT_LOST"))
        self.assertEqual(first.wait(timeout=4), action_gate_cli.EXIT_BEFORE_COMMIT)
        self.start()
        self.assertEqual(self.status()["status"], "PREPARED")
        self.assertEqual(oracle.observe(self.journal)["ledger"], self.before["ledger"])
        response, code = self.submit()
        self.assertEqual((code, response["result"]), (0, "COMMITTED"))
        repeated, code = self.submit()
        self.assertEqual((code, repeated["result"], repeated["receipt"]),
                         (0, "ALREADY_COMMITTED", response["receipt"]))
        self.audited(response["receipt"])

    def test_exit_after_commit_recovers_receipt_by_original_id(self):
        self.freeze_execution()
        first = self.start("--exit-after-commit-once")
        response, code = self.submit()
        self.assertEqual((code, response["status"], response["reason"]), (2, "AMBIGUOUS", "TRANSPORT_LOST"))
        self.assertEqual(first.wait(timeout=4), action_gate_cli.EXIT_AFTER_COMMIT)
        self.start()
        recovered = self.status()
        self.assertEqual(recovered["status"], "COMMITTED")
        self.assertEqual(recovered["request_sha256"], digest(self.request))
        repeated, code = self.submit()
        self.assertEqual((code, repeated["result"], repeated["receipt"]),
                         (0, "ALREADY_COMMITTED", recovered["receipt"]))
        self.audited(recovered["receipt"])

    def test_lost_reply_recovers_one_recorded_counter_effect(self):
        self.freeze_execution()
        server = self.start()
        frame = canonical_json({"op": "execute", "request": self.request})
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(self.sock))
            client.sendall(struct.pack("!I", len(frame)) + frame)
            client.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + 3
        row = self.status()
        while row["status"] == "PREPARED" and time.monotonic() < deadline:
            time.sleep(0.025)
            row = self.status()
        self.assertEqual(row["status"], "COMMITTED")
        retries = []
        with ThreadPoolExecutor(max_workers=3) as pool:
            for response, code in pool.map(lambda _: self.submit(), range(3)):
                self.assertEqual((code, response["result"], response["receipt"]),
                                 (0, "ALREADY_COMMITTED", row["receipt"]))
                retries.append(response["result"])
        result, audit, after = self.audited(row["receipt"])
        self.stop_process(server)
        evidence_dir = os.environ.get("WT_ALIBI_FIXTURE_EVIDENCE")
        if evidence_dir:
            artifacts = PublicArtifacts(Path(evidence_dir))
            for name, data in self.records.items():
                artifacts.write(name, data)
            for name, document in {
                "pins": self.pins, "audit-pins": audit, "intent": self.intent, "profile": self.profile,
                "request": self.request, "receipt": row["receipt"], "before": self.before,
                "after": after, "review": result,
                "observations": {"evidence": "FABRICATED_SIGNED_FIXTURES", "approval_driver": "SCRIPTED_PTY",
                    "actual_human_approval": "NOT_RUN", "terminal_events": self.events,
                    "role_accounts": "SAME_LOCAL_TEST_UID", "lost_reply": "CLIENT_CLOSED_WITHOUT_READING_REPLY",
                    "operation_id": self.request["operation_id"], "exact_retries": retries,
                    "gate_process_exit_code": server.returncode},
            }.items():
                artifacts.json(name + ".json", document)
            artifacts.json("artifact-manifest.json", {"files": artifacts.files.copy()})


if __name__ == "__main__":
    unittest.main()
