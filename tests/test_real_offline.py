"""Synthetic tests of Gate A plumbing; no genuine upstream result is claimed."""

from __future__ import annotations

import copy
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

from shirudo_adapter.model import AdapterError, canonical_json, strict_json
from scripts import shirudo_real_offline as gate


VERSION = "ab" * 32
NONCE = "cd" * 16


def fixture_document():
    return {
        "schema": 1, "kind": "shirudo-attestation", "nonce": NONCE,
        "ak": {"name": "000b" + "a1" * 32}, "ek": {"name": "000b" + "e1" * 32},
        "register": {"value": "11" * 32}, "quote": {"signature": "22" * 72},
        "pcrs": [{"index": pcr, "value": "33" * 32} for pcr in (7, 9, 11, 14)],
        "eventlog": [{"type": "init", "pcr_before": "00" * 32, "phase_before": "00" * 32}],
        "config": {"pcr": 14, "events": [{"root_hash": "44" * 32}]},
    }


def mock_report(accepted, failed="quote: ECDSA signature by the attestation key"):
    return {"schema": 1, "verdict": "ok" if accepted else "fail", "checks": [
        {"result": "ok" if accepted else "fail", "text": "nonce matches the request" if accepted else failed}
    ]}


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "memfd_create"), "requires Linux")
class RealOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="historical-gate-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = canonical_json(fixture_document())
        self.policy, self.nonce = gate.fixture_policy(self.raw, "candidate-config-history", VERSION)

    def output(self, name):
        path = self.root / name
        path.mkdir()
        return path

    def test_bounded_capture_preserves_real_failure_stderr(self):
        result = gate.capture([sys.executable, "-c", "import sys;sys.stderr.write('startup blocked\\n');sys.exit(7)"])
        self.assertEqual(result.exit_code, 7)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"startup blocked\n")
        self.assertIsNone(result.error)

    def test_capture_bounds_both_streams_and_timeout(self):
        for fd in (1, 2):
            with self.subTest(stream=fd):
                result = gate.capture([sys.executable, "-c", f"import os;os.write({fd},b'x'*1000000)"], stdout_limit=128)
                self.assertEqual(result.error, "OUTPUT_LIMIT")
                self.assertLessEqual(len(result.stdout), 128)
                self.assertLessEqual(len(result.stderr), gate.STREAM_LIMIT)
        before = time.monotonic()
        result = gate.capture([sys.executable, "-c", "import time;time.sleep(5)"], timeout=0.1)
        self.assertEqual(result.error, "TIMEOUT")
        self.assertLess(time.monotonic() - before, 1.5)

    def test_source_uses_pinned_git_objects_and_content_digests(self):
        fixture_pin = {
            "path": "historical.json", "bytes": len(self.raw), "sha256": gate.sha256(self.raw),
            "git_blob_sha": hashlib.sha1(b"blob " + str(len(self.raw)).encode() + b"\0" + self.raw).hexdigest(),
        }
        replies = [gate.Capture(0, (gate.UPSTREAM_COMMIT + "\n").encode()), gate.Capture(0, self.raw)]
        with mock.patch.object(gate, "FIXTURES", {"test": fixture_pin}), mock.patch.object(gate, "capture", side_effect=replies) as captured:
            source, data = gate.load_fixtures(self.root, self.output("source-good"))
        self.assertEqual(data["test"], self.raw)
        self.assertEqual(source["fixtures"]["test"]["sha256"], fixture_pin["sha256"])
        args = captured.call_args_list[-1].args[0]
        self.assertIn("--no-replace-objects", args)
        self.assertEqual(args[-3:], ["cat-file", "blob", gate.UPSTREAM_COMMIT + ":historical.json"])
        replies = [gate.Capture(0, (gate.UPSTREAM_COMMIT + "\n").encode()), gate.Capture(0, self.raw + b" ")]
        with mock.patch.object(gate, "FIXTURES", {"test": fixture_pin}), mock.patch.object(gate, "capture", side_effect=replies):
            with self.assertRaises(AdapterError) as caught:
                gate.load_fixtures(self.root, self.output("source-bad"))
        self.assertEqual(caught.exception.code, "SOURCE_FIXTURE")

    def test_policy_is_historical_and_mutations_do_not_recompute_expectations(self):
        before = canonical_json(self.policy)
        controls = gate.negative_controls(self.raw, self.nonce)
        self.assertEqual(self.policy["assurance"], "SYNTHETIC")
        self.assertEqual(self.policy["enrollment"]["method"], "synthetic_fixture")
        self.assertEqual(self.policy["enrollment"]["record_sha256"], gate.sha256(self.raw))
        self.assertEqual(canonical_json(self.policy), before)
        self.assertEqual(len(controls), 6)
        changed = next(case for case in controls if case["name"] == "config-history-bitflip")
        evidence = strict_json(changed["evidence"])
        self.assertNotEqual(evidence["config"]["events"][-1]["root_hash"], self.policy["expected"]["config_root"])
        wrong_nonce = next(case for case in controls if case["name"] == "wrong-expected-nonce")
        self.assertEqual(wrong_nonce["evidence"], self.raw)
        self.assertNotEqual(wrong_nonce["nonce"], self.nonce)
        args = gate.upstream_arguments(self.policy, self.nonce, "/fixture")
        self.assertIn("--expect-chain=" + self.policy["expected"]["chain"], args)
        self.assertIn("--require-initrd", args)
        self.assertFalse(any("allow-runtime" in arg or "trust-presented" in arg for arg in args))

    def run_case(self, raw_report, adapter_report, *, expected="candidate_accept", assertion=None):
        accepted = raw_report["verdict"] == "ok"
        case = {"name": "case", "evidence": self.raw, "nonce": self.nonce,
                "expected": expected, "failure_assertion": assertion}
        raw = gate.Capture(0 if accepted else 1, canonical_json(raw_report) + b"\n")
        adapter = {"accepted": adapter_report["verdict"] == "ok",
                   "exit_code": 0 if adapter_report["verdict"] == "ok" else 1,
                   "report": adapter_report}
        with mock.patch.object(gate, "capture", return_value=raw), mock.patch.object(gate.runner, "run_verifier", return_value=adapter):
            return gate.run_case(self.output("case"), 123, "/not-executed", self.policy, case)

    def test_raw_and_adapter_must_agree_and_specific_mutation_must_fail(self):
        result = self.run_case(mock_report(True), mock_report(False))
        self.assertEqual(result["status"], "INTERFACE_MISMATCH")
        self.assertFalse(result["expected_outcome_observed"])
        # A different pre-existing failure must not pass a signature control.
        wrong_reason = mock_report(False, "state: register equals the expected value")
        with mock.patch.object(self, "output", return_value=self.output("different-case")):
            result = self.run_case(wrong_reason, wrong_reason, expected="reject",
                                   assertion="quote: ECDSA signature by the attestation key")
        self.assertTrue(result["interface_compatible"])
        self.assertFalse(result["expected_outcome_observed"])

    def test_raw_report_rejects_boolean_schema_and_rc_verdict_mismatch(self):
        value = mock_report(True)
        value["schema"] = True
        self.assertIsNone(gate.raw_report(gate.Capture(0, canonical_json(value))))
        self.assertIsNone(gate.raw_report(gate.Capture(1, canonical_json(mock_report(True)))))
        self.assertIsNone(gate.raw_report(gate.Capture(0, canonical_json(mock_report(False)))))

    def exercise_gate(self, name, *, startup=None, candidate_accepted=True, bad_control=False):
        executable = self.root / (name + "-fake-elf")
        binary = b"\x7fELFunit-test-bytes-never-executed"
        executable.write_bytes(binary)
        fixtures = {"known-negative": self.raw, "candidate-config-history": self.raw}
        startup = startup or gate.Capture(0, (VERSION + "\n").encode())

        def snapshot(stack, *args):
            fd = os.open(os.devnull, os.O_RDONLY)
            stack.callback(os.close, fd)
            return fd, gate.sha256(binary)

        def case_result(output, fd, path, policy, case):
            candidate = case["name"] == "candidate-config-history"
            accepted = candidate and candidate_accepted
            report = mock_report(accepted)
            observed = accepted if candidate else not (bad_control and case["name"] == "quote-signature-bitflip")
            return {"name": case["name"], "expected": case["expected"],
                    "status": "ACCEPTED" if accepted else "REJECTED", "interface_compatible": True,
                    "expected_outcome_observed": observed,
                    "raw_upstream": {"report": report, "exit_code": 0 if accepted else 1}}

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(gate, "OFFICIAL_ELF_SHA256", gate.sha256(binary)))
            stack.enter_context(mock.patch.object(gate, "load_fixtures", return_value=({"commit": gate.UPSTREAM_COMMIT}, fixtures)))
            stack.enter_context(mock.patch.object(gate.runner, "_executable_snapshot", side_effect=snapshot))
            stack.enter_context(mock.patch.object(gate, "capture", return_value=startup))
            cases = stack.enter_context(mock.patch.object(gate, "run_case", side_effect=case_result))
            summary, code = gate.run_gate(self.root, str(executable), self.root / name)
        return summary, code, cases

    def test_startup_failure_is_recorded_without_fabricated_cases(self):
        stderr = b"hardening: cannot lock process memory: Cannot allocate memory\n"
        summary, code, cases = self.exercise_gate("startup", startup=gate.Capture(1, stderr=stderr))
        self.assertEqual(code, 1)
        self.assertEqual(summary["result"], "STARTUP_BLOCKED")
        self.assertFalse(summary["binary_ready"])
        self.assertIsNone(summary["version_id"])
        self.assertEqual(summary["candidate_validity"], "NOT_RUN")
        self.assertEqual((self.root / "startup" / "startup.stderr").read_bytes(), stderr)
        cases.assert_not_called()

    def test_candidate_rejection_does_not_become_startup_failure_or_pass(self):
        summary, code, cases = self.exercise_gate("candidate-rejected", candidate_accepted=False)
        self.assertEqual(code, 1)
        self.assertTrue(summary["binary_ready"])
        self.assertEqual(summary["result"], "CANDIDATE_NOT_QUALIFIED")
        self.assertEqual(summary["candidate_validity"], "REJECTED")
        self.assertFalse(summary["negative_controls_validated_against_passing_baseline"])
        self.assertEqual(cases.call_count, 8)

    def test_one_failed_control_prevents_qualification(self):
        summary, code, _ = self.exercise_gate("bad-control", bad_control=True)
        self.assertEqual(code, 1)
        self.assertEqual(summary["result"], "NEGATIVE_CONTROL_FAILURE")
        self.assertFalse(summary["negative_controls_passed"])

    def test_complete_simulated_plumbing_stays_historical_without_receipts(self):
        summary, code, _ = self.exercise_gate("all-passing")
        self.assertEqual(code, 0)
        self.assertEqual(summary["result"], "QUALIFIED")
        self.assertEqual(summary["scope"], "HISTORICAL_FIXTURE_COMPATIBILITY")
        for key in ("fresh_target_claim", "enrollment_performed", "receipt_created", "hardware_tpm_claim"):
            self.assertIs(summary[key], False)
        self.assertTrue((self.root / "all-passing" / "gate-a-report.json").is_file())

    def test_nonempty_output_cannot_reuse_stale_success_artifacts(self):
        output = self.output("stale")
        (output / "gate-a-report.json").write_bytes(b"old success")
        with self.assertRaises(AdapterError) as caught:
            gate.run_gate(self.root, "/not-executed", output)
        self.assertEqual(caught.exception.code, "OUTPUT_PATH")
        self.assertEqual((output / "gate-a-report.json").read_bytes(), b"old success")


if __name__ == "__main__":
    unittest.main()
