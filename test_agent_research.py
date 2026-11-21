"""Synthetic tests for local, unsigned AgentProbe research aggregates."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import stat
import tempfile
import unittest

from wolfalibi.agent_probe import AgentProbe
from wolfalibi.agent_research import (OUTCOME_TAGS, SCHEMA, VERSION,
                                      ResearchExportError, export_research)
from wolfalibi.receipts import verify_negative_access_receipt


class AgentResearchExportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="wolfalibi-agent-research-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.output = self.directory / "research.json"

    def _summary(self, *, close=True):
        probe = AgentProbe(consent=True, agent_type="custom")
        probe.record(surface="tool", operation="invoke", outcome="success", duration_ms=12)
        probe.record(surface="filesystem", operation="read", outcome="denied", duration_ms=0)
        if close:
            probe.close()
        return probe.summary()

    def test_explicit_consent_and_fixed_nonreceipt_schema(self):
        summary = self._summary()
        with self.assertRaises(ResearchExportError):
            export_research(summary, self.output, outcome="PASS")
        self.assertFalse(self.output.exists())

        self.assertEqual(export_research(summary, self.output, consent=True, outcome="PASS"),
                         self.output)
        report = json.loads(self.output.read_text())
        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(report["version"], VERSION)
        self.assertEqual(report["outcome"], "PASS")
        self.assertEqual(report["observation"], {
            "agent_type": "custom",
            "assurance": "OBSERVATIONAL_ONLY",
            "coverage": "EXPLICITLY_WRAPPED_CALLS_AND_DECLARED_MANUAL_EVENTS",
            "completion": "COMPLETE_WRAPPED_CALLS",
            "events": 2,
            "manual_events": 2,
            "counts": {"filesystem.read.denied": 1, "tool.invoke.success": 1},
            "duration_buckets_ms": {"0-9": 1, "10-99": 1},
        })
        self.assertEqual(report["provenance"], {
            "kind": "UNSIGNED_OPERATOR_LOCAL_RESEARCH_EXPORT",
            "cryptographic_receipt": False,
            "witnessed": False,
            "replay_protection": "NONE",
            "network_upload": False,
            "automatic_sharing": False,
        })
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_identifiers_paths_hashes_raw_values_and_unknown_fields_are_omitted(self):
        summary = copy.deepcopy(self._summary())
        sensitive = "SYNTHETIC_SECRET_DO_NOT_EXPORT"
        summary.update({
            "manifest_sha256": "f" * 64,
            "path": "/synthetic/private/path",
            "raw_args": [sensitive],
            "unknown_future_field": {"prompt": sensitive},
        })
        export_research(summary, self.output, consent=True, outcome="AGENT_ERROR")
        report_text = self.output.read_text()
        for forbidden in (
            summary["run_id"], summary["manifest_sha256"], summary["path"], sensitive,
            "raw_args", "unknown_future_field",
        ):
            self.assertNotIn(forbidden, report_text)
        report = json.loads(report_text)
        self.assertEqual(report["reproducibility"], {
            "semantics": "SCHEMA_AND_BUCKET_SEMANTICS_ONLY_NO_EXECUTION_CONFIGURATION",
        })
        self.assertNotIn("run_id", report)
        self.assertNotIn("manifest_sha256", report)
        self.assertNotIn("path", report)

    def test_incomplete_snapshot_requires_and_preserves_incomplete_outcome(self):
        summary = self._summary(close=False)
        self.assertFalse(summary["complete_wrapped_calls"])
        self.assertEqual(summary["inflight"], 0)
        with self.assertRaises(ResearchExportError):
            export_research(summary, self.output, consent=True, outcome="PASS")
        self.assertFalse(self.output.exists())
        export_research(summary, self.output, consent=True, outcome="INCOMPLETE")
        report = json.loads(self.output.read_text())
        self.assertEqual(report["outcome"], "INCOMPLETE")
        self.assertEqual(report["observation"]["completion"], "INCOMPLETE_WRAPPED_CALLS")

    def test_complete_wrappers_can_honestly_report_an_incomplete_run_boundary(self):
        summary = self._summary()
        export_research(summary, self.output, consent=True, outcome="INCOMPLETE")
        report = json.loads(self.output.read_text())
        self.assertEqual(report["outcome"], "INCOMPLETE")
        self.assertEqual(report["observation"]["completion"], "COMPLETE_WRAPPED_CALLS")

    def test_legacy_wrapped_only_summary_can_omit_optional_manual_events(self):
        probe = AgentProbe(consent=True, agent_type="custom")
        wrapped = probe.wrap(lambda: "synthetic")
        self.assertEqual(wrapped(), "synthetic")
        probe.close()
        summary = probe.summary()
        self.assertEqual(summary["coverage"], "EXPLICITLY_WRAPPED_CALLS_ONLY")
        summary.pop("manual_events")
        export_research(summary, self.output, consent=True, outcome="PASS")
        report = json.loads(self.output.read_text())
        self.assertEqual(report["observation"]["coverage"], "EXPLICITLY_WRAPPED_CALLS_ONLY")
        self.assertEqual(report["observation"]["manual_events"], 0)

    def test_manual_coverage_without_a_valid_manual_count_is_refused(self):
        summary = self._summary()
        summary.pop("manual_events")
        with self.assertRaises(ResearchExportError):
            export_research(summary, self.output, consent=True, outcome="PASS")
        self.assertFalse(self.output.exists())

    def test_incoherent_or_unsafe_summaries_are_refused_before_writing(self):
        summary = self._summary()
        cases = []
        unstable = copy.deepcopy(summary)
        unstable["inflight"] = 1
        cases.append(unstable)
        wrong_total = copy.deepcopy(summary)
        wrong_total["events"] = 3
        cases.append(wrong_total)
        raw_category = copy.deepcopy(summary)
        raw_category["counts"]["tool.invoke.account=123"] = 1
        raw_category["events"] += 1
        raw_category["duration_buckets_ms"]["0-9"] += 1
        cases.append(raw_category)
        fake_semantics = copy.deepcopy(summary)
        fake_semantics["nonaccess_proof"] = True
        cases.append(fake_semantics)
        unhashable_category = copy.deepcopy(summary)
        unhashable_category["agent_type"] = {"raw": "SYNTHETIC_VALUE"}
        cases.append(unhashable_category)
        for bad in cases:
            with self.subTest(bad=bad):
                with self.assertRaises(ResearchExportError):
                    export_research(bad, self.output, consent=True, outcome="PASS")
                self.assertFalse(self.output.exists())

    def test_outcome_is_strict_and_existing_report_is_never_overwritten(self):
        summary = self._summary()
        for outcome in ("raw exception: SYNTHETIC_SECRET", "success", "", None):
            with self.subTest(outcome=outcome):
                with self.assertRaises(ResearchExportError):
                    export_research(summary, self.output, consent=True, outcome=outcome)
        self.assertFalse(self.output.exists())
        self.assertIn("PASS", OUTCOME_TAGS)
        self.assertTrue({"TIMEOUT", "INTERRUPTED", "EXPECTATION_FAILED"} <= OUTCOME_TAGS)
        export_research(summary, self.output, consent=True, outcome="PASS")
        before = self.output.read_bytes()
        with self.assertRaises(FileExistsError):
            export_research(summary, self.output, consent=True, outcome="PASS")
        self.assertEqual(self.output.read_bytes(), before)

    def test_unknown_top_level_fields_do_not_change_normalized_report(self):
        summary = self._summary()
        clean = self.directory / "clean.json"
        extra = self.directory / "extra.json"
        export_research(summary, clean, consent=True, outcome="PASS")
        augmented = dict(summary, unrecognized={"raw": "SYNTHETIC_VALUE"})
        export_research(augmented, extra, consent=True, outcome="PASS")
        self.assertEqual(clean.read_bytes(), extra.read_bytes())

    def test_unsigned_aggregate_is_not_a_negative_access_receipt(self):
        export_research(self._summary(), self.output, consent=True, outcome="PASS")
        report = json.loads(self.output.read_text())
        verification = verify_negative_access_receipt(
            report, broker_pub=b"b" * 32, witness_pub=b"w" * 32,
            challenge=b"c" * 32, policy={}, lo=b"a", hi=b"b", run_id="synthetic",
            code_digest=b"d" * 32, epochs=(1, 1),
        )
        self.assertEqual(verification["outcome"], "REJECTED", verification)


if __name__ == "__main__":
    unittest.main(verbosity=2)
