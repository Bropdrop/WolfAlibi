"""Focused regressions for the independent qualification predicates."""
import unittest
from research.wt_swarm.review import Mismatch
from research.sovereign.review import distinct, eligible, partition


class Qualification(unittest.TestCase):
    def test_last_effect_precedes_fence(self):
        windows = [(0, "first"), (3, "second")]
        eligible(windows, 3, "first", set(), "grant")
        with self.assertRaisesRegex(Mismatch, "STALE_FENCE"):
            eligible(windows, 4, "first", set(), "grant")
        eligible(windows, 4, "second", set(), "grant")

    def test_no_effect_before_activation(self):
        with self.assertRaises((Mismatch, IndexError)):
            eligible([(0, "first")], 0, "first", set(), "grant")

    def test_revocation_wins(self):
        with self.assertRaisesRegex(Mismatch, "STALE_FENCE"):
            eligible([(0, "first")], 1, "first", {"grant"}, "grant")

    def test_duplicate_survives_renumbering(self):
        with self.assertRaisesRegex(Mismatch, "DUPLICATE_SETTLEMENT"):
            distinct([dict(op="x", seq=1), dict(op="x", seq=2)], 2)

    def test_missing_sequence(self):
        with self.assertRaisesRegex(Mismatch, "COUNTER_SEQUENCE"):
            distinct([dict(op="x", seq=2)], 1)

    def test_unavailable_is_indeterminate(self):
        partition(dict(state="DENIED", reason="QUORUM_UNAVAILABLE"))
        with self.assertRaisesRegex(Mismatch, "UNSAFE_PARTITION"):
            partition(dict(state="NOT_COMMITTED", reason="QUORUM_UNAVAILABLE"))
