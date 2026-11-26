import json
from pathlib import Path
import tempfile
import unittest
from research.continuity.history import verify, HistoricalDecoder
from research.continuity.trial import run


class Lineage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.out = Path(temp.name) / "trial"
        run(cls.out)

    def load(self, name):
        return json.loads((self.out / (name + ".json")).read_bytes())

    def test_original_receipts_across_two_retirements(self):
        history = verify(self.load("lineage"), self.load("segments"))
        self.assertEqual(sorted(x["epoch"] for x in history.values()), [1, 3])
        self.assertEqual(len({x["gate"] for x in history.values()}), 2)

    def test_historical_decoder_has_no_execution_interface(self):
        self.assertFalse(hasattr(HistoricalDecoder, "execute"))
        self.assertFalse(hasattr(HistoricalDecoder, "prepare"))

    def test_omissions_and_substitutions(self):
        self.assertEqual(len(self.load("mutations")), 12)

    def test_authenticated_recovery_after_relocation(self):
        self.assertEqual(
            [r["expected"] for r in self.load("recovery")["observations"]],
            ["COMMITTED", "UNRESOLVED", "NOT_COMMITTED", "DENIED"],
        )
