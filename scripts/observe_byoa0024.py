"""Record durable state before fixture cleanup in the existing guarded regressions."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_byoa002_closure import ClosureTests
from test_byoa002_custody import CustodyTests
from wolfalibi.byoa002_custody import inspect_history


class Observation:
    def setUp(self):
        super().setUp()
        self.responses = []

    def observe_reply(self, action, reply):
        self.responses.append({"action": action, "outcome": reply["outcome"],
                               "body_present": "record" in reply})
        return reply

    def dispatch(self, *args, **kwargs):
        return self.observe_reply("dispatch", super().dispatch(*args, **kwargs))

    def recover(self, *args, **kwargs):
        return self.observe_reply("historical_inquiry", super().recover(*args, **kwargs))

    def tearDown(self):
        with closing(sqlite3.connect(self.db.as_uri() + "?mode=ro", uri=True)) as db:
            rows = db.execute("SELECT operation_id, receipt FROM effects ORDER BY operation_id").fetchall()
            effects = [{"operation": key, "receipt": json.loads(raw)} for key, raw in rows]
            target_head = json.loads(db.execute("SELECT receipt FROM decisions WHERE id=0").fetchone()[0])
            revoked = [row[0] for row in db.execute("SELECT grant_id FROM revoked ORDER BY grant_id")]
        history = []
        journal_head = None
        if self.journal.path.exists():
            with closing(sqlite3.connect(self.journal.path.as_uri() + "?mode=ro", uri=True)) as journal:
                history = [json.loads(raw) for raw, in journal.execute("SELECT record FROM history ORDER BY seq")]
            journal_head = inspect_history(history, self.journal.enrollment, self.target_key.pub)
        try:
            verifier = self.verifier.head()
        except ValueError as exc:
            verifier = {"outcome": "BLOCKED", "reason": str(exc)}
        print(json.dumps({"test": self._testMethodName, "responses": self.responses, "effects": effects,
                          "revoked": revoked, "target_head": target_head, "journal_head": journal_head,
                          "journal_history": history, "verifier": verifier}))
        super().tearDown()


class CustodyObservation(Observation, CustodyTests):
    pass


class ClosureObservation(Observation, ClosureTests):
    pass


if __name__ == "__main__":
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
                               for cls in (CustodyObservation, ClosureObservation))
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(int(not result.wasSuccessful() or bool(result.skipped) or result.testsRun != expected))
