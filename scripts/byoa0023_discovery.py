"""Inventory every discovered test and execute the explicitly bounded defensive suite."""
import argparse
import json
from pathlib import Path
import sys
import unittest

EXCLUDED = "test_byoa002_target.TargetAuthorityTests.test_joint_store_restore_requires_a_separately_retained_head"


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    loader = unittest.TestLoader()
    tests = list(flatten(loader.discover(".")))
    ids = [test.id() for test in tests]
    selected = [test for test in tests if test.id() != EXCLUDED]
    args.inventory.write_text(json.dumps({"discovered": ids, "excluded": [EXCLUDED],
                                          "loader_errors": loader.errors}, indent=2) + "\n")
    if loader.errors or ids.count(EXCLUDED) != 1 or len(set(ids)) != len(ids):
        raise SystemExit("inconsistent discovery inventory")
    class ExecutionLog(unittest.TextTestResult):
        def startTest(self, test):
            self.started.append(test.id())
            super().startTest(test)

        def startTestRun(self):
            self.started = []
            super().startTestRun()

    result = unittest.TextTestRunner(verbosity=2, resultclass=ExecutionLog).run(unittest.TestSuite(selected))
    inventory = json.loads(args.inventory.read_text())
    inventory.update(started=result.started, completed_count=result.testsRun,
                     failures=[test.id() for test, _ in result.failures],
                     errors=[test.id() for test, _ in result.errors],
                     skipped=[test.id() for test, _ in result.skipped])
    args.inventory.write_text(json.dumps(inventory, indent=2) + "\n")
    return int(not result.wasSuccessful() or bool(result.skipped or result.expectedFailures)
               or result.started != [test_id for test_id in ids if test_id != EXCLUDED])


if __name__ == "__main__":
    sys.exit(main())
