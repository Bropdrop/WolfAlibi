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
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(selected))
    return int(not result.wasSuccessful() or bool(result.skipped or result.expectedFailures)
               or result.testsRun != len(selected))


if __name__ == "__main__":
    sys.exit(main())
