#!/usr/bin/env python3
import sys
import unittest

if __name__ == "__main__":
    test_args = [a for a in sys.argv[1:] if not a.startswith("-")]
    # Reset sys.argv so option_parser doesn't try to parse pytest flags like -q
    sys.argv = [sys.argv[0]]

    if not test_args:
        test_args = ["zenmap/test/test_tui.py"]

    suite = unittest.TestSuite()
    for arg in test_args:
        if arg.endswith(".py"):
            mod_name = arg[:-3].replace("/", ".")
        else:
            mod_name = arg.replace("/", ".")
        try:
            suite.addTests(unittest.defaultTestLoader.loadTestsFromName(mod_name))
        except Exception:
            suite.addTests(unittest.defaultTestLoader.discover(start_dir="zenmap/test", pattern="test_*.py"))

    runner = unittest.TextTestRunner(verbosity=1)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
