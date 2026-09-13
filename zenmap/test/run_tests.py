#!/usr/bin/env python3

import unittest

if __name__ == "__main__":
    import sys
    import os
    if not hasattr(unittest.defaultTestLoader, "discover"):
        print("Python unittest discovery missing. Requires Python 3.0 or newer.")  # noqa
        sys.exit(0)

    test_dir = os.path.dirname(os.path.abspath(__file__))
    zenmap_dir = os.path.dirname(test_dir)
    os.chdir(zenmap_dir)
    suite = unittest.defaultTestLoader.discover(
        start_dir="test",
        pattern="*.py"
        )
    res = unittest.TextTestRunner().run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
