#!/usr/bin/env python3
# bridge/emu/tests/run_tests.py: runs the bridge's Python test suite (S5 §14 `test:emu` lane, Python half).
#   python -I bridge/emu/tests/run_tests.py [-k PATTERN] [-q]
# Lanes that need unicorn/capstone/pefile or the gcc fixtures skip with a named reason when those are missing
# ("python with unicorn 2.1.x not found", "gcc toolchain unavailable: ..."). Every process a test started is killed
# at the end even when a test fails.
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import support  # noqa: E402


def main(argv):
    verbosity = 1 if "-q" in argv else 2
    patterns = [argv[i + 1] for i, a in enumerate(argv) if a == "-k" and i + 1 < len(argv)]
    loader = unittest.TestLoader()
    if patterns:
        loader.testNamePatterns = [f"*{p}*" for p in patterns]
    suite = loader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)
    leaked = []
    try:
        result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
        # leak assertion (S5 §14.1): every bridge a test started has exited by now
        leaked = [p.pid for p in support.OWNED if p.poll() is None]
    finally:
        support.kill_owned()
    if leaked:
        print(f"LEAK: bridge processes still running after the suite: {leaked} (killed)", file=sys.stderr)
    print(f"bridge processes started: {len(support.OWNED)}, leaked: {len(leaked)}", file=sys.stderr)
    return 0 if result.wasSuccessful() and not leaked else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
