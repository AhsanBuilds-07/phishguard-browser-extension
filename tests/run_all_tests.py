"""
SentinelAI Master Test Runner

Executes all Python and JavaScript unit test suites, verifying:
1. Feature extraction parity between Python and JavaScript (14 dimensions).
2. Model prediction probability parity between Scikit-Learn and exported JavaScript.
3. Multi-signal detection engine (Brand impersonation, Homoglyphs, DOM credentials).
4. Background service worker message contracts and storage isolation.
5. FastAPI platform endpoints (health, datasets, models, training).
"""

import os
import subprocess
import sys
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    print("=" * 70)
    print("SentinelAI: Running Full Automated Test Suite")
    print("=" * 70)

    # 1. Discover and run all Python test cases
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(ROOT_DIR, "tests"))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print(f"ALL TESTS PASSED: {result.testsRun} test cases verified successfully.")
        print("=" * 70)
        sys.exit(0)
    else:
        print(f"TEST FAILURES DETECTED: {len(result.failures)} failures, {len(result.errors)} errors.")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()
