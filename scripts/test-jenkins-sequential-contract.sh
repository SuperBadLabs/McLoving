#!/usr/bin/env bash
# Read-only fixture authoring gates; this does not execute Jenkinsfiles or shells.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
fixture_dir="${repo_root}/compat/jenkins-worker/fixtures/sequential-v1"

PYTHONDONTWRITEBYTECODE=1 python3 "${fixture_dir}/validate.py"
PYTHONDONTWRITEBYTECODE=1 python3 - "${fixture_dir}" <<'PY'
import sys
import unittest

suite = unittest.defaultTestLoader.discover(sys.argv[1], pattern="test_manifest.py")
expected = 17
actual = suite.countTestCases()
if actual != expected:
    raise SystemExit(f"fixture integrity test population changed: expected {expected}, got {actual}")
result = unittest.TextTestRunner(verbosity=1).run(suite)
if not result.wasSuccessful() or result.skipped or result.testsRun != expected:
    raise SystemExit("fixture integrity tests failed, skipped, or did not execute completely")
PY

(
  cd "${repo_root}/compat/jenkins-worker"
  timeout 60 clojure -M:foundation fixtures/sequential-v1/check_literals.clj "${repo_root}"
)
