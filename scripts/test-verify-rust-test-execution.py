#!/usr/bin/env python3
"""Negative controls for the focused Rust test-execution verifier."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-rust-test-execution.py")
RUNNER = Path(__file__).with_name("run-verified-rust-test.sh")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("verify_rust_test_execution", SCRIPT)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def summary(passed: int, failed: int = 0) -> str:
    return (
        f"running {passed + failed} tests\n"
        f"test result: ok. {passed} passed; {failed} failed; 0 ignored; "
        "0 measured; 0 filtered out; finished in 0.01s\n"
    )


class ExactRustTestExecutionTests(unittest.TestCase):
    def test_exact_population_is_accepted(self) -> None:
        self.assertEqual(VERIFY.require_exact_execution(summary(6), 6, "suite"), 6)

    def test_zero_tests_is_not_success(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "observed 0 passed"):
            VERIFY.require_exact_execution(summary(0), 1, "canary")

    def test_partial_population_is_refused(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "observed 5 passed"):
            VERIFY.require_exact_execution(summary(5), 6, "suite")

    def test_missing_summary_is_refused(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "found 0"):
            VERIFY.require_exact_execution("cargo exited without a summary", 1, "canary")

    def test_multiple_summaries_cannot_hide_a_zero_test_run(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "found 2"):
            VERIFY.require_exact_execution(summary(0) + summary(1), 1, "canary")

    def test_failed_tests_are_refused_even_if_pass_count_matches(self) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, "1 failed"):
            VERIFY.require_exact_execution(summary(1, 1), 1, "canary")

    def test_postgres_runner_refuses_a_missing_database_url(self) -> None:
        environment = os.environ.copy()
        environment.pop("MCLOVING_TEST_DATABASE_URL", None)
        result = subprocess.run(
            ["bash", RUNNER, "1", "database-suite", "--require-postgres", "true"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires MCLOVING_TEST_DATABASE_URL", result.stderr)

    def test_runner_accepts_one_exact_successful_summary(self) -> None:
        environment = os.environ.copy()
        environment["MCLOVING_TEST_DATABASE_URL"] = "postgres://unused"
        result = subprocess.run(
            [
                "bash",
                RUNNER,
                "1",
                "database-suite",
                "--require-postgres",
                "bash",
                "-c",
                f"printf '%b' {summary(1)!r}",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rust-test-execution-ok", result.stdout)

    def test_runner_propagates_a_test_command_failure(self) -> None:
        result = subprocess.run(
            ["bash", RUNNER, "1", "failed-suite", "bash", "-c", "exit 7"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("command failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
