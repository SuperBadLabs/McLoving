#!/usr/bin/env python3
"""Mutation-oriented tests for protected workflow aggregate checks."""

from __future__ import annotations

import importlib.util
import itertools
import re
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
VERIFIER = SCRIPT_DIR / "verify-workflow-aggregate.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("workflow_aggregate", VERIFIER)
assert SPEC and SPEC.loader
AGGREGATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AGGREGATE)

FOUNDATION_WORKFLOW = REPO_ROOT / ".github/workflows/foundation.yml"
WINDOWS_WORKFLOW = REPO_ROOT / ".github/workflows/windows-agent.yml"
RESULTS = ("success", "failure", "cancelled", "skipped", "unknown")


def workflow_jobs(path: Path) -> dict[str, str]:
    """Return top-level job ids and their complete indented YAML blocks."""
    text = path.read_text(encoding="utf-8")
    try:
        text = text.split("\njobs:\n", 1)[1]
    except IndexError as error:
        raise AssertionError(f"workflow has no jobs mapping: {path}") from error
    matches = list(re.finditer(r"(?m)^  ([a-z0-9-]+):\n", text))
    return {
        match.group(1): text[match.start() : matches[index + 1].start()]
        if index + 1 < len(matches)
        else text[match.start() :]
        for index, match in enumerate(matches)
    }


def needs(block: str) -> tuple[str, ...]:
    match = re.search(r"(?m)^    needs:\n((?:^      - [a-z0-9-]+\n)+)", block)
    if not match:
        return ()
    return tuple(re.findall(r"(?m)^      - ([a-z0-9-]+)$", match.group(1)))


def assert_rejected(test: unittest.TestCase, function, values: dict[str, str]) -> None:
    with redirect_stdout(StringIO()), test.assertRaises(AGGREGATE.AggregateError):
        function(values)


class AggregateDecisionTests(unittest.TestCase):
    def test_foundation_accepts_only_all_success(self) -> None:
        # This is the complete 5^8 state space, not one mutation per lane.
        # It proves success has exactly one accepting state and that multiple
        # simultaneous failures cannot interact into an accidental pass.
        with redirect_stdout(StringIO()):
            for combination in itertools.product(
                RESULTS, repeat=len(AGGREGATE.FOUNDATION_JOBS)
            ):
                candidate = dict(zip(AGGREGATE.FOUNDATION_JOBS, combination))
                accepted = True
                try:
                    AGGREGATE.require_foundation(candidate)
                except AGGREGATE.AggregateError:
                    accepted = False
                self.assertEqual(
                    accepted,
                    all(result == "success" for result in combination),
                    combination,
                )

    def test_foundation_refuses_missing_or_unexpected_lanes(self) -> None:
        baseline = {job: "success" for job in AGGREGATE.FOUNDATION_JOBS}
        missing = dict(baseline)
        missing.pop(AGGREGATE.FOUNDATION_JOBS[0])
        unexpected = dict(baseline, surprise="success")
        assert_rejected(self, AGGREGATE.require_foundation, missing)
        assert_rejected(self, AGGREGATE.require_foundation, unexpected)

    def test_windows_accepts_only_the_two_consistent_outcomes(self) -> None:
        decisions = ("true", "false", "", "unknown")
        for impact, decision, windows in itertools.product(RESULTS, decisions, RESULTS):
            values = {
                "impact": impact,
                "run-windows": decision,
                "windows-agent": windows,
            }
            accepted = impact == "success" and (
                (decision == "true" and windows == "success")
                or (decision == "false" and windows == "skipped")
            )
            with self.subTest(impact=impact, decision=decision, windows=windows):
                if accepted:
                    with redirect_stdout(StringIO()):
                        AGGREGATE.require_windows(values)
                else:
                    assert_rejected(self, AGGREGATE.require_windows, values)

    def test_parser_refuses_malformed_or_duplicate_fields(self) -> None:
        for values in (("rust",), ("=success",), ("rust=success", "rust=failure")):
            with self.subTest(values=values), self.assertRaises(AGGREGATE.AggregateError):
                AGGREGATE.parse_results(values)


class WorkflowWiringTests(unittest.TestCase):
    def test_foundation_aggregate_covers_every_terminal_lane(self) -> None:
        jobs = workflow_jobs(FOUNDATION_WORKFLOW)
        self.assertEqual(
            set(jobs),
            {
                "rust-lint",
                "rust-tests",
                "rust-source-acquirer",
                "rust-boundary-suites",
                "rust",
                "dependencies",
                "secrets",
                "architecture",
                "formal",
                "controller-postgres",
                "recovery-drill",
                "deployment",
                "foundation",
            },
        )
        self.assertEqual(needs(jobs["rust"]), (
            "rust-lint",
            "rust-tests",
            "rust-source-acquirer",
            "rust-boundary-suites",
        ))
        self.assertEqual(needs(jobs["foundation"]), AGGREGATE.FOUNDATION_JOBS)
        self.assertIn("\n    name: Foundation\n", jobs["foundation"])
        self.assertIn("\n    if: always()\n", jobs["foundation"])

        env_names = {
            "rust": "RUST_RESULT",
            "dependencies": "DEPENDENCIES_RESULT",
            "secrets": "SECRETS_RESULT",
            "architecture": "ARCHITECTURE_RESULT",
            "formal": "FORMAL_RESULT",
            "controller-postgres": "CONTROLLER_POSTGRES_RESULT",
            "recovery-drill": "RECOVERY_DRILL_RESULT",
            "deployment": "DEPLOYMENT_RESULT",
        }
        for job, env_name in env_names.items():
            self.assertIn(
                f"{env_name}: ${{{{ needs.{job}.result }}}}", jobs["foundation"]
            )
            self.assertIn(f'{job}="${{{env_name}}}"', jobs["foundation"])
        self.assertIn(
            "python3 scripts/verify-workflow-aggregate.py foundation",
            jobs["foundation"],
        )

    def test_windows_aggregate_covers_classification_and_execution(self) -> None:
        jobs = workflow_jobs(WINDOWS_WORKFLOW)
        self.assertEqual(set(jobs), {"impact", "windows-agent", "windows"})
        self.assertEqual(needs(jobs["windows"]), ("impact", "windows-agent"))
        self.assertIn("\n    name: Windows\n", jobs["windows"])
        self.assertIn("\n    if: always()\n", jobs["windows"])
        self.assertIn("IMPACT_RESULT: ${{ needs.impact.result }}", jobs["windows"])
        self.assertIn(
            "RUN_WINDOWS: ${{ needs.impact.outputs.run-windows }}", jobs["windows"]
        )
        self.assertIn(
            "WINDOWS_AGENT_RESULT: ${{ needs.windows-agent.result }}", jobs["windows"]
        )
        for argument in (
            'impact="${IMPACT_RESULT}"',
            'run-windows="${RUN_WINDOWS}"',
            'windows-agent="${WINDOWS_AGENT_RESULT}"',
        ):
            self.assertIn(argument, jobs["windows"])
        self.assertIn(
            "python3 scripts/verify-workflow-aggregate.py windows", jobs["windows"]
        )

    def test_hosted_and_local_gates_run_this_suite(self) -> None:
        foundation = FOUNDATION_WORKFLOW.read_text(encoding="utf-8")
        local = (SCRIPT_DIR / "validate-foundation.sh").read_text(encoding="utf-8")
        self.assertIn("python3 scripts/test-workflow-aggregate.py", foundation)
        self.assertIn('python3 "${repo_root}/scripts/test-workflow-aggregate.py"', local)
        self.assertIn("source tools/versions.env", foundation)
        self.assertIn("${ACTIONLINT_VERSION}", foundation)
        self.assertIn("${ACTIONLINT_SHA256}", foundation)
        self.assertIn('"${actionlint_dir}/actionlint" .github/workflows/*.yml', foundation)


if __name__ == "__main__":
    unittest.main()
