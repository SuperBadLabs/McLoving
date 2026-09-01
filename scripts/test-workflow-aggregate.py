#!/usr/bin/env python3
"""Mutation-oriented tests for protected workflow aggregate checks."""

from __future__ import annotations

import importlib.util
import itertools
import os
import re
import subprocess
import sys
import tempfile
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
WINDOWS_IMPACT = SCRIPT_DIR / "windows-agent-impact.py"
RESULTS = ("success", "failure", "cancelled", "skipped", "unknown")
CHECKOUT_STEP = (
    "      - name: Check out aggregate verifier\n"
    "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
)
SOURCE_CHECKOUT_STEP = (
    "      - name: Check out source\n"
    "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
)
HOSTED_SUITE_STEP = (
    "      - name: Test protected workflow aggregates\n"
    "        run: /usr/bin/python3 -I scripts/test-workflow-aggregate.py\n"
)
ACTIONLINT_STEP = (
    "      - name: Lint workflows with verified actionlint\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    "          source tools/versions.env\n"
    '          actionlint_archive="${RUNNER_TEMP}/actionlint-${ACTIONLINT_VERSION}.tar.gz"\n'
    '          actionlint_dir="${RUNNER_TEMP}/actionlint-${ACTIONLINT_VERSION}"\n'
    "          curl --fail --location --silent --show-error \\\n"
    '            "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" \\\n'
    '            --output "${actionlint_archive}"\n'
    "          printf '%s  %s\\n' \"${ACTIONLINT_SHA256}\" \"${actionlint_archive}\" \\\n"
    "            | sha256sum -c -\n"
    '          install -d -m 0755 "${actionlint_dir}"\n'
    '          tar -xzf "${actionlint_archive}" -C "${actionlint_dir}"\n'
    '          "${actionlint_dir}/actionlint" .github/workflows/*.yml\n'
)
FOUNDATION_RUN = (
    "          /usr/bin/python3 -I scripts/verify-workflow-aggregate.py foundation \\\n"
    "            rust=\"${RUST_RESULT}\" \\\n"
    "            dependencies=\"${DEPENDENCIES_RESULT}\" \\\n"
    "            secrets=\"${SECRETS_RESULT}\" \\\n"
    "            architecture=\"${ARCHITECTURE_RESULT}\" \\\n"
    "            formal=\"${FORMAL_RESULT}\" \\\n"
    "            controller-postgres=\"${CONTROLLER_POSTGRES_RESULT}\" \\\n"
    "            recovery-drill=\"${RECOVERY_DRILL_RESULT}\" \\\n"
    "            deployment=\"${DEPLOYMENT_RESULT}\"\n"
)
WINDOWS_RUN = (
    "          /usr/bin/python3 -I scripts/verify-workflow-aggregate.py windows \\\n"
    "            impact=\"${IMPACT_RESULT}\" \\\n"
    "            run-windows=\"${RUN_WINDOWS}\" \\\n"
    "            windows-agent=\"${WINDOWS_AGENT_RESULT}\"\n"
)
FOUNDATION_ENV = (
    ("RUST_RESULT", "${{ needs.rust.result }}"),
    ("DEPENDENCIES_RESULT", "${{ needs.dependencies.result }}"),
    ("SECRETS_RESULT", "${{ needs.secrets.result }}"),
    ("ARCHITECTURE_RESULT", "${{ needs.architecture.result }}"),
    ("FORMAL_RESULT", "${{ needs.formal.result }}"),
    ("CONTROLLER_POSTGRES_RESULT", "${{ needs.controller-postgres.result }}"),
    ("RECOVERY_DRILL_RESULT", "${{ needs.recovery-drill.result }}"),
    ("DEPLOYMENT_RESULT", "${{ needs.deployment.result }}"),
)
WINDOWS_ENV = (
    ("IMPACT_RESULT", "${{ needs.impact.result }}"),
    ("RUN_WINDOWS", "${{ needs.impact.outputs.run-windows }}"),
    ("WINDOWS_AGENT_RESULT", "${{ needs.windows-agent.result }}"),
)
WINDOWS_IMPACT_JOB = r"""  impact:
    name: Classify Windows impact
    runs-on: ubuntu-24.04
    outputs:
      run-windows: ${{ steps.impact.outputs.run-windows }}
    steps:
      - name: Check out source and comparison history
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - name: Classify exact change
        id: impact
        env:
          EVENT_NAME: ${{ github.event_name }}
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
        run: |
          if [[ "${EVENT_NAME}" == "push" ]]; then
            printf 'run-windows=true\n' >> "${GITHUB_OUTPUT}"
          else
            /usr/bin/python3 -I scripts/windows-agent-impact.py \
              --base "${BASE_SHA}" \
              --head "${HEAD_SHA}" \
              >> "${GITHUB_OUTPUT}"
          fi
      - name: Install pinned Rust toolchain
        if: github.event_name == 'pull_request'
        run: rustup toolchain install 1.97.1 --profile minimal
      - name: Test impact classifier
        if: github.event_name == 'pull_request'
        run: /usr/bin/python3 -I scripts/test-windows-agent-impact.py

"""


def workflow_jobs(path: Path) -> dict[str, str]:
    """Return top-level job ids and their complete indented YAML blocks."""
    text = path.read_text(encoding="utf-8")
    try:
        prefix, text = text.split("\njobs:\n", 1)
    except IndexError as error:
        raise AssertionError(f"workflow has no jobs mapping: {path}") from error
    top_level = tuple(
        line
        for line in prefix.splitlines()
        if line and not line[0].isspace() and not line.startswith("#")
    )
    allowed_top_levels = {
        ("name: Foundation", "on:", "permissions:", "concurrency:"),
        ("name: Windows Agent", "on:", "permissions:", "concurrency:"),
    }
    if top_level not in allowed_top_levels:
        raise AssertionError(f"workflow has noncanonical top-level controls: {path}")
    trailing_top_level = tuple(
        line
        for line in text.splitlines()
        if line and not line[0].isspace() and not line.startswith("#")
    )
    if trailing_top_level:
        raise AssertionError(f"workflow has controls after the jobs mapping: {path}")
    job_lines = tuple(
        line
        for line in text.splitlines()
        if line.startswith("  ")
        and not line.startswith("    ")
        and line.strip()
        and not line[2:].startswith("#")
    )
    if any(not re.fullmatch(r"  [a-z0-9-]+:", line) for line in job_lines):
        raise AssertionError(f"workflow has a noncanonical job key: {path}")
    job_ids = tuple(line[2:-1] for line in job_lines)
    if len(job_ids) != len(set(job_ids)):
        raise AssertionError(f"workflow has a duplicate job key: {path}")
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


def step_blocks(block: str) -> tuple[str, ...]:
    """Return the exact step mappings inside one top-level job block."""
    steps = block.split("\n    steps:\n", 1)[1]
    matches = list(re.finditer(r"(?m)^      -(?: .*)?$", steps))
    return tuple(
        steps[match.start() : matches[index + 1].start()]
        if index + 1 < len(matches)
        else steps[match.start() :]
        for index, match in enumerate(matches)
    )


def assert_safe_aggregate_job(
    test: unittest.TestCase,
    block: str,
    *,
    expected_name: str,
    expected_needs: tuple[str, ...],
    expected_step_name: str,
    expected_env: tuple[tuple[str, str], ...],
    expected_run: str,
) -> None:
    """Reject workflow controls that can turn verifier failure into success."""
    test.assertNotIn("continue-on-error:", block)
    job_fields = tuple(
        line[4:]
        for line in block.splitlines()
        if line.startswith("    ")
        and not line.startswith("      ")
        and line.strip()
        and not line[4:].startswith("#")
    )
    test.assertEqual(
        job_fields,
        (
            f"name: {expected_name}",
            "runs-on: ubuntu-24.04",
            "needs:",
            "if: always()",
            "steps:",
        ),
    )
    test.assertEqual(needs(block), expected_needs)

    steps = step_blocks(block)
    test.assertEqual(len(steps), 2)
    checkout, verifier = steps
    test.assertEqual(checkout, CHECKOUT_STEP)
    test.assertEqual(
        re.findall(r"(?m)^        ([a-z][a-z-]*):", checkout),
        ["uses"],
    )
    test.assertEqual(
        re.findall(r"(?m)^        ([a-z][a-z-]*):", verifier),
        ["env", "run"],
    )
    test.assertNotIn("\n        if:", verifier)
    expected_verifier = (
        f"      - name: {expected_step_name}\n"
        "        env:\n"
        + "".join(f"          {key}: {value}\n" for key, value in expected_env)
        + "        run: |\n"
        + expected_run
    )
    test.assertEqual(verifier, expected_verifier)
    test.assertEqual(
        tuple(re.findall(r"(?m)^          ([A-Z][A-Z0-9_]*): (.+)$", verifier)),
        expected_env,
    )
    test.assertEqual(verifier.split("        run: |\n", 1)[1], expected_run)


def assert_exact_windows_impact(test: unittest.TestCase, block: str) -> None:
    """Pin classifier controls, trust order, environment, and commands."""
    test.assertEqual(block, WINDOWS_IMPACT_JOB)


def assert_rejected(test: unittest.TestCase, function, values: dict[str, str]) -> None:
    with redirect_stdout(StringIO()), test.assertRaises(AGGREGATE.AggregateError):
        function(values)


def assert_exact_command(test: unittest.TestCase, text: str, command: str) -> None:
    """Require one executable line with no shell suffix or duplicate."""
    test.assertEqual(
        re.findall(rf"(?m)^[ \t]*({re.escape(command)})[ \t]*$", text),
        [command],
    )


class AggregateDecisionTests(unittest.TestCase):
    def test_isolated_python_refuses_candidate_module_shadowing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / VERIFIER.name
            candidate.write_text(VERIFIER.read_text(encoding="utf-8"), encoding="utf-8")
            (Path(directory) / "argparse.py").write_text(
                "raise SystemExit(41)\n", encoding="utf-8"
            )
            valid = [
                sys.executable,
                "-I",
                str(candidate),
                "foundation",
                *(f"{job}=success" for job in AGGREGATE.FOUNDATION_JOBS),
            ]
            isolated = subprocess.run(valid, capture_output=True, check=False)
            self.assertEqual(isolated.returncode, 0, isolated.stderr)
            shadowed = subprocess.run(
                [valid[0], *valid[2:]], capture_output=True, check=False
            )
            self.assertEqual(shadowed.returncode, 41)

            impact = Path(directory) / WINDOWS_IMPACT.name
            impact.write_text(
                WINDOWS_IMPACT.read_text(encoding="utf-8"), encoding="utf-8"
            )
            isolated_impact = subprocess.run(
                [sys.executable, "-I", str(impact), "--help"],
                capture_output=True,
                check=False,
            )
            self.assertEqual(isolated_impact.returncode, 0, isolated_impact.stderr)
            shadowed_impact = subprocess.run(
                [sys.executable, str(impact), "--help"],
                capture_output=True,
                check=False,
            )
            self.assertEqual(shadowed_impact.returncode, 41)

    def test_foundation_accepts_only_all_success(self) -> None:
        # This is the complete 5^8 state space, not one mutation per lane.
        # It proves success has exactly one accepting state and that multiple
        # simultaneous failures cannot interact into an accidental pass.
        # Discard millions of diagnostic lines instead of retaining them in a
        # StringIO while the complete state space is exercised.
        with open(os.devnull, "w", encoding="utf-8") as sink, redirect_stdout(sink):
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
        assert_safe_aggregate_job(
            self,
            jobs["foundation"],
            expected_name="Foundation",
            expected_needs=AGGREGATE.FOUNDATION_JOBS,
            expected_step_name="Require every Foundation lane to succeed",
            expected_env=FOUNDATION_ENV,
            expected_run=FOUNDATION_RUN,
        )

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
            "/usr/bin/python3 -I scripts/verify-workflow-aggregate.py foundation",
            jobs["foundation"],
        )

    def test_windows_aggregate_covers_classification_and_execution(self) -> None:
        workflow = WINDOWS_WORKFLOW.read_text(encoding="utf-8")
        jobs = workflow_jobs(WINDOWS_WORKFLOW)
        self.assertEqual(set(jobs), {"impact", "windows-agent", "windows"})
        assert_exact_windows_impact(self, jobs["impact"])
        self.assertEqual(needs(jobs["windows"]), ("impact", "windows-agent"))
        assert_safe_aggregate_job(
            self,
            jobs["windows"],
            expected_name="Windows",
            expected_needs=("impact", "windows-agent"),
            expected_step_name="Require the classified Windows outcome",
            expected_env=WINDOWS_ENV,
            expected_run=WINDOWS_RUN,
        )
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
            "/usr/bin/python3 -I scripts/verify-workflow-aggregate.py windows",
            jobs["windows"],
        )
        assert_exact_command(
            self,
            workflow,
            "run: /usr/bin/python3 -I scripts/test-windows-agent-impact.py",
        )
        assert_exact_command(
            self, workflow, "/usr/bin/python3 -I scripts/windows-agent-impact.py \\"
        )
        impact_mutations = {
            "job PATH override": jobs["impact"].replace(
                "    outputs:\n",
                "    env:\n      PATH: ${{ github.workspace }}/attacker-bin:/usr/bin:/bin\n"
                "    outputs:\n",
            ),
            "mutable predecessor": jobs["impact"].replace(
                "      - name: Classify exact change\n",
                "      - name: Install candidate command wrapper\n"
                "        run: printf attacker >> \"${GITHUB_PATH}\"\n"
                "      - name: Classify exact change\n",
            ),
        }
        for name, mutation in impact_mutations.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                assert_exact_windows_impact(self, mutation)

    def test_fail_open_workflow_controls_are_rejected(self) -> None:
        jobs = workflow_jobs(FOUNDATION_WORKFLOW)
        baseline = jobs["foundation"]
        mutations = {
            "job continue-on-error": baseline.replace(
                "    if: always()\n", "    continue-on-error: true\n    if: always()\n"
            ),
            "quoted job continue-on-error": baseline.replace(
                "    if: always()\n",
                '    "continue-on-error": true\n    if: always()\n',
            ),
            "spaced job continue-on-error": baseline.replace(
                "    if: always()\n",
                "    continue-on-error : true\n    if: always()\n",
            ),
            "verifier continue-on-error": baseline.replace(
                "      - name: Require every Foundation lane to succeed\n",
                "      - name: Require every Foundation lane to succeed\n"
                "        continue-on-error: true\n",
            ),
            "verifier skipped": baseline.replace(
                "      - name: Require every Foundation lane to succeed\n",
                "      - name: Require every Foundation lane to succeed\n"
                "        if: false\n",
            ),
            "quoted verifier continue-on-error": baseline.replace(
                "      - name: Require every Foundation lane to succeed\n",
                "      - name: Require every Foundation lane to succeed\n"
                '        "continue-on-error": true\n',
            ),
            "extra success step": baseline
            + "      - name: Override failure\n        run: true\n",
            "unnamed verifier substitution step": baseline.replace(
                "    steps:\n",
                "    steps:\n"
                "      - run: printf malicious > scripts/verify-workflow-aggregate.py\n",
            ),
            "extra verifier environment": baseline.replace(
                "        env:\n",
                "        env:\n          PATH: /tmp/attacker-bin:/usr/bin:/bin\n",
            ),
            "quoted extra verifier environment": baseline.replace(
                "        env:\n",
                '        env:\n          "PATH": ${{ github.workspace }}/attacker-bin:/usr/bin:/bin\n',
            ),
            "mutable checkout with pinned digest in comment": baseline.replace(
                "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n",
                "        uses: actions/checkout@main # uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n",
            ),
            "verifier failure ignored in shell": baseline.replace(
                '            deployment="${DEPLOYMENT_RESULT}"\n',
                '            deployment="${DEPLOYMENT_RESULT}" || true\n',
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                assert_safe_aggregate_job(
                    self,
                    mutation,
                    expected_name="Foundation",
                    expected_needs=AGGREGATE.FOUNDATION_JOBS,
                    expected_step_name="Require every Foundation lane to succeed",
                    expected_env=FOUNDATION_ENV,
                    expected_run=FOUNDATION_RUN,
                )

        workflow_text = FOUNDATION_WORKFLOW.read_text(encoding="utf-8")
        for name, suffix in {
            "quoted duplicate aggregate job": '\n  "foundation":\n    uses: attacker.yml\n',
            "plain duplicate aggregate job": "\n  foundation:\n    uses: attacker.yml\n",
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                candidate = Path(directory) / "mutation.yml"
                try:
                    candidate.write_text(workflow_text + suffix, encoding="utf-8")
                    with self.assertRaises(AssertionError):
                        workflow_jobs(candidate)
                finally:
                    candidate.unlink(missing_ok=True)

    def test_hosted_and_local_gates_run_this_suite(self) -> None:
        foundation = FOUNDATION_WORKFLOW.read_text(encoding="utf-8")
        local = (SCRIPT_DIR / "validate-foundation.sh").read_text(encoding="utf-8")
        hosted_command = "/usr/bin/python3 -I scripts/test-workflow-aggregate.py"
        local_command = 'python3 -I "${repo_root}/scripts/test-workflow-aggregate.py"'
        architecture = workflow_jobs(FOUNDATION_WORKFLOW)["architecture"]
        architecture_fields = tuple(
            line[4:]
            for line in architecture.splitlines()
            if line.startswith("    ")
            and not line.startswith("      ")
            and line.strip()
            and not line[4:].startswith("#")
        )
        self.assertEqual(
            architecture_fields,
            ("name: Architecture records", "runs-on: ubuntu-24.04", "steps:"),
        )
        architecture_steps = step_blocks(architecture)
        self.assertEqual(len(architecture_steps), 6)
        self.assertEqual(architecture_steps[0], SOURCE_CHECKOUT_STEP)
        self.assertEqual(architecture_steps[1], HOSTED_SUITE_STEP)
        self.assertEqual(architecture_steps[2], ACTIONLINT_STEP)
        assert_exact_command(self, local, local_command)

        suppressed_hosted = architecture.replace(
            hosted_command, hosted_command + " || true"
        )
        with self.assertRaises(AssertionError):
            self.assertEqual(step_blocks(suppressed_hosted)[1], HOSTED_SUITE_STEP)
        suppressed_local = local.replace(local_command, local_command + " || true")
        with self.assertRaises(AssertionError):
            assert_exact_command(self, suppressed_local, local_command)

    def test_workflow_level_shell_authority_is_rejected(self) -> None:
        workflow_text = FOUNDATION_WORKFLOW.read_text(encoding="utf-8")
        mutations = {
            "control before jobs": workflow_text.replace(
                "\njobs:\n",
                "\nenv:\n  BASH_ENV: scripts/bypass-aggregate.sh\n\njobs:\n",
            ),
            "flow-style control after jobs": workflow_text.replace(
                "\n  foundation:\n",
                "\nenv: {BASH_ENV: scripts/bypass-aggregate.sh}\n\n  foundation:\n",
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                candidate = Path(directory) / "foundation.yml"
                candidate.write_text(mutation, encoding="utf-8")
                with self.assertRaises(AssertionError):
                    workflow_jobs(candidate)


if __name__ == "__main__":
    unittest.main()
