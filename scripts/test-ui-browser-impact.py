#!/usr/bin/env python3
"""Tests for the UI browser impact classifier.

The classifier is the only thing standing between "the browser gate did not run"
and "the browser gate was not needed". Every test here is about the difference
between those two, because a classifier that silently answers `false` turns a
required lane into an implicit waiver -- the TM-052 shape.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent / "ui-browser-impact.py"
_spec = importlib.util.spec_from_file_location("ui_browser_impact", MODULE_PATH)
IMPACT = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(IMPACT)


class Repository:
    """A throwaway git repository, so the tests classify real diffs."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def seed(self) -> str:
        """A baseline tree carrying every path the classifier knows about."""
        for path in sorted(IMPACT.CLIENT_PATHS):
            self.write(path, "\n".join(f"line {n}" for n in range(60)) + "\n")
        for path in sorted(IMPACT.GATE_DEFINITION_PATHS | IMPACT.SERVING_PATHS):
            self.write(path, "original\n")
        self.write("README.md", "unrelated\n")
        return self.commit("seed")


class ClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.repository = Repository(Path(self._temporary.name))
        self.base = self.repository.seed()

    def classify(self) -> tuple[bool, bool, str]:
        head = self.repository.commit("change")
        return IMPACT.classify(self.base, head, self.repository.root)

    def test_unrelated_change_runs_nothing(self) -> None:
        self.repository.write("README.md", "still unrelated, but edited\n")
        run_gate, run_mutations, reason = self.classify()
        self.assertFalse(run_gate)
        self.assertFalse(run_mutations)
        self.assertIn("no UI", reason)

    def test_every_gate_definition_path_runs_the_full_lane(self) -> None:
        # Enumerated rather than sampled: a path silently dropped from the set
        # is exactly how a gate stops being re-proved.
        for path in sorted(IMPACT.GATE_DEFINITION_PATHS):
            with self.subTest(path=path):
                repository = Repository(Path(tempfile.mkdtemp(dir=self._temporary.name)))
                base = repository.seed()
                repository.write(path, "changed\n")
                head = repository.commit("change")
                run_gate, run_mutations, reason = IMPACT.classify(
                    base, head, repository.root
                )
                self.assertTrue(run_gate, reason)
                self.assertTrue(run_mutations, reason)

    def test_serving_change_runs_the_gate_but_not_the_mutation_proof(self) -> None:
        self.repository.write("crates/controller-api/src/lib.rs", "changed\n")
        run_gate, run_mutations, reason = self.classify()
        self.assertTrue(run_gate)
        self.assertFalse(run_mutations)
        self.assertIn("served", reason)

    def test_small_client_change_runs_the_gate_only(self) -> None:
        self.repository.write(
            "crates/controller-api/ui/app.css",
            "\n".join(f"line {n}" for n in range(59)) + "\nadded\n",
        )
        run_gate, run_mutations, reason = self.classify()
        self.assertTrue(run_gate)
        self.assertFalse(run_mutations, reason)

    def test_client_change_at_the_threshold_runs_the_mutation_proof(self) -> None:
        # Exactly at the boundary, because ">" instead of ">=" here would waive
        # the proof for the very change the threshold was chosen to catch.
        replaced = IMPACT.MUTATION_LINE_THRESHOLD // 2
        lines = [f"line {n}" for n in range(60)]
        for index in range(replaced):
            lines[index] = f"changed {index}"
        self.repository.write(
            "crates/controller-api/ui/app.js", "\n".join(lines) + "\n"
        )
        run_gate, run_mutations, reason = self.classify()
        self.assertTrue(run_gate)
        self.assertTrue(run_mutations, reason)
        self.assertIn(str(IMPACT.MUTATION_LINE_THRESHOLD), reason)

    def test_client_change_below_the_threshold_does_not_run_the_proof(self) -> None:
        lines = [f"line {n}" for n in range(60)]
        lines[0] = "changed"
        self.repository.write(
            "crates/controller-api/ui/app.js", "\n".join(lines) + "\n"
        )
        run_gate, run_mutations, _ = self.classify()
        self.assertTrue(run_gate)
        self.assertFalse(run_mutations)

    def test_unreadable_revisions_raise_rather_than_answering_false(self) -> None:
        """classify() must refuse, not guess. main() turns that into a full run."""
        with self.assertRaises(IMPACT.ClassificationError):
            IMPACT.classify("does-not-exist", "also-missing", self.repository.root)

    def test_main_turns_a_classification_failure_into_a_full_run(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(MODULE_PATH),
                "--base",
                "does-not-exist",
                "--head",
                "also-missing",
                "--repository",
                str(self.repository.root),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("run-ui-gate=true", completed.stdout)
        self.assertIn("run-ui-mutations=true", completed.stdout)
        self.assertIn("classification failed", completed.stderr)

    def test_the_classifier_knows_about_every_gate_file_that_exists(self) -> None:
        """A gate file the classifier has never heard of is never re-proved."""
        repository_root = Path(__file__).resolve().parent.parent
        tracked = {
            path
            for path in subprocess.run(
                ["git", "ls-files", "scripts/ui-browser", "scripts/test-ui-browser.sh",
                 "scripts/test-ui-browser-mutations.py", "scripts/verify-ui-browser-gate.py",
                 "scripts/ui-browser-impact.py", "scripts/test-ui-browser-impact.py"],
                cwd=repository_root,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.split()
        }
        missing = sorted(tracked - IMPACT.GATE_DEFINITION_PATHS)
        self.assertEqual(
            missing,
            [],
            f"gate files the impact classifier does not watch: {missing}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=1)
