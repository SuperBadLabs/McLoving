#!/usr/bin/env python3
"""Known-good and known-bad tests for the execution-board verifier."""

from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Callable
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = Path(__file__).with_name("verify-execution-board.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("verify_execution_board", SCRIPT)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

BoardTransform = Callable[[str], str]
ReadmeTransform = Callable[[str], str]


class ExecutionBoardVerifierTests(unittest.TestCase):
    def run_verifier(
        self,
        board_transform: BoardTransform = lambda text: text,
        readme_transform: ReadmeTransform = lambda text: text,
    ) -> tuple[int, str, str]:
        board_text = board_transform(
            (REPOSITORY / "docs" / "EXECUTION_BOARD.md").read_text(encoding="utf-8")
        )
        readme_text = readme_transform(
            (REPOSITORY / "README.md").read_text(encoding="utf-8")
        )

        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            scripts = root / "scripts"
            docs = root / "docs"
            scripts.mkdir()
            docs.mkdir()
            synthetic_script = scripts / SCRIPT.name
            synthetic_script.write_text("# verifier fixture\n", encoding="utf-8")
            (docs / "EXECUTION_BOARD.md").write_text(board_text, encoding="utf-8")
            (root / "README.md").write_text(readme_text, encoding="utf-8")

            original_file = VERIFY.__file__
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                VERIFY.__file__ = str(synthetic_script)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    try:
                        VERIFY.main()
                    except SystemExit as error:
                        code = int(error.code or 0)
                    else:
                        code = 0
            finally:
                VERIFY.__file__ = original_file

        return code, stdout.getvalue(), stderr.getvalue()

    def test_current_repository_passes(self) -> None:
        code, stdout, stderr = self.run_verifier()
        self.assertEqual(code, 0, stderr)
        self.assertIn("execution-board-ok", stdout)

    def test_staged_board_skips_commit_date_check(self) -> None:
        worktree_clean = mock.Mock(returncode=0)
        index_dirty = mock.Mock(returncode=1)
        with mock.patch.object(
            VERIFY.subprocess,
            "run",
            side_effect=(worktree_clean, index_dirty),
        ) as run:
            code, stdout, stderr = self.run_verifier()

        self.assertEqual(code, 0, stderr)
        self.assertIn("execution-board-ok", stdout)
        self.assertEqual(run.call_count, 2)

    def test_shallow_repository_skips_commit_date_check(self) -> None:
        worktree_clean = mock.Mock(returncode=0)
        index_clean = mock.Mock(returncode=0)
        shallow_repository = mock.Mock(returncode=0, stdout="true\n")
        with mock.patch.object(
            VERIFY.subprocess,
            "run",
            side_effect=(worktree_clean, index_clean, shallow_repository),
        ) as run:
            code, stdout, stderr = self.run_verifier()

        self.assertEqual(code, 0, stderr)
        self.assertIn("execution-board-ok", stdout)
        self.assertEqual(run.call_count, 3)

    def test_stale_current_slot_status_fails(self) -> None:
        expected_message = ""

        def stale_status(text: str) -> str:
            nonlocal expected_message
            match = next(
                (
                    VERIFY.CURRENT_SLOT_ROW.match(line)
                    for line in text.splitlines()
                    if VERIFY.CURRENT_SLOT_ROW.match(line)
                ),
                None,
            )
            self.assertIsNotNone(match)
            assert match is not None
            _, _, status = match.groups()
            replacement = "ACTIVE" if status != "ACTIVE" else "PENDING"
            old = match.group(0)
            new = old.replace(f"| {status} |", f"| {replacement} |", 1)
            expected_message = (
                f"is {replacement}, ticket table says {status}"
            )
            return text.replace(old, new, 1)

        code, _, stderr = self.run_verifier(board_transform=stale_status)
        self.assertEqual(code, 1)
        self.assertIn(expected_message, stderr)

    def test_nonremaining_current_slot_status_fails(self) -> None:
        expected_message = ""

        def nonremaining_status(text: str) -> str:
            nonlocal expected_message
            match = next(
                (
                    VERIFY.CURRENT_SLOT_ROW.match(line)
                    for line in text.splitlines()
                    if VERIFY.CURRENT_SLOT_ROW.match(line)
                ),
                None,
            )
            self.assertIsNotNone(match)
            assert match is not None
            _, _, status = match.groups()
            old = match.group(0)
            new = old.replace(f"| {status} |", "| DONE |", 1)
            expected_message = f"is DONE, ticket table says {status}"
            return text.replace(old, new, 1)

        code, _, stderr = self.run_verifier(board_transform=nonremaining_status)
        self.assertEqual(code, 1)
        self.assertIn(expected_message, stderr)

    def test_unknown_trailing_current_slot_status_fails(self) -> None:
        def unknown_status(text: str) -> str:
            matches = [
                match
                for line in text.splitlines()
                if (match := VERIFY.CURRENT_SLOT_ROW.match(line)) is not None
            ]
            self.assertTrue(matches)
            match = matches[-1]
            _, _, status = match.groups()
            old = match.group(0)
            new = old.replace(f"| {status} |", "| COMPLETE |", 1)
            return text.replace(old, new, 1)

        code, _, stderr = self.run_verifier(board_transform=unknown_status)
        self.assertEqual(code, 1)
        self.assertIn("has invalid status 'COMPLETE'", stderr)

    def test_unready_current_slot_fails(self) -> None:
        def unready_slot(text: str) -> str:
            old = "| 1 | `IDP-001` | ACTIVE |"
            self.assertIn(old, text)
            return text.replace(old, "| 1 | `AUTHZ-001` | PENDING |", 1)

        code, _, stderr = self.run_verifier(board_transform=unready_slot)
        self.assertEqual(code, 1)
        self.assertIn("unfinished dependencies: IDP-001", stderr)

    def test_pinned_protected_main_fails(self) -> None:
        def pin_head(text: str) -> str:
            heading = "## Current state and dispatch queue\n"
            self.assertIn(heading, text)
            return text.replace(
                heading,
                heading
                + "\nProtected `main` is `"
                + "a" * 40
                + "`.\n",
                1,
            )

        code, _, stderr = self.run_verifier(board_transform=pin_head)
        self.assertEqual(code, 1)
        self.assertIn("pins protected main to a commit", stderr)

    def test_invalid_updated_date_fails(self) -> None:
        def invalidate_date(text: str) -> str:
            match = VERIFY.UPDATED_ROW.search(text)
            self.assertIsNotNone(match)
            assert match is not None
            return text[: match.start(1)] + "2026-99-99" + text[match.end(1) :]

        code, _, stderr = self.run_verifier(board_transform=invalidate_date)
        self.assertEqual(code, 1)
        self.assertIn("invalid Updated date", stderr)

    def test_obsolete_readme_claim_fails(self) -> None:
        code, _, stderr = self.run_verifier(
            readme_transform=lambda text: text
            + "\nThe binary crates are compilable placeholders.\n"
        )
        self.assertEqual(code, 1)
        self.assertIn("README contains obsolete implementation claim", stderr)


if __name__ == "__main__":
    unittest.main()
