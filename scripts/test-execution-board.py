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

    def test_malformed_trailing_current_slot_ticket_fails(self) -> None:
        def malformed_ticket(text: str) -> str:
            matches = [
                match
                for line in text.splitlines()
                if (match := VERIFY.CURRENT_SLOT_ROW.match(line)) is not None
            ]
            self.assertTrue(matches)
            match = matches[-1]
            _, ticket, _ = match.groups()
            old = match.group(0)
            new = old.replace(f"`{ticket}`", ticket, 1)
            return text.replace(old, new, 1)

        code, _, stderr = self.run_verifier(board_transform=malformed_ticket)
        self.assertEqual(code, 1)
        self.assertIn("has malformed ticket cell", stderr)

    def test_unready_current_slot_fails(self) -> None:
        def unready_slot(text: str) -> str:
            synthetic_dependency = "TEST-UNREADY"
            self.assertNotIn(
                synthetic_dependency,
                {
                    match.group(1)
                    for line in text.splitlines()
                    if (match := VERIFY.TICKET_ROW.match(line)) is not None
                },
            )
            current = next(
                (
                    match
                    for line in text.splitlines()
                    if (match := VERIFY.CURRENT_SLOT_ROW.match(line)) is not None
                ),
                None,
            )
            self.assertIsNotNone(current)
            assert current is not None
            _, current_ticket, _ = current.groups()
            ticket_row = next(
                (
                    match
                    for line in text.splitlines()
                    if (match := VERIFY.TICKET_ROW.match(line)) is not None
                    and match.group(1) == current_ticket
                ),
                None,
            )
            self.assertIsNotNone(ticket_row)
            assert ticket_row is not None
            _, _, dependency_cell = ticket_row.groups()
            dependencies = dependency_cell.strip()
            replacement = synthetic_dependency
            if dependencies != "-":
                replacement = f"{dependencies}, {synthetic_dependency}"
            old = ticket_row.group(0)
            new = old.replace(
                f"| {dependency_cell} |",
                f"| {replacement} |",
                1,
            )
            synthetic_row = (
                f"\n| {synthetic_dependency} | DEFERRED | - | verifier fixture |\n"
            )
            return text.replace(old, new, 1) + synthetic_row

        code, _, stderr = self.run_verifier(board_transform=unready_slot)
        self.assertEqual(code, 1)
        self.assertIn("unfinished dependencies: TEST-UNREADY", stderr)

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


class RequiredEdgeTests(unittest.TestCase):
    """The boundary-sharing rule, proved able to fail in both directions.

    A well-formedness check cannot tell a missing edge from a correct graph.
    These fix the rule that can, including the exception mechanism -- an
    allowance that outlives the gap it excused is itself a silent pass.
    """

    def tokens(self, acceptance: str) -> set[str]:
        return VERIFY.boundary_tokens(acceptance)

    def edges(self, board: str) -> list[str]:
        return VERIFY.required_edges(board)

    BOARD = (
        "| Ticket | Status | Depends on | Objective and acceptance |\n"
        "|---|---|---|---|\n"
        "| AAA-001 | DONE | \u2014 | Owns `shared-thing.sh` |\n"
        "| BBB-001 | PENDING | \u2014 | Also rewrites `shared-thing.sh` |\n"
    )

    def test_an_undeclared_shared_boundary_fails(self) -> None:
        errors = self.edges(self.BOARD)
        self.assertTrue(
            any("share a boundary" in error for error in errors), errors
        )

    def test_declaring_the_edge_clears_it(self) -> None:
        board = self.BOARD.replace(
            "| BBB-001 | PENDING | \u2014 |", "| BBB-001 | PENDING | AAA-001 |"
        )
        self.assertEqual(self.edges(board), [])

    def test_an_argued_allowance_clears_it(self) -> None:
        board = self.BOARD + (
            "\n<!-- board-graph: allow AAA-001 ~ BBB-001 -- "
            "they touch different halves of the file -->\n"
        )
        self.assertEqual(self.edges(board), [])

    def test_a_stale_allowance_fails(self) -> None:
        board = self.BOARD.replace(
            "| BBB-001 | PENDING | \u2014 |", "| BBB-001 | PENDING | AAA-001 |"
        ) + (
            "\n<!-- board-graph: allow AAA-001 ~ BBB-001 -- no longer needed -->\n"
        )
        errors = self.edges(board)
        self.assertTrue(any("is stale" in error for error in errors), errors)

    def test_an_allowance_for_a_non_ticket_fails(self) -> None:
        board = self.BOARD + (
            "\n<!-- board-graph: allow AAA-001 ~ GHOST-999 -- typo -->\n"
        )
        errors = self.edges(board)
        self.assertTrue(any("is not a ticket" in error for error in errors), errors)

    def test_two_closed_tickets_are_not_flagged(self) -> None:
        board = self.BOARD.replace("| BBB-001 | PENDING |", "| BBB-001 | DONE |")
        self.assertEqual(self.edges(board), [])

    def test_the_same_family_flags_without_a_shared_token(self) -> None:
        board = (
            "| Ticket | Status | Depends on | Objective and acceptance |\n"
            "|---|---|---|---|\n"
            "| CCC-001 | PENDING | \u2014 | One thing |\n"
            "| CCC-002 | PENDING | \u2014 | A different thing |\n"
        )
        errors = self.edges(board)
        self.assertTrue(any("same ticket family" in error for error in errors), errors)

    def test_a_whole_component_directory_is_not_a_boundary(self) -> None:
        """`bins/agent` is shared by everything that touches the agent."""
        self.assertNotIn("agent", self.tokens("rewrites `bins/agent` substantially"))

    def test_a_named_file_is_a_boundary(self) -> None:
        self.assertIn(
            "mcloving-deploy-lib.sh",
            self.tokens("rewrites `deploy/bin/mcloving-deploy-lib.sh`"),
        )

    def test_ticket_ids_and_shas_are_not_boundaries(self) -> None:
        found = self.tokens("see `DEPLOY-004` at `4bf882b8ad041b990e45cc5f1e79dee81429a3e7`")
        self.assertEqual(found, set())

    def test_threat_ids_are_boundaries(self) -> None:
        self.assertIn("TM-050", self.tokens("moves the TM-050 boundary"))


class RequiredEdgeWiringTests(ExecutionBoardVerifierTests):
    """The check must run from `main()`, not merely exist.

    An earlier version of this suite called `required_edges` directly, so
    deleting its call site left every test green -- the check was present,
    unwired, and untested for being wired.
    """

    def test_an_undeclared_shared_boundary_fails_the_verifier(self) -> None:
        def add_pair(board: str) -> str:
            return board + (
                "\n## Synthetic\n\n"
                "| Ticket | Status | Depends on | Objective and acceptance |\n"
                "|---|---|---|---|\n"
                "| ZZA-001 | DONE | \u2014 | Owns `synthetic-boundary.sh` |\n"
                "| ZZB-001 | PENDING | \u2014 | Rewrites `synthetic-boundary.sh` |\n"
            )

        code, _stdout, stderr = self.run_verifier(board_transform=add_pair)
        self.assertEqual(code, 1, stderr)
        self.assertIn("share a boundary", stderr)


class RequiredEdgeHistoryTests(unittest.TestCase):
    """The rule is only worth its false positives if it catches the real ones.

    Checked against the four graph corrections whose findings this rule exists
    to have caught -- the parents of c02ad71, abb32d7, 6145984 and eb74330.
    Those boards are history and are not reachable from a test fixture, so what
    is pinned here is the property that made all four catchable: each pair was
    unordered at the time, and each is ordered now.
    """

    PAIRS = (
        ("DEPLOY-002", "DEPLOY-003"),
        ("DEPLOY-002", "DEPLOY-004"),
        ("DEPLOY-003", "DEPLOY-004"),
        ("SEC-005", "DEPLOY-003"),
    )

    def test_every_historically_missing_edge_is_declared_today(self) -> None:
        board = (REPOSITORY / "docs" / "EXECUTION_BOARD.md").read_text(encoding="utf-8")
        self.assertEqual(VERIFY.required_edges(board), [])
        rows = {}
        for line in board.splitlines():
            match = VERIFY.TICKET_ROW_FULL.match(line)
            if match:
                rows[match.group(1)] = VERIFY.TICKET_ID.findall(match.group(3))
        for successor, predecessor in self.PAIRS:
            self.assertIn(
                predecessor,
                rows.get(successor, []),
                f"{successor} must declare {predecessor}; it was a missing edge once",
            )


if __name__ == "__main__":
    unittest.main()
