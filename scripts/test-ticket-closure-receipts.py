#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Negative controls for the ticket-closure gate.

Every check here is proved able to FAIL. A gate whose tests only ever show it
passing is the failure it exists to prevent: on this project a mechanism that
reports success in the absence of the thing it checks has now been found six
times, and the gate itself was the seventh -- an empty receipt and a threat
model sentence reading "has not been reviewed yet" satisfied both obligations.

The synthetic cases clear the historical ledgers, because those name real
tickets and a synthetic board does not contain them.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPTS = Path(__file__).resolve().parent
REPOSITORY = SCRIPTS.parent
# Importing the verifier by path would otherwise drop a version-specific
# .pyc into scripts/__pycache__ and dirty the worktree.
sys.dont_write_bytecode = True

_spec = importlib.util.spec_from_file_location(
    "verify_ticket_closure_receipts", SCRIPTS / "verify-ticket-closure-receipts.py"
)
VERIFY = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(VERIFY)


BOARD = """\
# Board

Updated: 2026-08-26

## Wave 0

| Ticket | Status | Depends on | Objective and acceptance |
|---|---|---|---|
| AAA-001 | DONE | — | Closed with a receipt and an attributed review |
| BBB-001 | PENDING | — | Not closed |

## Remaining execution topology

### Lanes

| Lane | Ticket or ordered chain | Class | Start gate | Rule |
|---|---|---|---|---|
| First lane | `AAA-001` | DONE | — | — |
| Second lane | `BBB-001` | SERIAL | — | — |
"""

THREAT_MODEL = """\
# Threat model

## Security verification ownership

| Area | First implementation ticket |
|---|---|
| The first area | AAA-001 |

## Closure attribution

| Ticket | Evidence |
|---|---|
| AAA-001 | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |
"""

RECEIPT = "# AAA-001 security review\n\n" + ("AAA-001 reviewed the boundary. " * 60)

# HYG-002: the two redundant views whose third column is NOT overloaded. The
# base fixture carries only a Lane table, and a Lane table is the one place an
# execution class legitimately sits there -- so the bypass could not be written
# against the fixture at all until these existed.
BATCH_LEDGER = (
    "\n## Batch ledger\n\n"
    "| Batch | Tickets | Status | Outcome |\n|---|---|---|---|\n"
    "| W0-A | AAA-001 | DONE | closed with a receipt |\n"
)
DISPATCH_QUEUE = (
    "\n## Current dispatch\n\n"
    "| Slot | Current ticket | Status | Dependency-critical successors |\n"
    "|---:|---|---|---|\n"
    "| 1 | `BBB-001` | PENDING | — |\n"
)


def build(board: str = BOARD, threat_model: str = THREAT_MODEL) -> TemporaryDirectory:
    """Materialise a synthetic repository that passes, ready to be broken."""
    directory = TemporaryDirectory()
    root = Path(directory.name)
    (root / "docs" / "evidence").mkdir(parents=True)
    (root / "docs" / "threat-model").mkdir(parents=True)
    (root / "docs" / "EXECUTION_BOARD.md").write_text(board, encoding="utf-8")
    (root / "docs" / "threat-model" / "README.md").write_text(
        threat_model, encoding="utf-8"
    )
    (root / "docs" / "evidence" / "AAA-001_SECURITY_REVIEW.md").write_text(
        RECEIPT, encoding="utf-8"
    )
    # A real document that names a DIFFERENT ticket, so a test can point an
    # attribution at evidence which exists and is about somebody else.
    (root / "docs" / "evidence" / "ZZZ-001_SECURITY_REVIEW.md").write_text(
        "# ZZZ-001 security review\n\n" + ("ZZZ-001 reviewed the boundary. " * 60),
        encoding="utf-8",
    )
    return directory


@contextlib.contextmanager
def synthetic(closed=("AAA-001",), **overrides):
    """Run against a synthetic board with the historical ledgers cleared."""
    saved = {
        name: getattr(VERIFY, name).copy()
        for name in (
            "RECEIPT_EXEMPT",
            "THREAT_MODEL_EXEMPT",
            "RECEIPT_DEBT",
            "THREAT_MODEL_DEBT",
        )
    }
    saved_floor = VERIFY.MINIMUM_TICKET_ROWS
    saved_closed = VERIFY.CLOSED_TICKETS
    saved_tables = VERIFY.EXPECTED_TABLES
    # The fixture board carries one ticket table and one lane table.
    VERIFY.EXPECTED_TABLES = {
        VERIFY.TICKET_TABLE_HEADER: 1,
        VERIFY.LANE_TABLE_HEADER: 1,
    }
    saved_baselines = {
        name: getattr(VERIFY, name)
        for name in (
            "RECEIPT_EXEMPT_BASELINE",
            "THREAT_MODEL_EXEMPT_BASELINE",
            "RECEIPT_DEBT_BASELINE",
            "THREAT_MODEL_DEBT_BASELINE",
        )
    }
    # The fixture board's closed tickets. Empty would now fail, because a DONE
    # row missing from the terminal baseline is an error, and so is a baseline
    # name with no DONE row.
    VERIFY.CLOSED_TICKETS = frozenset(closed)
    for _name in saved_baselines:
        setattr(VERIFY, _name, frozenset())
    for name in saved:
        getattr(VERIFY, name).clear()
    VERIFY.MINIMUM_TICKET_ROWS = 1
    for name, value in overrides.items():
        getattr(VERIFY, name).update(value)
        if hasattr(VERIFY, f"{name}_BASELINE"):
            setattr(VERIFY, f"{name}_BASELINE", frozenset(getattr(VERIFY, name)))
    try:
        yield
    finally:
        for name, value in saved.items():
            getattr(VERIFY, name).clear()
            getattr(VERIFY, name).update(value)
        VERIFY.MINIMUM_TICKET_ROWS = saved_floor
        VERIFY.CLOSED_TICKETS = saved_closed
        VERIFY.EXPECTED_TABLES = saved_tables
        for _name, _value in saved_baselines.items():
            setattr(VERIFY, _name, _value)


def check(root: Path, strict: bool = False) -> tuple[list[str], list[str], str]:
    return VERIFY.verify(root, strict)


class SyntheticBaseline(unittest.TestCase):
    def test_a_correct_repository_passes(self):
        with build() as name, synthetic():
            errors, debt, summary = check(Path(name))
        self.assertEqual(errors, [], "the unmodified fixture must pass")
        self.assertEqual(debt, [])
        self.assertIn("done=1 receipted=1 reviewed=1", summary)


class ReceiptSubstance(unittest.TestCase):
    """`touch <receipt>` must not close a ticket."""

    def _defect(self, mutate) -> list[str]:
        with build() as name, synthetic():
            root = Path(name)
            mutate(root / "docs" / "evidence" / "AAA-001_SECURITY_REVIEW.md")
            errors, _, _ = check(root)
        return errors

    def test_empty_receipt_fails(self):
        errors = self._defect(lambda path: path.write_text("", encoding="utf-8"))
        self.assertTrue(any("is 0 bytes" in error for error in errors), errors)

    def test_stub_receipt_fails(self):
        errors = self._defect(
            lambda path: path.write_text("# AAA-001\n", encoding="utf-8")
        )
        self.assertTrue(any("bytes" in error for error in errors), errors)

    def test_receipt_that_never_names_its_ticket_fails(self):
        errors = self._defect(
            lambda path: path.write_text(
                "# Review\n\n" + ("Something else entirely. " * 60), encoding="utf-8"
            )
        )
        self.assertTrue(any("never names AAA-001" in e for e in errors), errors)

    def test_receipt_without_a_heading_fails(self):
        errors = self._defect(
            lambda path: path.write_text(
                "AAA-001 was reviewed. " * 60, encoding="utf-8"
            )
        )
        self.assertTrue(any("no heading" in error for error in errors), errors)


class ClosureAttribution(unittest.TestCase):
    """The attribution field, and every bypass that defeated its predecessor.

    The class this replaces tested a predicate that read English in three
    structural shapes with a negation veto. Nine of its tests were veto tests,
    and each recorded a real bypass found in review. They are all kept here --
    not as veto tests, which would be meaningless now, but as the stronger
    assertion the old design could never make: this English, WHEREVER it
    appears, does not attribute a review, because the only field that attributes
    one cannot hold English at all.

    Note on fixtures: every negative below supplies a WELL-FORMED attribution
    table crediting some other ticket. Without one the table is missing, the
    gate says so, and `attributes no review` appears for reasons that have
    nothing to do with the bypass under test -- a green negative proving nothing.
    That trap is not hypothetical; the first cut of this class fell into it.
    """

    OTHER = (
        "\n## Closure attribution\n\n"
        "| Ticket | Evidence |\n|---|---|\n"
        "| BBB-001 | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
    )

    def _errors(self, threat_model: str, closed=("AAA-001",)) -> list[str]:
        with build(threat_model=threat_model) as name, synthetic(closed=closed):
            errors, _, _ = check(Path(name))
        return errors

    def _unattributed(self, threat_model: str) -> None:
        errors = self._errors(threat_model)
        self.assertTrue(
            any("attributes no review" in error for error in errors), errors
        )

    def test_the_attribution_table_attributes_the_review(self):
        with build() as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertEqual(errors, [])

    def test_a_missing_table_attributes_nothing(self):
        """Absence attributes nothing, and says so rather than passing."""
        errors = self._errors("# Threat model\n")
        self.assertTrue(
            any("has no closure-attribution table" in error for error in errors),
            errors,
        )

    def test_two_tables_are_refused(self):
        """Whichever came first would decide, which is nobody deciding."""
        errors = self._errors(
            "# Threat model\n"
            + self.OTHER
            + "\n## Closure attribution\n\n| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
        )
        self.assertTrue(
            any(
                "closure-attribution tables" in error
                or "Closure attribution` sections" in error
                for error in errors
            ),
            errors,
        )

    # --- the nine recorded bypasses, each now structurally impossible ---

    def test_prose_only_mention_does_not_attribute(self):
        self._unattributed(
            "# Threat model\n\nAAA-001 was reviewed thoroughly.\n" + self.OTHER
        )

    def test_a_denial_in_prose_does_not_attribute(self):
        self._unattributed(
            "# Threat model\n\nTODO: AAA-001 has not been reviewed yet.\n" + self.OTHER
        )

    def test_a_denial_in_a_heading_does_not_attribute(self):
        self._unattributed(
            "# Threat model\n\n## TODO: AAA-001 has not been reviewed yet\n"
            + self.OTHER
        )

    def test_a_ticket_led_denial_heading_does_not_attribute(self):
        self._unattributed(
            "# Threat model\n\n## AAA-001 review has not happened\n" + self.OTHER
        )

    def test_a_closure_review_heading_does_not_attribute(self):
        """The old Shape A, affirmative and now inert: a heading is prose."""
        self._unattributed(
            "# Threat model\n\n## AAA-001 threat-model closure review\n" + self.OTHER
        )

    def test_an_ownership_row_does_not_attribute(self):
        """The old Shape B, now inert."""
        self._unattributed(
            "# Threat model\n\n## Security verification ownership\n\n"
            "| Area | First implementation ticket |\n|---|---|\n"
            "| The first area | AAA-001 |\n" + self.OTHER
        )

    def test_a_register_verification_cell_does_not_attribute(self):
        """The old Shape C, now inert."""
        self._unattributed(
            "# Threat model\n\n| ID | Scenario | Primary mitigations | Required "
            "verification | Owner | Residual risk |\n|---|---|---|---|---|---|\n"
            "| TM-999 | a threat | a mitigation | receipt in AAA-001 | SEC | none |\n"
            + self.OTHER
        )

    def test_a_denial_in_the_ticket_column_is_not_a_ticket_id(self):
        """The denial, in the one column that counts. It is not a denial the
        gate detects -- it is a cell that is not a ticket id."""
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 review has not happened | "
            "`docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
        )
        self.assertTrue(any("is not a ticket id" in error for error in errors), errors)
        self.assertTrue(
            any("attributes no review" in error for error in errors), errors
        )

    def test_a_denial_with_no_vetoed_word_still_fails(self):
        """The bypass the old design conceded it could not close.

        `review was declined by the boundary owner` contains no word the old
        negation veto looked for, sits inside the one affirmative structure that
        counted, and would have attributed a review. Here it is simply not a
        ticket id, and no vocabulary decides that.
        """
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 review was declined by the boundary owner | "
            "`docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
        )
        self.assertTrue(any("is not a ticket id" in error for error in errors), errors)
        self.assertTrue(
            any("attributes no review" in error for error in errors), errors
        )

    def test_prose_adjacent_to_a_valid_row_is_not_read(self):
        """The assertion the old code could never make.

        A correct attribution for AAA-001, with a denial of that same review
        immediately above and below it. The field is data; its surroundings are
        not read at all, so the denial changes nothing.
        """
        with build(
            threat_model=(
                "# Threat model\n\nAAA-001 has never been reviewed.\n\n"
                "## Closure attribution\n\n| Ticket | Evidence |\n|---|---|\n"
                "| AAA-001 | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n\n"
                "TODO: the AAA-001 review has not happened and is outstanding.\n"
            )
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertEqual(errors, [])

    # --- the field's own rules ---

    def test_a_longer_ticket_id_does_not_credit_a_shorter_one(self):
        """`-` is not a word boundary; the column is fullmatched, not searched."""
        self._unattributed(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001-HARDEN | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
        )

    def test_an_evidence_cell_that_is_not_a_path_is_refused(self):
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 | reviewed by the boundary owner |\n"
        )
        self.assertTrue(
            any("is not a backticked path" in error for error in errors), errors
        )

    def test_an_evidence_cell_containing_a_path_is_still_refused(self):
        """The cell IS the path. A cell that merely contains one is prose."""
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 | see `docs/evidence/AAA-001_SECURITY_REVIEW.md` for detail |\n"
        )
        self.assertTrue(
            any("is not a backticked path" in error for error in errors), errors
        )

    def test_an_evidence_path_that_does_not_exist_is_refused(self):
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 | `docs/evidence/NOT_WRITTEN.md` |\n"
        )
        self.assertTrue(any("does not exist" in error for error in errors), errors)

    def test_a_ticket_attributed_twice_is_refused(self):
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
            "| AAA-001 | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
        )
        self.assertTrue(any("attributed twice" in error for error in errors), errors)

    def test_an_attribution_for_an_open_ticket_is_refused(self):
        """Both ways. An entry for a ticket that never closed is stale or
        premature, and nothing else in this file would ever notice."""
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
            "| BBB-001 | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
        )
        self.assertTrue(any("not DONE" in error for error in errors), errors)

    def test_an_evidence_document_that_never_names_the_ticket_is_refused(self):
        """Existence was never the claim the row makes.

        The row says a named document records THIS ticket's review. A path that
        merely resolves witnesses the wrong fact, and this branch's own first
        cut proved it: `ALPHA-001` was attributed to `docs/ALPHA_DEMO.md`, which
        never mentions the ticket.
        """
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 | `docs/evidence/ZZZ-001_SECURITY_REVIEW.md` |\n"
        )
        self.assertTrue(any("never names it" in error for error in errors), errors)

    def test_an_evidence_path_that_escapes_docs_is_refused(self):
        """`.` is a filename character, so `docs/../..` looks like a docs path."""
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 | `docs/../../etc/passwd` |\n"
        )
        self.assertTrue(any("leaves docs/" in error for error in errors), errors)

    def test_a_table_outside_the_heading_is_not_the_attribution_table(self):
        """The heading is the rule, not a comment about the rule."""
        errors = self._errors(
            "# Threat model\n\n## Something else\n\n"
            "| Ticket | Evidence |\n|---|---|\n"
            "| AAA-001 | `docs/evidence/AAA-001_SECURITY_REVIEW.md` |\n"
        )
        self.assertTrue(
            any("has no closure-attribution table" in error for error in errors),
            errors,
        )

    def test_a_symlinked_evidence_document_cannot_escape_docs(self):
        """Lexical containment is not containment.

        The cited string has no `..` in it at all. A committed symlink at
        `docs/evidence/AAA-001_SECURITY_REVIEW.md -> ../../outside.md` passes
        every spelling test and is then followed out of the tree by `is_file()`
        and `read_text()`. Measured before the fix: evidence living outside the
        repository was accepted, with `receipted=1`. This repository learned the
        same lesson one ticket earlier, in DEPLOY-004's ancestor walk.
        """
        with build() as name, synthetic():
            root = Path(name)
            outside = root / "outside.md"
            outside.write_text(
                "# outside\n\nAAA-001 was reviewed, honestly.\n" + ("x " * 600),
                encoding="utf-8",
            )
            receipt = root / "docs" / "evidence" / "AAA-001_SECURITY_REVIEW.md"
            receipt.unlink()
            receipt.symlink_to(Path("..") / ".." / "outside.md")
            errors, _, _ = check(root)
        self.assertTrue(any("leaves docs/" in error for error in errors), errors)

    def test_a_short_row_is_an_error_not_a_skip(self):
        """An unreadable attribution row and an absent one look identical to the
        ticket each was supposed to credit."""
        errors = self._errors(
            "# Threat model\n\n## Closure attribution\n\n"
            "| Ticket | Evidence |\n|---|---|\n| AAA-001 |\n"
        )
        self.assertTrue(
            any("cells, not the 2" in error for error in errors), errors
        )


class BoardParsing(unittest.TestCase):
    """A row the gate cannot read must be an error, never a skip."""

    def _with_board(self, board: str, **kwargs) -> list[str]:
        with build(board=board) as name, synthetic(**kwargs):
            errors, _, _ = check(Path(name))
        return errors

    def test_unknown_status_fails(self):
        errors = self._with_board(BOARD.replace("| AAA-001 | DONE |", "| AAA-001 | Done |"))
        self.assertTrue(any("is not one of" in error for error in errors), errors)

    def test_padded_row_is_still_read(self):
        errors = self._with_board(
            BOARD.replace("| AAA-001 | DONE |", "| AAA-001  |  DONE  |")
        )
        self.assertEqual(errors, [], "padding must not delete a row from the board")

    def test_a_duplicate_ticket_row_fails_even_when_statuses_agree(self):
        """Two rows, one id: the verifiers can read different definitions."""
        errors = self._with_board(
            BOARD.replace(
                "| BBB-001 | PENDING |",
                "| AAA-001 | DONE | \u2014 | A second, different row |\n"
                "| BBB-001 | PENDING |",
            )
        )
        self.assertTrue(
            any("more than one authoritative row" in e for e in errors), errors
        )

    def test_non_ticket_in_the_first_column_fails(self):
        errors = self._with_board(BOARD.replace("| AAA-001 | DONE |", "| notaticket | DONE |"))
        self.assertTrue(any("is not a ticket id" in error for error in errors), errors)

    def test_a_row_with_extra_columns_fails(self):
        """An accidental pipe silently truncates the acceptance text."""
        errors = self._with_board(
            BOARD.replace(
                "| AAA-001 | DONE | \u2014 | Closed with a receipt and an attributed review |",
                "| AAA-001 | DONE | \u2014 | Closed | and also rewrites `shared.sh` |",
            )
        )
        self.assertTrue(
            any("not the 4 the table declares" in e for e in errors), errors
        )

    def test_a_row_missing_columns_fails(self):
        """Two cells are enough to be counted here and omitted over there."""
        errors = self._with_board(
            BOARD.replace(
                "| BBB-001 | PENDING |",
                "| NEW-001 | PENDING |\n| BBB-001 | PENDING |",
            )
        )
        self.assertTrue(
            any("not the 4 the table declares" in e for e in errors), errors
        )

    def test_a_truncated_redundant_view_row_fails(self):
        """A lane row too short to state a status cross-checks nothing."""
        board = BOARD.replace(
            "| First lane | `AAA-001` | DONE | \u2014 | \u2014 |",
            "| First lane | `AAA-001` |",
        )
        with build(board=board) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertTrue(
            any("cross-checks nothing" in error for error in errors), errors
        )

    def test_a_mistyped_view_header_fails(self):
        """A mistyped `Batches` removes the cross-check exactly when it matters."""
        errors = self._with_board(BOARD.replace("| Lane | Ticket or ordered chain |", "| Lanes | Ticket or ordered chain |"))
        self.assertTrue(
            any("removes that table from every check" in error for error in errors),
            errors,
        )

    def test_an_unrelated_informational_table_is_allowed(self):
        """Pinning the expected tables must not ban new ones."""
        errors = self._with_board(
            BOARD + "\n## Notes\n\n| Metric | Value |\n|---|---|\n| Coverage | 91% |\n"
        )
        self.assertEqual(errors, [])

    def test_a_view_row_with_a_corrupted_id_fails(self):
        """`FOUND-001_bad` still yields FOUND-001 and would pass silently."""
        errors = self._with_board(
            BOARD.replace("| First lane | `AAA-001` | DONE |", "| First lane | `AAA-001_bad` | DONE |")
        )
        self.assertTrue(
            any("is not a ticket" in error for error in errors), errors
        )

    def test_a_view_row_naming_no_ticket_fails(self):
        """An empty ticket cell leaves the row claiming a status it checks nothing against."""
        errors = self._with_board(
            BOARD.replace("| First lane | `AAA-001` | DONE |", "| First lane |  | DONE |")
        )
        self.assertTrue(
            any("names no ticket" in error for error in errors), errors
        )

    def test_a_ticket_row_under_a_mistyped_header_fails(self):
        """`Tickets` hides a table here while the board verifier still reads it."""
        errors = self._with_board(
            BOARD
            + "\n## Sneaky\n\n| Tickets | Status | Depends on | Objective |\n"
            "|---|---|---|---|\n| NEW-001 | DONE | \u2014 | closed with nothing |\n"
        )
        self.assertTrue(
            any("not inside a table headed" in error for error in errors), errors
        )

    def test_the_lane_and_batch_tables_are_not_mistaken_for_tickets(self):
        """The real board must not trip the orphan check."""
        board = (REPOSITORY / "docs" / "EXECUTION_BOARD.md").read_text(encoding="utf-8")
        _statuses, errors = VERIFY.board_statuses(board)
        self.assertEqual(
            [e for e in errors if "not inside a table headed" in e], []
        )

    def test_a_shrinking_denominator_fails(self):
        with build() as name:
            saved = VERIFY.MINIMUM_TICKET_ROWS
            VERIFY.MINIMUM_TICKET_ROWS = 500
            try:
                with synthetic():
                    VERIFY.MINIMUM_TICKET_ROWS = 500
                    errors, _, _ = check(Path(name))
            finally:
                VERIFY.MINIMUM_TICKET_ROWS = saved
        self.assertTrue(any("below the pinned floor" in e for e in errors), errors)


class RedundantViews(unittest.TestCase):
    def test_lane_disagreeing_with_its_ticket_row_fails(self):
        with build(
            board=BOARD.replace("| First lane | `AAA-001` | DONE |", "| First lane | `AAA-001` | PENDING |")
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertTrue(any("but its ticket row reads" in e for e in errors), errors)

    def test_a_view_naming_a_hyphen_suffixed_ticket_reads_it_whole(self):
        """A narrow parser read `AAA-001-HARDEN` as `AAA-001`."""
        board = BOARD.replace("| First lane | `AAA-001` | DONE |", "| First lane | `AAA-001-HARDEN` | DONE |")
        with build(board=board) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertTrue(
            any("AAA-001-HARDEN" in error and "no row in any ticket table" in error
                for error in errors),
            errors,
        )

    def test_lane_naming_an_unknown_ticket_fails(self):
        with build(
            board=BOARD.replace("`AAA-001` | DONE |", "`GHOST-999` | DONE |")
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertTrue(any("no row in any ticket table" in e for e in errors), errors)

    def test_lane_with_a_nonsense_third_column_fails(self):
        with build(
            board=BOARD.replace("| Second lane | `BBB-001` | SERIAL |", "| Second lane | `BBB-001` | BANANA |")
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertTrue(any("neither a status nor an execution class" in e for e in errors), errors)

    # --- HYG-002: an execution class was accepted in ANY view's third column ---

    def _errors_for(self, board: str) -> list[str]:
        with build(board=board) as name, synthetic():
            errors, _, _ = check(Path(name))
        return errors

    def test_a_batch_row_may_not_state_an_execution_class(self):
        """The half that was live end-to-end.

        Rewriting the real board's Batch ledger row `W0-A` from `DONE` to
        `SERIAL` passed BOTH verifiers: the class was accepted, the status
        comparison was skipped, and the batch stopped asserting anything about
        the ticket it names while still looking exactly like a claim.
        """
        errors = self._errors_for(
            BOARD + BATCH_LEDGER.replace("| DONE |", "| SERIAL |")
        )
        self.assertTrue(
            any("an execution class; only Lane rows overload" in e for e in errors),
            errors,
        )

    def test_a_dispatch_row_may_not_state_an_execution_class(self):
        """The half the ticket describes as unguarded, which is not quite right.

        `verify-execution-board.py` already rejects a dispatch slot whose status
        is not a ticket status. It is guarded here as well so that neither
        cross-check depends on the other file continuing to carry it.
        """
        errors = self._errors_for(
            BOARD + DISPATCH_QUEUE.replace("| PENDING |", "| SERIAL |")
        )
        self.assertTrue(
            any("an execution class; only Lane rows overload" in e for e in errors),
            errors,
        )

    def test_a_correct_batch_row_passes(self):
        self.assertEqual(self._errors_for(BOARD + BATCH_LEDGER), [])

    def test_a_lane_row_may_still_state_an_execution_class(self):
        """The overload is real for Lane rows; the fix must not remove it.

        Without this, tightening the rule to "the third column is always a
        status" would pass every other test in this class and break every open
        lane on the real board.
        """
        errors = self._errors_for(BOARD)
        self.assertEqual([e for e in errors if "only Lane rows overload" in e], [])


class CitedEvidence(unittest.TestCase):
    def test_a_closed_ticket_citing_a_missing_document_fails(self):
        with build(
            board=BOARD.replace(
                "Closed with a receipt and an attributed review",
                "Closure: `docs/evidence/GHOST-999_SECURITY_REVIEW.md`",
            )
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertTrue(any("which does not exist" in error for error in errors), errors)

    def test_a_closed_ticket_citing_a_real_document_passes(self):
        with build(
            board=BOARD.replace(
                "Closed with a receipt and an attributed review",
                "Closure: `docs/evidence/AAA-001_SECURITY_REVIEW.md`",
            )
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertEqual(errors, [])

    # --- HYG-002: the check read only backticked paths ---
    #
    # Four bypasses were demonstrated against the real board, and only ONE is
    # the undelimited case the ticket describes. The other three are properly
    # backticked and read as ordinary citations, which is why "require
    # backticks" was never the fix: backticks are how a citation should be
    # written, not what makes text a citation.

    MISSING = "docs/architecture/DOES_NOT_EXIST.md"

    def _cite(self, spelling: str) -> list[str]:
        with build(
            board=BOARD.replace(
                "Closed with a receipt and an attributed review",
                f"Closure: {spelling}",
            )
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        return errors

    def _fabricated(self, spelling: str) -> None:
        errors = self._cite(spelling)
        self.assertTrue(
            any("which does not exist" in error for error in errors), errors
        )

    def test_a_citation_that_escapes_docs_fails(self):
        """Same containment rule as the attribution field, same reason."""
        errors = self._cite("`docs/../../etc/passwd`")
        self.assertTrue(any("does not exist" in error for error in errors), errors)

    def test_an_unbackticked_missing_document_fails(self):
        """The one the ticket names. The bare-path rule in the board verifier
        cannot backstop it: that rule fires only when the path RESOLVES."""
        self._fabricated(self.MISSING)

    def test_a_dot_slash_prefixed_missing_document_fails(self):
        self._fabricated(f"`./{self.MISSING}`")

    def test_an_angle_bracketed_missing_document_fails(self):
        self._fabricated(f"`<{self.MISSING}>`")

    def test_a_trailing_space_inside_backticks_does_not_hide_a_missing_document(self):
        """One space between the path and the closing backtick was enough."""
        self._fabricated(f"`{self.MISSING} `")

    def test_an_unbackticked_real_document_passes(self):
        """Loosening the scan must not turn every undelimited path into an error."""
        self.assertEqual(self._cite("docs/evidence/AAA-001_SECURITY_REVIEW.md"), [])

    def test_a_template_path_in_a_done_row_is_refused(self):
        """Why the check asks `is_file`, not `exists`.

        Scanning undelimited text picks up the leading fragment of a template
        such as `docs/evidence/<TICKET>_SECURITY_REVIEW.md`, which truncates to
        the real DIRECTORY `docs/evidence`. Relaxing to `exists` would admit
        that -- and with it every citation of a directory where a document was
        meant, which is most of the value of the rule.

        Measured before choosing: no DONE row on the real board spells a
        template, and all 25 of their cited paths resolve to files. So the
        relaxation defended a case that does not exist, at the cost of one that
        does. A DONE row citing a template is not naming its evidence anyway --
        a closed ticket has a specific document, not a pattern -- so refusing it
        is the right answer rather than a tolerated cost.
        """
        errors = self._cite("`docs/evidence/<TICKET>_SECURITY_REVIEW.md`")
        self.assertTrue(any("docs/evidence" in error for error in errors), errors)

    def test_an_open_ticket_may_name_a_document_it_will_write(self):
        """Planning work must not require a placeholder file first."""
        with build(
            board=BOARD.replace(
                "| BBB-001 | PENDING | \u2014 | Not closed |",
                "| BBB-001 | PENDING | \u2014 | Will produce "
                "`docs/architecture/NEW_CONTRACT.md` |",
            )
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertEqual(errors, [])


class LedgerDiscipline(unittest.TestCase):
    def test_a_ticket_outside_the_baseline_fails(self):
        """A newly closed ticket may not be admitted to a historical ledger."""
        with build() as name, synthetic():
            saved = VERIFY.RECEIPT_DEBT_BASELINE
            VERIFY.RECEIPT_DEBT_BASELINE = frozenset()
            VERIFY.RECEIPT_DEBT["AAA-001"] = "an admitted gap that should not fit"
            try:
                errors, _, _ = check(Path(name))
            finally:
                VERIFY.RECEIPT_DEBT_BASELINE = saved
        self.assertTrue(any("may only shrink" in error for error in errors), errors)

    def test_paying_one_debt_does_not_buy_room_for_another(self):
        """The regression a cardinality cap cannot see.

        Swapping a paid ticket for a newly closed one leaves `len(ledger)`
        unchanged, so a count-based ratchet passes while a fresh gap is
        laundered into history. Membership is what has to be pinned.
        """
        with build() as name, synthetic():
            saved = VERIFY.RECEIPT_DEBT_BASELINE
            VERIFY.RECEIPT_DEBT_BASELINE = frozenset({"OLD-001"})
            VERIFY.RECEIPT_DEBT["AAA-001"] = "swapped in for the one just paid"
            try:
                errors, _, _ = check(Path(name))
                size = len(VERIFY.RECEIPT_DEBT)
            finally:
                VERIFY.RECEIPT_DEBT_BASELINE = saved
        self.assertEqual(
            size, 1, "one out, one in: the count a cap would compare is unchanged"
        )
        self.assertTrue(
            any("not in the receipt debt baseline" in error for error in errors),
            errors,
        )

    def test_a_baseline_that_outlives_its_ledger_entry_fails(self):
        """A paid name left in the baseline stays permanently re-admittable."""
        with build() as name, synthetic():
            VERIFY.RECEIPT_DEBT_BASELINE = frozenset({"PAID-001"})
            errors, _, _ = check(Path(name))
        self.assertTrue(
            any("has left the ledger" in error for error in errors), errors
        )

    def test_a_stale_ledger_entry_fails(self):
        with build() as name, synthetic(RECEIPT_DEBT={"AAA-001": "already receipted"}):
            errors, _, _ = check(Path(name))
        self.assertTrue(any("is stale" in error for error in errors), errors)

    def test_a_ledger_entry_for_an_unknown_ticket_fails(self):
        with build() as name, synthetic(RECEIPT_DEBT={"GHOST-999": "not a ticket"}):
            errors, _, _ = check(Path(name))
        self.assertTrue(any("unknown ticket GHOST-999" in e for e in errors), errors)

    def test_exempt_and_debt_are_mutually_exclusive(self):
        with build(board=BOARD.replace("| AAA-001 | DONE | — | Closed with a receipt and an attributed review |", "| AAA-001 | DONE | — | x |\n| CCC-001 | DONE | — | y |")) as name, synthetic(
            closed=("AAA-001", "CCC-001"),
            RECEIPT_EXEMPT={"CCC-001": "nothing owed"},
            RECEIPT_DEBT={"CCC-001": "something owed"},
            THREAT_MODEL_EXEMPT={"CCC-001": "nothing owed"},
        ):
            errors, _, _ = check(Path(name))
        self.assertTrue(any("both exempt and debt" in error for error in errors), errors)


class FailClosed(unittest.TestCase):
    def test_a_missing_board_exits_one(self):
        with TemporaryDirectory() as name:
            with self.assertRaises(SystemExit) as raised:
                with contextlib.redirect_stderr(io.StringIO()):
                    check(Path(name))
        self.assertEqual(raised.exception.code, 1)

    def test_a_board_with_no_ticket_rows_exits_nonzero(self):
        with build(board="# Board\n\nNo tables here.\n") as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertIn("no ticket rows were found", errors)


class ThisRepository(unittest.TestCase):
    """The real board, through the real command line."""

    def test_the_repository_passes_as_a_subprocess(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify-ticket-closure-receipts.py")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("closure-receipts-ok", completed.stdout)

    def test_the_repository_never_slips_backwards(self):
        """A ratchet, not a pin: obligations may be paid, never accrued."""
        errors, debt, summary = check(REPOSITORY)
        self.assertEqual(errors, [], "\n".join(errors))
        # 30, then 33 when register attribution narrowed to the Required
        # verification column and exposed MIG-002/006/007, then 31 when
        # identifier matching stopped `\b` hiding ADMIN-001 and CONSUMER-001
        # inside their own receipt filenames, then 50 under HYG-002, then 51 when that
        # ticket's own binding rule caught ALPHA-001 pointing at a document that
        # never names it.
        #
        # THE ARGUMENT FOR RAISING IT, since the comment above demands one.
        # HYG-002 replaced a predicate that read English with a table that holds
        # a ticket id and a path. Nineteen tickets stopped being credited, and
        # every one of them lost a credit it should never have had: seventeen
        # were attributed by the `Area | First implementation ticket` table,
        # which records who BUILT an area, and two by a register cell citing a
        # different ticket's closure document. No review was undone and no
        # discipline slipped. The bound went up because the measurement stopped
        # flattering us, which is the only reason it is ever allowed to.
        #
        # Lower this as debt is paid. Raising it again needs its own argument,
        # in this comment, naming what was disclosed and why it was not a
        # regression.
        self.assertLessEqual(
            len(debt), 51, "closure debt may only shrink; lower this bound as it is paid"
        )
        done = int(summary.split("done=")[1].split()[0])
        self.assertGreaterEqual(done, 80, "DONE tickets should not vanish from the board")

    def test_a_closed_ticket_cannot_leave_the_board(self):
        """Swapping a removed row for a new one keeps the count and drops the debt."""
        board = (REPOSITORY / "docs" / "EXECUTION_BOARD.md").read_text(encoding="utf-8")
        victim = sorted(VERIFY.CLOSED_TICKETS)[0]
        with build(board=board.replace(f"| {victim} | DONE |", f"| {victim} | DEFERRED |")) as name:
            errors, _, _ = check(Path(name))
        self.assertTrue(
            any(f"{victim} was closed" in error for error in errors), errors[:3]
        )

    def test_a_new_closure_must_join_the_terminal_baseline(self):
        """Otherwise its row can be removed later and nothing notices."""
        with build() as name, synthetic(closed=()):
            errors, _, _ = check(Path(name))
        self.assertTrue(
            any("is not in CLOSED_TICKETS" in error for error in errors), errors
        )

    def test_the_closed_set_matches_the_board(self):
        """A pinned set smaller than the board's DONE rows guards nothing."""
        board = (REPOSITORY / "docs" / "EXECUTION_BOARD.md").read_text(encoding="utf-8")
        statuses, _ = VERIFY.board_statuses(board)
        done = {t for t, s in statuses.items() if s == "DONE"}
        self.assertEqual(
            done - set(VERIFY.CLOSED_TICKETS),
            set(),
            "add newly closed tickets to CLOSED_TICKETS",
        )

    def test_every_ledger_entry_states_a_reason(self):
        for ledger in (
            VERIFY.RECEIPT_EXEMPT,
            VERIFY.THREAT_MODEL_EXEMPT,
            VERIFY.RECEIPT_DEBT,
            VERIFY.THREAT_MODEL_DEBT,
        ):
            for ticket, reason in ledger.items():
                self.assertGreater(len(reason.strip()), 20, f"{ticket} states no reason")

    def test_the_parse_floor_matches_the_board_it_guards(self):
        """A floor below the real row count would let rows vanish unnoticed."""
        board = (REPOSITORY / "docs" / "EXECUTION_BOARD.md").read_text(encoding="utf-8")
        rows = sum(
            len(rows)
            for header, rows in VERIFY.tables(board)
            if header and header[0] == VERIFY.TICKET_TABLE_HEADER
        )
        self.assertEqual(
            rows,
            VERIFY.MINIMUM_TICKET_ROWS,
            "raise MINIMUM_TICKET_ROWS with the board; a slack floor guards nothing",
        )

    def test_every_ledger_is_within_its_baseline(self):
        for ledger, baseline, label in (
            (VERIFY.RECEIPT_EXEMPT, VERIFY.RECEIPT_EXEMPT_BASELINE, "receipt exempt"),
            (VERIFY.THREAT_MODEL_EXEMPT, VERIFY.THREAT_MODEL_EXEMPT_BASELINE, "tm exempt"),
            (VERIFY.RECEIPT_DEBT, VERIFY.RECEIPT_DEBT_BASELINE, "receipt debt"),
            (VERIFY.THREAT_MODEL_DEBT, VERIFY.THREAT_MODEL_DEBT_BASELINE, "tm debt"),
        ):
            self.assertLessEqual(set(ledger), set(baseline), f"{label} grew")

    def test_no_baseline_is_derived_from_the_ledger_it_bounds(self):
        """`frozenset(RECEIPT_DEBT)` would be an assertion that cannot fail."""
        source = (SCRIPTS / "verify-ticket-closure-receipts.py").read_text(
            encoding="utf-8"
        )
        for ledger in (
            "RECEIPT_EXEMPT",
            "THREAT_MODEL_EXEMPT",
            "RECEIPT_DEBT",
            "THREAT_MODEL_DEBT",
        ):
            self.assertNotIn(
                f"{ledger}_BASELINE = frozenset({ledger})",
                source,
                f"{ledger}_BASELINE must be written out literally",
            )


if __name__ == "__main__":
    unittest.main(verbosity=1)
