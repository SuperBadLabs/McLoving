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
"""

RECEIPT = "# AAA-001 security review\n\n" + ("AAA-001 reviewed the boundary. " * 60)


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
    return directory


@contextlib.contextmanager
def synthetic(**overrides):
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
    for name in saved:
        getattr(VERIFY, name).clear()
    VERIFY.MINIMUM_TICKET_ROWS = 1
    for name, value in overrides.items():
        getattr(VERIFY, name).update(value)
    try:
        yield
    finally:
        for name, value in saved.items():
            getattr(VERIFY, name).clear()
            getattr(VERIFY, name).update(value)
        VERIFY.MINIMUM_TICKET_ROWS = saved_floor


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


class ThreatModelAttribution(unittest.TestCase):
    """A mention is not a review; a negative mention is the opposite of one."""

    def _with_threat_model(self, threat_model: str) -> list[str]:
        with build(threat_model=threat_model) as name, synthetic():
            errors, _, _ = check(Path(name))
        return errors

    def test_prose_only_mention_fails(self):
        errors = self._with_threat_model(
            "# Threat model\n\nAAA-001 supplied some evidence elsewhere.\n"
        )
        self.assertTrue(any("attributes no review" in e for e in errors), errors)

    def test_a_sentence_denying_the_review_does_not_satisfy_it(self):
        errors = self._with_threat_model(
            "# Threat model\n\nTODO: AAA-001 has not been reviewed yet.\n"
        )
        self.assertTrue(any("attributes no review" in e for e in errors), errors)

    def test_a_negative_heading_does_not_satisfy_it(self):
        """Placement is not meaning: the same denial, in a heading."""
        errors = self._with_threat_model(
            "# Threat model\n\n## TODO: AAA-001 has not been reviewed yet\n"
        )
        self.assertTrue(any("attributes no review" in e for e in errors), errors)

    def test_a_negative_table_row_does_not_satisfy_it(self):
        errors = self._with_threat_model(
            "# Threat model\n\n| note | AAA-001 still outstanding |\n"
        )
        self.assertTrue(any("attributes no review" in e for e in errors), errors)

    def test_a_negative_threat_register_row_does_not_satisfy_it(self):
        """A register row is only an attribution in the verification column."""
        errors = self._with_threat_model(
            "# Threat model\n\n| ID | Scenario | Primary mitigations | Required "
            "verification | Owner | Residual risk |\n|---|---|---|---|---|---|\n"
            "| TM-999 | AAA-001 review has not happened | none | none | SEC | none |\n"
        )
        self.assertTrue(any("attributes no review" in e for e in errors), errors)

    def test_the_register_verification_column_attributes_the_review(self):
        with build(
            threat_model=(
                "# Threat model\n\n| ID | Scenario | Primary mitigations | Required "
                "verification | Owner | Residual risk |\n|---|---|---|---|---|---|\n"
                "| TM-999 | a threat | a mitigation | receipt in AAA-001 | SEC | none |\n"
            )
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertEqual(errors, [])

    def test_a_residual_risk_mention_is_not_a_review(self):
        errors = self._with_threat_model(
            "# Threat model\n\n| ID | Scenario | Primary mitigations | Required "
            "verification | Owner | Residual risk |\n|---|---|---|---|---|---|\n"
            "| TM-999 | a threat | a mitigation | none | SEC | AAA-001 must still run |\n"
        )
        self.assertTrue(any("attributes no review" in e for e in errors), errors)

    def test_a_heading_attributes_the_review(self):
        with build(
            threat_model="# Threat model\n\n## AAA-001 threat-model closure review\n\nReviewed.\n"
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertEqual(errors, [])


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

    def test_non_ticket_in_the_first_column_fails(self):
        errors = self._with_board(BOARD.replace("| AAA-001 | DONE |", "| notaticket | DONE |"))
        self.assertTrue(any("is not a ticket id" in error for error in errors), errors)

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


class CitedEvidence(unittest.TestCase):
    def test_citing_a_document_that_does_not_exist_fails(self):
        with build(
            board=BOARD + "\nSee `docs/evidence/GHOST-999_SECURITY_REVIEW.md`.\n"
        ) as name, synthetic():
            errors, _, _ = check(Path(name))
        self.assertTrue(any("which does not exist" in error for error in errors), errors)

    def test_citing_a_document_that_exists_passes(self):
        with build(
            board=BOARD + "\nSee `docs/evidence/AAA-001_SECURITY_REVIEW.md`.\n"
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
        # 30 until register attribution was narrowed to the Required
        # verification column, which exposed MIG-002, MIG-006 and MIG-007.
        # Those gaps are older than the rule that found them. Lower this as
        # debt is paid; raising it needs the same argument.
        self.assertLessEqual(
            len(debt), 33, "closure debt may only shrink; lower this bound as it is paid"
        )
        done = int(summary.split("done=")[1].split()[0])
        self.assertGreaterEqual(done, 80, "DONE tickets should not vanish from the board")

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
