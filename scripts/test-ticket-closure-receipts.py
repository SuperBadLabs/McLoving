#!/usr/bin/env python3
"""Known-good and known-bad tests for the ticket-closure receipt gate."""

from __future__ import annotations

import importlib.util
import io
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Callable


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = Path(__file__).with_name("verify-ticket-closure-receipts.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("verify_ticket_closure_receipts", SCRIPT)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

Transform = Callable[[str], str]


def identity(text: str) -> str:
    return text


class ClosureReceiptTests(unittest.TestCase):
    def run_gate(
        self,
        board_transform: Transform = identity,
        threat_model_transform: Transform = identity,
        receipts: Callable[[Path], None] | None = None,
        strict: bool = False,
    ) -> tuple[int, str, str]:
        """Run the gate against a synthetic copy of the repository documents."""
        board_text = board_transform(
            (REPOSITORY / "docs" / "EXECUTION_BOARD.md").read_text(encoding="utf-8")
        )
        threat_model_text = threat_model_transform(
            (REPOSITORY / VERIFY.THREAT_MODEL).read_text(encoding="utf-8")
        )

        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            scripts = root / "scripts"
            scripts.mkdir()
            evidence = root / VERIFY.RECEIPT_DIRECTORY
            evidence.mkdir(parents=True)
            shutil.copytree(
                REPOSITORY / VERIFY.RECEIPT_DIRECTORY, evidence, dirs_exist_ok=True
            )
            threat_model = root / VERIFY.THREAT_MODEL
            threat_model.parent.mkdir(parents=True, exist_ok=True)
            threat_model.write_text(threat_model_text, encoding="utf-8")
            (root / "docs" / "EXECUTION_BOARD.md").write_text(
                board_text, encoding="utf-8"
            )
            if receipts is not None:
                receipts(evidence)

            synthetic_script = scripts / SCRIPT.name
            synthetic_script.write_text("# gate fixture\n", encoding="utf-8")

            original_file = VERIFY.__file__
            original_argv = sys.argv
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                VERIFY.__file__ = str(synthetic_script)
                sys.argv = [SCRIPT.name] + (["--strict"] if strict else [])
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    try:
                        VERIFY.main()
                    except SystemExit as error:
                        code = int(error.code or 0)
                    else:
                        code = 0
            finally:
                VERIFY.__file__ = original_file
                sys.argv = original_argv

        return code, stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def close(ticket: str) -> Transform:
        """Flip ``ticket``'s board row to DONE."""

        def transform(text: str) -> str:
            lines = []
            replaced = False
            for line in text.splitlines():
                match = VERIFY.TICKET_ROW.match(line)
                if match is not None and match.group(1) == ticket:
                    line = line.replace(
                        f"| {ticket} | {match.group(2)} |",
                        f"| {ticket} | DONE |",
                        1,
                    )
                    replaced = True
                lines.append(line)
            assert replaced, f"{ticket} has no board row"
            return "\n".join(lines) + "\n"

        return transform

    def test_current_repository_passes(self) -> None:
        code, stdout, stderr = self.run_gate()
        self.assertEqual(code, 0, stderr)
        self.assertIn("closure-receipts-ok", stdout)

    def test_recorded_debt_is_reported_but_does_not_fail(self) -> None:
        code, stdout, stderr = self.run_gate()
        self.assertEqual(code, 0, stderr)
        self.assertIn("closure-receipts debt:", stderr)
        self.assertIn("debt=", stdout)

    def test_recorded_debt_fails_under_strict(self) -> None:
        code, _, stderr = self.run_gate(strict=True)
        self.assertEqual(code, 1)
        self.assertIn("unpaid closure debt", stderr)

    def test_closing_a_ticket_without_a_receipt_fails(self) -> None:
        # The case the gate exists for: DEPLOY-001 shipped 15,206 lines of
        # deployment lane across two merges with neither artifact.
        code, _, stderr = self.run_gate(board_transform=self.close("DEPLOY-001"))
        self.assertEqual(code, 1)
        self.assertIn(
            "DEPLOY-001 is DONE without docs/evidence/DEPLOY-001_SECURITY_REVIEW.md",
            stderr,
        )
        self.assertIn("DEPLOY-001 is DONE but is named nowhere", stderr)

    def test_a_receipt_alone_does_not_satisfy_the_threat_model_rule(self) -> None:
        code, _, stderr = self.run_gate(
            board_transform=self.close("DEPLOY-001"),
            receipts=lambda evidence: (
                evidence / f"DEPLOY-001{VERIFY.RECEIPT_SUFFIX}"
            ).write_text("# receipt\n", encoding="utf-8"),
        )
        self.assertEqual(code, 1)
        self.assertNotIn("DEPLOY-001 is DONE without", stderr)
        self.assertIn("DEPLOY-001 is DONE but is named nowhere", stderr)

    def test_a_threat_model_entry_alone_does_not_satisfy_the_receipt(self) -> None:
        code, _, stderr = self.run_gate(
            board_transform=self.close("DEPLOY-001"),
            threat_model_transform=lambda text: text
            + "\n## DEPLOY-001 threat-model closure review\n",
        )
        self.assertEqual(code, 1)
        self.assertIn("DEPLOY-001 is DONE without", stderr)
        self.assertNotIn("DEPLOY-001 is DONE but is named nowhere", stderr)

    def test_both_artifacts_close_a_ticket_cleanly(self) -> None:
        code, stdout, stderr = self.run_gate(
            board_transform=self.close("DEPLOY-001"),
            threat_model_transform=lambda text: text
            + "\n## DEPLOY-001 threat-model closure review\n",
            receipts=lambda evidence: (
                evidence / f"DEPLOY-001{VERIFY.RECEIPT_SUFFIX}"
            ).write_text("# receipt\n", encoding="utf-8"),
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("closure-receipts-ok", stdout)

    def test_alternate_receipt_must_exist(self) -> None:
        path, _ = VERIFY.ALTERNATE_RECEIPTS["REL-001"]
        code, _, stderr = self.run_gate(
            receipts=lambda evidence, name=Path(path).name: (
                evidence / name
            ).unlink()
        )
        self.assertEqual(code, 1)
        self.assertIn("REL-001 is DONE without", stderr)

    def test_stale_receipt_exemption_fails(self) -> None:
        exempt = next(iter(VERIFY.RECEIPT_EXEMPT))
        code, _, stderr = self.run_gate(
            receipts=lambda evidence, ticket=exempt: (
                evidence / f"{ticket}{VERIFY.RECEIPT_SUFFIX}"
            ).write_text("# receipt\n", encoding="utf-8")
        )
        self.assertEqual(code, 1)
        self.assertIn(f"receipt exemption for {exempt} is stale", stderr)

    def test_stale_threat_model_debt_fails(self) -> None:
        indebted = "SCM-001"
        self.assertIn(indebted, VERIFY.THREAT_MODEL_DEBT)
        code, _, stderr = self.run_gate(
            threat_model_transform=lambda text: text
            + f"\n## {indebted} threat-model closure review\n"
        )
        self.assertEqual(code, 1)
        self.assertIn(f"threat-model debt for {indebted} is stale", stderr)

    def test_exemption_for_a_reopened_ticket_fails(self) -> None:
        exempt = next(iter(VERIFY.THREAT_MODEL_EXEMPT))

        def reopen(text: str) -> str:
            lines = []
            for line in text.splitlines():
                match = VERIFY.TICKET_ROW.match(line)
                if match is not None and match.group(1) == exempt:
                    line = line.replace(f"| {exempt} | DONE |", f"| {exempt} | ACTIVE |", 1)
                lines.append(line)
            return "\n".join(lines) + "\n"

        code, _, stderr = self.run_gate(board_transform=reopen)
        self.assertEqual(code, 1)
        self.assertIn(f"threat-model exemption names {exempt}, which is ACTIVE", stderr)

    def test_no_ticket_rows_fails(self) -> None:
        code, _, stderr = self.run_gate(board_transform=lambda text: "# empty board\n")
        self.assertEqual(code, 1)
        self.assertIn("no ticket rows were found", stderr)

    def test_every_ledger_entry_states_a_reason(self) -> None:
        ledgers = (
            ("receipt exemption", VERIFY.RECEIPT_EXEMPT),
            ("threat-model exemption", VERIFY.THREAT_MODEL_EXEMPT),
            ("receipt debt", VERIFY.RECEIPT_DEBT),
            ("threat-model debt", VERIFY.THREAT_MODEL_DEBT),
        )
        for name, ledger in ledgers:
            for ticket, reason in ledger.items():
                with self.subTest(ledger=name, ticket=ticket):
                    self.assertGreater(len(reason.strip()), 20)


if __name__ == "__main__":
    unittest.main()
