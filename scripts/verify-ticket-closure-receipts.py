#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Enforce the board's ticket-closure Working rule mechanically.

Two obligations bind every `DONE` row in `docs/EXECUTION_BOARD.md`:

* the repository convention that a closed boundary ticket carries
  `docs/evidence/<TICKET>_SECURITY_REVIEW.md`, and
* the Working rule that "No implementation ticket may become `DONE` until
  `docs/threat-model/README.md` is reviewed for all affected boundaries ...
  and updated with the affected threats, mitigations, verification evidence,
  and residual risks; unchanged sections require an explicit reviewed
  no-change receipt."

Neither was checked by anything, so both were satisfied by reviewer attention
alone. A ticket that names no boundary in the threat model leaves no record
that the boundary was reviewed at all, which is indistinguishable from never
having looked.

A ticket satisfies an obligation by carrying the artifact, or by an explicit
exemption below that names the ticket and states why it needs none. Tickets
that closed without either are recorded as debt: they are reported on every
run and cannot grow, but they do not fail the build, because the gate is
being added after they closed and paying that debt is the custodian's call.
Run with `--strict` to fail on the debt too.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# Matches the same ticket-status rows as scripts/verify-execution-board.py.
TICKET_STATUSES = ("PENDING", "ACTIVE", "BLOCKED", "DONE", "DEFERRED")
TICKET_ROW = re.compile(
    r"^\| ([A-Z][A-Z0-9-]+) \| (" + "|".join(TICKET_STATUSES) + r") \| ([^|]+) \|"
)

RECEIPT_DIRECTORY = Path("docs") / "evidence"
RECEIPT_SUFFIX = "_SECURITY_REVIEW.md"
THREAT_MODEL = Path("docs") / "threat-model" / "README.md"

# REL-001 is the one closed ticket whose receipt is a release ceremony rather
# than a security review. Its board row names this exact path as its closure,
# and the file must still exist for the ticket to pass.
ALTERNATE_RECEIPTS = {
    "REL-001": (
        RECEIPT_DIRECTORY / "REL-001_RELEASE_CEREMONY.md",
        "closure is a signed release ceremony, not a boundary security review; "
        "the board row names this exact path",
    ),
}

# The first `docs/evidence/` receipt landed in `0da0356` (IDP-001,
# 2026-08-04). Every ticket below had already read `DONE` on the board before
# that commit, so no receipt was ever owed. Determined by replaying the board
# across its history, not by judgement.
_PRE_RECEIPT_CONVENTION = (
    "closed before the docs/evidence/<TICKET>_SECURITY_REVIEW.md convention "
    "existed; the first receipt landed in 0da0356 (IDP-001, 2026-08-04)"
)
RECEIPT_EXEMPT: dict[str, str] = {
    ticket: _PRE_RECEIPT_CONVENTION
    for ticket in (
        "FOUND-001", "CI-001", "ARCH-001", "FOUND-002", "SEC-001", "IR-001",
        "IR-002", "ARCH-002", "CTRL-001", "CTRL-002", "SEC-002", "AGENT-001",
        "AGENT-002", "AGENT-003", "UX-001", "E2E-001", "E2E-002", "E2E-003",
        "CTRL-003", "OPS-001", "OPS-002", "AGENT-004", "AGENT-005",
        "AGENT-006", "WIN-004", "WIN-001", "WIN-002", "WIN-003", "IR-003",
        "IR-004", "CTRL-004", "SEC-003", "AUDIT-001", "OPS-003", "TEST-001",
        "API-002", "UX-002", "UI-001", "INV-001", "INV-002", "INV-003",
        "INV-004", "MIG-000", "MIG-001", "MIG-002", "MIG-003", "MIG-004",
        "MIG-005A", "MIG-005", "DIFF-001",
    )
}

# The threat-model Working rule entered the board in `abb7c91` (2026-07-30).
# Every ticket below had already read `DONE` before that commit and is still
# named nowhere in the threat model. Pre-rule tickets the threat model does
# name -- ARCH-001, IR-001, CTRL-001, SEC-002, SEC-003, AGENT-001/002/003,
# OPS-001/002 -- need no exemption and are deliberately absent, so removing
# their reference later fails this gate rather than passing silently.
_PRE_THREAT_MODEL_RULE = (
    "closed before the threat-model closure Working rule entered the board "
    "in abb7c91 (2026-07-30)"
)
THREAT_MODEL_EXEMPT: dict[str, str] = {
    ticket: _PRE_THREAT_MODEL_RULE
    for ticket in (
        "FOUND-001", "FOUND-002", "SEC-001", "IR-002", "ARCH-002", "CTRL-002",
        "UX-001", "E2E-001", "E2E-002", "E2E-003", "CTRL-003", "AGENT-004",
        "AGENT-005", "AGENT-006", "WIN-004", "IR-003", "IR-004", "CTRL-004",
        "AUDIT-001", "OPS-003", "TEST-001", "API-002", "UX-002", "UI-001",
    )
}

# Closed after the obligation existed and carrying no receipt. Reported on
# every run; a ticket may only leave this ledger by gaining a receipt or an
# exemption that states a reason. Nothing may be added here without the
# custodian's decision -- an entry is an admitted gap, not a waiver.
RECEIPT_DEBT: dict[str, str] = {
    "DIFF-002": "2026-08-14 ec18c5d; board row names "
    "docs/architecture/STATE_POLICY_DIFFERENTIAL_V1.md as its closure",
    "MIG-006": "2026-08-15 6ac9be9; board row names "
    "docs/architecture/DIFFERENTIAL_AGGREGATE_V1.md as its closure",
    "MIG-007": "2026-08-16 4b2d38a; migration-package closure, no receipt",
    "SHADOW-001": "2026-08-16 7912a0f; board row names "
    "docs/architecture/SHADOW_QUALIFICATION_V1.md as its closure",
    "ALPHA-001": "2026-08-17 c6a238a; board row names docs/ALPHA_DEMO.md as "
    "its closure, and the threat model carries an ALPHA-001 review section",
    "CANARY-000": "2026-08-20 03a1f5d; no receipt and no threat-model entry",
    "EXEC-001": "2026-08-23 77b3d07; product-hardening batch, no receipt",
    "EXEC-002": "2026-08-23 77b3d07; product-hardening batch, no receipt",
    "EXEC-003": "2026-08-23 77b3d07; product-hardening batch, no receipt",
    "EXEC-004": "2026-08-23 77b3d07; product-hardening batch, no receipt",
    "OUTBOX-001": "2026-08-23 77b3d07; product-hardening batch, no receipt",
    "HYG-001": "2026-08-23 77b3d07; product-hardening batch, no receipt",
}

# Closed after the Working rule and named nowhere in the threat model. Four
# of these did edit the threat model at closure but added an unattributed
# TM-nnn register row, so no record ties the review to the ticket.
THREAT_MODEL_DEBT: dict[str, str] = {
    "CI-001": "2026-07-31 1348e34; CI routing change, threat model untouched",
    "MIG-001": "2026-07-31 0d78b1a; compiler boundary, threat model untouched",
    "MIG-003": "2026-07-31 759b633; compiler boundary, threat model untouched",
    "MIG-004": "2026-07-31 759b633; compiler boundary, threat model untouched",
    "MIG-005": "2026-08-01 393c938; library compiler, threat model untouched",
    "CONSUMER-001": "2026-08-04 8102990; added TM-031 without naming the "
    "ticket, and the verification-ownership table has no entry for it",
    "ADMIN-001": "2026-08-05 1324bca; added TM-032 without naming the "
    "ticket, and the verification-ownership table has no entry for it",
    "SCM-001": "2026-08-08 0ca0142; source-acquisition boundary closed "
    "without touching the threat model at all",
    "CACHE-001": "2026-08-10 3787b42; added TM-036 without naming the "
    "ticket, and the verification-ownership table has no entry for it",
    "SECRET-001": "2026-08-13 ccd9b7c; added TM-041 without naming the "
    "ticket, and the verification-ownership table has no entry for it",
    "CANARY-000": "2026-08-20 03a1f5d; no receipt and no threat-model entry",
    "EXEC-001": "2026-08-23 77b3d07; product-hardening batch, unreferenced",
    "EXEC-002": "2026-08-23 77b3d07; product-hardening batch, unreferenced",
    "EXEC-003": "2026-08-23 77b3d07; product-hardening batch, unreferenced",
    "EXEC-004": "2026-08-23 77b3d07; product-hardening batch, unreferenced",
    "OUTBOX-001": "2026-08-23 77b3d07; product-hardening batch, unreferenced",
    "HYG-001": "2026-08-23 77b3d07; product-hardening batch, unreferenced",
}


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(f"closure-receipts error: cannot read {path}: {error}", file=sys.stderr)
        raise SystemExit(1)


def board_statuses(text: str) -> tuple[dict[str, str], list[str]]:
    statuses: dict[str, str] = {}
    errors: list[str] = []
    for line in text.splitlines():
        match = TICKET_ROW.match(line)
        if match is None:
            continue
        ticket, status, _ = match.groups()
        if ticket in statuses and statuses[ticket] != status:
            errors.append(f"ticket {ticket} is declared with conflicting statuses")
            continue
        statuses[ticket] = status
    if not statuses:
        errors.append("no ticket rows were found")
    return statuses, errors


def receipt_for(repository: Path, ticket: str) -> Path | None:
    """Return the receipt backing ``ticket``, or None if it carries none."""
    conventional = repository / RECEIPT_DIRECTORY / f"{ticket}{RECEIPT_SUFFIX}"
    if conventional.is_file():
        return conventional
    alternate = ALTERNATE_RECEIPTS.get(ticket)
    if alternate is not None and (repository / alternate[0]).is_file():
        return repository / alternate[0]
    return None


def check_ledger(
    obligation: str,
    exempt: dict[str, str],
    debt: dict[str, str],
    statuses: dict[str, str],
    satisfied: set[str],
) -> list[str]:
    """Reject stale or misdirected ledger entries so neither ledger drifts."""
    errors: list[str] = []
    for name, ledger in (("exemption", exempt), ("debt", debt)):
        for ticket in sorted(ledger):
            if ticket not in statuses:
                errors.append(
                    f"{obligation} {name} names unknown ticket {ticket}"
                )
            elif statuses[ticket] != "DONE":
                errors.append(
                    f"{obligation} {name} names {ticket}, which is "
                    f"{statuses[ticket]}, not DONE"
                )
            elif ticket in satisfied:
                errors.append(
                    f"{obligation} {name} for {ticket} is stale: the ticket now "
                    "satisfies the obligation, so remove the entry"
                )
    for ticket in sorted(set(exempt) & set(debt)):
        errors.append(
            f"{obligation} lists {ticket} as both exempt and debt; an exemption "
            "states why nothing is owed, debt admits something is"
        )
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail on recorded closure debt as well as on new violations",
    )
    arguments = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    statuses, errors = board_statuses(read(repository / "docs" / "EXECUTION_BOARD.md"))
    if not statuses:
        for message in errors:
            print(f"closure-receipts error: {message}", file=sys.stderr)
        raise SystemExit(1)

    threat_model = read(repository / THREAT_MODEL)
    done = sorted(ticket for ticket, status in statuses.items() if status == "DONE")

    receipted = {ticket for ticket in done if receipt_for(repository, ticket)}
    reviewed = {
        ticket
        for ticket in done
        if re.search(rf"\b{re.escape(ticket)}\b", threat_model)
    }

    errors += check_ledger(
        "receipt", RECEIPT_EXEMPT, RECEIPT_DEBT, statuses, receipted
    )
    errors += check_ledger(
        "threat-model", THREAT_MODEL_EXEMPT, THREAT_MODEL_DEBT, statuses, reviewed
    )

    outstanding: list[str] = []
    for ticket in done:
        if ticket not in receipted and ticket not in RECEIPT_EXEMPT:
            message = (
                f"{ticket} is DONE without "
                f"{RECEIPT_DIRECTORY}/{ticket}{RECEIPT_SUFFIX}"
            )
            if ticket in RECEIPT_DEBT:
                outstanding.append(f"{message} [{RECEIPT_DEBT[ticket]}]")
            else:
                errors.append(
                    f"{message}; write the receipt, or add an exemption naming "
                    "the ticket and the reason it needs none"
                )
        if ticket not in reviewed and ticket not in THREAT_MODEL_EXEMPT:
            message = f"{ticket} is DONE but is named nowhere in {THREAT_MODEL}"
            if ticket in THREAT_MODEL_DEBT:
                outstanding.append(f"{message} [{THREAT_MODEL_DEBT[ticket]}]")
            else:
                errors.append(
                    f"{message}; the Working rule requires the affected "
                    "boundaries to be reviewed and the threats, mitigations, "
                    "verification evidence, and residual risks recorded, or an "
                    "explicit reviewed no-change receipt"
                )

    for message in outstanding:
        print(f"closure-receipts debt: {message}", file=sys.stderr)

    if arguments.strict:
        errors += [f"unpaid closure debt: {message}" for message in outstanding]

    if errors:
        for message in errors:
            print(f"closure-receipts error: {message}", file=sys.stderr)
        raise SystemExit(1)

    print(
        "closure-receipts-ok "
        f"done={len(done)} receipted={len(receipted)} reviewed={len(reviewed)} "
        f"receipt_exempt={len(RECEIPT_EXEMPT)} "
        f"threat_model_exempt={len(THREAT_MODEL_EXEMPT)} "
        f"debt={len(outstanding)}"
    )


if __name__ == "__main__":
    main()
