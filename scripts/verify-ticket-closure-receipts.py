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


TICKET_STATUSES = ("PENDING", "ACTIVE", "BLOCKED", "DONE", "DEFERRED")

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


# WIN-003 is named in the threat model only in running prose. A prose mention
# is not an attributed review: it cannot be told apart from a passing
# reference, and a sentence saying a ticket was NOT reviewed matches just as
# well as one saying it was. Recorded as debt rather than credited.
THREAT_MODEL_DEBT["WIN-003"] = (
    "2026-08-04 d854c97; named only in prose at docs/threat-model/README.md, "
    "with no ownership-table row, register row, or closure-review heading"
)

# Both ledgers are closed sets that may only shrink, and what follows is the
# mechanism behind that sentence rather than a request that it be honoured.
#
# Capping the COUNT is not enough, and the first version of this did exactly
# that: paying one historical debt while admitting one newly closed ticket
# leaves the cardinality unchanged, so the ratchet passes and a fresh gap has
# been laundered into history. What has to be pinned is MEMBERSHIP. A ticket
# may leave a ledger by earning its artifact; none may ever enter.
#
# Removals need no edit here: a ticket that pays its debt and leaves the ledger
# cannot quietly return, because `check_ledger` already rejects an entry for a
# ticket that satisfies its obligation.
# Written out literally on purpose. Deriving a baseline from the ledger it
# bounds -- `frozenset(RECEIPT_DEBT)` -- is an assertion that cannot fail.
RECEIPT_EXEMPT_BASELINE = frozenset({
    "AGENT-001", "AGENT-002", "AGENT-003", "AGENT-004", "AGENT-005",
    "AGENT-006", "API-002", "ARCH-001", "ARCH-002", "AUDIT-001",
    "CI-001", "CTRL-001", "CTRL-002", "CTRL-003", "CTRL-004",
    "DIFF-001", "E2E-001", "E2E-002", "E2E-003", "FOUND-001",
    "FOUND-002", "INV-001", "INV-002", "INV-003", "INV-004", "IR-001",
    "IR-002", "IR-003", "IR-004", "MIG-000", "MIG-001", "MIG-002",
    "MIG-003", "MIG-004", "MIG-005", "MIG-005A", "OPS-001", "OPS-002",
    "OPS-003", "SEC-001", "SEC-002", "SEC-003", "TEST-001", "UI-001",
    "UX-001", "UX-002", "WIN-001", "WIN-002", "WIN-003", "WIN-004"
})
THREAT_MODEL_EXEMPT_BASELINE = frozenset({
    "AGENT-004", "AGENT-005", "AGENT-006", "API-002", "ARCH-002",
    "AUDIT-001", "CTRL-002", "CTRL-003", "CTRL-004", "E2E-001",
    "E2E-002", "E2E-003", "FOUND-001", "FOUND-002", "IR-002", "IR-003",
    "IR-004", "OPS-003", "SEC-001", "TEST-001", "UI-001", "UX-001",
    "UX-002", "WIN-004"
})
RECEIPT_DEBT_BASELINE = frozenset({
    "ALPHA-001", "CANARY-000", "DIFF-002", "EXEC-001", "EXEC-002",
    "EXEC-003", "EXEC-004", "HYG-001", "MIG-006", "MIG-007",
    "OUTBOX-001", "SHADOW-001"
})
THREAT_MODEL_DEBT_BASELINE = frozenset({
    "ADMIN-001", "CACHE-001", "CANARY-000", "CI-001", "CONSUMER-001",
    "EXEC-001", "EXEC-002", "EXEC-003", "EXEC-004", "HYG-001",
    "MIG-001", "MIG-003", "MIG-004", "MIG-005", "OUTBOX-001", "SCM-001",
    "SECRET-001", "WIN-003"
})

# The board's 15 tables in 4 row formats. Only the nine whose first header
# cell is `Ticket` carry authoritative status; the lane, batch and dispatch
# tables are redundant views and are cross-checked against them.
TICKET_TABLE_HEADER = "Ticket"
LANE_TABLE_HEADER = "Lane"
BATCH_TABLE_HEADER = "Batch"
DISPATCH_TABLE_HEADER = "Slot"

# Lane tables overload their third column: it holds a status for closed lanes
# and an execution class for open ones. A class is not an unknown status.
EXECUTION_CLASSES = ("SERIAL", "BATCH", "PARALLEL")

# A floor under the parse. Every silent-skip failure on this project looked
# like a smaller number that nobody was watching, so the count is pinned:
# format drift that drops rows fails the gate instead of shrinking the
# denominator. Raise this when tickets are added.
MINIMUM_TICKET_ROWS = 104

# A receipt must be able to carry a review. The smallest real receipt on the
# board is 2,862 bytes; every one names the ticket it closes and is headed
# markdown. `touch docs/evidence/<TICKET>_SECURITY_REVIEW.md` must not close a
# ticket, so an empty or stub file is a violation, not a receipt.
RECEIPT_MINIMUM_BYTES = 1000

TABLE_SEPARATOR = re.compile(r"^\|[\s:|-]+\|$")
DOC_PATH = re.compile(r"`(docs/[A-Za-z0-9_./-]+)`")


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(f"closure-receipts error: cannot read {path}: {error}", file=sys.stderr)
        raise SystemExit(1)


def cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.split("|")[1:-1]]


def tables(text: str) -> list[tuple[list[str], list[tuple[int, list[str]]]]]:
    """Split the board into (header, rows) pairs, one per markdown table.

    A table is a `|`-row whose successor is a separator. The dispatch table's
    separator is right-aligned (`|---:|`), so alignment colons are allowed.
    """
    lines = text.splitlines()
    found: list[tuple[list[str], list[tuple[int, list[str]]]]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if (
            line.startswith("|")
            and index + 1 < len(lines)
            and TABLE_SEPARATOR.match(lines[index + 1])
        ):
            header = cells(line)
            rows: list[tuple[int, list[str]]] = []
            cursor = index + 2
            while cursor < len(lines) and lines[cursor].startswith("|"):
                rows.append((cursor + 1, cells(lines[cursor])))
                cursor += 1
            found.append((header, rows))
            index = cursor
            continue
        index += 1
    return found


def board_statuses(text: str) -> tuple[dict[str, str], list[str]]:
    """Read every authoritative ticket row, and refuse to skip one silently.

    The predecessor of this function matched rows with a regex and `continue`d
    past anything that did not match, so a row with aligned padding or a
    title-case status vanished from the denominator while the gate still
    printed `-ok`. Here a row inside a ticket table that cannot be read is an
    error, because an unreadable row and an absent obligation are the same
    thing from outside.
    """
    statuses: dict[str, str] = {}
    errors: list[str] = []
    rows_seen = 0
    for header, rows in tables(text):
        if not header or header[0] != TICKET_TABLE_HEADER:
            continue
        for number, row in rows:
            rows_seen += 1
            if len(row) < 2:
                errors.append(f"line {number}: ticket row has fewer than two cells")
                continue
            ticket, status = row[0], row[1]
            if not re.fullmatch(r"[A-Z][A-Z0-9-]+", ticket):
                errors.append(
                    f"line {number}: {ticket!r} is not a ticket id, but it sits in "
                    "the first column of a ticket table"
                )
                continue
            if status not in TICKET_STATUSES:
                errors.append(
                    f"line {number}: {ticket} has status {status!r}, which is not "
                    f"one of {', '.join(TICKET_STATUSES)}"
                )
                continue
            if ticket in statuses and statuses[ticket] != status:
                errors.append(f"ticket {ticket} is declared with conflicting statuses")
                continue
            statuses[ticket] = status
    if not statuses:
        errors.append("no ticket rows were found")
    elif rows_seen < MINIMUM_TICKET_ROWS:
        errors.append(
            f"only {rows_seen} ticket rows parsed, below the pinned floor of "
            f"{MINIMUM_TICKET_ROWS}; a row the gate cannot see carries no "
            "obligation, so shrinking the denominator fails rather than passes"
        )
    return statuses, errors


def cross_check_views(text: str, statuses: dict[str, str]) -> list[str]:
    """Hold the lane, batch and dispatch tables to the authoritative rows.

    These three formats restate ticket status in a different shape. Nothing
    compared them, so a lane could read DONE while its ticket row did not.
    """
    errors: list[str] = []
    for header, rows in tables(text):
        if not header or header[0] not in (
            LANE_TABLE_HEADER,
            BATCH_TABLE_HEADER,
            DISPATCH_TABLE_HEADER,
        ):
            continue
        view = header[0]
        for number, row in rows:
            if len(row) < 3:
                continue
            claimed = row[2]
            for ticket in re.findall(r"[A-Z][A-Z0-9]*-[0-9]+[A-Z]?", row[1]):
                if ticket not in statuses:
                    errors.append(
                        f"line {number}: the {view} table names {ticket}, which has "
                        "no row in any ticket table"
                    )
                elif claimed in TICKET_STATUSES and statuses[ticket] != claimed:
                    errors.append(
                        f"line {number}: the {view} table reads {ticket} as "
                        f"{claimed}, but its ticket row reads {statuses[ticket]}"
                    )
                elif claimed not in TICKET_STATUSES and claimed not in EXECUTION_CLASSES:
                    errors.append(
                        f"line {number}: the {view} table gives {ticket} a third "
                        f"column of {claimed!r}, which is neither a status nor an "
                        "execution class"
                    )
    return errors


def cited_documents(repository: Path, text: str) -> list[str]:
    """Every `docs/...` path the board cites must exist.

    A closure that cites a receipt nobody wrote reads exactly like one that
    cites a receipt somebody did. Scoped to `docs/` deliberately: rows also
    cite code paths they RETIRED, such as HYG-001 naming `crates/state-machine`
    after deleting it, and those are history rather than broken links.
    """
    errors: list[str] = []
    for path in sorted(set(DOC_PATH.findall(text))):
        if not (repository / path).is_file():
            errors.append(
                f"the board cites {path}, which does not exist; write it, or stop "
                "citing it as evidence"
            )
    return errors


def receipt_path(repository: Path, ticket: str) -> Path | None:
    """Return where ``ticket``'s receipt lives, whether or not it is adequate."""
    conventional = repository / RECEIPT_DIRECTORY / f"{ticket}{RECEIPT_SUFFIX}"
    if conventional.is_file():
        return conventional
    alternate = ALTERNATE_RECEIPTS.get(ticket)
    if alternate is not None and (repository / alternate[0]).is_file():
        return repository / alternate[0]
    return None


def receipt_defects(path: Path, ticket: str) -> list[str]:
    """Reject a file that occupies the receipt's name without doing its work.

    Existence was the whole test before this. An empty file passed, so the
    obligation could be discharged with `touch` -- the gate against closing a
    ticket on nothing was itself satisfiable by nothing.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [f"cannot be read: {error}"]
    defects: list[str] = []
    size = len(text.encode("utf-8"))
    if size < RECEIPT_MINIMUM_BYTES:
        defects.append(
            f"is {size} bytes; a receipt records what was reviewed, what was "
            f"found, and what residual risk was accepted, which does not fit in "
            f"under {RECEIPT_MINIMUM_BYTES}"
        )
    if not re.search(rf"\b{re.escape(ticket)}\b", text):
        defects.append(f"never names {ticket}, so nothing ties it to the closure")
    if not any(line.startswith("#") for line in text.splitlines()):
        defects.append("has no heading, so it is not a structured review document")
    return defects


OWNERSHIP_HEADING = "## Security verification ownership"
REGISTER_ID = re.compile(r"TM-\d+")


def threat_model_attribution(text: str, ticket: str) -> str | None:
    """Return where the threat model AFFIRMATIVELY attributes a review.

    Three shapes count, and nothing else: a row in the verification-ownership
    table whose ticket column names it, a row in the threat register, or a
    closure-review heading the ticket leads.

    Two weaker rules were tried and both could be satisfied by a sentence
    saying the review had not happened. A bare substring search credited
    `TODO: <TICKET> has not been reviewed yet`. Requiring merely a table row
    or a heading credited `## TODO: <TICKET> has not been reviewed yet`, which
    is the same claim in a structure. Placement is not meaning; what makes an
    attribution affirmative is that the shape only exists to record a review.
    """
    pattern = re.compile(rf"\b{re.escape(ticket)}\b")
    heading = re.compile(rf"^#{{2,3}} {re.escape(ticket)}\b.*\breview\b", re.I)

    lines = text.splitlines()
    ownership_start: int | None = None
    ownership_end = len(lines)
    for number, line in enumerate(lines):
        if line.startswith(OWNERSHIP_HEADING):
            ownership_start = number
        elif ownership_start is not None and number > ownership_start:
            if line.startswith("## "):
                ownership_end = number
                break

    for number, line in enumerate(lines, start=1):
        if heading.match(line):
            return f"closure-review heading at line {number}"
        if not line.startswith("|") or not pattern.search(line):
            continue
        row = [cell.strip() for cell in line.split("|")[1:-1]]
        if not row:
            continue
        within_ownership = (
            ownership_start is not None
            and ownership_start < number - 1 < ownership_end
        )
        if within_ownership and len(row) >= 2 and pattern.search(row[-1]):
            return f"verification-ownership row at line {number}"
        if REGISTER_ID.fullmatch(row[0]):
            return f"threat-register row at line {number}"
    return None


def check_ledger(
    obligation: str,
    exempt: dict[str, str],
    debt: dict[str, str],
    statuses: dict[str, str],
    satisfied: set[str],
    exempt_baseline: frozenset[str],
    debt_baseline: frozenset[str],
) -> list[str]:
    """Reject stale or misdirected ledger entries so neither ledger drifts."""
    errors: list[str] = []
    for name, ledger, baseline in (
        ("exemption", exempt, exempt_baseline),
        ("debt", debt, debt_baseline),
    ):
        for ticket in sorted(set(ledger) - baseline):
            errors.append(
                f"{ticket} is not in the {obligation} {name} baseline; that ledger "
                "may only shrink. A ticket closing today owes the artifact -- write "
                "it, rather than admitting a new gap into a set that exists to "
                "record old ones"
            )
        for ticket in sorted(ledger):
            if ticket not in statuses:
                errors.append(f"{obligation} {name} names unknown ticket {ticket}")
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


def verify(repository: Path, strict: bool) -> tuple[list[str], list[str], str]:
    """Return (errors, debt, summary) for ``repository``."""
    board = read(repository / "docs" / "EXECUTION_BOARD.md")
    statuses, errors = board_statuses(board)
    if not statuses:
        return errors, [], ""

    threat_model = read(repository / THREAT_MODEL)
    done = sorted(ticket for ticket, status in statuses.items() if status == "DONE")

    errors += cross_check_views(board, statuses)
    errors += cited_documents(repository, board)

    receipted: set[str] = set()
    for ticket in done:
        path = receipt_path(repository, ticket)
        if path is None:
            continue
        defects = receipt_defects(path, ticket)
        if defects:
            for defect in defects:
                errors.append(
                    f"{ticket}'s receipt {path.relative_to(repository)} {defect}"
                )
            continue
        receipted.add(ticket)

    reviewed = {
        ticket
        for ticket in done
        if threat_model_attribution(threat_model, ticket) is not None
    }

    errors += check_ledger(
        "receipt",
        RECEIPT_EXEMPT,
        RECEIPT_DEBT,
        statuses,
        receipted,
        RECEIPT_EXEMPT_BASELINE,
        RECEIPT_DEBT_BASELINE,
    )
    errors += check_ledger(
        "threat-model",
        THREAT_MODEL_EXEMPT,
        THREAT_MODEL_DEBT,
        statuses,
        reviewed,
        THREAT_MODEL_EXEMPT_BASELINE,
        THREAT_MODEL_DEBT_BASELINE,
    )

    debt: list[str] = []
    for ticket in done:
        if ticket not in receipted and ticket not in RECEIPT_EXEMPT:
            message = (
                f"{ticket} is DONE without "
                f"{RECEIPT_DIRECTORY}/{ticket}{RECEIPT_SUFFIX}"
            )
            if ticket in RECEIPT_DEBT:
                debt.append(f"{message} [{RECEIPT_DEBT[ticket]}]")
            else:
                errors.append(
                    f"{message}; write the receipt, or add an exemption naming "
                    "the ticket and the reason it needs none"
                )
        if ticket not in reviewed and ticket not in THREAT_MODEL_EXEMPT:
            message = (
                f"{ticket} is DONE but {THREAT_MODEL} attributes no review to it "
                "in a table row or a heading"
            )
            if ticket in THREAT_MODEL_DEBT:
                debt.append(f"{message} [{THREAT_MODEL_DEBT[ticket]}]")
            else:
                errors.append(
                    f"{message}; the Working rule requires the affected "
                    "boundaries to be reviewed and the threats, mitigations, "
                    "verification evidence, and residual risks recorded, or an "
                    "explicit reviewed no-change receipt"
                )

    if strict:
        errors += [f"unpaid closure debt: {message}" for message in debt]

    summary = (
        "closure-receipts-ok "
        f"done={len(done)} receipted={len(receipted)} reviewed={len(reviewed)} "
        f"receipt_exempt={len(RECEIPT_EXEMPT)} "
        f"threat_model_exempt={len(THREAT_MODEL_EXEMPT)} "
        f"debt={len(debt)}"
    )
    return errors, debt, summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail on recorded closure debt as well as on new violations",
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root to check (defaults to this script's repository)",
    )
    arguments = parser.parse_args()

    errors, debt, summary = verify(arguments.repository, arguments.strict)

    for message in debt:
        print(f"closure-receipts debt: {message}", file=sys.stderr)
    if errors:
        for message in errors:
            print(f"closure-receipts error: {message}", file=sys.stderr)
        raise SystemExit(1)
    print(summary)


if __name__ == "__main__":
    main()
