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
from collections import Counter
import sys
from pathlib import Path


TICKET_STATUSES = ("PENDING", "ACTIVE", "BLOCKED", "DONE", "DEFERRED")

# `\b` does not delimit a ticket id, because `-` is a non-word character: it
# matches AAA-001 inside AAA-001-HARDEN, so a review of the longer ticket would
# be credited to the shorter one. Ticket characters are the delimiter.
TICKET_CHARACTER = "A-Za-z0-9-"


def names(ticket: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?<![{TICKET_CHARACTER}]){re.escape(ticket)}(?![{TICKET_CHARACTER}])"
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
    # CONSUMER-001 and ADMIN-001 left this ledger when identifier matching was
    # corrected: TM-031 and TM-032 DO name them, in the Required verification
    # column, as `docs/evidence/<TICKET>_SECURITY_REVIEW.md`. `\b` had refused
    # that because `_` is a word character, so two real attributions read as
    # absent for as long as the gate has existed.
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
# Exposed by tightening register attribution to the verification column. All
# three were credited by a mention in "Primary mitigations" or "Residual risk",
# neither of which asserts that the ticket's evidence verified anything. The
# gaps are older than the rule that found them: the ledger widened because the
# predicate got stricter, not because closure discipline slipped.
for _ticket in ("MIG-002", "MIG-006", "MIG-007"):
    THREAT_MODEL_DEBT[_ticket] = (
        "named in the threat register outside the Required verification column, "
        "so no row asserts that this ticket's evidence verified the threat"
    )

# HYG-002 disclosed nineteen gaps that the prose predicate had been hiding, and
# the argument is the same one the MIG-002/006/007 block above makes: the ledger
# widened because the predicate got stricter, not because closure discipline
# slipped. It is worth being exact about what was being read, because it is
# worse than "a loose rule".
#
# SEVENTEEN of these were credited by the table headed
# `| Area | First implementation ticket |`. That table records WHICH TICKET
# FIRST IMPLEMENTED AN AREA. It asserts nothing whatever about a review, and it
# never claimed to -- the gate was reading an ownership map as an attestation.
# Deleting those rows was never an option either: they are true, and they are
# the only record of who owns each area.
for _ticket in (
    "AGENT-001", "AGENT-002", "AGENT-003", "ARCH-001", "CTRL-001",
    "INV-001", "INV-002", "INV-003", "INV-004", "IR-001", "MIG-000",
    "OPS-001", "OPS-002", "SEC-002", "SEC-003", "WIN-001", "WIN-002",
):
    THREAT_MODEL_DEBT[_ticket] = (
        "credited before HYG-002 only by the `Area | First implementation "
        "ticket` ownership table, which records which ticket first implemented "
        "an area and asserts nothing about a review having happened"
    )

# The other two were credited by a register verification cell whose only cited
# document is ANOTHER ticket's closure: DIFF-001's names the aggregate contract
# whose own header reads `Status: MIG-006 complete`, and MIG-005A's names the
# migration package belonging to MIG-007. Each ticket has a document that does
# name it -- `JENKINS_NATIVE_DIFFERENTIAL_V1.md` and `STATE_TRANSFER_V1.md` --
# and neither is cited by any board row or threat-model structure, so promoting
# one here would be this gate inventing an attribution rather than reading one.
for _ticket in ("DIFF-001", "MIG-005A"):
    THREAT_MODEL_DEBT[_ticket] = (
        "credited before HYG-002 by a register verification cell whose only "
        "cited document is another ticket's closure evidence, so no row asserts "
        "that this ticket's own evidence verified the threat"
    )

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
# WIDENED ONCE, DELIBERATELY, BY HYG-002 -- and this paragraph is the argument
# the ledger's own comment demands before an entry is permitted.
#
# The nineteen names below the blank line did not acquire a gap when HYG-002
# landed; HYG-002 stopped hiding one they already had. Seventeen were credited
# by a table that records which ticket first implemented an area, and two by a
# register cell citing another ticket's closure document. Nothing in the threat
# model asserted a review for any of them, before or after.
#
# This is the second time this ledger has widened for this reason -- the
# MIG-002/006/007 block did the same when register attribution was narrowed to
# the verification column -- and both times the number got worse because the
# measurement got honest. A ratchet that could never widen would have forced
# the opposite choice: keep reading the ownership table as an attestation, and
# keep the count at 31.
THREAT_MODEL_DEBT_BASELINE = frozenset({
    "CACHE-001", "CANARY-000", "CI-001",
    "EXEC-001", "EXEC-002", "EXEC-003", "EXEC-004", "HYG-001",
    "MIG-001", "MIG-003", "MIG-004", "MIG-005", "OUTBOX-001", "SCM-001",
    "MIG-002", "MIG-006", "MIG-007", "SECRET-001", "WIN-003",

    "AGENT-001", "AGENT-002", "AGENT-003", "ARCH-001", "CTRL-001",
    "DIFF-001", "INV-001", "INV-002", "INV-003", "INV-004", "IR-001",
    "MIG-000", "MIG-005A", "OPS-001", "OPS-002", "SEC-002", "SEC-003",
    "WIN-001", "WIN-002",
})

# The board's 15 tables in 4 row formats. Only the nine whose first header
# cell is `Ticket` carry authoritative status; the lane, batch and dispatch
# tables are redundant views and are cross-checked against them.
TICKET_TABLE_HEADER = "Ticket"
# Ticket | Status | Depends on | Objective and acceptance
TICKET_TABLE_COLUMNS = 4
# The same identifier shape the authoritative rows use. A narrower pattern read
# `AAA-001-HARDEN` as `AAA-001`, so a view could be checked against the wrong
# ticket's status, or a valid row could fail as an unknown shorter ticket.
VIEW_TICKET_ID = re.compile(r"[A-Z][A-Z0-9]*-[0-9]+[A-Z]?(?:-[A-Z0-9]+)*")
LANE_TABLE_HEADER = "Lane"
BATCH_TABLE_HEADER = "Batch"
DISPATCH_TABLE_HEADER = "Slot"
KNOWN_TABLE_HEADERS = frozenset(
    {TICKET_TABLE_HEADER, LANE_TABLE_HEADER, BATCH_TABLE_HEADER, DISPATCH_TABLE_HEADER}
)
# Raise a count when a table is genuinely added; a change here is deliberate.
EXPECTED_TABLES = {
    TICKET_TABLE_HEADER: 9,
    LANE_TABLE_HEADER: 4,
    BATCH_TABLE_HEADER: 1,
    DISPATCH_TABLE_HEADER: 1,
}

# Lane tables overload their third column: it holds a status for closed lanes
# and an execution class for open ones. A class is not an unknown status.
EXECUTION_CLASSES = ("SERIAL", "BATCH", "PARALLEL")

# A floor under the parse. Every silent-skip failure on this project looked
# like a smaller number that nobody was watching, so the count is pinned:
# format drift that drops rows fails the gate instead of shrinking the
# denominator. Raise this when tickets are added.
MINIMUM_TICKET_ROWS = 105

# Pinning the row COUNT is not enough: an edit that adds one ticket while
# making another unparsable holds the count at 104 and silently drops the
# removed ticket's obligations. DONE is terminal, so this set may only grow.
# A name that leaves it has either lost its row or stopped reading DONE, and
# both retire a closure obligation that nothing else records.
CLOSED_TICKETS = frozenset({
    "ADMIN-001", "AGENT-001", "AGENT-002", "AGENT-003", "AGENT-004",
    "AGENT-005", "AGENT-006", "ALPHA-001", "API-002", "ARCH-001",
    "ARCH-002", "AUDIT-001", "AUTHZ-001", "CACHE-001", "CANARY-000",
    "CI-001", "CONSUMER-001", "CTRL-001", "CTRL-002", "CTRL-003",
    "CTRL-004", "DEP-001", "DEPLOY-004", "DIFF-001", "DIFF-002",
    "DIFF-003",
    "DISC-001", "E2E-001", "E2E-002", "E2E-003", "EXEC-001", "EXEC-002",
    "EXEC-003", "EXEC-004", "EXT-001", "EXT-002", "FOUND-001",
    "FOUND-002", "HYG-001", "IDP-001", "INPUT-001", "INV-001",
    "INV-002", "INV-003", "INV-004", "IR-001", "IR-002", "IR-003",
    "IR-004", "JOBSTATE-001", "MIG-000", "MIG-001", "MIG-002",
    "MIG-003", "MIG-004", "MIG-005", "MIG-005A", "MIG-006", "MIG-007",
    "OBS-001", "OPS-001", "OPS-002", "OPS-003", "OUTBOX-001",
    "PROV-001", "REL-001", "SCM-001", "SEC-001", "SEC-002", "SEC-003",
    "SECRET-001", "SHADOW-001", "TEST-001", "TRIG-001", "UI-001",
    "UX-001", "UX-002", "WIN-001", "WIN-002", "WIN-003", "WIN-004"
})

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


# `\|` is an escaped pipe inside a cell, not a boundary. Splitting on every
# pipe shifts every later cell left, so a mitigations cell ending in
# `... \| AAA-001` would put that ticket into the slot the verification column
# is read from, crediting a review the real column never claimed.
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


def cells(line: str) -> list[str]:
    parts = UNESCAPED_PIPE.split(line)[1:-1]
    return [part.replace("\\|", "|").strip() for part in parts]


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
    authoritative: set[int] = set()
    for header, rows in tables(text):
        if not header or header[0] != TICKET_TABLE_HEADER:
            continue
        authoritative.update(number for number, _ in rows)
        for number, row in rows:
            rows_seen += 1
            # Four cells, as the board verifier requires. A shorter row is
            # counted here and omitted there, so a new ticket could satisfy
            # the row floor while its dependencies, execution class and
            # shared boundaries went unvalidated.
            if len(row) != TICKET_TABLE_COLUMNS:
                errors.append(
                    f"line {number}: the row for {row[0] if row else '<empty>'} "
                    f"has {len(row)} cells, not the {TICKET_TABLE_COLUMNS} the "
                    "table declares; a short row is counted here and omitted by "
                    "the board verifier, and a long one loses the acceptance text "
                    "past its extra pipe"
                )
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
            if ticket in statuses:
                # Even when the statuses agree the rows may differ in their
                # dependencies or acceptance text, and last-one-wins means two
                # verifiers can read two different definitions of one ticket.
                errors.append(
                    f"ticket {ticket} has more than one authoritative row "
                    f"(line {number}); one ticket, one row"
                )
                continue
            statuses[ticket] = status
    # A row that looks like a ticket but sits outside a recognised table is
    # invisible here while `verify-execution-board.py` still counts it, so a
    # mistyped header ("Tickets") would carry a DONE ticket past this gate and
    # leave the row floor satisfied. Skipping a table is a parse failure, and
    # this gate does not skip.
    for number, line in enumerate(text.splitlines(), start=1):
        if number in authoritative or not line.startswith("|"):
            continue
        row = cells(line)
        if len(row) < 2 or row[1] not in TICKET_STATUSES:
            continue
        if not re.fullmatch(r"[A-Z][A-Z0-9-]+", row[0]):
            continue
        errors.append(
            f"line {number}: {row[0]} reads as a ticket row but is not inside a "
            f"table headed {TICKET_TABLE_HEADER!r}; a ticket outside an "
            "authoritative table carries no closure obligation here while the "
            "board verifier still counts it"
        )

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
    # A mistyped header ("Batches") makes a cross-check vanish exactly when the
    # view it checks might disagree. Rejecting every unfamiliar header would
    # instead fail any future informational table, so what is pinned is that
    # the expected tables are all still present and still spelled right.
    seen = Counter(header[0] for header, _ in tables(text) if header)
    for expected, count in sorted(EXPECTED_TABLES.items()):
        if seen[expected] != count:
            errors.append(
                f"the board has {seen[expected]} tables headed {expected!r}, not "
                f"{count}; a renamed or mistyped header removes that table from "
                "every check, and a new one needs this count raised deliberately"
            )
    for header, rows in tables(text):
        if not header:
            continue
        if header[0] == TICKET_TABLE_HEADER or header[0] not in KNOWN_TABLE_HEADERS:
            continue
        view = header[0]
        for number, row in rows:
            if len(row) < 3:
                errors.append(
                    f"line {number}: the {view} table row has {len(row)} cells "
                    "and cannot state a status, so it cross-checks nothing"
                )
                continue
            claimed = row[2]
            leftover = VIEW_TICKET_ID.sub(" ", row[1])
            if re.search(r"[A-Za-z0-9_]", leftover.replace("`", " ")):
                errors.append(
                    f"line {number}: the {view} table row has identifier text "
                    f"{leftover.strip()!r} that is not a ticket; a corrupted id "
                    "keeps the row claiming a status it checks nothing against"
                )
                continue
            named = VIEW_TICKET_ID.findall(row[1])
            if not named:
                errors.append(
                    f"line {number}: the {view} table row names no ticket, so it "
                    "cross-checks nothing while still claiming a status"
                )
                continue
            for ticket in named:
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
    cites a receipt somebody did.

    Restricted to DONE rows, because an open ticket's acceptance criteria
    routinely name the document it will produce, and requiring those to exist
    would make the board refuse to plan work without a placeholder -- this gate
    failing closed on correct work.

    Scoped to `docs/` deliberately: rows also cite code paths they RETIRED,
    such as HYG-001 naming `crates/state-machine` after deleting it, and those
    are history rather than broken links.
    """
    errors: list[str] = []
    for header, rows in tables(text):
        if not header or header[0] != TICKET_TABLE_HEADER:
            continue
        for number, row in rows:
            if len(row) != TICKET_TABLE_COLUMNS or row[1] != "DONE":
                continue
            for path in sorted(set(DOC_PATH.findall(row[3]))):
                if not (repository / path).is_file():
                    errors.append(
                        f"line {number}: {row[0]} is DONE and cites {path}, which "
                        "does not exist; write it, or stop citing it as evidence"
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
    if not names(ticket).search(text):
        defects.append(f"never names {ticket}, so nothing ties it to the closure")
    if not any(line.startswith("#") for line in text.splitlines()):
        defects.append("has no heading, so it is not a structured review document")
    return defects


# THE ATTRIBUTION FIELD, AND WHY IT HOLDS NO SENTENCES.
#
# Attribution used to be inferred from English in three structural shapes -- a
# verification-ownership row, a threat-register verification cell, a
# closure-review heading the ticket led -- with a negation veto on top. PR #96's
# review defeated four successive versions of that predicate with the same
# denial in a new wrapper, and the function's own docstring conceded the rest:
# a denial phrased without a vetoed word, inside an affirmative structure, would
# still pass.
#
# That argument cannot be won by tightening, because the defect is not in any
# particular pattern. It is that a field which can hold a sentence can hold a
# sentence that lies, and no amount of reading decides which. So this field
# holds no sentences. Two columns, each FULLMATCHED -- a ticket id, and a
# backticked path under docs/ -- and nothing else fits in either. The old
# bypass, `AAA-001 review has not happened`, is no longer a denial the gate has
# to detect; it is simply not a ticket id. There is nothing to veto because
# there is nowhere to write it. (HYG-002)
#
# The prose did not go away and should not: the register above still explains
# what was reviewed and what residual risk remains. It is no longer LOAD-BEARING,
# which is the only claim this change makes about it.
ATTRIBUTION_HEADING = "## Closure attribution"
ATTRIBUTION_HEADER = ["Ticket", "Evidence"]
# Anchored with fullmatch at both call sites below. A ticket id is the whole
# cell or the row is refused; `MIG-005A` and `W0-A` are why the shape is spelled
# out rather than approximated by `[A-Z][A-Z0-9-]+`, which admits both a bare
# `ABC` and the batch id `W0-A` that is not a ticket at all.
ATTRIBUTION_TICKET = re.compile(r"[A-Z][A-Z0-9]*-[0-9]+[A-Z]?(?:-[A-Z0-9]+)*")
# The same spelling `DOC_PATH` uses, but fullmatched rather than searched: the
# cell IS the path, so a cell that merely CONTAINS one is refused.
ATTRIBUTION_EVIDENCE = re.compile(r"`(docs/[A-Za-z0-9_./-]+)`")


def closure_attributions(text: str) -> tuple[dict[str, str], list[str]]:
    """Read the closure-attribution table -> {ticket: evidence path}, defects.

    Parsed ONCE per run rather than re-scanned per ticket. The old predicate was
    called for every DONE ticket and re-read the whole threat model each time;
    parsing once is what makes the both-ways checks in verify() affordable.

    NOTHING HERE SKIPS. A row this function cannot read is an error, never a
    silent omission, because an unreadable attribution row and an absent one
    look identical to the ticket each was supposed to credit -- which is this
    repository's signature failure and the reason the gate exists.
    """
    attributions: dict[str, str] = {}
    errors: list[str] = []
    matching = [rows for header, rows in tables(text) if header == ATTRIBUTION_HEADER]
    if not matching:
        errors.append(
            f"{THREAT_MODEL} has no closure-attribution table; the gate reads "
            f"attribution from a table headed `{' | '.join(ATTRIBUTION_HEADER)}` "
            f"under `{ATTRIBUTION_HEADING}`, and its absence attributes nothing "
            "rather than everything"
        )
        return attributions, errors
    if len(matching) > 1:
        # Two tables with this header is ambiguous, and the ambiguity is
        # exploitable: a second table appended below could attribute a review
        # the first never claimed, and whichever the gate read first would win.
        errors.append(
            f"{THREAT_MODEL} has {len(matching)} closure-attribution tables; "
            "exactly one may exist, or which of them attributes a review is "
            "decided by document order rather than by anyone"
        )
        return attributions, errors
    for number, row in matching[0]:
        if len(row) != len(ATTRIBUTION_HEADER):
            errors.append(
                f"line {number}: the closure-attribution row has {len(row)} "
                f"cells, not the {len(ATTRIBUTION_HEADER)} the table declares"
            )
            continue
        ticket, evidence = row[0], row[1]
        if not ATTRIBUTION_TICKET.fullmatch(ticket):
            errors.append(
                f"line {number}: {ticket!r} is not a ticket id. The ticket "
                "column holds an id and nothing else -- no prose, no "
                "qualification, and so no denial"
            )
            continue
        match = ATTRIBUTION_EVIDENCE.fullmatch(evidence)
        if match is None:
            errors.append(
                f"line {number}: {ticket}'s evidence cell {evidence!r} is not a "
                "backticked path under docs/. The evidence column holds a path "
                "and nothing else"
            )
            continue
        if ticket in attributions:
            errors.append(
                f"line {number}: {ticket} is attributed twice; two rows for one "
                "ticket means two evidence paths, and nothing decides between them"
            )
            continue
        attributions[ticket] = match.group(1)
    return attributions, errors


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
        for ticket in sorted(baseline - set(ledger)):
            errors.append(
                f"the {obligation} {name} baseline still names {ticket}, which has "
                "left the ledger; drop it from the baseline in the same commit, or "
                "the name stays permanently re-admittable and the ratchet only "
                "holds against tickets that never owed anything"
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

    for ticket in sorted(
        {name for name, status in statuses.items() if status == "DONE"}
        - CLOSED_TICKETS
    ):
        errors.append(
            f"{ticket} reads DONE but is not in CLOSED_TICKETS; add it, so that "
            "removing its row later is an error rather than a quiet retirement"
        )
    for ticket in sorted(CLOSED_TICKETS):
        if statuses.get(ticket) != "DONE":
            errors.append(
                f"{ticket} was closed and no longer reads DONE on the board "
                f"(now {statuses.get(ticket, 'absent')}); a ticket cannot shed a "
                "closure obligation by leaving the table"
            )

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

    attributions, attribution_errors = closure_attributions(threat_model)
    errors += attribution_errors
    # BOTH WAYS. The old predicate only ever asked "is this DONE ticket
    # attributed?", so an attribution could name a path that had been deleted,
    # or a ticket that was never closed, and nothing noticed. Neither rot is
    # hypothetical here: `docs/evidence/` already holds a receipt for
    # `DEPLOY-001`, which reads ACTIVE, and no check in this file sees it.
    for ticket, evidence in sorted(attributions.items()):
        if not (repository / evidence).is_file():
            errors.append(
                f"{ticket} is attributed to {evidence}, which does not exist; "
                "an attribution pointing at nothing is worse than none, because "
                "it reads as evidence"
            )
        if statuses.get(ticket) != "DONE":
            errors.append(
                f"{ticket} carries a closure attribution but reads "
                f"{statuses.get(ticket, '<no row>')}, not DONE; closure "
                "attribution records a review that closed a ticket, so an entry "
                "for one that is open is either premature or stale"
            )
    reviewed = {ticket for ticket in done if ticket in attributions}

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
                f"{ticket} is DONE but {THREAT_MODEL} attributes no review to "
                "it in the closure-attribution table"
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
