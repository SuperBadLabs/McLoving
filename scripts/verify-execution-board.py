#!/usr/bin/env python3
"""Verify ticket dependencies, execution topology, and current documentation."""

from __future__ import annotations

import posixpath
import re
import sys
from datetime import date
from pathlib import Path


TICKET_STATUSES = ("PENDING", "ACTIVE", "BLOCKED", "DONE", "DEFERRED")
TICKET_STATUS_PATTERN = "|".join(TICKET_STATUSES)
TICKET_ID = re.compile(r"[A-Z][A-Z0-9-]+")
EXECUTION_CLASSES = {"SERIAL", "BATCH", "PARALLEL"}
REMAINING_STATUSES = {"PENDING", "ACTIVE", "BLOCKED"}
UPDATED_ROW = re.compile(r"^Updated: (\d{4}-\d{2}-\d{2})$", re.MULTILINE)
CURRENT_SLOT_ROW = re.compile(
    r"^\| ([1-9][0-9]*) \| `([A-Z][A-Z0-9-]+)` \| "
    r"([^|]+) \|"
)
CURRENT_DISPATCH_HEADER = (
    "| Slot | Current ticket | Status | Dependency-critical successors |"
)
CURRENT_DISPATCH_SEPARATOR = "|---:|---|---|---|"
OBSOLETE_README_MARKERS = (
    "currently at its architecture-foundation milestone",
    "binary crates are compilable placeholders",
    "no controller, scheduler, or agent runtime is represented as implemented",
)


# --- Required-edge inference -------------------------------------------------
#
# The checks above validate that every DECLARED edge is well formed: it points
# at a real ticket, and the graph is acyclic. Nothing asked whether a REQUIRED
# edge is present, and four times a ticket's acceptance criteria depended on
# another ticket's work with no edge declared between them. This verifier
# passed cleanly every time, because a missing edge is not an invalid one --
# absence and correctness look identical to a well-formedness check.
#
# Two ways a pair is judged to share a boundary. Both were tested against the
# four historical misses (the parents of c02ad71, abb32d7, 6145984, eb74330):
# the shared-token rule alone catches two, the family rule alone catches three,
# and together they catch all four.
# Rows are read by splitting cells. An exact-spacing regex omits a row padded
# for alignment, and a row this function cannot see carries no boundary, so a
# padded DONE row could share a file with an open ticket and pass.
TICKET_CELL_ID = re.compile(r"^[A-Z][A-Z0-9-]+$")
BACKTICKED = re.compile(r"`([^`]+)`")
# The boundary rule only sees backticked tokens, so an unbackticked path is
# invisible to it. Detecting bare path-shaped text is not an option -- the
# board's prose is full of `I/O`, `API/CLI`, `134/162` and `Linux/Windows`,
# 337 such tokens, none of which is a file. So the convention is enforced
# instead: if an unbackticked token resolves to a real file in this
# repository, it was meant to be a path and must be quoted like one.
BARE_PATH = re.compile(r"(?<![`\w/.-])((?:[\w.-]+/)+[\w.-]+)(?![`\w])")
CODE_SPAN = re.compile(r"`[^`]*`")
# `\|` is an escaped pipe inside a cell, not a cell boundary. Splitting on
# every pipe would cut the acceptance text short and drop the boundaries that
# follow it.
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


def row_cells(line: str) -> list[str]:
    parts = UNESCAPED_PIPE.split(line)[1:-1]
    return [part.replace("\\|", "|").strip() for part in parts]


def ticket_row(line: str) -> tuple[str, str, str, str] | None:
    """Read one authoritative ticket row, whatever its cell padding.

    The exact-spacing regex this replaces dropped a row padded for alignment,
    and a dropped row is not validated at all -- its declared dependencies go
    unchecked while every gate stays green.
    """
    if not line.startswith("|"):
        return None
    cells = row_cells(line)
    if len(cells) < 4 or not TICKET_CELL_ID.match(cells[0]):
        return None
    if cells[1] not in TICKET_STATUSES:
        return None
    return cells[0], cells[1], cells[2], cells[3]
THREAT_ID = re.compile(r"\bTM-\d+\b")
SHA_LIKE = re.compile(r"^[0-9a-f]{7,40}$")
ALLOWED_PAIR = re.compile(
    r"<!-- board-graph: allow ([A-Z][A-Z0-9-]+) ~ ([A-Z][A-Z0-9-]+) -- (.+?) -->"
)
# Whole components are too coarse to be boundaries: `bins/agent` is shared by
# every ticket that touches the agent at all. A path token is compared whole
# and normalised -- two different `config.rs` files under different crates are
# two boundaries, and `scripts/x.py` and `./scripts/x.py` are one.
BOUNDARY_STOPLIST = {
    "main", "master", "README.md", "docs", "x86_64", "true", "false", "DONE",
}


FILE_SUFFIX = re.compile(r"\.[A-Za-z0-9]{1,5}$")
SEPARATED = re.compile(r"[-_]")


def is_boundary(token: str) -> bool:
    """Is this code span a thing two tickets can SHARE, or just a word?

    The rule is about files, helpers and `TM-nnn` boundaries. Every backticked
    span of three characters or more was reaching it, so two unrelated tickets
    quoting `--strict` or `unsupported` were required to declare an edge -- the
    check refusing correct work rather than catching a missing dependency.
    """
    if THREAT_ID.fullmatch(token):
        return True
    if token.startswith("-"):  # a CLI flag is a spelling, not a boundary
        return False
    if "/" in token or FILE_SUFFIX.search(token):
        return True
    if token.endswith("="):  # a systemd directive
        return True
    return SEPARATED.search(token) is not None


def boundary_tokens(acceptance: str, repository: Path | None = None) -> set[str]:
    """Named things a ticket's acceptance criteria commit it to."""
    found: set[str] = set()
    for token in BACKTICKED.findall(acceptance):
        token = token.strip()
        if len(token) < 3 or TICKET_ID.fullmatch(token) or SHA_LIKE.match(token):
            continue
        if "/" in token:
            # Keep the whole path, normalised. Reducing to a basename made
            # `crates/a/config.rs` and `crates/b/config.rs` one boundary, and
            # leaving it raw made `scripts/x.py` and `./scripts/x.py` two.
            token = posixpath.normpath(token)
            #
            # Directories are not boundaries; files are. An extension cannot
            # tell them apart -- `deploy/bin/mcloving-install` is a 20 KB
            # executable with no dot in it.
            #
            # Ask the repository when it knows the path. When it does not --
            # a file the ticket is about to create -- fall back to shape: a
            # dotted basename names a file, and so does a nested path, while
            # a two-segment path with no dot is a component root such as
            # `bins/agent` or `crates/domain`. The fallback must be textual,
            # because the same board has to give the same answer whether or
            # not the working tree is beside it.
            resolved = None if repository is None else repository / token
            if resolved is not None and resolved.exists():
                if resolved.is_dir():
                    continue
            elif "." not in token.rsplit("/", 1)[-1] and token.count("/") < 2:
                continue
        if not token or token in BOUNDARY_STOPLIST or not is_boundary(token):
            continue
        found.add(token)
    found.update(THREAT_ID.findall(acceptance))
    return found


def required_edges(text: str, repository: Path | None = None) -> list[str]:
    """Flag unordered ticket pairs that acceptance criteria say share a boundary."""
    rows: dict[str, tuple[str, list[str], str]] = {}
    for line in text.splitlines():
        parsed = ticket_row(line)
        if parsed is None:
            continue
        ticket, status, dependency_cell, acceptance = parsed
        rows[ticket] = (status, TICKET_ID.findall(dependency_cell), acceptance)

    reachable: dict[str, set[str]] = {}

    def walk(ticket: str, seen: set[str]) -> None:
        for dependency in rows.get(ticket, ("", [], ""))[1]:
            if dependency in rows and dependency not in seen:
                seen.add(dependency)
                walk(dependency, seen)

    for ticket in rows:
        reachable[ticket] = set()
        walk(ticket, reachable[ticket])

    allowed = {
        frozenset((a, b)): reason for a, b, reason in ALLOWED_PAIR.findall(text)
    }
    tokens = {
        ticket: boundary_tokens(row[2], repository) for ticket, row in rows.items()
    }

    errors: list[str] = []
    if repository is not None:
        for ticket in sorted(rows):
            plain = CODE_SPAN.sub(" ", rows[ticket][2])
            for candidate in sorted({m.rstrip(".,;") for m in BARE_PATH.findall(plain)}):
                if (repository / candidate).is_file():
                    errors.append(
                        f"{ticket} names the file {candidate} without backticks; "
                        "the boundary rule only reads backticked tokens, so an "
                        "unquoted path is invisible to it"
                    )
    names = sorted(rows)
    for index, first in enumerate(names):
        for second in names[index + 1:]:
            first_status = rows[first][0]
            second_status = rows[second][0]
            if (
                first_status not in REMAINING_STATUSES
                and second_status not in REMAINING_STATUSES
            ):
                continue
            if second in reachable[first] or first in reachable[second]:
                continue
            if frozenset((first, second)) in allowed:
                continue
            shared = tokens[first] & tokens[second]
            family = (
                first.rsplit("-", 1)[0] == second.rsplit("-", 1)[0]
                and first_status in REMAINING_STATUSES
                and second_status in REMAINING_STATUSES
            )
            if not shared and not family:
                continue
            why = (
                f"both name {', '.join(sorted(shared))}"
                if shared
                else "they are the same ticket family and both are remaining"
            )
            errors.append(
                f"{first} and {second} share a boundary ({why}) but neither "
                "reaches the other in the dependency graph; declare the edge, "
                f"or record an argued exception as "
                f"`<!-- board-graph: allow {first} ~ {second} -- reason -->`"
            )
    for pair in sorted(allowed, key=sorted):
        first, second = sorted(pair)
        if first not in rows or second not in rows:
            errors.append(
                f"board-graph allowance names {first} ~ {second}, and one of "
                "them is not a ticket"
            )
        elif second in reachable[first] or first in reachable[second]:
            errors.append(
                f"board-graph allowance for {first} ~ {second} is stale: the "
                "edge is now declared, so remove the allowance"
            )
        elif not (tokens[first] & tokens[second]) and not (
            first.rsplit("-", 1)[0] == second.rsplit("-", 1)[0]
            and rows[first][0] in REMAINING_STATUSES
            and rows[second][0] in REMAINING_STATUSES
        ):
            errors.append(
                f"board-graph allowance for {first} ~ {second} is stale: they no "
                "longer share a boundary, and an allowance kept past its finding "
                "would silently excuse the next one"
            )
    return errors


def fail(messages: list[str]) -> None:
    for message in messages:
        print(f"execution-board error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    board = repository / "docs" / "EXECUTION_BOARD.md"
    readme = repository / "README.md"
    try:
        text = board.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail([f"cannot read {board}: {error}"])
    try:
        readme_text = readme.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail([f"cannot read {readme}: {error}"])
    errors: list[str] = []

    updated_matches = UPDATED_ROW.findall(text)
    if len(updated_matches) != 1:
        errors.append("execution board must contain exactly one ISO Updated date")
    else:
        try:
            updated = date.fromisoformat(updated_matches[0])
        except ValueError:
            errors.append(f"execution board has invalid Updated date: {updated_matches[0]}")
        else:
            if updated > date.today():
                errors.append(f"execution board Updated date is in the future: {updated}")

    if re.search(r"Protected `main` is `[0-9a-f]{40}`", text):
        errors.append(
            "current-state prose pins protected main to a commit; use ticket and "
            "batch status instead"
        )
    for marker in OBSOLETE_README_MARKERS:
        if marker in readme_text:
            errors.append(f"README contains obsolete implementation claim: {marker}")

    tickets: dict[str, tuple[str, list[str]]] = {}
    for line in text.splitlines():
        parsed = ticket_row(line)
        if parsed is None:
            continue
        ticket, status, dependency_cell, _acceptance = parsed
        if ticket in tickets:
            errors.append(f"ticket {ticket} is declared more than once")
            continue
        tickets[ticket] = (status, TICKET_ID.findall(dependency_cell))

    if not tickets:
        errors.append("no ticket rows were found")

    for ticket, (_, dependencies) in tickets.items():
        for dependency in dependencies:
            if dependency not in tickets:
                errors.append(f"ticket {ticket} references missing dependency {dependency}")

    state: dict[str, int] = {}

    def visit(ticket: str, path: list[str]) -> None:
        if state.get(ticket) == 2:
            return
        if state.get(ticket) == 1:
            cycle_start = path.index(ticket)
            errors.append(
                "dependency cycle: " + " -> ".join(path[cycle_start:] + [ticket])
            )
            return
        state[ticket] = 1
        for dependency in tickets[ticket][1]:
            if dependency in tickets:
                visit(dependency, path + [ticket])
        state[ticket] = 2

    for ticket in tickets:
        visit(ticket, [])

    topology_match = re.search(
        r"^## Remaining execution topology\n(.*?)(?=^## Wave 0)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if topology_match is None:
        errors.append("remaining execution topology section is missing")
        fail(errors)

    classified: dict[str, str] = {}
    for line in topology_match.group(1).splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) < 6 or cells[3] not in EXECUTION_CLASSES:
            continue
        execution_class = cells[3]
        row_tickets = TICKET_ID.findall(cells[2])
        if not row_tickets:
            errors.append(f"topology row has no tickets: {line}")
            continue
        if execution_class == "PARALLEL" and len(row_tickets) != 1:
            errors.append(
                "PARALLEL topology rows must contain one standalone ticket: " + cells[2]
            )
        if execution_class == "BATCH" and len(row_tickets) < 2:
            errors.append(f"BATCH topology row must contain at least two tickets: {cells[2]}")
        if execution_class == "SERIAL":
            for predecessor, successor in zip(row_tickets, row_tickets[1:]):
                if successor in tickets and predecessor not in tickets[successor][1]:
                    errors.append(
                        f"SERIAL chain {predecessor} -> {successor} lacks a direct "
                        f"dependency edge on {successor}"
                    )
        for ticket in row_tickets:
            if ticket in classified:
                errors.append(
                    f"ticket {ticket} is classified more than once "
                    f"({classified[ticket]} and {execution_class})"
                )
            else:
                classified[ticket] = execution_class

    remaining = {
        ticket
        for ticket, (status, _) in tickets.items()
        if status in REMAINING_STATUSES
    }
    missing_classification = sorted(remaining - classified.keys())
    stale_classification = sorted(classified.keys() - remaining)
    if missing_classification:
        errors.append(
            "remaining tickets lack an execution class: "
            + ", ".join(missing_classification)
        )
    if stale_classification:
        errors.append(
            "topology classifies tickets that are not remaining: "
            + ", ".join(stale_classification)
        )

    board_lines = text.splitlines()
    dispatch_headers = [
        index
        for index, line in enumerate(board_lines)
        if line == CURRENT_DISPATCH_HEADER
    ]
    dispatch_rows: list[str] = []
    if len(dispatch_headers) != 1:
        errors.append("execution board must contain exactly one current dispatch table")
    else:
        header_index = dispatch_headers[0]
        separator_index = header_index + 1
        if (
            separator_index >= len(board_lines)
            or board_lines[separator_index] != CURRENT_DISPATCH_SEPARATOR
        ):
            errors.append("current dispatch table has a malformed separator")
        else:
            for line in board_lines[separator_index + 1 :]:
                if not line.strip():
                    break
                dispatch_rows.append(line)

    current_slots: dict[int, tuple[str, str]] = {}
    current_ticket_slots: dict[str, int] = {}
    for line in dispatch_rows:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            errors.append(f"malformed current dispatch row: {line}")
            continue
        slot_text, ticket_cell, stated_status, _ = cells
        if re.fullmatch(r"[1-9][0-9]*", slot_text) is None:
            errors.append(f"current dispatch row has invalid slot {slot_text!r}")
            continue
        slot = int(slot_text)
        if slot in current_slots:
            errors.append(f"current dispatch slot {slot} is declared more than once")
            continue
        ticket_match = re.fullmatch(r"`([A-Z][A-Z0-9-]+)`", ticket_cell)
        if ticket_match is None:
            current_slots[slot] = ("", stated_status)
            errors.append(
                f"current dispatch slot {slot} has malformed ticket cell "
                f"{ticket_cell!r}"
            )
            continue
        ticket = ticket_match.group(1)
        if ticket in current_ticket_slots:
            errors.append(
                f"current dispatch ticket {ticket} appears in slots "
                f"{current_ticket_slots[ticket]} and {slot}"
            )
        current_slots[slot] = (ticket, stated_status)
        current_ticket_slots[ticket] = slot

        if stated_status not in TICKET_STATUSES:
            errors.append(
                f"current dispatch slot {slot} has invalid status {stated_status!r}"
            )

        if ticket not in tickets:
            errors.append(f"current dispatch slot {slot} references missing ticket {ticket}")
            continue
        actual_status, dependencies = tickets[ticket]
        if actual_status != stated_status:
            errors.append(
                f"current dispatch slot {slot} says {ticket} is {stated_status}, "
                f"ticket table says {actual_status}"
            )
        if actual_status not in REMAINING_STATUSES:
            errors.append(
                f"current dispatch slot {slot} references non-remaining ticket "
                f"{ticket} ({actual_status})"
            )
        unready = [
            dependency
            for dependency in dependencies
            if dependency in tickets and tickets[dependency][0] != "DONE"
        ]
        if unready:
            errors.append(
                f"current dispatch slot {slot} ticket {ticket} has unfinished "
                f"dependencies: {', '.join(unready)}"
            )

    if not current_slots:
        errors.append("current dispatch table has no slots")
    elif len(current_slots) > 3:
        errors.append("current dispatch table exceeds the three-slot limit")
    elif sorted(current_slots) != list(range(1, len(current_slots) + 1)):
        errors.append("current dispatch slots must be contiguous starting at 1")

    errors += required_edges(text, repository)

    if errors:
        fail(errors)

    counts = {
        execution_class: sum(
            1 for value in classified.values() if value == execution_class
        )
        for execution_class in sorted(EXECUTION_CLASSES)
    }
    print(
        "execution-board-ok "
        f"tickets={len(tickets)} remaining={len(remaining)} "
        f"current_slots={len(current_slots)} "
        + " ".join(f"{key.lower()}={value}" for key, value in counts.items())
    )


if __name__ == "__main__":
    main()
