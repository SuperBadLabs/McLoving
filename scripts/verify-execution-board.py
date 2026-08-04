#!/usr/bin/env python3
"""Verify ticket dependencies, execution topology, and current documentation."""

from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path


TICKET_STATUSES = ("PENDING", "ACTIVE", "BLOCKED", "DONE", "DEFERRED")
TICKET_STATUS_PATTERN = "|".join(TICKET_STATUSES)
TICKET_ROW = re.compile(
    r"^\| ([A-Z][A-Z0-9-]+) \| "
    rf"({TICKET_STATUS_PATTERN}) \| ([^|]+) \|"
)
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
        match = TICKET_ROW.match(line)
        if match is None:
            continue
        ticket, status, dependency_cell = match.groups()
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
