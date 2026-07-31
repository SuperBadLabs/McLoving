#!/usr/bin/env python3
"""Verify ticket dependencies and the remaining execution topology."""

from __future__ import annotations

import re
import sys
from pathlib import Path


TICKET_ROW = re.compile(
    r"^\| ([A-Z][A-Z0-9-]+) \| "
    r"(PENDING|ACTIVE|BLOCKED|DONE|DEFERRED) \| ([^|]+) \|"
)
TICKET_ID = re.compile(r"[A-Z][A-Z0-9-]+")
EXECUTION_CLASSES = {"SERIAL", "BATCH", "PARALLEL"}
REMAINING_STATUSES = {"PENDING", "ACTIVE", "BLOCKED"}


def fail(messages: list[str]) -> None:
    for message in messages:
        print(f"execution-board error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    board = Path(__file__).resolve().parents[1] / "docs" / "EXECUTION_BOARD.md"
    try:
        text = board.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail([f"cannot read {board}: {error}"])
    errors: list[str] = []

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
        + " ".join(f"{key.lower()}={value}" for key, value in counts.items())
    )


if __name__ == "__main__":
    main()
