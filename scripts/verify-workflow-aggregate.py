#!/usr/bin/env python3
"""Fail closed unless a protected workflow aggregate has the exact valid state."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence


FOUNDATION_JOBS = (
    "rust",
    "dependencies",
    "secrets",
    "architecture",
    "formal",
    "controller-postgres",
    "ui-impact",
    "ui-browser",
    "recovery-drill",
    "deployment",
)
WINDOWS_FIELDS = ("impact", "run-windows", "windows-agent")

# `ui-browser` is the one Foundation lane that does not always execute: the
# mutation proof inside it is twenty-two browser runs, so `ui-impact` decides
# whether the change can affect the interface at all. That makes it the same
# shape as the Windows lane, and it carries the same hazard -- a skipped
# required check reads as a pass to branch protection (TM-052). So the waiver
# has to be EXPLICIT: the classifier's own result must be a success, its
# decision must be one of exactly two literal strings, and the lane must then
# have executed or been skipped to match. A missing, empty or unrecognised
# decision is an error, never a waiver.
FOUNDATION_CONDITIONAL_JOB = "ui-browser"
FOUNDATION_DECISION_FIELD = "run-ui-gate"
FOUNDATION_CLASSIFIER_JOB = "ui-impact"
FOUNDATION_FIELDS = FOUNDATION_JOBS + (FOUNDATION_DECISION_FIELD,)
FOUNDATION_UNCONDITIONAL_JOBS = tuple(
    job for job in FOUNDATION_JOBS if job != FOUNDATION_CONDITIONAL_JOB
)


class AggregateError(ValueError):
    """The observed child results do not prove a successful aggregate."""


def _require_exact_fields(results: Mapping[str, str], expected: Sequence[str]) -> None:
    missing = sorted(set(expected) - results.keys())
    unexpected = sorted(results.keys() - set(expected))
    if missing or unexpected:
        raise AggregateError(
            f"aggregate fields differ: missing={missing} unexpected={unexpected}"
        )


def require_foundation(results: Mapping[str, str]) -> None:
    """Literal success from every lane, or an explicitly classified UI waiver."""
    _require_exact_fields(results, FOUNDATION_FIELDS)
    for field in FOUNDATION_FIELDS:
        print(f"{field}: {results[field]}")

    rejected = [
        job for job in FOUNDATION_UNCONDITIONAL_JOBS if results[job] != "success"
    ]
    if rejected:
        raise AggregateError(f"Foundation lanes did not succeed: {rejected}")

    decision = results[FOUNDATION_DECISION_FIELD]
    conditional = results[FOUNDATION_CONDITIONAL_JOB]
    if decision == "true":
        if conditional != "success":
            raise AggregateError(
                f"{FOUNDATION_CONDITIONAL_JOB} was required but did not succeed: "
                f"{conditional}"
            )
        return
    if decision == "false":
        # "Not run" is only acceptable as the literal skip the classifier asked
        # for. A failed or cancelled lane reported alongside a false decision is
        # a contradiction, not a waiver.
        if conditional != "skipped":
            raise AggregateError(
                f"{FOUNDATION_CONDITIONAL_JOB} was waived but was not skipped: "
                f"{conditional}"
            )
        return
    raise AggregateError(
        f"{FOUNDATION_DECISION_FIELD} is not a classification: {decision!r}"
    )


def require_windows(results: Mapping[str, str]) -> None:
    """Accept only an executed success or an explicit classified skip."""
    _require_exact_fields(results, WINDOWS_FIELDS)
    for field in WINDOWS_FIELDS:
        print(f"{field}: {results[field]}")

    if results["impact"] != "success":
        raise AggregateError("Windows impact classification did not succeed")
    if results["run-windows"] == "true":
        if results["windows-agent"] != "success":
            raise AggregateError("Windows execution was required but did not succeed")
        return
    if results["run-windows"] == "false":
        if results["windows-agent"] != "skipped":
            raise AggregateError("Windows execution was waived but was not skipped")
        return
    raise AggregateError("Windows impact classifier emitted no valid decision")


def parse_results(values: Sequence[str]) -> dict[str, str]:
    """Parse unique NAME=VALUE observations without guessing malformed input."""
    results: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise AggregateError(f"aggregate result is not NAME=VALUE: {value!r}")
        name, result = value.split("=", 1)
        if not name or name in results:
            raise AggregateError(f"aggregate result name is empty or repeated: {name!r}")
        results[name] = result
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("aggregate", choices=("foundation", "windows"))
    parser.add_argument("results", nargs="*")
    args = parser.parse_args()

    try:
        results = parse_results(args.results)
        if args.aggregate == "foundation":
            require_foundation(results)
        else:
            require_windows(results)
    except AggregateError as error:
        raise SystemExit(f"workflow-aggregate-error: {error}") from error
    print(f"workflow-aggregate-ok aggregate={args.aggregate}")


if __name__ == "__main__":
    main()
