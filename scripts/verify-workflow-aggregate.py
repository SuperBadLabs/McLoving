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
    "recovery-drill",
    "deployment",
)
WINDOWS_FIELDS = ("impact", "run-windows", "windows-agent")


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
    """Accept only literal success from every Foundation terminal lane."""
    _require_exact_fields(results, FOUNDATION_JOBS)
    rejected = [job for job in FOUNDATION_JOBS if results[job] != "success"]
    for job in FOUNDATION_JOBS:
        print(f"{job}: {results[job]}")
    if rejected:
        raise AggregateError(f"Foundation lanes did not succeed: {rejected}")


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
