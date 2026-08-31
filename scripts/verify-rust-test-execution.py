#!/usr/bin/env python3
"""Require one focused Rust test binary to execute an exact test count."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


SUMMARY = re.compile(
    r"^test result: ok\. (?P<passed>[0-9]+) passed; "
    r"(?P<failed>[0-9]+) failed; .*?$",
    re.MULTILINE,
)


class VerificationError(ValueError):
    """The cargo output does not prove the requested test execution."""


def require_exact_execution(output: str, expected: int, label: str) -> int:
    """Return the executed count or raise when the focused run is unproved."""
    summaries = list(SUMMARY.finditer(output))
    if len(summaries) != 1:
        raise VerificationError(
            f"{label}: expected one successful Rust test summary, found {len(summaries)}"
        )
    passed = int(summaries[0].group("passed"))
    failed = int(summaries[0].group("failed"))
    if failed != 0 or passed != expected:
        raise VerificationError(
            f"{label}: expected exactly {expected} passed and 0 failed, "
            f"observed {passed} passed and {failed} failed"
        )
    return passed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("expected", type=int)
    parser.add_argument("label")
    args = parser.parse_args()
    if args.expected < 1:
        parser.error("expected test count must be positive")
    try:
        count = require_exact_execution(
            args.log.read_text(encoding="utf-8", errors="replace"),
            args.expected,
            args.label,
        )
    except (OSError, VerificationError) as error:
        raise SystemExit(f"rust-test-execution-error: {error}") from error
    print(f"rust-test-execution-ok label={args.label} tests={count}")


if __name__ == "__main__":
    main()
