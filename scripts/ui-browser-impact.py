#!/usr/bin/env python3
"""Classify whether a change needs the UI browser gate, and how much of it.

The gate is the only thing in this repository that can observe a rendered
console, a viewport or a focus ring, so it must run when the interface or the
gate itself moves. It is also the most expensive lane on the board -- the
mutation proof alone is seventeen full browser runs -- so running all of it on
every push buys nothing on the overwhelming majority of changes, which touch no
UI at all.

Two decisions come out of here, not one:

  run-ui-gate       the executing browser gate, ~90s plus image build
  run-ui-mutations  the mutation proof, ~20 minutes

They are separate because they protect different things. The gate proves the
*client* still behaves; the mutation proof proves the *assertions still bind*.
An assertion stops binding when the gate's own definition changes, or when the
client drifts far enough that a mutation no longer targets anything real -- and
that second case is already refused, cheaply and on every single push, by
`scripts/verify-ui-browser-gate.py`, which fails if any mutation's find-text is
absent from the client. So the mutation proof is required when the gate
definition moves, and otherwise only when the client changes by more than a
trivial amount.

Nothing here executes changed configuration: the classification is read out of
`git diff` and nothing else.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# The client the gate renders. A change to any of these needs the gate.
CLIENT_PATHS = frozenset(
    {
        "crates/controller-api/ui/index.html",
        "crates/controller-api/ui/app.js",
        "crates/controller-api/ui/app.css",
    }
)

# The gate's own definition, the fixture it drives, and the workflow that runs
# it. A change to any of these makes every assertion unproven until the mutation
# proof runs again, so these demand the full lane rather than just the gate.
GATE_DEFINITION_PATHS = frozenset(
    {
        ".github/workflows/foundation.yml",
        "crates/controller-api/examples/ui_browser_fixture.rs",
        "scripts/test-ui-browser-mutations.py",
        "scripts/test-ui-browser.sh",
        "scripts/test-ui-browser-impact.py",
        "scripts/ui-browser-impact.py",
        "scripts/ui-browser/Containerfile",
        "scripts/ui-browser/browser-pin.json",
        "scripts/ui-browser/build-image.sh",
        "scripts/ui-browser/gate.py",
        "scripts/ui-browser/mutations.json",
        "scripts/verify-ui-browser-gate.py",
    }
)

# `static_ui_router`, the CSP and the `include_str!` of the client all live in
# this file, so it decides what the browser is actually served. It needs the
# gate; it does not by itself make the assertions stop binding.
SERVING_PATHS = frozenset({"crates/controller-api/src/lib.rs"})

# The strict-YAML compiler is a *behavioural* input to the gate, not just a
# dependency of it: `strict_yaml_refusal_surfaced_to_user` submits a duplicate
# mapping key and asserts on the compiler's own refusal wording, through the
# same `compile_strict_yaml_with_parameters` the shipped handler calls. A parser
# change that started accepting duplicate keys, or that reworded the rejection,
# would break that assertion while touching nothing this classifier otherwise
# watches -- so it would ship without the gate ever running. Directory prefix
# rather than a file list, because the crate is the unit that has this property.
SERVING_PREFIXES = ("crates/pipeline-ir/",)

# The lane rebuilds `ui_browser_fixture` from these, so a dependency bump can
# change the fixture's HTTP or parsing behaviour -- and therefore the rendered
# journey -- with no file the classifier otherwise watches having moved.
BUILD_INPUT_PATHS = frozenset(
    {
        "Cargo.lock",
        "Cargo.toml",
        "crates/controller-api/Cargo.toml",
        "crates/pipeline-ir/Cargo.toml",
        "rust-toolchain.toml",
    }
)

# Changed lines across the client files, added plus removed, at or above which
# the mutation proof is required even though the gate definition did not move.
#
# The three client files are 639 lines together. Twenty is about three percent
# of that, and is smaller than the smallest of the three repairs UI-002 itself
# made -- so a change of the size that has historically broken one of these
# assertions re-proves them, and a typo fix does not. It is a threshold, so it
# is a judgement: raising it trades browser minutes for the chance that a small
# client change quietly makes an assertion vacuous, which is the exact failure
# UI-002 exists to correct. Lower it before raising it.
MUTATION_LINE_THRESHOLD = 20


class ClassificationError(RuntimeError):
    """The revisions cannot be compared, so no waiver can be justified."""


def git(*arguments: str, repository: Path) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ClassificationError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()[:400]}"
        )
    return completed.stdout


def changed_paths(base: str, head: str, repository: Path) -> set[str]:
    output = git(
        "diff", "--no-renames", "--name-only", "-z", base, head, repository=repository
    )
    return {entry for entry in output.split("\0") if entry}


def changed_client_lines(base: str, head: str, repository: Path) -> int:
    """Added plus removed lines across the client files only.

    `--numstat` reports `-\t-` for binary files; none of the client files are
    binary, but treat an unparsable count as "large" rather than as zero. A
    number that cannot be read must not become a waiver.
    """
    output = git(
        "diff",
        "--no-renames",
        "--numstat",
        base,
        head,
        "--",
        *sorted(CLIENT_PATHS),
        repository=repository,
    )
    total = 0
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        added, removed = fields[0], fields[1]
        if added == "-" or removed == "-":
            return MUTATION_LINE_THRESHOLD
        total += int(added) + int(removed)
    return total


def classify(base: str, head: str, repository: Path) -> tuple[bool, bool, str]:
    paths = changed_paths(base, head, repository)

    definition = sorted(paths & GATE_DEFINITION_PATHS)
    if definition:
        return (
            True,
            True,
            f"gate definition changed, so every assertion is unproven: {definition[0]}",
        )

    client = sorted(paths & CLIENT_PATHS)
    serving = (
        sorted(paths & SERVING_PATHS)
        + sorted(path for path in paths if path.startswith(SERVING_PREFIXES))
        + sorted(paths & BUILD_INPUT_PATHS)
    )
    if not client and not serving:
        return False, False, "no UI, serving or gate path changed"

    if not client:
        return (
            True,
            False,
            f"what is served or how it is validated may have changed: {serving[0]}",
        )

    lines = changed_client_lines(base, head, repository)
    if lines >= MUTATION_LINE_THRESHOLD:
        return (
            True,
            True,
            f"client changed by {lines} lines, at or above the "
            f"{MUTATION_LINE_THRESHOLD}-line mutation threshold",
        )
    return (
        True,
        False,
        f"client changed by {lines} lines, below the "
        f"{MUTATION_LINE_THRESHOLD}-line mutation threshold; the mutation set is "
        "still checked against the client by verify-ui-browser-gate.py",
    )


def emit(run_gate: bool, run_mutations: bool, reason: str) -> None:
    print(f"UI browser impact decision: {reason}", file=sys.stderr)
    print(f"run-ui-gate={'true' if run_gate else 'false'}")
    print(f"run-ui-mutations={'true' if run_mutations else 'false'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    arguments = parser.parse_args()

    try:
        run_gate, run_mutations, reason = classify(
            arguments.base, arguments.head, arguments.repository.resolve()
        )
    except ClassificationError as error:
        # A classifier that cannot classify must not produce a waiver. Run
        # everything and say why.
        emit(True, True, f"classification failed, running the full lane: {error}")
        return 0
    emit(run_gate, run_mutations, reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
