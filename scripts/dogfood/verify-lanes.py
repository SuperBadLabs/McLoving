#!/usr/bin/env python3
"""Keep the dogfood lanes aligned with Foundation (PAR-005).

Each `scripts/dogfood/<lane>.sh` mirrors one Foundation job. For every lane
this check names the commands the job runs to verify the tree and requires
each to appear both in `.github/workflows/foundation.yml` and in the lane
script (the lane spells the toolchain as `"+${RUST_TOOLCHAIN}"` where the
workflow pins `+1.97.1`). A command Foundation drops, renames or adds to
this list fails here rather than drifting silently; runner provisioning
(toolchain installs, caches, downloads) is not mirrored and not listed.
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/foundation.yml"
LANES = ROOT / "scripts/dogfood"

MIRRORED: dict[str, list[str]] = {
    "rust-lint.sh": [
        "cargo +1.97.1 fmt --all -- --check",
        "cargo +1.97.1 metadata --locked --no-deps --format-version 1 >/dev/null",
        "cargo +1.97.1 clippy --locked --workspace --all-targets -- -D warnings",
    ],
    "rust-tests.sh": [
        "cargo +1.97.1 test --locked --workspace",
        "--exclude mcloving-source-acquirer",
    ],
    "dependencies.sh": [
        "cargo-deny",
        "command: check",
    ],
    "secrets.sh": [
        "detect --source /repo --no-banner --redact --verbose",
    ],
    "architecture.sh": [
        "bash scripts/verify-jenkins-sequential-retained.sh",
        "/usr/bin/python3 -I scripts/test-workflow-aggregate.py",
        "/usr/bin/python3 -I scripts/test-sequential-runtime-gate.py",
        "timeout 60 clojure -M:test",
        "./test-plugin-directory.sh",
        "../../scripts/test-jenkins-sequential-contract.sh",
        "../../scripts/test-jenkins-sequential-compiler.sh",
        "bash -n scripts/validate-foundation.sh",
        "bash -n scripts/ui-browser/build-image.sh",
        "python3 scripts/test-execution-board.py",
        "python3 scripts/verify-execution-board.py",
        "python3 scripts/test-ticket-closure-receipts.py",
        "python3 scripts/verify-ticket-closure-receipts.py",
        "python3 scripts/test-verify-rust-test-execution.py",
        "python3 scripts/verify-ui-browser-gate.py",
        "test \"$(find docs/adr -maxdepth 1 -name '[0-9][0-9][0-9][0-9]-*.md' | wc -l)\" -eq 16",
        "test -s docs/architecture/CHARTER.md",
        "test -s docs/ALPHA_DEMO.md",
        "test -s docs/threat-model/README.md",
        "test -s docs/EXECUTION_BOARD.md",
        "actionlint",
    ],
    "controller-postgres.sh": [
        "cargo +1.97.1 test --locked -p mcloving-controller-store --test postgres_truth",
        "--test route_denials",
        "--test deployable_runtime -- --ignored",
        "--test remote_work -- --test-threads=1",
        "bash scripts/test-cache-product.sh",
        "bash scripts/test-input-product.sh",
        "bash scripts/test-sequential-runtime.sh",
    ],
}

# Where a lane runs a repository script that itself carries the Foundation
# commands, the script is the lane's body and is checked instead.
DELEGATED = {
    "controller-postgres.sh": ROOT / "scripts/test-controller-postgres.sh",
}

# Commands whose Foundation form is a pinned action or container the lane
# names differently: the workflow must name the left form, the lane the
# right one.
SPELLINGS = {
    "cargo-deny": ("cargo-deny", "cargo-deny"),
    "command: check": ("command: check", "cargo-deny\" check"),
    "actionlint": ("actionlint", "actionlint"),
    # The dogfood tree has no history, so the lane scans the tree from its
    # root with the same image and rules.
    "detect --source /repo --no-banner --redact --verbose": (
        "detect --source /repo --no-banner --redact --verbose",
        "detect --source . --no-banner --redact --verbose --no-git",
    ),
}


def lane_spellings(command: str) -> tuple[str, ...]:
    # A lane names the toolchain from RUST_TOOLCHAIN; a delegated script
    # runs inside the pinned Rust image and names none.
    return (
        command.replace("cargo +1.97.1", 'cargo "+${RUST_TOOLCHAIN}"'),
        command.replace("cargo +1.97.1", "cargo"),
    )


def main() -> int:
    workflow = WORKFLOW.read_text()
    failures: list[str] = []
    for script, commands in MIRRORED.items():
        lane = (LANES / script).read_text()
        delegated = DELEGATED.get(script)
        body = lane + (delegated.read_text() if delegated else "")
        for command in commands:
            if command in SPELLINGS:
                workflow_form, lane_form = SPELLINGS[command]
                lane_forms: tuple[str, ...] = (lane_form,)
            else:
                workflow_form, lane_forms = command, lane_spellings(command)
            if workflow_form not in workflow:
                failures.append(f"{script}: Foundation no longer runs `{workflow_form}`")
            if not any(form in body for form in lane_forms):
                failures.append(f"{script}: the lane does not run `{lane_forms[0]}`")
    for failure in failures:
        print(f"dogfood-lanes error: {failure}")
    if failures:
        return 1
    print(f"dogfood-lanes-ok lanes={len(MIRRORED)} commands={sum(len(c) for c in MIRRORED.values())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
