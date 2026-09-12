#!/usr/bin/env python3
"""Keep the dogfood lanes aligned with Foundation (PAR-005).

Each `scripts/dogfood/<lane>.sh` mirrors one Foundation job. This check reads
the job's steps from `.github/workflows/foundation.yml` and requires every
command line a `run:` step executes to appear in the lane script (the lane
spells the toolchain as `"+${RUST_TOOLCHAIN}"` where the workflow pins
`+1.97.1`), unless the line is runner provisioning (a named step that
installs a toolchain, restores a cache, reclaims disk or downloads a pinned
tool, or shell scaffolding around such a download) or is recorded below as
deliberately unmirrored with its reason. A command Foundation adds, drops or
renames therefore fails here rather than drifting silently. Steps that are
pinned actions or container invocations rather than `run:` lines are
checked by the pinned reference both sides must name.
"""
from __future__ import annotations

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/foundation.yml"
LANES = ROOT / "scripts/dogfood"

# lane script -> Foundation job id.
MIRRORED: dict[str, str] = {
    "rust-lint.sh": "rust-lint",
    "rust-tests.sh": "rust-tests",
    "dependencies.sh": "dependencies",
    "secrets.sh": "secrets",
    "architecture.sh": "architecture",
    "controller-postgres.sh": "controller-postgres",
}

# Steps, by name, that provision the runner rather than verify the tree.
RUNNER_STEP_NAMES = re.compile(
    r"^(Check out source|Install pinned .*|Restore Rust cache|Reclaim runner disk.*|"
    r"Download verified .*|Lint workflows with verified actionlint|Build shipped controller.*)$"
)
# Shell scaffolding inside a verification step that carries no command of
# its own (control flow, variable plumbing, the actionlint download).
SCAFFOLDING = re.compile(
    r"^(set -euo pipefail|readonly .*|unset .*|shopt .*|\(\(.*\)\)|if .*|elif .*|else|fi|"
    r"while .*|done.*|for .*|exit \d+|.*=\(|\)|\.github/workflows/\*\.ya?ml|"
    r"[A-Za-z_]+=.*|curl .*|\"https://.*|--output .*|printf .*|\| sha256sum -c -|install -d .*|"
    r"tar .*|: > .*|\"\$\{actionlint_dir\}/actionlint\" \\|-config-file .*|\"\$\{workflow_files\[@\]\}\"|"
    r"timeout 60 clojure -M:test|\./test-plugin-directory\.sh|\.\./\.\./scripts/test-jenkins-sequential-.*\.sh|"
    r"sudo .*|df -h.*|rustup .*|cargo \+1\.97\.1 build --locked -p mcloving-controller -p mcloving-cache -p mcloving-input-adapter|"
    r"bash scripts/run-verified-rust-test\.sh.*|\d+ [a-z-]+ --require-postgres.*|-p mcloving-.*|--test .*|-- --test-threads=1)$"
)
# Foundation commands a lane deliberately does not carry, each with the
# reason; the workflow must still run them, so a change there is noticed.
UNMIRRORED: dict[str, dict[str, str]] = {
    "architecture.sh": {
        "bash scripts/verify-jenkins-sequential-retained.sh": (
            "walks the commit's ancestry; the sealed acquirer publishes the tree without history"
        ),
    },
}
# Steps whose Foundation form is a pinned action or a container: the
# reference both sides must name (workflow form, lane form).
PINNED: dict[str, list[tuple[str, str]]] = {
    "dependencies.sh": [("cargo-deny-action", "cargo-deny"), ("command: check", 'cargo-deny" check')],
    "secrets.sh": [
        ("ghcr.io/gitleaks/gitleaks@sha256", "MCLOVING_GITLEAKS_IMAGE"),
        ("detect --source /repo --no-banner --redact --verbose", "detect --source . --no-banner --redact --verbose --no-git"),
    ],
    "architecture.sh": [("actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz", "actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz")],
    "controller-postgres.sh": [("MCLOVING_TEST_PODMAN: \"1\"", "MCLOVING_TEST_PODMAN=1")],
}
# The Jenkins compatibility contracts run from their own directory in the
# workflow; the lane runs the same four commands from that directory.
COMPAT_COMMANDS = [
    "timeout 60 clojure -M:test",
    "./test-plugin-directory.sh",
    "../../scripts/test-jenkins-sequential-contract.sh",
    "../../scripts/test-jenkins-sequential-compiler.sh",
]


def lane_forms(command: str) -> tuple[str, ...]:
    return (
        command.replace("cargo +1.97.1", 'cargo "+${RUST_TOOLCHAIN}"'),
        command.replace("cargo +1.97.1", "cargo"),
    )


def without_comments(text: str) -> str:
    """Drop comment-only lines so a command mentioned in prose or commented
    out cannot satisfy the check."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def run_lines(job: dict) -> list[str]:
    lines: list[str] = []
    for step in job.get("steps", []):
        if RUNNER_STEP_NAMES.match(step.get("name", "")):
            continue
        run = step.get("run")
        if not run:
            continue
        text = " ".join(part.strip() for part in run.splitlines()) if ">" in str(run)[:0] else run
        for raw in text.splitlines():
            line = raw.strip().rstrip("\\").strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
    return lines


def folded(job: dict) -> list[str]:
    """Commands of folded (`>-`) steps come as one line already; block (`|`)
    steps come line by line. PyYAML has folded them, so every `run` is a
    string whose lines are commands."""
    return run_lines(job)


def main() -> int:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    workflow_text = without_comments(WORKFLOW.read_text())
    failures: list[str] = []
    checked = 0
    for script, job_id in MIRRORED.items():
        job = workflow["jobs"].get(job_id)
        if job is None:
            failures.append(f"{script}: Foundation has no job {job_id}")
            continue
        lane = without_comments((LANES / script).read_text())
        unmirrored = UNMIRRORED.get(script, {})
        for command in folded(job):
            if command in unmirrored:
                if command in lane:
                    failures.append(f"{script}: runs `{command}`, recorded as unmirrored ({unmirrored[command]})")
                continue
            if SCAFFOLDING.match(command):
                continue
            if command.startswith("docker run ") and script in PINNED:
                # A container invocation: the pinned image and its arguments
                # are checked below in the form the lane names.
                continue
            checked += 1
            if not any(form in lane for form in lane_forms(command)):
                failures.append(f"{script}: Foundation {job_id} runs `{command}` but the lane does not")
        for command, reason in unmirrored.items():
            if command not in folded(job):
                failures.append(f"{script}: Foundation no longer runs the unmirrored `{command}` ({reason}); drop it here")
        for workflow_form, lane_form in PINNED.get(script, []):
            checked += 1
            if workflow_form not in workflow_text:
                failures.append(f"{script}: Foundation no longer names `{workflow_form}`")
            if lane_form not in lane:
                failures.append(f"{script}: the lane does not name `{lane_form}`")
    architecture = without_comments((LANES / "architecture.sh").read_text())
    for command in COMPAT_COMMANDS:
        checked += 1
        if command not in workflow_text:
            failures.append(f"architecture.sh: Foundation no longer runs `{command}`")
        if command not in architecture:
            failures.append(f"architecture.sh: the lane does not run `{command}`")
    for failure in failures:
        print(f"dogfood-lanes error: {failure}")
    if failures:
        return 1
    unmirrored_count = sum(len(c) for c in UNMIRRORED.values())
    print(f"dogfood-lanes-ok lanes={len(MIRRORED)} checked={checked} unmirrored={unmirrored_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
