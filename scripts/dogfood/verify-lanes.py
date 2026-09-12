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

The workflow is read with the standard library alone: a job is the block
under `  <id>:` at two spaces, a step the block under `      - name:` at six,
and a `run:` scalar is inline, a literal block (`|`) whose lines are
commands, or a folded block (`>`) that is one command. That is the whole
shape this workflow uses, and a shape it does not use fails the check
rather than being guessed at.
"""
from __future__ import annotations

import pathlib
import re
import sys

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


class Step:
    def __init__(self, name: str, run: list[str]) -> None:
        self.name = name
        self.run = run


def parse_jobs(text: str) -> dict[str, list[Step]]:
    """The workflow's jobs and their steps' run commands, from the file's own
    indentation: jobs at two spaces under `jobs:`, steps at six under
    `steps:`, and a `run:` scalar inline, literal or folded. Every item
    under `steps:` must be a named step (`- name:`); a step of another
    shape (`- run:`, `- uses:` first) fails the check rather than
    vanishing from it."""
    lines = text.splitlines()
    jobs: dict[str, list[Step]] = {}
    job: str | None = None
    in_jobs = False
    in_steps = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == "jobs:":
            in_jobs = True
            i += 1
            continue
        if not in_jobs:
            i += 1
            continue
        job_match = re.match(r"^  ([a-z][a-z0-9-]*):\s*$", line)
        if job_match:
            job = job_match.group(1)
            jobs[job] = []
            in_steps = False
            i += 1
            continue
        if re.match(r"^    [a-z_-]+:", line):
            in_steps = line.rstrip() == "    steps:"
            i += 1
            continue
        if in_steps and job is not None and line.startswith("      - ") and not line.startswith("      - name: "):
            raise SystemExit(f"unnamed step in job {job!r}: {line.strip()!r}; every Foundation step must carry a name")
        step_match = re.match(r"^      - name: (.*)$", line)
        if in_steps and step_match and job is not None:
            name = step_match.group(1).strip()
            run: list[str] = []
            i += 1
            while i < len(lines) and not re.match(r"^      - |^  [a-z][a-z0-9-]*:\s*$|^    [a-z_-]+:", lines[i]):
                run_match = re.match(r"^        run: (.*)$", lines[i])
                if run_match:
                    scalar = run_match.group(1).strip()
                    if scalar in ("|", "|-", ">", ">-"):
                        block: list[str] = []
                        i += 1
                        while i < len(lines) and (lines[i].startswith("          ") or not lines[i].strip()):
                            block.append(lines[i][10:])
                            i += 1
                        if scalar.startswith(">"):
                            run.append(" ".join(part.strip() for part in block if part.strip()))
                        else:
                            run.extend(part.strip() for part in block if part.strip())
                        continue
                    if scalar.startswith(("|", ">")):
                        raise SystemExit(f"unsupported run scalar in step {name!r}: {scalar!r}")
                    run.append(scalar)
                i += 1
            jobs[job].append(Step(name, run))
            continue
        i += 1
    return jobs


def lane_forms(command: str) -> tuple[str, ...]:
    return (
        command.replace("cargo +1.97.1", 'cargo "+${RUST_TOOLCHAIN}"'),
        command.replace("cargo +1.97.1", "cargo"),
    )


def without_comments(text: str) -> str:
    """Drop comment-only lines so a command mentioned in prose or commented
    out cannot satisfy the check."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def job_commands(steps: list[Step]) -> list[str]:
    commands: list[str] = []
    for step in steps:
        if RUNNER_STEP_NAMES.match(step.name):
            continue
        for raw in step.run:
            line = raw.strip().rstrip("\\").strip()
            if line and not line.startswith("#"):
                commands.append(line)
    return commands


def clojure_pin_matches(workflow_raw: str) -> str | None:
    """The Clojure CLI Foundation installs (setup-clojure's `cli:`) must be
    the one scripts/dogfood/versions.env pins; answers the mismatch, if any."""
    workflow_pins = set(re.findall(r"^\s+cli:\s*['\"]?([0-9][0-9.]+)['\"]?\s*$", workflow_raw, re.M))
    pins = (ROOT / "scripts/dogfood/versions.env").read_text()
    match = re.search(r'^CLOJURE_CLI_VERSION="([^"]+)"$', pins, re.M)
    lane_pin = match.group(1) if match else None
    if workflow_pins != {lane_pin}:
        return f"Foundation pins the Clojure CLI at {sorted(workflow_pins)}, the dogfood lanes at {lane_pin!r}"
    return None


def main() -> int:
    workflow_raw = WORKFLOW.read_text()
    if (mismatch := clojure_pin_matches(workflow_raw)) is not None:
        print(f"dogfood-lanes-drift: {mismatch}", file=sys.stderr)
        return 1
    jobs = parse_jobs(workflow_raw)
    workflow_text = without_comments(workflow_raw)
    failures: list[str] = []
    checked = 0
    for script, job_id in MIRRORED.items():
        steps = jobs.get(job_id)
        if steps is None:
            failures.append(f"{script}: Foundation has no job {job_id}")
            continue
        lane = without_comments((LANES / script).read_text())
        unmirrored = UNMIRRORED.get(script, {})
        commands = job_commands(steps)
        if not commands and script not in PINNED:
            failures.append(f"{script}: Foundation {job_id} yielded no commands; the parser or the job changed shape")
        for command in commands:
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
            if command not in commands:
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
