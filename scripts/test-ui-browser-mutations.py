#!/usr/bin/env python3
"""Mutation-prove the UI-002 browser gate to `HYG-002`'s standard.

An assertion that cannot fail is not a gate. For every assertion the browser
gate makes, `scripts/ui-browser/mutations.json` names a defect that breaks
exactly what that assertion claims to check. This harness introduces each one
against the shipped client, runs the gate, and requires the named assertion to
turn red. A mutation that leaves its assertion green is a harness failure, not a
curiosity: it means the claim is decoration.

The client source is restored on every exit path, including interruption.
"""

import argparse
import json
import pathlib
import signal
import subprocess
import sys
import tempfile

UI_FILES = ("index.html", "app.js", "app.css")


def run_gate(repo_root, output_dir, label, expected_assertions):
    """Run the gate without enforcing, and return its parsed verdict."""
    result = subprocess.run(
        [
            "bash",
            str(repo_root / "scripts" / "test-ui-browser.sh"),
            "--output-dir",
            str(output_dir),
            "--label",
            label,
            "--expected-assertions",
            str(expected_assertions),
            "--record-only",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    verdict_path = output_dir / "gate-results.json"
    if not verdict_path.exists():
        raise RuntimeError(
            f"gate produced no verdict for {label}\n"
            f"stdout:\n{result.stdout[-3000:]}\nstderr:\n{result.stderr[-3000:]}"
        )
    return json.loads(verdict_path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-assertions", type=int, default=16)
    parser.add_argument("--output-dir", type=pathlib.Path)
    parser.add_argument(
        "--only", action="append", default=[],
        help="run only the named mutation(s); for iterating, not for CI",
    )
    arguments = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    ui_dir = repo_root / "crates" / "controller-api" / "ui"
    spec = json.loads((repo_root / "scripts" / "ui-browser" / "mutations.json").read_text())
    mutations = spec["mutations"]
    if arguments.only:
        mutations = [m for m in mutations if m["name"] in arguments.only]
        if not mutations:
            print(f"no mutation matched {arguments.only}", file=sys.stderr)
            return 64

    output_dir = arguments.output_dir or pathlib.Path(
        tempfile.mkdtemp(prefix="mcloving-ui-mutations.")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    originals = {name: (ui_dir / name).read_bytes() for name in UI_FILES}

    def restore():
        for name, data in originals.items():
            (ui_dir / name).write_bytes(data)

    # `finally` covers a normal return and an exception, but not Ctrl-C from a
    # terminal or a `kill` from CI, and leaving the client mutated in the
    # working tree is exactly the kind of quiet corruption this repository keeps
    # finding. Restore on the signals that can be caught, then die as asked.
    def restore_and_exit(number, _frame):
        restore()
        print(
            f"\nsignal {number}: restored the client source before exiting",
            file=sys.stderr,
        )
        sys.exit(128 + number)

    for caught in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(caught, restore_and_exit)

    records = []
    try:
        # The unmutated client must pass everything first. Without this, a
        # mutation could "fail correctly" for a reason that had nothing to do
        # with the mutation.
        print("Baseline: unmutated client must pass every assertion", flush=True)
        baseline = run_gate(
            repo_root, output_dir / "baseline", "mutation-baseline",
            arguments.expected_assertions,
        )
        if baseline["failed"]:
            print(
                "unmutated client does not pass the gate; fix that before "
                f"mutation-proving: {baseline['failing_assertions']}",
                file=sys.stderr,
            )
            return 1
        print(f"  baseline clean: {baseline['passed']} assertions\n", flush=True)

        for index, mutation in enumerate(mutations, start=1):
            name, assertion = mutation["name"], mutation["assertion"]
            print(
                f"[{index}/{len(mutations)}] {name} -> expects {assertion} red",
                flush=True,
            )
            restore()
            target = ui_dir / mutation["file"]
            source = target.read_text()
            if mutation["find"] not in source:
                raise RuntimeError(
                    f"mutation {name}: its find text is absent from "
                    f"{mutation['file']}, so it mutates nothing"
                )
            target.write_text(source.replace(mutation["find"], mutation["replace"], 1))

            verdict = run_gate(
                repo_root, output_dir / name, f"mutation-{name}",
                arguments.expected_assertions,
            )
            failing = verdict["failing_assertions"]
            caught = assertion in failing
            collateral = [a for a in failing if a != assertion]
            records.append(
                {
                    "mutation": name,
                    "file": mutation["file"],
                    "expected_red": assertion,
                    "caught": caught,
                    "failing_assertions": failing,
                    "collateral_failures": collateral,
                }
            )
            status = "caught" if caught else "ESCAPED"
            detail = f", also red: {collateral}" if collateral else ""
            print(f"    {status}{detail}", flush=True)
    finally:
        restore()

    escaped = [r for r in records if not r["caught"]]
    summary = {
        "gate_protocol": "mcloving.ui.browser/1",
        "expected_assertions": arguments.expected_assertions,
        "mutations_run": len(records),
        "caught": len(records) - len(escaped),
        "escaped": [r["mutation"] for r in escaped],
        "results": records,
    }
    (output_dir / "mutation-results.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    print(
        f"\n{summary['caught']} of {summary['mutations_run']} mutations caught",
        flush=True,
    )
    print(f"Mutation evidence written to {output_dir}", flush=True)
    if escaped:
        print(
            "assertions that did not bind: "
            + ", ".join(f"{r['expected_red']} (mutation {r['mutation']})" for r in escaped),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
