#!/usr/bin/env python3
"""Keep the UI browser gate's pins from drifting apart.

The gate is only fail-closed if the numbers that make it fail-closed agree with
each other. Three of them are written in three different files, and nothing else
would notice if one moved:

  * the assertion count pinned in `scripts/test-ui-browser.sh`,
  * the assertions `scripts/ui-browser/gate.py` actually emits,
  * the mutations in `scripts/ui-browser/mutations.json` that prove each one binds.

An assertion added without a mutation is unproved. A mutation naming an
assertion that no longer exists proves nothing. A pinned count that drifts above
the real one turns the count check into a permanent failure, and one that drifts
below lets assertions disappear silently -- which is the failure `UI-002` exists
to correct.

This runs in a second and needs no browser.
"""

import ast
import importlib.util
import json
import pathlib
import re
import sys


def emitted_assertions(gate_path):
    """Every literal name passed to self.assertion(...) in the gate."""
    tree = ast.parse(gate_path.read_text())
    names = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if not (isinstance(function, ast.Attribute) and function.attr == "assertion"):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            raise SystemExit(
                f"{gate_path.name}:{node.lineno}: assertion name is not a literal "
                "string, so it cannot be pinned or mutation-proved"
            )
        names.append(first.value)
    return names


def main():
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    gate_path = repo_root / "scripts" / "ui-browser" / "gate.py"
    runner_path = repo_root / "scripts" / "test-ui-browser.sh"
    mutations_path = repo_root / "scripts" / "ui-browser" / "mutations.json"
    pin_path = repo_root / "scripts" / "ui-browser" / "browser-pin.json"
    containerfile = repo_root / "scripts" / "ui-browser" / "Containerfile"
    workflow = repo_root / ".github" / "workflows" / "foundation.yml"

    failures = []

    names = emitted_assertions(gate_path)
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        failures.append(
            f"gate.py emits duplicate assertion names, so a failure could not be "
            f"attributed: {duplicates}"
        )
    emitted = set(names)

    runner = runner_path.read_text()
    match = re.search(r"^expected_assertions=(\d+)$", runner, re.MULTILINE)
    if not match:
        failures.append(f"{runner_path.name} does not pin expected_assertions")
        pinned = None
    else:
        pinned = int(match.group(1))
        if pinned != len(names):
            failures.append(
                f"{runner_path.name} pins {pinned} assertions but gate.py emits "
                f"{len(names)}"
            )

    # The pinned count must live in exactly one place. A second copy -- a
    # default in the mutation harness, say -- silently disagrees the moment an
    # assertion is added, and every gate run in the proof then fails the count
    # check instead of the mutation.
    harness = (repo_root / "scripts" / "test-ui-browser-mutations.py").read_text()
    stray = re.search(
        r'add_argument\(\s*"--expected-assertions".*?default\s*=\s*(\d+)',
        harness,
        re.DOTALL,
    )
    if stray:
        failures.append(
            f"test-ui-browser-mutations.py hardcodes a default assertion count "
            f"of {stray.group(1)}; the pin in {runner_path.name} is the only "
            "place that count may live"
        )

    spec = json.loads(mutations_path.read_text())
    mutations = spec["mutations"]
    # An assertion may carry several mutations. Requiring exactly one was itself
    # a way to leave a surface unproved: review found the build-panel and
    # live-refresh assertions each covered one call site while a second,
    # unasserted one sat beside it, and a one-mutation rule forbade closing that.
    covered = [m["assertion"] for m in mutations]
    unproved = sorted(emitted - set(covered))
    if unproved:
        failures.append(
            f"assertions with no mutation proving they bind: {unproved}"
        )
    orphaned = sorted(set(covered) - emitted)
    if orphaned:
        failures.append(
            f"mutations naming assertions the gate no longer emits: {orphaned}"
        )

    mutation_names = [m["name"] for m in mutations]
    if len(set(mutation_names)) != len(mutation_names):
        failures.append("mutations.json contains duplicate mutation names")

    # Every mutation must actually mutate the client it is aimed at, or it
    # "passes" by changing nothing.
    ui_dir = repo_root / "crates" / "controller-api" / "ui"
    for mutation in mutations:
        target = ui_dir / mutation["file"]
        try:
            source = target.read_text()
        except OSError as error:
            # A renamed or deleted client file must be reported alongside every
            # other coherence failure, not raised as a traceback that hides them.
            failures.append(
                f"mutation {mutation['name']}: cannot read {mutation['file']}: {error}"
            )
            continue
        if mutation["find"] not in source:
            failures.append(
                f"mutation {mutation['name']}: its find text is absent from "
                f"{mutation['file']}, so it would mutate nothing"
            )
        elif mutation["find"] == mutation["replace"]:
            failures.append(
                f"mutation {mutation['name']}: replaces its find text with itself"
            )

    pin = json.loads(pin_path.read_text())
    for component in ("chrome", "chromedriver"):
        digest = pin["downloads"][component]["sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            failures.append(f"browser pin for {component} is not a SHA-256 digest")
        version = pin["chrome_for_testing_version"]
        if version not in pin["downloads"][component]["url"]:
            failures.append(
                f"browser pin for {component} points at a URL that is not the "
                f"pinned version {version}"
            )
    base_digest = pin["base_image"]["manifest_digest"]
    if base_digest not in containerfile.read_text():
        failures.append(
            "the Containerfile's base image is not the digest pinned in "
            "browser-pin.json"
        )

    # The lane is conditional, so the thing that decides whether it runs is now
    # part of the gate. A classifier watching a path that no longer exists
    # watches nothing, and the lane it guards stops being re-proved silently.
    impact_spec = importlib.util.spec_from_file_location(
        "ui_browser_impact", repo_root / "scripts" / "ui-browser-impact.py"
    )
    impact = importlib.util.module_from_spec(impact_spec)
    assert impact_spec.loader is not None
    impact_spec.loader.exec_module(impact)
    watched = (
        impact.GATE_DEFINITION_PATHS
        | impact.CLIENT_PATHS
        | impact.SERVING_PATHS
        | impact.BUILD_INPUT_PATHS
    )
    absent = sorted(path for path in watched if not (repo_root / path).is_file())
    absent += sorted(
        prefix
        for prefix in impact.SERVING_PREFIXES
        if not (repo_root / prefix.rstrip("/")).is_dir()
    )
    if absent:
        failures.append(
            f"the impact classifier watches paths that do not exist, so those "
            f"changes could never trigger the lane: {absent}"
        )
    if impact.MUTATION_LINE_THRESHOLD < 1:
        failures.append(
            "the mutation line threshold is not positive, which waives the "
            "mutation proof for every client change"
        )

    # --record-only exists to capture a pre-repair baseline, where the failures
    # are the evidence. In CI it would turn the gate into a reporter.
    workflow_text = workflow.read_text()
    if "test-ui-browser.sh" not in workflow_text:
        failures.append("foundation.yml does not run the browser gate at all")
    if "scripts/ui-browser-impact.py" not in workflow_text:
        failures.append(
            "foundation.yml does not run the impact classifier, so the "
            "conditional lane has nothing deciding whether it should run"
        )
    if "needs.ui-impact.outputs.run-ui-gate == 'true'" not in workflow_text:
        failures.append(
            "the ui-browser lane is not gated on the classifier's decision"
        )
    if "needs.ui-impact.outputs.run-ui-mutations == 'true'" not in workflow_text:
        failures.append(
            "the mutation proof is not gated on the classifier's decision"
        )
    for line in workflow_text.splitlines():
        if "--record-only" in line and not line.lstrip().startswith("#"):
            failures.append(
                "foundation.yml passes --record-only, which would let the "
                f"browser gate report failures instead of failing: {line.strip()!r}"
            )

    # Four separate review rounds caught a retained evidence README stating a
    # count its own gate-results.json contradicted. Fixing the instances did not
    # stop it recurring, because nothing read the two together. This does: each
    # retained README must contain the verdict string derived from the JSON
    # beside it, so a changed count forces the prose to move with it.
    evidence = repo_root / "docs" / "evidence"
    for name in ("ui-002-browser-v1", "ui-002-browser-v2"):
        directory = evidence / name
        try:
            verdict = json.loads((directory / "gate-results.json").read_text())
            readme = (directory / "README.md").read_text()
        except (OSError, json.JSONDecodeError) as error:
            failures.append(f"{name}: cannot read its retained evidence: {error}")
            continue
        expected = f"{verdict['passed']} of {verdict['observed_assertions']} assertions passed"
        if expected not in readme:
            failures.append(
                f"{name}/README.md does not state the verdict its own "
                f"gate-results.json records ({expected!r})"
            )
    try:
        mutation = json.loads((evidence / "ui-002-mutation-v1" / "mutation-results.json").read_text())
        mutation_readme = (evidence / "ui-002-mutation-v1" / "README.md").read_text()
    except (OSError, json.JSONDecodeError) as error:
        failures.append(f"ui-002-mutation-v1: cannot read its retained evidence: {error}")
    else:
        expected = f"{mutation['caught']} of {mutation['mutations_run']} caught"
        if expected not in mutation_readme:
            failures.append(
                f"ui-002-mutation-v1/README.md does not state the result its own "
                f"mutation-results.json records ({expected!r})"
            )
        if str(mutation["expected_assertions"]) not in mutation_readme:
            failures.append(
                f"ui-002-mutation-v1/README.md does not state the assertion count "
                f"its own mutation-results.json records "
                f"({mutation['expected_assertions']})"
            )

    if failures:
        for failure in failures:
            print(f"UI browser gate coherence failure: {failure}", file=sys.stderr)
        return 1

    print(
        f"UI browser gate coherence passed: {len(names)} assertions, "
        f"all pinned at {pinned} and all mutation-proved."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
