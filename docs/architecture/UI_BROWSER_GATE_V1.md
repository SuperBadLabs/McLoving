# UI browser gate v1

Status: accepted, 2026-09-10. Introduced by `UI-002`.

This record argues the browser driver and the isolation boundary the UI gate
runs inside. `UI-002` requires that "a browser driver is introduced deliberately,
pinned by version and digest, and the choice is argued rather than assumed" —
this is that argument.

## What the gate exists to correct

`UI-001` closed asserting that a browser journey gate proved the full desktop
flow, strict-YAML validation, the audit and explainability views, a clean
console, and a 390-pixel viewport without page overflow.

No such gate ran. `crates/controller-api/examples/ui_browser_fixture.rs` sat in
the tree unreferenced by any workflow, script or test, and the repository
contained no browser driver at all. The one executing check,
`static_ui_is_csp_locked_external_only_and_accessibility_structured`, asserts on
the served HTML **as text**. Text cannot observe a console, and it cannot observe
whether a 390-pixel viewport overflows. Two of the closure's claims were
therefore unfalsifiable, and `UI-001` is named in both exemption sets of the
closure-receipt verifier, so nothing would ever have noticed. This is the
absence-looks-like-success class the board has named repeatedly.

The static check is **retained**. It guards the CSP and the served-asset contract
cheaply and without a browser, and this gate does not replace it.

## The driver: pinned Chrome for Testing, driven over WebDriver classic

**Chosen:** Chrome for Testing 153.0.8010.36 plus the matching chromedriver,
pinned by URL and SHA-256 in `scripts/ui-browser/browser-pin.json`, driven from
`scripts/ui-browser/gate.py` over WebDriver classic.

The reasoning, in the order it actually mattered:

- **Nothing new enters the dependency surface.** WebDriver classic is HTTP and
  JSON, so the gate needs `urllib.request` and `json` and nothing else. Python 3
  is already a hard CI dependency — a dozen gates in `scripts/` are written in it.
  The repository gains a browser, not a toolchain.
- **Both halves are content-addressed.** Chrome for Testing publishes immutable
  versioned archive paths, so a recorded SHA-256 pins exactly what runs. This is
  the same shape as the existing actionlint digest pin in `foundation.yml` and
  the base-image digest pin in `compat/jenkins-worker/build-image.sh`.
  `build-image.sh` refuses to build on a mismatch and deletes the offending
  archive so a later run cannot inherit trust in it.
- **The console is reachable.** chromedriver's browser log endpoint surfaces
  uncaught exceptions and failed resource loads, which is what "clean console"
  has to mean. A driver that could not report the console would leave one of
  `UI-001`'s claims unprovable all over again.

**Playwright or Puppeteer, rejected.** Both would pull a `node_modules` tree into
a repository with no JavaScript toolchain. Their browser downloads are
version-pinned but the surrounding package tree is not digest-pinned without a
lockfile audit this ticket is not scoped to do, and the supply-chain surface is
large next to a 639-line client. They buy ergonomics the gate does not need.

**geckodriver and Firefox, rejected.** The shipped CSP and client are exercised
against Chromium, and the Firefox available on the development hosts is
snap-packaged, which is not digest-pinnable in the way the acceptance requires.
There is a real argument for cross-engine coverage; it is a separate ticket, and
this one is explicitly bounded to earning claims already made.

## The boundary: the container, not the browser's own sandbox

Chrome's renderer sandbox requires unprivileged user namespaces. Ubuntu 23.10+
restricts those through AppArmor (`kernel.apparmor_restrict_unprivileged_userns
= 1`), which covers both the development hosts and the CI runners, and Chrome
aborts at startup with `No usable sandbox!` rather than degrading quietly.

**Chosen:** the browser runs inside a rootless podman container, built from a
base image pinned by manifest digest. The container's namespaces are the
isolation boundary, and `--no-sandbox` is passed **only inside it**.

- It is the repository's existing idiom. Contained execution is how the Jenkins
  compiler worker, the release builder and the sequential runtime gates already
  isolate untrusted or environment-sensitive work.
- It mutates no host. The alternative that keeps Chrome's own sandbox is a named
  AppArmor profile granting `userns create,` — the shape
  `deploy/apparmor/mcloving-source-acquirer` already uses — but it requires a
  root profile load on every host and every CI runner before the gate can run at
  all. The container needs nothing but podman.
- It is honest about what it buys. Chrome's renderer sandbox defends against
  hostile page content. This gate loads exactly one origin: a fixture it starts
  itself, serving the repository's own client. Disabling that sandbox *inside a
  container* removes a defence against a threat the gate does not face, and the
  container still bounds the process, filesystem and user namespaces.

The container joins the host network namespace (`--network=host`). That is
deliberate: the fixture stays bound to `127.0.0.1` rather than being published on
a routable address for the browser's benefit. Loopback-only binding is the
stronger of the two properties available here.

`--userns=keep-id` maps the invoking user onto the image's runtime UID so the
gate writes its own evidence directory as itself; rootless podman would otherwise
map it to a subordinate UID that cannot write the mount.

## Fail-closed properties

- **The assertion count is pinned.** `--expected-assertions` is required, and a
  mismatch exits 65 — including under `--record-only`. A gate that quietly stops
  running assertions must fail rather than report success.
- **`--record-only` never runs in CI.** It exists to capture a pre-repair
  baseline, where the failures *are* the evidence. `scripts/validate-foundation.sh`
  asserts the workflow does not pass it, so the flag cannot drift into the
  enforcing path.
- **The package closure is pinned, not just the browser.** The image installs
  Chrome's shared-library closure from the same immutable Debian snapshot the
  base image was built from, which the base records in its own apt sources.
  Without that, `apt-get update` resolves whatever the archive holds that day, so
  one commit and one set of pinned Chrome archives could still yield different
  NSS, font, rendering and Python environments on different days — layout results
  could move, or the gate could break, with nothing in the repository having
  changed. Review found this; the digest pinning had covered the browser and the
  base image but stopped at the packages between them.
- **The image is rebuilt when its recipe changes.** The cached image is reused
  only when the browser digests *and* the SHA-256 of the Containerfile itself
  match what is pinned. Without the recipe digest, editing the Containerfile
  leaves a stale image that still carries matching browser digests, and the gate
  runs against an environment the repository no longer describes.
- **Every assertion is mutation-proved.** `scripts/ui-browser/mutations.json`
  names, for each of the 18 assertions, at least one client defect that breaks
  exactly what that assertion claims. `scripts/test-ui-browser-mutations.py`
  introduces each one and requires the named assertion to turn red, and refuses
  to read a verdict from a gate run that exited non-zero for any reason other
  than the assertion failures it was expecting.
- **An assertion may carry more than one mutation.** Requiring exactly one was
  itself a way to leave a surface unproved: review found the build-panel and
  live-refresh assertions each covering one call site while a second, unasserted
  one sat beside it, and a one-mutation rule forbade closing that.

## When the lane runs, and why it is allowed not to

This is the most expensive lane on the board: the mutation proof alone is
seventeen full browser runs, roughly twenty minutes. Running all of it on every
push buys nothing on the overwhelming majority of changes, which touch no UI at
all. So `scripts/ui-browser-impact.py` classifies each change into two separate
decisions.

| Decision | What it costs | When it is required |
|---|---|---|
| `run-ui-gate` | ~6 minutes | any change to the client, to `crates/controller-api/src/lib.rs` (which decides what is served), to `crates/pipeline-ir/` (the strict parser whose refusal wording one assertion checks), or to the gate's own definition |
| `run-ui-mutations` | ~20 minutes | any change to the gate's own definition, or a client change of at least `MUTATION_LINE_THRESHOLD` (20) changed lines |

They are separate because they protect different things. The gate proves the
**client** still behaves. The mutation proof proves the **assertions still
bind** — and an assertion stops binding either when the gate's definition
changes, or when the client drifts so far that a mutation no longer targets
anything real. **That second case is already refused on every single push**, in
the Architecture records lane, by `verify-ui-browser-gate.py`, which fails if any
mutation's find-text is absent from the client. So the expensive proof is
required when the definition moves, and otherwise only above a threshold.

The threshold is a judgement, and it is the one thing here that trades safety for
minutes. Twenty lines is about three percent of the 639-line client and is
smaller than the smallest of the three repairs `UI-002` itself made, so a change
of the size that has historically broken one of these assertions re-proves them
while a typo fix does not. **Lower it before raising it.**

### The waiver is explicit, never implicit

A skipped required check reads as a pass to branch protection. That is `TM-052`,
and it is exactly the hole a naive `paths:` filter would open here — a filtered
job reports `skipped`, and an aggregate that accepted `skipped` would accept a
lane that never ran for any reason at all, including a broken one.

So the lane is wired on the same pattern as the Windows agent, and
`require_foundation` enforces it:

- `ui-impact` is itself an **unconditional** lane. Its failure is caught before
  its decision is ever read, so a classifier that crashed after emitting
  `run-ui-gate=false` cannot waive anything.
- The decision must be one of exactly two literal strings. Empty, misspelled or
  missing is an error, not a waiver.
- `run-ui-gate=true` requires `ui-browser` to be **`success`**; `false` requires
  it to be **`skipped`**. Any other pairing — waived-but-failed,
  required-but-skipped — is a contradiction and is refused.
- A push with no usable predecessor (a new branch, a force push, the all-zero
  sentinel) has nothing to compare, so it runs the full lane rather than
  guessing.
- A classifier that cannot classify runs the full lane and says why, rather than
  answering `false`.

The complete decision-by-result cross product is enumerated in
`scripts/test-workflow-aggregate.py`, and
`scripts/test-ui-browser-impact.py` enumerates every gate-definition path rather
than sampling — a path silently dropped from that set is precisely how a gate
stops being re-proved.

## Evidence

- `docs/evidence/ui-002-browser-v1/` — the initial rendered baseline of the
  shipped client, before any repair, with its three failing assertions. Retained
  unchanged.
- `docs/evidence/ui-002-browser-v2/` — the accepted baseline, bound to the
  repaired client source. This is the baseline `UI-006` compares against.
- `docs/evidence/ui-002-mutation-v1/` — the mutation proof.

## What this gate does not cover

Assistive-technology behaviour is not checked mechanically. The gate asserts the
rendered structures screen readers consume — landmark roles, resolved accessible
names on every control, live-region attributes together with observed text
changes, and a visible focus ring at every keyboard stop — but it does not
observe what any screen reader announces. No assertion here should be read as
evidence that it did. `UI-001`'s original claim is qualified accordingly in
`docs/EXECUTION_BOARD.md`; see also the manual convention recorded there.

Cross-engine rendering is not covered: one pinned Chromium is the whole
population. A second engine belongs with the interface `UI-006` onwards builds,
not with the one this gate exists to pin down.

**The gate's own coverage is the thing most worth distrusting.** Its first
version made sixteen assertions, all passing and all mutation-proved, while the
entire artifact surface sat outside it — the fixture served `[]`, so
`renderArtifacts` never ran, and the focus repair claimed for it had no evidence
behind it. Nothing in the mutation proof could detect that, because a mutation
can only break code an assertion already reaches. Review caught it, and then caught the
same shape again one round later: the replacement assertion proved artifact rows
and Download controls *rendered* but never activated one, leaving the click
listener, the download URL and the response handling untested. When adding an
assertion here, ask which call sites it does *not* reach, prefer the surface that
changes on its own over the one a test can click, and go one step past
"it rendered" to "it did the thing".
